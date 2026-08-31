import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from control_flow import analyze_control_flow
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class ConditionInterproceduralTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-condition-interprocedural-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, progaddr)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(source.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        report = analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )
        return source, report

    def test_proven_equal_compare_prunes_conditional_fallthrough(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     LDA #5\n"
            "     COMP #5\n"
            "     JEQ TAKEN\n"
            "DEAD LDA #9\n"
            "TAKEN RSUB\n"
            "     END MAIN\n"
        )
        jeq = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        self.assertEqual(jeq["registers_in"]["CC"], "EQ")
        fallthrough = next(edge for edge in report["edges"] if edge["source"] == jeq["address"] and edge["kind"] == "fallthrough")
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["reason"], "condition-false")
        self.assertEqual(fallthrough["resolution"], "abstract-condition")
        dead = next(node for node in report["instructions"] if "DEAD" in node["symbols"])
        self.assertFalse(dead["reachable"])

    def test_proven_unequal_compare_prunes_taken_branch(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     LDA #4\n"
            "     COMP #5\n"
            "     JEQ TAKEN\n"
            "FALL LDA #1\n"
            "     J DONE\n"
            "TAKEN LDA #2\n"
            "DONE RSUB\n"
            "     END MAIN\n"
        )
        jeq = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        self.assertEqual(jeq["registers_in"]["CC"], "LT")
        branch = next(edge for edge in report["edges"] if edge["source"] == jeq["address"] and edge["kind"] == "branch")
        fallthrough = next(edge for edge in report["edges"] if edge["source"] == jeq["address"] and edge["kind"] == "fallthrough")
        self.assertFalse(branch["resolved"])
        self.assertEqual(branch["reason"], "condition-false")
        self.assertTrue(fallthrough["resolved"])
        taken = next(node for node in report["instructions"] if "TAKEN" in node["symbols"])
        self.assertFalse(taken["reachable"])

    def test_unknown_memory_compare_keeps_both_conditional_edges(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     LDA #4\n"
            "     COMP VALUE\n"
            "     JEQ TAKEN\n"
            "FALL LDA #1\n"
            "     J DONE\n"
            "TAKEN LDA #2\n"
            "DONE RSUB\n"
            "VALUE RESW 1\n"
            "     END MAIN\n"
        )
        jeq = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        self.assertIsNone(jeq["registers_in"]["CC"])
        outgoing = [edge for edge in report["edges"] if edge["source"] == jeq["address"]]
        self.assertEqual({edge["kind"] for edge in outgoing}, {"branch", "fallthrough"})
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_tixr_proves_condition_code_and_prunes_edge(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     CLEAR X\n"
            "     LDT #1\n"
            "     TIXR T\n"
            "     JEQ DONE\n"
            "DEAD LDA #9\n"
            "DONE RSUB\n"
            "     END MAIN\n"
        )
        tixr = next(node for node in report["instructions"] if node["base_mnemonic"] == "TIXR")
        self.assertEqual(tixr["registers_out"]["X"], 1)
        self.assertEqual(tixr["registers_out"]["CC"], "EQ")
        dead = next(node for node in report["instructions"] if "DEAD" in node["symbols"])
        self.assertFalse(dead["reachable"])

    def test_callee_summary_preserves_base_for_post_call_resolution(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     +LDB #FAR\n"
            "     BASE FAR\n"
            "     +JSUB ROUTN\n"
            "     J FAR\n"
            "     RESB 4096\n"
            "FAR  RSUB\n"
            "ROUTN LDA #1\n"
            "      RSUB\n"
            "     END MAIN\n"
        )
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        self.assertIsNotNone(jump["target"])
        self.assertEqual(jump["target_resolution"], "dataflow-base")

    def test_callee_constant_base_write_replaces_pre_call_base(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     +LDB #FAR\n"
            "     BASE FAR\n"
            "     +JSUB ROUTN\n"
            "     J FAR\n"
            "     RESB 4096\n"
            "FAR  RSUB\n"
            "ROUTN CLEAR B\n"
            "      RSUB\n"
            "     END MAIN\n"
        )
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        self.assertEqual(jump["registers_in"]["B"], 0)
        self.assertEqual(jump["target"], 0)
        self.assertEqual(jump.get("target_resolution"), "register-postcondition-base")
        edge = next(
            edge for edge in report["edges"]
            if edge["source"] == jump["address"] and edge["kind"] == "jump"
        )
        self.assertFalse(edge["resolved"])
        self.assertEqual(edge["target"], 0)


if __name__ == "__main__":
    unittest.main()
