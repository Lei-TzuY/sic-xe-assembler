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


class CrossDomainFixedPointTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cross-domain-")
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
        return analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )

    def test_store_load_constant_prunes_branch_after_memory_feedback(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA TEMP\n"
            "      LDA TEMP\n"
            "      COMP #5\n"
            "      JEQ TAKEN\n"
            "DEAD  LDA #9\n"
            "TAKEN RSUB\n"
            "TEMP  RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDA" and node.get("memory_cell_read"))
        dead = next(node for node in report["instructions"] if "DEAD" in node.get("symbols", ()))
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        fallthrough = next(edge for edge in report["edges"] if edge["source"] == branch["address"] and edge["kind"] == "fallthrough")

        self.assertEqual(load["memory_constant"], 5)
        self.assertEqual(load["memory_feedback"], "load")
        self.assertEqual(load["registers_out"]["A"], 5)
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["reason"], "condition-false")
        self.assertFalse(dead["reachable"])
        self.assertGreaterEqual(report["cross_domain_iterations"], 2)

    def test_memory_loaded_base_resolves_base_relative_control_target(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +LDA #FAR\n"
            "      STA BASEV\n"
            "      LDB BASEV\n"
            "      BASE FAR\n"
            "      J FAR\n"
            "BASEV RESW 1\n"
            "      RESB 4096\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        load_b = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        far = next(node for node in report["instructions"] if "FAR" in node.get("symbols", ()))

        self.assertEqual(load_b["memory_feedback"], "load")
        self.assertEqual(load_b["registers_out"]["B"], far["address"])
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "dataflow-base")
        self.assertTrue(any(edge["source"] == jump["address"] and edge.get("target") == far["address"] and edge["resolved"] for edge in report["edges"]))

    def test_memory_free_callee_preserves_precise_store_and_constant(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "ROUTN CLEAR X\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")

        self.assertEqual(call["memory_call_effect"]["may_write_cells"], [])
        self.assertFalse(call["memory_call_effect"]["unknown_write"])
        self.assertEqual(load["memory_sources"], [store["store_definition_id"]])
        self.assertEqual(load["memory_constant"], 5)
        self.assertFalse(any(source.startswith("MC") for source in load["memory_sources"]))

    def test_callee_clobbers_only_cells_it_may_write(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      LDA #7\n"
            "      STA OTHER\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      LDX OTHER\n"
            "      RSUB\n"
            "ROUTN LDA #9\n"
            "      STA OTHER\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "OTHER RESW 1\n"
            "      END ENTRY\n"
        )
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        loads = [node for node in report["instructions"] if node["base_mnemonic"] in ("LDB", "LDX")]
        slot_load = next(node for node in loads if node["base_mnemonic"] == "LDB")
        other_load = next(node for node in loads if node["base_mnemonic"] == "LDX")

        self.assertEqual(len(call["memory_call_effect"]["may_write_cells"]), 1)
        self.assertEqual(slot_load["memory_constant"], 5)
        self.assertFalse(any(source.startswith("MC") for source in slot_load["memory_sources"]))
        self.assertIsNone(other_load["memory_constant"])
        self.assertTrue(any(source.startswith("MC") for source in other_load["memory_sources"]))

    def test_nested_callee_memory_effects_compose(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA SLOT\n"
            "      +JSUB OUTER\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER LDA #2\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        outer_call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB" and node.get("target") is not None and any(summary.get("entry") == node.get("target") and "OUTER" in summary.get("symbols", ()) for summary in report["memory_subroutines"]))
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")

        self.assertEqual(len(outer_call["memory_call_effect"]["may_write_cells"]), 1)
        self.assertIsNone(load["memory_constant"])
        self.assertTrue(any(source.startswith("MC") for source in load["memory_sources"]))

    def test_memory_feedback_surfaces_in_metrics(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #3\n"
            "      STA TEMP\n"
            "      LDA TEMP\n"
            "      ADD #2\n"
            "      STA TEMP\n"
            "      LDB TEMP\n"
            "      RSUB\n"
            "TEMP  RESW 1\n"
            "      END ENTRY\n"
        )
        self.assertGreaterEqual(report["metrics"]["memory_feedback_instructions"], 2)
        self.assertGreaterEqual(report["metrics"]["cross_domain_iterations"], 2)
        self.assertGreaterEqual(report["metrics"]["memory_subroutines"], 0)


if __name__ == "__main__":
    unittest.main()
