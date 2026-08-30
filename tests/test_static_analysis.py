import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from control_flow import analyze_control_flow, render_control_flow_report
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class StaticDataflowCfgTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def build(self, source_text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-static-analysis-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(source_text, encoding="utf-8")
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
        return source, manifest, debug, report

    def test_ldb_constant_resolves_base_relative_jump(self):
        _, _, _, report = self.build(
            "MAIN START 0\n"
            "     +LDB #FAR\n"
            "     BASE FAR\n"
            "     J FAR\n"
            "     RESB 4096\n"
            "FAR  RSUB\n"
            "     END MAIN\n"
        )
        nodes = {node["address"]: node for node in report["instructions"]}
        load = nodes[0x4000]
        jump = nodes[0x4004]
        far = next(node for node in report["instructions"] if "FAR" in node["symbols"])

        self.assertEqual(load["registers_out"]["B"], far["address"])
        self.assertEqual(jump["registers_in"]["B"], far["address"])
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "dataflow-base")
        self.assertEqual(jump["base_value"], far["address"])
        edge = next(edge for edge in report["edges"] if edge["source"] == jump["address"])
        self.assertTrue(edge["resolved"])
        self.assertEqual(edge["target"], far["address"])
        self.assertEqual(edge["resolution"], "dataflow-base")
        self.assertTrue(far["reachable"])

        text = render_control_flow_report(report)
        self.assertIn("target-resolution=dataflow-base", text)
        self.assertIn(f"B={far['address']:06X}", text)

    def test_rmo_propagates_constant_into_base_register(self):
        _, _, _, report = self.build(
            "MAIN START 0\n"
            "     +LDA #FAR\n"
            "     RMO A,B\n"
            "     BASE FAR\n"
            "     J FAR\n"
            "     RESB 4096\n"
            "FAR  RSUB\n"
            "     END MAIN\n"
        )
        far = next(node for node in report["instructions"] if "FAR" in node["symbols"])
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        self.assertEqual(jump["registers_in"]["A"], far["address"])
        self.assertEqual(jump["registers_in"]["B"], far["address"])
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "dataflow-base")

    def test_conflicting_base_values_join_to_unknown(self):
        _, _, _, report = self.build(
            "MAIN START 0\n"
            "     JEQ LEFT\n"
            "     +LDB #ONE\n"
            "     J MERGE\n"
            "LEFT +LDB #TWO\n"
            "     BASE TARGET\n"
            "MERGE J TARGET\n"
            "ONE  WORD 1\n"
            "TWO  WORD 2\n"
            "     RESB 4096\n"
            "TARGET RSUB\n"
            "     END MAIN\n"
        )
        merge = next(node for node in report["instructions"] if "MERGE" in node["symbols"])
        target = next(node for node in report["instructions"] if "TARGET" in node["symbols"])
        self.assertIsNone(merge["registers_in"]["B"])
        self.assertIsNone(merge["target"])
        self.assertNotIn("target_resolution", merge)
        edge = next(edge for edge in report["edges"] if edge["source"] == merge["address"])
        self.assertFalse(edge["resolved"])
        self.assertEqual(edge["reason"], "unresolved-addressing")
        self.assertFalse(target["reachable"])

    def test_dominators_natural_loop_and_complexity(self):
        _, _, _, report = self.build(
            "MAIN START 0\n"
            "LOOP LDA #1\n"
            "     JEQ DONE\n"
            "     J LOOP\n"
            "DONE RSUB\n"
            "     END MAIN\n"
        )
        self.assertEqual(report["metrics"]["cyclomatic_complexity"], 2)
        self.assertEqual(report["metrics"]["decision_points"], 1)
        self.assertEqual(report["metrics"]["natural_loops"], 1)
        self.assertEqual(len(report["back_edges"]), 1)
        self.assertEqual(len(report["loops"]), 1)

        entry_block = report["entry_block"]
        loop = report["loops"][0]
        self.assertEqual(loop["header"], entry_block)
        self.assertIn(entry_block, loop["blocks"])
        for block in report["blocks"]:
            if block["reachable"]:
                self.assertIn(entry_block, block["dominators"])

    def test_call_graph_preserves_resolved_subroutine_target(self):
        _, _, _, report = self.build(
            "MAIN START 0\n"
            "     JSUB ROUTN\n"
            "     RSUB\n"
            "ROUTN RSUB\n"
            "     END MAIN\n"
        )
        self.assertEqual(len(report["calls"]), 1)
        call = report["calls"][0]
        self.assertTrue(call["resolved"])
        self.assertIn("ROUTN", call["target_symbols"])
        self.assertEqual(call["caller_section"], "MAIN")
        self.assertEqual(call["callee_section"], "MAIN")
        self.assertIsNotNone(call["source_block"])
        self.assertIsNotNone(call["target_block"])


if __name__ == "__main__":
    unittest.main()
