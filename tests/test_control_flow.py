import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from debug_analysis import build_control_flow_graph, render_control_flow_graph
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class ControlFlowTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def make_program(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cfg-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "flow.asm"
        source.write_text(
            "MAIN START 0\n"
            "ENTRY LDA #0\n"
            "      JEQ ZERO\n"
            "      JSUB SUBR\n"
            "      J DONE\n"
            "DEAD  LDX #9\n"
            "ZERO  LDX #1\n"
            "DONE  RSUB\n"
            "SUBR  CLEAR A\n"
            "      RSUB\n"
            "      END ENTRY\n",
            encoding="utf-8",
        )
        return source

    def build_graph(self):
        source = self.make_program()
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        graph = build_control_flow_graph(
            image,
            0x4000,
            debug,
            entry_address=0x4000,
        )
        return source, graph

    def test_cfg_splits_branch_call_jump_return_and_unreachable_blocks(self):
        _, graph = self.build_graph()
        self.assertEqual(graph["instruction_count"], 9)
        self.assertEqual(graph["block_count"], 7)
        self.assertEqual(graph["reachable_block_count"], 6)
        self.assertEqual(graph["unresolved_edge_count"], 0)
        self.assertIsNotNone(graph["entry_block"])

        by_start = {block["start"]: block for block in graph["blocks"]}
        entry = by_start[0x4000]
        self.assertEqual(
            [edge["kind"] for edge in entry["successors"]],
            ["branch", "fallthrough"],
        )
        self.assertEqual(
            [edge["target"] for edge in entry["successors"]],
            [0x400F, 0x4006],
        )

        call = by_start[0x4006]
        self.assertEqual(
            [edge["kind"] for edge in call["successors"]],
            ["call", "fallthrough"],
        )
        self.assertEqual(call["successors"][0]["target"], 0x4015)
        self.assertEqual(call["successors"][1]["target"], 0x4009)

        jump = by_start[0x4009]
        self.assertEqual(len(jump["successors"]), 1)
        self.assertEqual(jump["successors"][0]["kind"], "branch")
        self.assertEqual(jump["successors"][0]["target"], 0x4012)

        dead = by_start[0x400C]
        self.assertFalse(dead["reachable"])
        self.assertTrue(by_start[0x400F]["reachable"])
        self.assertTrue(by_start[0x4012]["reachable"])
        self.assertTrue(by_start[0x4015]["reachable"])

    def test_cfg_renderer_includes_blocks_edges_and_source_provenance(self):
        _, graph = self.build_graph()
        text = render_control_flow_graph(graph)
        self.assertIn("SIC/XE CONTROL FLOW GRAPH", text)
        self.assertIn("reachable=no symbols=DEAD", text)
        self.assertIn("-> branch", text)
        self.assertIn("-> call", text)
        self.assertIn("-> return", text)
        self.assertIn("source=2", text)
        self.assertTrue(text.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
