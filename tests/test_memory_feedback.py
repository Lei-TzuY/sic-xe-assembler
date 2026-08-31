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


class IntegratedMemoryFeedbackTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-memory-feedback-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, progaddr)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(
            source.with_suffix(".manifest.json").read_text(encoding="utf-8")
        )
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        return analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )

    def test_memory_constant_flows_back_into_condition_and_prunes_dead_path(self):
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
        load = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "LDA" and node.get("memory_cell_read")
        )
        dead = next(node for node in report["instructions"] if "DEAD" in node["symbols"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )

        self.assertEqual(load["memory_constant"], 5)
        self.assertEqual(load["registers_out"]["A"], 5)
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["reason"], "condition-false")
        self.assertEqual(fallthrough["resolution"], "memory-feedback-condition")
        self.assertFalse(dead["reachable"])
        self.assertGreaterEqual(report["metrics"]["memory_feedback_pruned_edges"], 1)

    def test_memory_interval_flows_back_when_exact_value_is_unknown(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA SOURCE\n"
            "      AND #1\n"
            "      STA TEMP\n"
            "      LDA TEMP\n"
            "      COMP #10\n"
            "      JLT TAKEN\n"
            "DEAD  LDA #9\n"
            "TAKEN RSUB\n"
            "SOURCE RESW 1\n"
            "TEMP  RESW 1\n"
            "      END ENTRY\n"
        )
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        load = max(
            (
                node for node in report["instructions"]
                if node["base_mnemonic"] == "LDA" and node.get("memory_cell_read")
            ),
            key=lambda node: node["address"],
        )
        dead = next(node for node in report["instructions"] if "DEAD" in node["symbols"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JLT")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )

        self.assertIsNone(store["stored_constant"])
        self.assertEqual(store["stored_range"], [0, 1])
        self.assertIsNone(load["memory_constant"])
        self.assertEqual(load["memory_range"], [0, 1])
        self.assertEqual(load["ranges_out"]["A"], (0, 1))
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "memory-feedback-range-condition")
        self.assertFalse(dead["reachable"])

    def test_callee_summary_preserves_unwritten_cell_and_constant(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "ROUTN LDA #1\n"
            "      STA OTHER\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "OTHER RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(item for item in report["calls"] if item["resolved"])
        summary = call["memory_effect_summary"]

        self.assertEqual(load["memory_constant"], 5)
        self.assertEqual(load["registers_out"]["B"], 5)
        self.assertFalse(summary["unknown_write"])
        self.assertEqual(len(summary["may_write_cells"]), 1)
        self.assertNotIn(load["memory_cell_read"], summary["may_write_cells"])

    def test_callee_write_clobbers_only_the_written_cell(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "ROUTN LDA #1\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(item for item in report["calls"] if item["resolved"])
        summary = call["memory_effect_summary"]
        cell = load["memory_cell_read"]

        self.assertIn(cell, summary["may_write_cells"])
        self.assertEqual(summary["return_constants"][cell], 1)
        self.assertEqual(load["memory_constant"], 1)
        self.assertEqual(load["registers_out"]["B"], 1)
        # The may-reaching store layer remains conservative even while the
        # independent must-value layer proves the callee's return value.
        self.assertTrue(any(source.startswith("MC") for source in load["memory_sources"]))

    def test_nested_callee_memory_summaries_compose(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #7\n"
            "      STA SLOT\n"
            "      +JSUB OUTER\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER LDA #1\n"
            "      STA OTHER\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "OTHER RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        outer = next(
            item for item in report["memory_effect_summaries"]
            if any(
                "OUTER" in node.get("symbols", ())
                for node in report["instructions"]
                if node["address"] == item["entry"]
            )
        )
        self.assertFalse(outer["unknown_write"])
        self.assertNotIn(load["memory_cell_read"], outer["may_write_cells"])
        self.assertEqual(load["memory_constant"], 7)

    def test_unknown_alias_inside_callee_falls_back_to_all_cells(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "ROUTN CLEAR X\n"
            "      STX SLOT,X\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(item for item in report["calls"] if item["resolved"])
        self.assertTrue(call["memory_effect_summary"]["unknown_write"])
        self.assertIsNone(load["memory_constant"])
        self.assertTrue(any(source.startswith("MC") for source in load["memory_sources"]))

    def test_report_surfaces_feedback_and_memory_effect_summaries(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA SLOT\n"
            "      LDA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("MEMORY FEEDBACK", rendered)
        self.assertIn("converged=true", rendered)
        self.assertGreaterEqual(report["memory_feedback"]["iterations"], 2)


if __name__ == "__main__":
    unittest.main()
