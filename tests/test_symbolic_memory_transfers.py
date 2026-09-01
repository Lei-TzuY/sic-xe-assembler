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


class SymbolicMemoryTransferTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-symbolic-memory-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        linked = self.run_script(LOADER, source.with_suffix(".obj"), progaddr)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(
            source.with_suffix(".manifest.json").read_text(encoding="utf-8")
        )
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        report = analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )
        return source, report

    def entry_for(self, report, symbol):
        return next(
            node["address"]
            for node in report["instructions"]
            if symbol in node.get("symbols", ())
        )

    def summary_for(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return next(
            summary
            for summary in report["symbolic_memory_transfer_summaries"]
            if summary["entry"] == entry
        )

    def slot_cell(self, report, symbol="SLOT"):
        address = next(
            region["loaded_address"]
            for section in report.get("source_map", {}).get("sections", ())
            for region in section.get("regions", ())
            if symbol in region.get("symbols", ())
        ) if report.get("source_map") else None
        if address is None:
            store = next(
                node
                for node in report["instructions"]
                if node["base_mnemonic"] in ("STA", "STB", "STX", "STS", "STT", "STL")
                and node.get("target") is not None
            )
            address = store["target"]
        return f"{address:05X}+3"

    def load_before(self, report, instruction):
        return max(
            (
                node for node in report["instructions"]
                if node["base_mnemonic"] == "LDA"
                and node["address"] < instruction["address"]
            ),
            key=lambda node: node["address"],
        )

    def test_multivariate_memory_return_instantiates_and_prunes_branch(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #9\n"
            "      LDX #1\n"
            "      +JSUB SETVAL\n"
            "      LDA #1\n"
            "      LDX #2\n"
            "      +JSUB SETVAL\n"
            "      CLEAR A\n"
            "      LDA SLOT\n"
            "      COMP #3\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "SETVAL ADDR X,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "SETVAL")
        cell = self.slot_cell(report)
        spec = summary["return_memory_linear_transfers"][cell]
        self.assertEqual(spec["kind"], "linear")
        self.assertEqual(spec["coefficients"], {"A": 1, "X": 1})
        calls = [node for node in report["instructions"] if node["base_mnemonic"] == "JSUB"]
        self.assertEqual(calls[-1]["symbolic_memory_instantiation"]["exact"][cell], 3)
        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        load = self.load_before(report, compare)
        self.assertEqual(load["memory_constant"], 3)
        self.assertEqual(compare["registers_in"]["A"], 3)
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "symbolic-memory-condition")

    def test_multivariate_memory_formula_instantiates_caller_range(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #20\n"
            "      CLEAR X\n"
            "      +JSUB SETVAL\n"
            "      COMP FLAG\n"
            "      JEQ ONE\n"
            "      LDA #2\n"
            "      J JOIN\n"
            "ONE   LDA #1\n"
            "JOIN  LDX #3\n"
            "      +JSUB SETVAL\n"
            "      CLEAR A\n"
            "      LDA SLOT\n"
            "      COMP #10\n"
            "      JLT GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "SETVAL ADDR X,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "FLAG  RESW 1\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        cell = self.slot_cell(report)
        calls = [node for node in report["instructions"] if node["base_mnemonic"] == "JSUB"]
        call = calls[-1]
        self.assertNotIn(cell, call["symbolic_memory_instantiation"]["exact"])
        self.assertEqual(call["symbolic_memory_instantiation"]["ranges"][cell], [4, 5])
        compare = max(
            (node for node in report["instructions"] if node["base_mnemonic"] == "COMP"),
            key=lambda node: node["address"],
        )
        load = self.load_before(report, compare)
        self.assertIsNone(load["memory_constant"])
        self.assertEqual(load["memory_range"], [4, 5])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JLT")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "symbolic-memory-range-condition")

    def test_symbolic_memory_value_can_resolve_base_relative_target(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #1\n"
            "      +JSUB SETVAL\n"
            "      +LDA #0x3FFF\n"
            "      LDX #1\n"
            "      +JSUB SETVAL\n"
            "      CLEAR B\n"
            "      LDB SLOT\n"
            "      BASE 0\n"
            "      J FAR\n"
            "SETVAL ADDR X,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        cell = self.slot_cell(report)
        calls = [node for node in report["instructions"] if node["base_mnemonic"] == "JSUB"]
        self.assertEqual(calls[-1]["symbolic_memory_instantiation"]["exact"][cell], 0x4000)
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        far = next(node for node in report["instructions"] if "FAR" in node.get("symbols", ()))
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "symbolic-memory-base")

    def test_nested_memory_formula_is_not_consumed_without_link_proof(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB OUTER\n"
            "      CLEAR A\n"
            "      LDA SLOT\n"
            "      COMP #3\n"
            "      JEQ MAYBE\n"
            "      LDA #9\n"
            "MAYBE RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER ADDR X,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        outer = self.summary_for(report, "OUTER")
        cell = self.slot_cell(report)
        self.assertIn(cell, outer["return_memory_linear_transfers"])
        self.assertFalse(outer["link_register_preserved"])
        call = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB" and node.get("target") == outer["entry"]
        )
        self.assertNotIn("symbolic_memory_instantiation", call)

    def test_partial_store_path_does_not_invent_memory_formula(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB MAYSET\n"
            "      RSUB\n"
            "MAYSET COMP FLAG\n"
            "      JEQ DONE\n"
            "      ADDR X,A\n"
            "      STA SLOT\n"
            "DONE  RSUB\n"
            "FLAG  RESW 1\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSET")
        cell = self.slot_cell(report)
        self.assertNotIn(cell, summary["return_memory_linear_transfers"])

    def test_five_source_memory_expression_degrades_to_unknown(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB WIDE\n"
            "      RSUB\n"
            "WIDE  ADDR X,A\n"
            "      ADDR B,A\n"
            "      ADDR S,A\n"
            "      ADDR T,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "WIDE")
        cell = self.slot_cell(report)
        self.assertNotIn(cell, summary["return_memory_linear_transfers"])

    def test_constant_memory_postcondition_stays_in_legacy_layer_and_report_surfaces_new_layer(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB SETSYM\n"
            "      +JSUB SETCONST\n"
            "      RSUB\n"
            "SETSYM ADDR X,A\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SETCONST LDA #7\n"
            "      STA FIXED\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "FIXED RESW 1\n"
            "      END ENTRY\n"
        )
        symbolic = self.summary_for(report, "SETSYM")
        fixed_entry = self.entry_for(report, "SETCONST")
        legacy_fixed = next(
            summary for summary in report["memory_effect_summaries"]
            if summary["entry"] == fixed_entry
        )
        new_fixed = next(
            summary for summary in report["symbolic_memory_transfer_summaries"]
            if summary["entry"] == fixed_entry
        )
        self.assertTrue(symbolic["return_memory_linear_transfers"])
        self.assertTrue(legacy_fixed["return_constants"])
        self.assertFalse(new_fixed["return_memory_linear_transfers"])
        rendered = render_control_flow_report(report)
        self.assertIn("SYMBOLIC MEMORY CALL TRANSFERS", rendered)
        self.assertIn("memory=", rendered)
        self.assertTrue(report["symbolic_memory_transfers"]["converged"])
        self.assertGreaterEqual(report["metrics"]["symbolic_memory_return_transfers"], 1)


if __name__ == "__main__":
    unittest.main()
