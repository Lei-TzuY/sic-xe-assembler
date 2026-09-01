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


class SparseLinearTransferTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-sparse-linear-")
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
        return report

    def entry_for(self, report, symbol):
        return next(
            node["address"]
            for node in report["instructions"]
            if symbol in node.get("symbols", ())
        )

    def sparse_summary_for(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return next(
            summary
            for summary in report["sparse_linear_transfer_summaries"]
            if summary["entry"] == entry
        )

    def test_multivariate_addr_is_instantiated_and_prunes_branch(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB MIXER\n"
            "      COMP #3\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "MIXER ADDR X,A\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.sparse_summary_for(report, "MIXER")
        self.assertEqual(
            summary["return_linear_transfers"]["A"],
            {
                "kind": "linear",
                "coefficients": {"A": 1, "X": 1},
                "offset": 0,
                "modulus": 1 << 24,
            },
        )
        legacy = next(
            item
            for item in report["register_transfer_summaries"]
            if item["entry"] == summary["entry"]
        )
        self.assertNotIn("A", legacy.get("return_transfers") or {})

        call = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
        )
        self.assertEqual(call["sparse_linear_instantiation"]["exact"]["A"], 3)
        compare = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
        )
        self.assertEqual(compare["registers_in"]["A"], 3)
        branch = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JEQ"
        )
        fallthrough = next(
            edge
            for edge in report["edges"]
            if edge["source"] == branch["address"]
            and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "sparse-linear-condition")
        dead = next(
            node
            for node in report["instructions"]
            if "DEAD" in node.get("symbols", ())
        )
        self.assertFalse(dead["reachable"])

    def test_multivariate_formula_shifts_caller_range(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY COMP FLAG\n"
            "      JEQ ONE\n"
            "      LDA #2\n"
            "      J JOIN\n"
            "ONE   LDA #1\n"
            "JOIN  LDX #3\n"
            "      +JSUB MIXER\n"
            "      COMP #10\n"
            "      JLT GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "MIXER ADDR X,A\n"
            "      RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        call = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
        )
        self.assertNotIn("A", call["sparse_linear_instantiation"]["exact"])
        self.assertEqual(
            call["sparse_linear_instantiation"]["ranges"]["A"],
            [4, 5],
        )
        compares = [
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
        ]
        compare = max(compares, key=lambda node: node["address"])
        self.assertEqual(compare["ranges_in"]["A"], (4, 5))
        branch = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JLT"
        )
        fallthrough = next(
            edge
            for edge in report["edges"]
            if edge["source"] == branch["address"]
            and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "sparse-linear-range-condition",
        )

    def test_multivariate_return_can_resolve_base_target(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +LDA #0x3FFF\n"
            "      LDX #1\n"
            "      +JSUB SETB\n"
            "      BASE 0\n"
            "      J FAR\n"
            "SETB  RMO A,B\n"
            "      ADDR X,B\n"
            "      RSUB\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.sparse_summary_for(report, "SETB")
        self.assertEqual(
            summary["return_linear_transfers"]["B"]["coefficients"],
            {"A": 1, "X": 1},
        )
        jump = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "J"
        )
        far = next(
            node
            for node in report["instructions"]
            if "FAR" in node.get("symbols", ())
        )
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "sparse-linear-base")

    def test_nested_multivariate_summary_composes_but_respects_link_gate(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB OUTER\n"
            "      COMP #4\n"
            "      JEQ MAYBE\n"
            "      LDA #9\n"
            "MAYBE RSUB\n"
            "OUTER +JSUB INNER\n"
            "      ADD #1\n"
            "      RSUB\n"
            "INNER ADDR X,A\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        outer = self.sparse_summary_for(report, "OUTER")
        self.assertEqual(
            outer["return_linear_transfers"]["A"],
            {
                "kind": "linear",
                "coefficients": {"A": 1, "X": 1},
                "offset": 1,
                "modulus": 1 << 24,
            },
        )
        self.assertFalse(outer["link_register_preserved"])
        compare = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
        )
        self.assertIsNone(compare["registers_in"]["A"])
        branch = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JEQ"
        )
        outgoing = [
            edge
            for edge in report["edges"]
            if edge["source"] == branch["address"]
        ]
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_term_budget_degrades_five_source_expression_to_unknown(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB WIDE\n"
            "      RSUB\n"
            "WIDE  RMO A,T\n"
            "      ADDR X,T\n"
            "      ADDR B,T\n"
            "      ADDR S,T\n"
            "      ADDR L,T\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.sparse_summary_for(report, "WIDE")
        self.assertNotIn("T", summary["return_linear_transfers"])
        self.assertNotIn("T", summary["multivariate_return_registers"])

    def test_single_source_schema_remains_affine_for_compatibility(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      +JSUB INC\n"
            "      RSUB\n"
            "INC   ADD #1\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        sparse = self.sparse_summary_for(report, "INC")
        self.assertEqual(
            sparse["return_linear_transfers"]["A"]["kind"],
            "affine",
        )
        legacy = next(
            summary
            for summary in report["register_transfer_summaries"]
            if summary["entry"] == sparse["entry"]
        )
        self.assertEqual(
            legacy["return_transfers"]["A"],
            sparse["return_linear_transfers"]["A"],
        )

    def test_text_report_surfaces_sparse_formula_and_instantiation(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB MIXER\n"
            "      RSUB\n"
            "MIXER ADDR X,A\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("SPARSE LINEAR CALL TRANSFERS", rendered)
        self.assertIn("A=A+X", rendered)
        self.assertIn("exact=A=000003", rendered)
        self.assertTrue(report["sparse_linear_transfers"]["converged"])
        self.assertGreaterEqual(
            report["metrics"]["sparse_linear_multivariate_transfers"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
