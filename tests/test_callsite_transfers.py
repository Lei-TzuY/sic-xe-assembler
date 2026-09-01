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


class CallsiteTransferTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-callsite-transfers-")
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

    def summary_for(self, report, symbol):
        entry = next(
            node["address"]
            for node in report["instructions"]
            if symbol in node.get("symbols", ())
        )
        return next(
            summary
            for summary in report["register_transfer_summaries"]
            if summary["entry"] == entry
        )

    def test_affine_return_is_instantiated_and_prunes_caller_branch(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      +JSUB ROUTN\n"
            "      COMP #5\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "ROUTN ADD #1\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "ROUTN")
        self.assertEqual(
            summary["return_transfers"]["A"],
            {"kind": "affine", "source": "A", "scale": 1, "offset": 1, "modulus": 1 << 24},
        )
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        self.assertEqual(call["call_transfer_instantiation"]["exact"]["A"], 5)
        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertEqual(compare["registers_in"]["A"], 5)
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "call-transfer-condition")
        dead = next(node for node in report["instructions"] if "DEAD" in node.get("symbols", ()))
        self.assertFalse(dead["reachable"])

    def test_same_summary_instantiates_differently_at_two_call_sites(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      +JSUB ROUTN\n"
            "      STA FIRST\n"
            "      LDA #9\n"
            "      +JSUB ROUTN\n"
            "      STA SECOND\n"
            "      RSUB\n"
            "ROUTN ADD #1\n"
            "      RSUB\n"
            "FIRST RESW 1\n"
            "SECOND RESW 1\n"
            "      END ENTRY\n"
        )
        calls = [
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
        ]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["call_transfer_instantiation"]["exact"]["A"], 5)
        self.assertEqual(calls[1]["call_transfer_instantiation"]["exact"]["A"], 10)
        self.assertEqual(
            calls[0]["register_transfer_summary"]["return_transfers"],
            calls[1]["register_transfer_summary"]["return_transfers"],
        )

    def test_affine_transfer_shifts_caller_interval(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY COMP FLAG\n"
            "      JEQ ONE\n"
            "      LDA #2\n"
            "      J JOIN\n"
            "ONE   LDA #1\n"
            "JOIN  +JSUB ROUTN\n"
            "      COMP #10\n"
            "      JLT GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "ROUTN ADD #1\n"
            "      RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        self.assertNotIn("A", call["call_transfer_instantiation"]["exact"])
        self.assertEqual(call["call_transfer_instantiation"]["ranges"]["A"], [2, 3])
        compares = [node for node in report["instructions"] if node["base_mnemonic"] == "COMP"]
        compare = max(compares, key=lambda node: node["address"])
        self.assertIsNone(compare["registers_in"]["A"])
        self.assertEqual(compare["ranges_in"]["A"], (2, 3))
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JLT")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "call-transfer-range-condition")

    def test_copy_transfer_can_resolve_returned_base(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +LDA #0x4000\n"
            "      +JSUB SETB\n"
            "      BASE 0\n"
            "      J FAR\n"
            "SETB  RMO A,B\n"
            "      RSUB\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "SETB")
        self.assertEqual(summary["return_transfers"]["B"]["source"], "A")
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        far = next(node for node in report["instructions"] if "FAR" in node.get("symbols", ()))
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "call-transfer-base")

    def test_multivariate_register_expression_remains_unsupported(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDX #2\n"
            "      +JSUB MIXER\n"
            "      COMP #3\n"
            "      JEQ MAYBE\n"
            "      LDA #9\n"
            "MAYBE RSUB\n"
            "MIXER ADDR X,A\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "MIXER")
        self.assertNotIn("A", summary["return_transfers"])
        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertIsNone(compare["registers_in"]["A"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        outgoing = [edge for edge in report["edges"] if edge["source"] == branch["address"]]
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_nested_symbolic_summary_is_not_consumed_without_link_proof(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      +JSUB OUTER\n"
            "      COMP #6\n"
            "      JEQ MAYBE\n"
            "      LDA #9\n"
            "MAYBE RSUB\n"
            "OUTER +JSUB INNER\n"
            "      ADD #1\n"
            "      RSUB\n"
            "INNER ADD #1\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        outer = self.summary_for(report, "OUTER")
        self.assertEqual(outer["return_transfers"]["A"]["offset"], 2)
        self.assertFalse(outer["link_register_preserved"])
        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertIsNone(compare["registers_in"]["A"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        outgoing = [edge for edge in report["edges"] if edge["source"] == branch["address"]]
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_text_report_surfaces_formulas_and_instantiations(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      +JSUB ROUTN\n"
            "      RSUB\n"
            "ROUTN ADD #1\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("CALL-SITE SYMBOLIC TRANSFERS", rendered)
        self.assertIn("A=A+1", rendered)
        self.assertIn("exact=A=000005", rendered)
        self.assertTrue(report["callsite_transfers"]["converged"])
        self.assertGreaterEqual(report["metrics"]["symbolic_return_transfers"], 1)


if __name__ == "__main__":
    unittest.main()
