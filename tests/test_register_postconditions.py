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


class RegisterPostconditionTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-register-postconditions-")
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

    def _summary_for_symbol(self, report, symbol):
        entry = next(
            node["address"]
            for node in report["instructions"]
            if symbol in node.get("symbols", ())
        )
        return next(
            summary
            for summary in report["register_return_summaries"]
            if summary["entry"] == entry
        )

    def test_constant_return_flows_to_caller_and_prunes_branch(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB ROUTN\n"
            "      COMP #7\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "ROUTN LDA #7\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self._summary_for_symbol(report, "ROUTN")
        self.assertEqual(summary["return_constants"]["A"], 7)
        self.assertEqual(summary["return_ranges"]["A"], [7, 7])
        self.assertTrue(summary["link_register_preserved"])

        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertEqual(compare["registers_in"]["A"], 7)
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        self.assertEqual(branch["registers_in"]["CC"], "EQ")
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "register-postcondition-condition")
        dead = next(node for node in report["instructions"] if "DEAD" in node.get("symbols", ()))
        self.assertFalse(dead["reachable"])

    def test_return_range_flows_to_caller_when_exact_value_disagrees(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB ROUTN\n"
            "      COMP #10\n"
            "      JLT GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "ROUTN COMP FLAG\n"
            "      JEQ ONE\n"
            "      LDA #2\n"
            "      J REND\n"
            "ONE   LDA #1\n"
            "REND  RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self._summary_for_symbol(report, "ROUTN")
        self.assertNotIn("A", summary["return_constants"])
        self.assertEqual(summary["return_ranges"]["A"], [1, 2])

        compare = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
            and (node.get("operand") or "").startswith("#")
            and node.get("target") == 10
        )
        self.assertIsNone(compare["registers_in"]["A"])
        self.assertEqual(compare["ranges_in"]["A"], (1, 2))
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JLT")
        self.assertEqual(branch["ranges_in"]["CC"], ("LT",))
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch["address"] and edge["kind"] == "fallthrough"
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["resolution"], "register-postcondition-range-condition")

    def test_caller_specific_memory_value_is_not_promoted_to_function_contract(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #7\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      COMP #7\n"
            "      JEQ MAYBE\n"
            "      LDA #1\n"
            "MAYBE RSUB\n"
            "ROUTN LDA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self._summary_for_symbol(report, "ROUTN")
        self.assertNotIn("A", summary["return_constants"])
        self.assertNotIn("A", summary["return_ranges"])
        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertIsNone(compare["registers_in"]["A"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        outgoing = [edge for edge in report["edges"] if edge["source"] == branch["address"]]
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_partial_output_path_does_not_invent_return_value(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB ROUTN\n"
            "      RSUB\n"
            "ROUTN COMP FLAG\n"
            "      JEQ DONE\n"
            "      LDA #7\n"
            "DONE  RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self._summary_for_symbol(report, "ROUTN")
        self.assertNotIn("A", summary["return_constants"])
        self.assertNotIn("A", summary["return_ranges"])

    def test_nested_postcondition_composes_but_unproven_outer_return_is_not_consumed(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB OUTER\n"
            "      COMP #10\n"
            "      JEQ MAYBE\n"
            "      LDA #1\n"
            "MAYBE RSUB\n"
            "OUTER +JSUB INNER\n"
            "      ADD #1\n"
            "      RSUB\n"
            "INNER LDA #9\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        inner = self._summary_for_symbol(report, "INNER")
        outer = self._summary_for_symbol(report, "OUTER")
        self.assertEqual(inner["return_constants"]["A"], 9)
        self.assertEqual(outer["return_constants"]["A"], 10)
        self.assertFalse(outer["link_register_preserved"])

        compare = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        self.assertIsNone(compare["registers_in"]["A"])
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        outgoing = [edge for edge in report["edges"] if edge["source"] == branch["address"]]
        self.assertTrue(all(edge["resolved"] for edge in outgoing))

    def test_returned_base_register_resolves_base_relative_jump(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB SETB\n"
            "      BASE 0\n"
            "      J FAR\n"
            "SETB  +LDB #0x4000\n"
            "      RSUB\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        summary = self._summary_for_symbol(report, "SETB")
        self.assertEqual(summary["return_constants"]["B"], 0x4000)
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        far = next(node for node in report["instructions"] if "FAR" in node.get("symbols", ()))
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "register-postcondition-base")
        edge = next(
            edge for edge in report["edges"]
            if edge["source"] == jump["address"] and edge["kind"] == "jump"
        )
        self.assertTrue(edge["resolved"])
        self.assertEqual(edge["target"], far["address"])

    def test_report_surfaces_register_return_contracts(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB ROUTN\n"
            "      RSUB\n"
            "ROUTN LDA #3\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("REGISTER POSTCONDITIONS", rendered)
        self.assertIn("REGISTER RETURN POSTCONDITIONS", rendered)
        self.assertIn("A=000003", rendered)
        self.assertTrue(report["register_postconditions"]["converged"])
        self.assertGreaterEqual(report["metrics"]["return_register_postconditions"], 1)


if __name__ == "__main__":
    unittest.main()
