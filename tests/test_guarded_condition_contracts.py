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


class GuardedConditionContractTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-guarded-cc-")
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
        return analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )

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
            for summary in report["guarded_transfer_summaries"]
            if summary["entry"] == entry
        )

    def calls_to(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return [
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
            and node.get("target") == entry
        ]

    def conditional_edges(self, report, address):
        return [
            edge
            for edge in report["edges"]
            if edge.get("source") == address
            and edge.get("kind") in ("branch", "fallthrough")
        ]

    def test_guarded_cases_expose_explicit_condition_postconditions(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB CLASS\n"
            "      RSUB\n"
            "CLASS COMP #0\n"
            "      JEQ SAME\n"
            "      LDB #7\n"
            "SAME  RSUB\n"
            "INPUT RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "CLASS")
        self.assertTrue(summary["guarded_supported"])
        self.assertEqual(summary["guarded_case_count"], 2)
        conditions = {
            tuple(case["condition_values"])
            for case in summary["guarded_cases"]
        }
        self.assertEqual(conditions, {("EQ",), ("LT", "GT")})

    def test_selected_exact_condition_prunes_caller_fallthrough(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY CLEAR A\n"
            "      +JSUB CLASS\n"
            "CHECK JEQ GOOD\n"
            "      LDB #1\n"
            "GOOD  RSUB\n"
            "CLASS COMP #0\n"
            "      JEQ SAME\n"
            "      LDX #7\n"
            "SAME  RSUB\n"
            "      END ENTRY\n"
        )
        call = self.calls_to(report, "CLASS")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(item["condition_mode"], "exact")
        self.assertTrue(item["condition_known"])
        self.assertEqual(item["exact_condition"], "EQ")
        self.assertEqual(item["range_conditions"], ["EQ"])

        check = next(
            node
            for node in report["instructions"]
            if "CHECK" in node.get("symbols", ())
        )
        edges = self.conditional_edges(report, check["address"])
        branch = next(edge for edge in edges if edge["kind"] == "branch")
        fallthrough = next(
            edge for edge in edges if edge["kind"] == "fallthrough"
        )
        self.assertTrue(branch["resolved"])
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "guarded-transfer-condition",
        )

    def test_guarded_condition_set_rules_out_only_impossible_relation(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      COMP #0\n"
            "      JEQ ZERO\n"
            "      LDA #1\n"
            "      J JOIN\n"
            "ZERO  CLEAR A\n"
            "JOIN  +JSUB CLASS\n"
            "CHECK JGT BAD\n"
            "      RSUB\n"
            "BAD   LDB #9\n"
            "      RSUB\n"
            "CLASS COMP #1\n"
            "      JEQ EQRET\n"
            "      JLT LTRET\n"
            "GTRET RSUB\n"
            "EQRET RSUB\n"
            "LTRET RSUB\n"
            "INPUT RESW 1\n"
            "      END ENTRY\n"
        )
        call = self.calls_to(report, "CLASS")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(item["condition_mode"], "set")
        self.assertTrue(item["condition_known"])
        self.assertIsNone(item["exact_condition"])
        self.assertEqual(item["range_conditions"], ["LT", "EQ"])

        check = next(
            node
            for node in report["instructions"]
            if "CHECK" in node.get("symbols", ())
        )
        branch = next(
            edge
            for edge in self.conditional_edges(report, check["address"])
            if edge["kind"] == "branch"
        )
        self.assertFalse(branch["resolved"])
        self.assertEqual(
            branch["resolution"],
            "guarded-transfer-range-condition",
        )

    def test_unknown_condition_writer_revokes_stale_comparison(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY CLEAR A\n"
            "      +JSUB MAYIO\n"
            "CHECK JEQ GOOD\n"
            "      LDB #1\n"
            "GOOD  RSUB\n"
            "MAYIO COMP #0\n"
            "      JEQ KEEP\n"
            "      LDX #7\n"
            "KEEP  TD DEVICE\n"
            "      RSUB\n"
            "DEVICE BYTE X'00'\n"
            "      END ENTRY\n"
        )
        call = self.calls_to(report, "MAYIO")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(item["condition_mode"], "unknown")
        self.assertFalse(item["condition_known"])
        self.assertIsNone(item["exact_condition"])
        self.assertIsNone(item["range_conditions"])

        check = next(
            node
            for node in report["instructions"]
            if "CHECK" in node.get("symbols", ())
        )
        edges = self.conditional_edges(report, check["address"])
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(edge["resolved"] for edge in edges))

    def test_nested_guarded_callee_condition_composes_into_outer_cases(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB OUTER\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      JEQ OKEQ\n"
            "      LDB #2\n"
            "OKEQ  RSUB\n"
            "INNER COMP #0\n"
            "      JEQ KEEP\n"
            "      LDX #7\n"
            "KEEP  RSUB\n"
            "INPUT RESW 1\n"
            "      END ENTRY\n"
        )
        inner = self.summary_for(report, "INNER")
        outer = self.summary_for(report, "OUTER")
        self.assertTrue(inner["guarded_supported"])
        self.assertTrue(outer["guarded_supported"])
        self.assertGreaterEqual(outer["guarded_nested_composed_calls"], 1)
        self.assertEqual(
            {
                tuple(case["condition_values"])
                for case in outer["guarded_cases"]
            },
            {("EQ",), ("LT", "GT")},
        )
        self.assertTrue(
            all(case["nested_cases"] for case in outer["guarded_cases"])
        )


if __name__ == "__main__":
    unittest.main()
