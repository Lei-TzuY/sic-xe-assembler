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


class GuardedReturnabilityTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-guarded-return-")
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

    def test_closed_cycle_and_return_are_explicit_returnability_cases(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB MAYSTOP\n"
            "      RSUB\n"
            "MAYSTOP COMP #0\n"
            "        JEQ RET\n"
            "SPIN    J SPIN\n"
            "RET     RSUB\n"
            "INPUT   RESW 1\n"
            "        END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSTOP")
        self.assertTrue(summary["guarded_returnability_supported"])
        self.assertEqual(summary["returnability_case_count"], 2)
        self.assertEqual(
            {case["returns"] for case in summary["returnability_cases"]},
            {True, False},
        )
        no_return = next(
            case for case in summary["returnability_cases"]
            if case["returns"] is False
        )
        self.assertEqual(no_return["terminal_kind"], "closed-cycle")
        self.assertIn(
            self.entry_for(report, "SPIN"),
            no_return["terminal_nodes"],
        )
        self.assertTrue(summary["guarded_may_return"])
        self.assertTrue(summary["guarded_may_not_return"])
        self.assertFalse(summary["guarded_must_return"])

    def test_exact_no_return_call_prunes_only_its_continuation(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY CLEAR A\n"
            "      +JSUB MAYSTOP\n"
            "NEXT  LDA #1\n"
            "      +JSUB MAYSTOP\n"
            "AFTER LDB #9\n"
            "      RSUB\n"
            "MAYSTOP COMP #0\n"
            "        JEQ RET\n"
            "SPIN    J SPIN\n"
            "RET     RSUB\n"
            "        END ENTRY\n"
        )
        calls = sorted(self.calls_to(report, "MAYSTOP"), key=lambda node: node["address"])
        self.assertEqual(len(calls), 2)
        first, second = calls
        self.assertEqual(
            first["guarded_transfer_instantiation"]["return_mode"],
            "returns",
        )
        self.assertEqual(
            second["guarded_transfer_instantiation"]["return_mode"],
            "no-return",
        )
        first_fallthrough = next(
            edge for edge in report["edges"]
            if edge.get("source") == first["address"]
            and edge.get("kind") == "fallthrough"
        )
        second_fallthrough = next(
            edge for edge in report["edges"]
            if edge.get("source") == second["address"]
            and edge.get("kind") == "fallthrough"
        )
        self.assertTrue(first_fallthrough["resolved"])
        self.assertFalse(second_fallthrough["resolved"])
        self.assertEqual(second_fallthrough["reason"], "guarded-no-return")
        self.assertEqual(
            second_fallthrough["resolution"],
            "guarded-returnability",
        )
        self.assertFalse(
            any(
                edge.get("synthetic_return")
                and edge.get("call_source") == second["address"]
                for edge in report["edges"]
            )
        )
        after = self.entry_for(report, "AFTER")
        self.assertFalse(
            next(
                node["reachable"]
                for node in report["instructions"]
                if node["address"] == after
            )
        )

    def test_unknown_input_keeps_mixed_returnability_and_continuation(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB MAYSTOP\n"
            "AFTER LDB #9\n"
            "      RSUB\n"
            "MAYSTOP COMP #0\n"
            "        JEQ RET\n"
            "SPIN    J SPIN\n"
            "RET     RSUB\n"
            "INPUT   RESW 1\n"
            "        END ENTRY\n"
        )
        call = self.calls_to(report, "MAYSTOP")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(item["return_mode"], "mixed")
        self.assertFalse(item["returnability_known"])
        self.assertTrue(item["may_return"])
        self.assertFalse(item["must_not_return"])
        fallthrough = next(
            edge for edge in report["edges"]
            if edge.get("source") == call["address"]
            and edge.get("kind") == "fallthrough"
        )
        self.assertTrue(fallthrough["resolved"])
        after = self.entry_for(report, "AFTER")
        self.assertTrue(
            next(
                node["reachable"]
                for node in report["instructions"]
                if node["address"] == after
            )
        )

    def test_unresolved_control_is_unknown_not_no_return(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      +JSUB MAYESC\n"
            "AFTER RSUB\n"
            "MAYESC COMP #0\n"
            "       JEQ RET\n"
            "       J @PTR\n"
            "RET    RSUB\n"
            "PTR    RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYESC")
        self.assertTrue(summary["guarded_returnability_supported"])
        self.assertNotIn(
            False,
            {case["returns"] for case in summary["returnability_cases"]},
        )
        self.assertIn(
            None,
            {case["returns"] for case in summary["returnability_cases"]},
        )
        call = self.calls_to(report, "MAYESC")[0]
        self.assertNotIn("guarded_transfer_instantiation", call)
        fallthrough = next(
            edge for edge in report["edges"]
            if edge.get("source") == call["address"]
            and edge.get("kind") == "fallthrough"
        )
        self.assertTrue(fallthrough["resolved"])

    def test_two_node_closed_scc_is_proven_no_return(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB MAYSTOP\n"
            "      RSUB\n"
            "MAYSTOP COMP #0\n"
            "        JEQ RET\n"
            "LOOPA   J LOOPB\n"
            "LOOPB   J LOOPA\n"
            "RET     RSUB\n"
            "INPUT   RESW 1\n"
            "        END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSTOP")
        no_return = next(
            case for case in summary["returnability_cases"]
            if case["returns"] is False
        )
        self.assertEqual(no_return["terminal_kind"], "closed-cycle")
        self.assertEqual(
            set(no_return["terminal_nodes"]),
            {self.entry_for(report, "LOOPA"), self.entry_for(report, "LOOPB")},
        )

    def test_nested_no_return_case_composes_through_outer_call(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      +JSUB OUTER\n"
            "AFTER LDB #9\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER COMP #0\n"
            "      JEQ RET\n"
            "SPIN  J SPIN\n"
            "RET   RSUB\n"
            "      END ENTRY\n"
        )
        outer = self.summary_for(report, "OUTER")
        self.assertTrue(outer["guarded_returnability_supported"])
        self.assertGreaterEqual(outer["returnability_nested_composed_calls"], 1)
        self.assertIn(
            False,
            {case["returns"] for case in outer["returnability_cases"]},
        )
        no_return = next(
            case for case in outer["returnability_cases"]
            if case["returns"] is False
        )
        self.assertEqual(no_return["terminal_kind"], "nested-no-return")
        self.assertTrue(no_return["nested_cases"])
        call = self.calls_to(report, "OUTER")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(item["return_mode"], "no-return")
        after = self.entry_for(report, "AFTER")
        self.assertFalse(
            next(
                node["reachable"]
                for node in report["instructions"]
                if node["address"] == after
            )
        )


if __name__ == "__main__":
    unittest.main()
