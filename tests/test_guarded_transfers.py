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


class GuardedTransferTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-guarded-transfer-")
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

    def summary_for(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return next(
            item for item in report["guarded_transfer_summaries"]
            if item["entry"] == entry
        )

    def calls_to(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return [
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
            and node.get("target") == entry
        ]

    def edge(self, report, source, kind):
        return next(
            edge for edge in report["edges"]
            if edge["source"] == source and edge["kind"] == kind
        )

    def test_exact_guard_selects_return_case_and_prunes_caller_branch(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #0\n"
            "      +JSUB CHOOSE\n"
            "      COMP #1\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "CHOOSE COMP #0\n"
            "      JEQ ZERO\n"
            "      LDA #2\n"
            "      RSUB\n"
            "ZERO  LDA #1\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "CHOOSE")
        self.assertTrue(summary["guarded_supported"])
        self.assertEqual(summary["guarded_case_count"], 2)
        call = self.calls_to(report, "CHOOSE")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["exact_registers"]["A"], 1)
        compare = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
            and node["address"] > call["address"]
            and node["address"] < summary["entry"]
        )
        self.assertEqual(compare["registers_in"]["A"], 1)
        branch = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JEQ"
            and node["address"] > call["address"]
            and node["address"] < summary["entry"]
        )
        fallthrough = self.edge(report, branch["address"], "fallthrough")
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "register-postcondition-condition",
        )

    def test_same_piecewise_summary_instantiates_differently_at_two_calls(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #0\n"
            "      +JSUB CHOOSE\n"
            "      STA OUT1\n"
            "      LDA #5\n"
            "      +JSUB CHOOSE\n"
            "      STA OUT2\n"
            "      RSUB\n"
            "CHOOSE COMP #0\n"
            "      JEQ ZERO\n"
            "      LDA #2\n"
            "      RSUB\n"
            "ZERO  LDA #1\n"
            "      RSUB\n"
            "OUT1  RESW 1\n"
            "OUT2  RESW 1\n"
            "      END ENTRY\n"
        )
        calls = self.calls_to(report, "CHOOSE")
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0]["guarded_transfer_instantiation"]["exact_registers"]["A"],
            1,
        )
        self.assertEqual(
            calls[1]["guarded_transfer_instantiation"]["exact_registers"]["A"],
            2,
        )
        self.assertNotEqual(
            calls[0]["guarded_transfer_instantiation"]["feasible_cases"],
            calls[1]["guarded_transfer_instantiation"]["feasible_cases"],
        )

    def test_range_guard_can_select_one_case_and_recover_exact_output(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY COMP FLAG\n"
            "      JEQ ZEROA\n"
            "      LDA #1\n"
            "      J JOIN\n"
            "ZEROA LDA #0\n"
            "JOIN  +JSUB PICKB\n"
            "      RMO B,A\n"
            "      COMP #10\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "PICKB COMP #10\n"
            "      JLT SMALL\n"
            "      LDB #100\n"
            "      RSUB\n"
            "SMALL LDB #10\n"
            "      RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        call = self.calls_to(report, "PICKB")[0]
        self.assertIsNone(call["registers_in"]["A"])
        self.assertEqual(call["ranges_in"]["A"], (0, 1))
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["exact_registers"]["B"], 10)
        branch = max(
            (
                node for node in report["instructions"]
                if node["base_mnemonic"] == "JEQ"
                and node["address"] < self.entry_for(report, "PICKB")
            ),
            key=lambda node: node["address"],
        )
        fallthrough = self.edge(report, branch["address"], "fallthrough")
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "register-postcondition-condition",
        )

    def test_memory_root_guard_selects_case_from_initialized_cell(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB CHOOSE\n"
            "      COMP #1\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "CHOOSE LDA FLAG\n"
            "      COMP #0\n"
            "      JEQ ZERO\n"
            "      LDA #2\n"
            "      RSUB\n"
            "ZERO  LDA #1\n"
            "      RSUB\n"
            "FLAG  WORD 0\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "CHOOSE")
        guards = [
            guard
            for case in summary["guarded_cases"]
            for guard in case["guards"]
        ]
        self.assertTrue(
            any(guard["left"].get("memory_coefficients") for guard in guards)
        )
        call = self.calls_to(report, "CHOOSE")[0]
        self.assertEqual(
            call["guarded_transfer_instantiation"]["exact_registers"]["A"],
            1,
        )

    def test_guarded_case_can_return_memory_value_to_caller(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #0\n"
            "      +JSUB SETVAL\n"
            "      CLEAR A\n"
            "      LDA SLOT\n"
            "      COMP #1\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "SETVAL COMP #0\n"
            "      JEQ ZERO\n"
            "      LDA #2\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "ZERO  LDA #1\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        call = self.calls_to(report, "SETVAL")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["exact_memory"]), 1)
        self.assertEqual(next(iter(item["exact_memory"].values())), 1)
        compare = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "COMP"
            and call["address"] < node["address"] < self.entry_for(report, "SETVAL")
        )
        self.assertEqual(compare["registers_in"]["A"], 1)

    def test_guarded_returned_base_resolves_base_relative_jump(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      +JSUB SETB\n"
            "      LDA #0\n"
            "      +JSUB SETB\n"
            "      BASE 0\n"
            "      J FAR\n"
            "SETB  COMP #0\n"
            "      JEQ GOODB\n"
            "      +LDB #0x4008\n"
            "      RSUB\n"
            "GOODB +LDB #0x4000\n"
            "      RSUB\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        calls = self.calls_to(report, "SETB")
        self.assertEqual(len(calls), 2)
        self.assertEqual(
            calls[0]["guarded_transfer_instantiation"]["exact_registers"]["B"],
            0x4008,
        )
        self.assertEqual(
            calls[1]["guarded_transfer_instantiation"]["exact_registers"]["B"],
            0x4000,
        )
        jump = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "J"
        )
        far = self.entry_for(report, "FAR")
        self.assertEqual(jump["target"], far)
        self.assertEqual(jump["target_resolution"], "guarded-transfer-base")

    def test_looped_function_degrades_instead_of_path_exploding(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA FLAG\n"
            "      +JSUB LOOPF\n"
            "      RSUB\n"
            "LOOPF COMP #0\n"
            "      JEQ DONE\n"
            "      SUB #1\n"
            "      J LOOPF\n"
            "DONE  RSUB\n"
            "FLAG  RESW 1\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "LOOPF")
        self.assertFalse(summary["guarded_supported"])
        self.assertEqual(summary["guarded_reason"], "loop-or-revisit")
        call = self.calls_to(report, "LOOPF")[0]
        self.assertNotIn("guarded_transfer_instantiation", call)

    def test_unproven_link_register_blocks_guarded_consumption_and_report_surfaces_cases(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #0\n"
            "      +JSUB OUTER\n"
            "      RSUB\n"
            "OUTER COMP #0\n"
            "      JEQ ZERO\n"
            "      +JSUB INNER\n"
            "      LDA #2\n"
            "      RSUB\n"
            "ZERO  LDA #1\n"
            "      RSUB\n"
            "INNER RSUB\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "OUTER")
        self.assertTrue(summary["guarded_supported"])
        self.assertFalse(summary["link_register_preserved"])
        call = self.calls_to(report, "OUTER")[0]
        self.assertNotIn("guarded_transfer_instantiation", call)
        rendered = render_control_flow_report(report)
        self.assertIn("GUARDED CALL TRANSFERS", rendered)
        self.assertIn("cases=", rendered)
        self.assertGreaterEqual(report["metrics"]["guarded_transfer_cases"], 2)


if __name__ == "__main__":
    unittest.main()
