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


class GuardedRegisterContractTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-guarded-register-")
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

    def test_partial_register_write_cases_distinguish_identity_from_value(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB MAYSET\n"
            "      RSUB\n"
            "MAYSET COMP #0\n"
            "       JEQ KEEP\n"
            "       LDB #7\n"
            "KEEP   RSUB\n"
            "INPUT  RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSET")
        self.assertTrue(summary["guarded_supported"])
        self.assertEqual(summary["guarded_case_count"], 2)
        self.assertIn("B", summary["register_contract_registers"])
        kinds = {
            case["register_outputs"]["B"]["kind"]
            for case in summary["guarded_cases"]
        }
        self.assertEqual(kinds, {"identity", "symbolic-linear"})
        self.assertTrue(
            all("B" in case["register_outputs"] for case in summary["guarded_cases"])
        )

    def test_selected_identity_register_preserves_base_and_resolves_target(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +LDB #0x4000\n"
            "      CLEAR A\n"
            "      +JSUB MAYSET\n"
            "      BASE 0\n"
            "      J FAR\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "MAYSET COMP #0\n"
            "       JEQ KEEP\n"
            "       LDB #7\n"
            "KEEP   RSUB\n"
            "       END ENTRY\n"
        )
        call = self.calls_to(report, "MAYSET")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["register_modes"]["B"], "identity")
        self.assertEqual(item["exact_registers"]["B"], 0x4000)
        jump = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "J"
            and node["address"] > call["address"]
        )
        self.assertEqual(jump["target"], self.entry_for(report, "FAR"))
        # Guarded identity is the semantic evidence that B survives the call.
        # If an earlier dataflow pass already owns the resulting target proof,
        # the later guarded layer must not relabel it.
        self.assertIn(
            jump["target_resolution"],
            {
                "dataflow-base",
                "range-singleton-base",
                "guarded-transfer-base",
                "guarded-transfer-range-base",
            },
        )

    def test_selected_unknown_register_revokes_caller_fact(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDB #3\n"
            "      LDA #1\n"
            "      +JSUB MAYUNK\n"
            "      RMO B,S\n"
            "      RSUB\n"
            "MAYUNK COMP #0\n"
            "       JEQ KEEP\n"
            "       LDB @PTR\n"
            "KEEP   RSUB\n"
            "PTR    RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYUNK")
        kinds = {
            case["register_outputs"]["B"]["kind"]
            for case in summary["guarded_cases"]
        }
        self.assertEqual(kinds, {"identity", "unknown"})
        call = self.calls_to(report, "MAYUNK")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["register_modes"]["B"], "unknown")
        self.assertNotIn("B", item["exact_registers"])
        self.assertNotIn("B", item["range_registers"])
        move = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "RMO"
            and node["address"] > call["address"]
        )
        self.assertIsNone(move["registers_in"]["B"])
        self.assertIsNone(move["ranges_in"]["B"])

    def test_nested_guarded_callee_composes_register_contracts(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB OUTER\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER COMP #0\n"
            "      JEQ KEEP\n"
            "      LDB #7\n"
            "KEEP  RSUB\n"
            "INPUT RESW 1\n"
            "      END ENTRY\n"
        )
        inner = self.summary_for(report, "INNER")
        outer = self.summary_for(report, "OUTER")
        self.assertTrue(inner["guarded_supported"])
        self.assertTrue(outer["guarded_supported"])
        self.assertEqual(outer["guarded_case_count"], 2)
        self.assertGreaterEqual(outer["guarded_nested_composed_calls"], 1)
        self.assertFalse(outer["link_register_preserved"])
        self.assertIn("B", outer["register_contract_registers"])
        kinds = {
            case["register_outputs"]["B"]["kind"]
            for case in outer["guarded_cases"]
        }
        self.assertEqual(kinds, {"identity", "symbolic-linear"})
        self.assertTrue(
            all(case["nested_cases"] for case in outer["guarded_cases"])
        )
        inner_entry = inner["entry"]
        self.assertTrue(
            all(
                case["nested_cases"][0]["callee_entry"] == inner_entry
                for case in outer["guarded_cases"]
            )
        )


if __name__ == "__main__":
    unittest.main()
