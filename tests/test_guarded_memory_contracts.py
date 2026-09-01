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


class GuardedMemoryContractTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-guarded-memory-")
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

    def test_partial_write_cases_explicitly_distinguish_identity_from_value(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB MAYSET\n"
            "      RSUB\n"
            "MAYSET COMP #0\n"
            "       JEQ KEEP\n"
            "       LDX #7\n"
            "       STX SLOT\n"
            "KEEP   RSUB\n"
            "INPUT  RESW 1\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSET")
        self.assertTrue(summary["guarded_supported"])
        self.assertEqual(summary["guarded_case_count"], 2)
        self.assertEqual(len(summary["memory_contract_cells"]), 1)
        cell = summary["memory_contract_cells"][0]
        kinds = {
            case["memory_outputs"][cell]["kind"]
            for case in summary["guarded_cases"]
        }
        self.assertEqual(kinds, {"identity", "symbolic-linear"})
        self.assertTrue(
            all(cell in case["memory_outputs"] for case in summary["guarded_cases"])
        )

    def test_selected_identity_case_preserves_caller_memory_fact(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDX #3\n"
            "      STX SLOT\n"
            "      CLEAR A\n"
            "      +JSUB MAYSET\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "MAYSET COMP #0\n"
            "       JEQ KEEP\n"
            "       LDX #7\n"
            "       STX SLOT\n"
            "KEEP   RSUB\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYSET")
        cell = summary["memory_contract_cells"][0]
        call = self.calls_to(report, "MAYSET")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["memory_modes"][cell], "identity")
        self.assertEqual(item["exact_memory"][cell], 3)
        load = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "LDB"
        )
        self.assertEqual(load["memory_constant"], 3)
        self.assertEqual(load["registers_out"]["B"], 3)

    def test_selected_unknown_case_does_not_invent_memory_fact(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDX #3\n"
            "      STX SLOT\n"
            "      LDA #1\n"
            "      +JSUB MAYUNK\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "MAYUNK COMP #0\n"
            "       JEQ KEEP\n"
            "       FIX\n"
            "       STA SLOT\n"
            "KEEP   RSUB\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        summary = self.summary_for(report, "MAYUNK")
        cell = summary["memory_contract_cells"][0]
        kinds = {
            case["memory_outputs"][cell]["kind"]
            for case in summary["guarded_cases"]
        }
        self.assertEqual(kinds, {"identity", "unknown"})
        call = self.calls_to(report, "MAYUNK")[0]
        item = call["guarded_transfer_instantiation"]
        self.assertEqual(len(item["feasible_cases"]), 1)
        self.assertEqual(item["memory_modes"][cell], "unknown")
        self.assertNotIn(cell, item["exact_memory"])
        self.assertNotIn(cell, item["range_memory"])
        load = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "LDB"
        )
        self.assertIsNone(load["memory_constant"])
        self.assertIsNone(load["memory_range"])

    def test_nested_guarded_callee_composes_memory_cases_into_outer_summary(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INPUT\n"
            "      +JSUB OUTER\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER COMP #0\n"
            "      JEQ KEEP\n"
            "      LDX #7\n"
            "      STX SLOT\n"
            "KEEP  RSUB\n"
            "INPUT RESW 1\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        inner = self.summary_for(report, "INNER")
        outer = self.summary_for(report, "OUTER")
        self.assertTrue(inner["guarded_supported"])
        self.assertTrue(outer["guarded_supported"])
        self.assertEqual(outer["guarded_case_count"], 2)
        self.assertGreaterEqual(outer["guarded_nested_composed_calls"], 1)
        self.assertFalse(outer["link_register_preserved"])
        self.assertEqual(len(outer["memory_contract_cells"]), 1)
        cell = outer["memory_contract_cells"][0]
        kinds = {
            case["memory_outputs"][cell]["kind"]
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
