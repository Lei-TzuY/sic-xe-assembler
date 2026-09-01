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


class SymbolicMemoryInputTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(
            prefix="sicxe-symbolic-memory-input-"
        )
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(
            assembled.returncode,
            0,
            assembled.stderr,
        )
        linked = self.run_script(
            LOADER,
            source.with_suffix(".obj"),
            progaddr,
        )
        self.assertEqual(
            linked.returncode,
            0,
            linked.stderr,
        )
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(
            source.with_suffix(
                ".manifest.json"
            ).read_text(encoding="utf-8")
        )
        debug, _ = load_linked_debug_map(
            source.with_suffix(".debug.json")
        )
        report = analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )
        report["_test_debug_map"] = debug
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
            summary
            for summary in report[
                "symbolic_memory_input_summaries"
            ]
            if summary["entry"] == entry
        )

    def cell_for(self, report, symbol):
        address = next(
            region["loaded_address"]
            for section in report[
                "_test_debug_map"
            ].get("sections", ())
            for region in section.get("regions", ())
            if symbol in region.get("symbols", ())
        )
        return f"{address:05X}+3"

    def branch_fallthrough(self, report, mnemonic):
        branch = next(
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == mnemonic
        )
        return next(
            edge
            for edge in report["edges"]
            if edge["source"] == branch["address"]
            and edge["kind"] == "fallthrough"
        )

    def calls_to(self, report, symbol):
        entry = self.entry_for(report, symbol)
        return [
            node
            for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB"
            and node.get("target") == entry
        ]

    def test_memory_input_returns_register_and_prunes_exact_branch(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA SLOT\n"
            "      +JSUB GET\n"
            "      LDA #7\n"
            "      STA SLOT\n"
            "      +JSUB GET\n"
            "      COMP #7\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "GET   LDA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        cell = self.cell_for(report, "SLOT")
        summary = self.summary_for(report, "GET")
        spec = summary[
            "return_register_memory_transfers"
        ]["A"]
        self.assertEqual(
            spec["memory_coefficients"],
            {cell: 1},
        )
        self.assertEqual(
            spec["register_coefficients"],
            {},
        )

        calls = self.calls_to(report, "GET")
        self.assertEqual(
            calls[-1][
                "symbolic_memory_input_instantiation"
            ]["exact_registers"]["A"],
            7,
        )
        fallthrough = self.branch_fallthrough(
            report,
            "JEQ",
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "symbolic-memory-input-condition",
        )

    def test_memory_input_returns_register_range_per_callsite(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #20\n"
            "      STA SLOT\n"
            "      +JSUB GET\n"
            "      COMP FLAG\n"
            "      JEQ ONE\n"
            "      LDA #5\n"
            "      J JOIN\n"
            "ONE   LDA #4\n"
            "JOIN  STA SLOT\n"
            "      +JSUB GET\n"
            "      COMP #10\n"
            "      JLT GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "GET   LDA SLOT\n"
            "      RSUB\n"
            "FLAG  RESW 1\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        calls = self.calls_to(report, "GET")
        item = calls[-1][
            "symbolic_memory_input_instantiation"
        ]
        self.assertNotIn("A", item["exact_registers"])
        self.assertEqual(
            item["range_registers"]["A"],
            [4, 5],
        )
        fallthrough = self.branch_fallthrough(
            report,
            "JLT",
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "symbolic-memory-input-range-condition",
        )

    def test_memory_output_can_mix_memory_and_register_inputs(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA INVAL\n"
            "      LDX #1\n"
            "      +JSUB MIX\n"
            "      LDA #4\n"
            "      STA INVAL\n"
            "      LDX #2\n"
            "      +JSUB MIX\n"
            "      CLEAR A\n"
            "      LDA OUTVAL\n"
            "      COMP #7\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "MIX   LDA INVAL\n"
            "      ADDR X,A\n"
            "      ADD #1\n"
            "      STA OUTVAL\n"
            "      RSUB\n"
            "INVAL RESW 1\n"
            "OUTVAL RESW 1\n"
            "      END ENTRY\n"
        )
        in_cell = self.cell_for(report, "INVAL")
        out_cell = self.cell_for(report, "OUTVAL")
        summary = self.summary_for(report, "MIX")
        spec = summary[
            "return_memory_input_transfers"
        ][out_cell]
        self.assertEqual(
            spec["memory_coefficients"],
            {in_cell: 1},
        )
        self.assertEqual(
            spec["register_coefficients"],
            {"X": 1},
        )
        self.assertEqual(spec["offset"], 1)

        calls = self.calls_to(report, "MIX")
        self.assertEqual(
            calls[-1][
                "symbolic_memory_input_instantiation"
            ]["exact_memory"][out_cell],
            7,
        )
        fallthrough = self.branch_fallthrough(
            report,
            "JEQ",
        )
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(
            fallthrough["resolution"],
            "symbolic-memory-input-condition",
        )

    def test_nested_memory_input_formula_composes_but_control_gate_remains_structural(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      STA INVAL\n"
            "      +JSUB OUTER\n"
            "      COMP #5\n"
            "      JEQ GOOD\n"
            "DEAD  LDA #9\n"
            "GOOD  RSUB\n"
            "OUTER RMO L,S\n"
            "      +JSUB INNER\n"
            "      RMO S,L\n"
            "      LDA OUTVAL\n"
            "      RSUB\n"
            "INNER LDA INVAL\n"
            "      ADD #1\n"
            "      STA OUTVAL\n"
            "      RSUB\n"
            "INVAL RESW 1\n"
            "OUTVAL RESW 1\n"
            "      END ENTRY\n"
        )
        in_cell = self.cell_for(report, "INVAL")
        outer = self.summary_for(report, "OUTER")
        spec = outer[
            "return_register_memory_transfers"
        ]["A"]
        self.assertEqual(
            spec["memory_coefficients"],
            {in_cell: 1},
        )
        self.assertEqual(spec["offset"], 1)

        # Structural subroutine analysis deliberately treats any nested JSUB
        # as a possible L clobber.  Symbolic save/restore evidence can compose
        # values, but it must not weaken that established control-flow gate.
        self.assertFalse(
            outer["link_register_preserved"]
        )
        call = self.calls_to(report, "OUTER")[0]
        self.assertNotIn(
            "symbolic_memory_input_instantiation",
            call,
        )

    def test_unproven_outer_return_blocks_instantiation(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #4\n"
            "      STA INVAL\n"
            "      +JSUB OUTER\n"
            "      RSUB\n"
            "OUTER +JSUB INNER\n"
            "      RSUB\n"
            "INNER LDA INVAL\n"
            "      ADD #1\n"
            "      RSUB\n"
            "INVAL RESW 1\n"
            "      END ENTRY\n"
        )
        outer = self.summary_for(report, "OUTER")
        self.assertIn(
            "A",
            outer[
                "return_register_memory_transfers"
            ],
        )
        self.assertFalse(
            outer["link_register_preserved"]
        )
        call = self.calls_to(report, "OUTER")[0]
        self.assertNotIn(
            "symbolic_memory_input_instantiation",
            call,
        )

    def test_indexed_load_does_not_create_memory_input_formula(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB GET\n"
            "      RSUB\n"
            "GET   LDA SLOT,X\n"
            "      RSUB\n"
            "SLOT  RESW 4\n"
            "      END ENTRY\n"
        )
        summary = self.summary_for(report, "GET")
        self.assertNotIn(
            "A",
            summary[
                "return_register_memory_transfers"
            ],
        )

    def test_five_memory_inputs_exceed_sparse_budget(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB WIDE\n"
            "      RSUB\n"
            "WIDE  LDA I1\n"
            "      ADD I2\n"
            "      ADD I3\n"
            "      ADD I4\n"
            "      ADD I5\n"
            "      STA OUTVAL\n"
            "      RSUB\n"
            "I1    RESW 1\n"
            "I2    RESW 1\n"
            "I3    RESW 1\n"
            "I4    RESW 1\n"
            "I5    RESW 1\n"
            "OUTVAL RESW 1\n"
            "      END ENTRY\n"
        )
        out_cell = self.cell_for(
            report,
            "OUTVAL",
        )
        summary = self.summary_for(report, "WIDE")
        self.assertNotIn(
            "A",
            summary[
                "return_register_memory_transfers"
            ],
        )
        self.assertNotIn(
            out_cell,
            summary[
                "return_memory_input_transfers"
            ],
        )

    def test_memory_input_returned_base_resolves_target(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA SLOT\n"
            "      +JSUB GETB\n"
            "      +LDA #0x4000\n"
            "      STA SLOT\n"
            "      +JSUB GETB\n"
            "      BASE 0\n"
            "      J FAR\n"
            "GETB  LDB SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "      END ENTRY\n"
        )
        calls = self.calls_to(report, "GETB")
        self.assertEqual(
            calls[-1][
                "symbolic_memory_input_instantiation"
            ]["exact_registers"]["B"],
            0x4000,
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
        self.assertEqual(
            jump["target"],
            far["address"],
        )
        self.assertEqual(
            jump["target_resolution"],
            "symbolic-memory-input-base",
        )

    def test_report_surfaces_memory_input_contracts(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #3\n"
            "      STA SLOT\n"
            "      +JSUB GET\n"
            "      RSUB\n"
            "GET   LDA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn(
            "SYMBOLIC MEMORY INPUT TRANSFERS",
            rendered,
        )
        self.assertIn("MEM[", rendered)
        self.assertTrue(
            report["symbolic_memory_inputs"][
                "converged"
            ]
        )
        self.assertGreaterEqual(
            report["metrics"][
                "symbolic_memory_input_return_registers"
            ],
            1,
        )


if __name__ == "__main__":
    unittest.main()
