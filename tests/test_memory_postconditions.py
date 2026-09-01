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


class MemoryPostconditionTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-memory-postconditions-")
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

    def test_initialized_word_seeds_memory_and_prunes_condition(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA INIT\n"
            "      COMP #5\n"
            "      JEQ TAKEN\n"
            "DEAD  LDA #9\n"
            "TAKEN RSUB\n"
            "INIT  WORD 5\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDA" and node.get("memory_cell_read"))
        dead = next(node for node in report["instructions"] if "DEAD" in node.get("symbols", ()))
        self.assertEqual(load["memory_constant"], 5)
        self.assertEqual(load["memory_value_resolution"], "linked-image-initializer")
        self.assertEqual(load["registers_out"]["A"], 5)
        self.assertFalse(dead["reachable"])
        self.assertTrue(any(item["region_kind"] == "word" for item in report["initialized_memory"]))

    def test_initialized_byte_can_flow_through_ldch(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY CLEAR A\n"
            "      LDCH CHAR\n"
            "      COMP #65\n"
            "      JEQ TAKEN\n"
            "DEAD  LDA #9\n"
            "TAKEN RSUB\n"
            "CHAR  BYTE C'A'\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDCH")
        dead = next(node for node in report["instructions"] if "DEAD" in node.get("symbols", ()))
        self.assertEqual(load["memory_constant"], 65)
        self.assertEqual(load["registers_out"]["A"], 65)
        self.assertFalse(dead["reachable"])
        self.assertTrue(any(item["region_kind"] == "byte" for item in report["initialized_memory"]))

    def test_initialized_literal_is_a_safe_memory_seed(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA =X'000005'\n"
            "      COMP #5\n"
            "      JEQ TAKEN\n"
            "DEAD  LDA #9\n"
            "TAKEN RSUB\n"
            "      LTORG\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDA" and node.get("memory_cell_read"))
        self.assertEqual(load["memory_constant"], 5)
        self.assertTrue(any(item["region_kind"] == "literal" for item in report["initialized_memory"]))

    def test_memory_loaded_base_resolves_base_relative_control_target(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +LDB BASEVL\n"
            "      BASE 0\n"
            "      J FAR\n"
            "      RESB 3000\n"
            "FAR   RSUB\n"
            "BASEVL WORD 16384\n"
            "      END ENTRY\n"
        )
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        far = next(node for node in report["instructions"] if "FAR" in node.get("symbols", ()))
        self.assertEqual(jump["target"], far["address"])
        self.assertEqual(jump["target_resolution"], "memory-feedback-base")
        edge = next(edge for edge in report["edges"] if edge["source"] == jump["address"] and edge["kind"] == "jump")
        self.assertTrue(edge["resolved"])
        self.assertEqual(edge["target"], far["address"])
        self.assertGreaterEqual(report["metrics"]["memory_base_resolutions"], 1)

    def test_callee_return_constant_becomes_post_call_memory_fact(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB SETVAL\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SETVAL LDA #7\n"
            "       STA SLOT\n"
            "       RSUB\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(call for call in report["calls"] if call.get("resolved"))
        cell = load["memory_cell_read"]
        summary = call["memory_effect_summary"]
        self.assertEqual(summary["return_constants"][cell], 7)
        self.assertEqual(load["memory_constant"], 7)
        self.assertTrue(load["memory_value_resolution"].startswith("callee-return@"))
        self.assertEqual(load["registers_out"]["B"], 7)

    def test_callee_return_range_composes_across_paths(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB SETVAL\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SETVAL COMP FLAG\n"
            "       JEQ TWO\n"
            "       LDA #1\n"
            "       J SAVE\n"
            "TWO    LDA #2\n"
            "SAVE   STA SLOT\n"
            "       RSUB\n"
            "FLAG   WORD 0\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(call for call in report["calls"] if call.get("resolved"))
        cell = load["memory_cell_read"]
        self.assertNotIn(cell, call["memory_effect_summary"]["return_constants"])
        self.assertEqual(call["memory_effect_summary"]["return_ranges"][cell], [1, 2])
        self.assertIsNone(load["memory_constant"])
        self.assertEqual(load["memory_range"], [1, 2])
        self.assertEqual(load["ranges_out"]["B"], (1, 2))

    def test_conditional_callee_write_stays_out_of_must_summary_but_guarded_refines_callsite(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #3\n"
            "      STA SLOT\n"
            "      +JSUB MAYSET\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "MAYSET COMP FLAG\n"
            "       JEQ DONE\n"
            "       LDA #7\n"
            "       STA SLOT\n"
            "DONE   RSUB\n"
            "FLAG   WORD 0\n"
            "SLOT   RESW 1\n"
            "       END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(call for call in report["calls"] if call.get("resolved"))
        cell = load["memory_cell_read"]
        self.assertNotIn(cell, call["memory_effect_summary"]["return_constants"])
        self.assertNotIn(cell, call["memory_effect_summary"]["return_ranges"])

        guarded = call["guarded_transfer_instantiation"]
        self.assertIsNotNone(guarded)
        self.assertEqual(len(guarded["feasible_cases"]), 1)
        self.assertEqual(guarded["exact_memory"][cell], 7)
        self.assertEqual(load["memory_constant"], 7)
        self.assertEqual(load["registers_out"]["B"], 7)

    def test_nested_callee_postcondition_composes_through_outer(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB OUTER\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "OUTER STL RETADR\n"
            "      +JSUB INNER\n"
            "      LDL RETADR\n"
            "      RSUB\n"
            "INNER LDA #9\n"
            "      STA SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "RETADR RESW 1\n"
            "      END ENTRY\n"
        )
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        outer_call = next(call for call in report["calls"] if any(
            node["address"] == call.get("target") and "OUTER" in node.get("symbols", ())
            for node in report["instructions"]
        ))
        cell = load["memory_cell_read"]
        self.assertEqual(outer_call["memory_effect_summary"]["return_constants"][cell], 9)
        self.assertEqual(load["memory_constant"], 9)
        self.assertGreater(report["metrics"]["return_memory_postconditions"], 0)

        rendered = render_control_flow_report(report)
        self.assertIn("initialized=", rendered)
        self.assertIn("return=", rendered)


if __name__ == "__main__":
    unittest.main()
