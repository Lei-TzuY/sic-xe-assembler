import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from control_flow import analyze_control_flow, render_control_flow_report
from liveness_analysis import instruction_use_def
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class LivenessFunctionTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-liveness-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, progaddr)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(source.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        report = analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )
        return source, report

    def test_overwritten_register_definition_is_reported_dead(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST LDA #1\n"
            "SECOND LDA #2\n"
            "       STA OUT\n"
            "       RSUB\n"
            "OUT    RESW 1\n"
            "       END FIRST\n"
        )
        first = next(node for node in report["instructions"] if "FIRST" in node["symbols"])
        second = next(node for node in report["instructions"] if "SECOND" in node["symbols"])
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        self.assertEqual(first["defs"], ["A"])
        self.assertEqual(first["dead_writes"], ["A"])
        self.assertNotIn("A", first["live_out"])
        self.assertEqual(second["dead_writes"], [])
        self.assertIn("A", second["live_out"])
        self.assertIn("A", store["uses"])
        self.assertTrue(store["memory_write"])
        self.assertTrue(store["side_effects"])
        self.assertEqual(report["metrics"]["dead_register_writes"], 1)

    def test_conditional_branch_consumes_condition_code(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     COMP VALUE\n"
            "     JEQ DONE\n"
            "     LDA #1\n"
            "DONE RSUB\n"
            "VALUE WORD 0\n"
            "     END MAIN\n"
        )
        comp = next(node for node in report["instructions"] if node["base_mnemonic"] == "COMP")
        branch = next(node for node in report["instructions"] if node["base_mnemonic"] == "JEQ")
        self.assertIn("CC", comp["defs"])
        self.assertIn("CC", comp["live_out"])
        self.assertFalse(comp["dead_condition_write"])
        self.assertIn("CC", branch["uses"])

    def test_base_and_index_addressing_are_register_uses(self):
        base_node = {
            "base_mnemonic": "LDA",
            "operand": "01234,X",
            "flags": "111100",
            "target": 0x1234,
        }
        facts = instruction_use_def(base_node)
        self.assertEqual(facts["uses"], ["B", "X"])
        self.assertEqual(facts["defs"], ["A"])

    def test_function_objects_capture_callers_callees_and_transitive_clobbers(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB FOO\n"
            "      +JSUB BAR\n"
            "      RSUB\n"
            "FOO   LDA #1\n"
            "      RSUB\n"
            "BAR   +JSUB FOO\n"
            "      CLEAR X\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        functions = {item["symbols"][0]: item for item in report["functions"] if item["symbols"]}
        self.assertEqual(len(report["functions"]), 3)
        entry = functions["ENTRY"]
        foo = functions["FOO"]
        bar = functions["BAR"]
        self.assertTrue(entry["is_program_entry"])
        self.assertIn(foo["id"], entry["callees"])
        self.assertIn(bar["id"], entry["callees"])
        self.assertIn(entry["id"], foo["callers"])
        self.assertIn(bar["id"], foo["callers"])
        self.assertIn(foo["id"], bar["callees"])
        self.assertIn("A", foo["may_clobber"])
        self.assertIn("A", bar["may_clobber"])
        self.assertIn("L", bar["may_clobber"])
        self.assertIn("X", bar["may_clobber"])
        self.assertGreaterEqual(entry["metrics"]["cyclomatic_complexity"], 1)

        calls = report["calls"]
        foo_calls = [call for call in calls if call.get("callee_function") == foo["id"]]
        self.assertEqual(len(foo_calls), 2)
        self.assertTrue(all(call["caller_functions"] for call in foo_calls))

    def test_shared_tail_is_not_forced_into_unique_function_ownership(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB FOO\n"
            "      +JSUB BAR\n"
            "      RSUB\n"
            "FOO   J COMMON\n"
            "BAR   J COMMON\n"
            "COMMON CLEAR A\n"
            "       RSUB\n"
            "       END ENTRY\n"
        )
        common = next(node for node in report["instructions"] if "COMMON" in node["symbols"])
        self.assertGreaterEqual(len(common["functions"]), 2)
        owning = [
            function["id"]
            for function in report["functions"]
            if common["address"] in function["instruction_addresses"]
        ]
        self.assertEqual(sorted(common["functions"]), sorted(owning))

    def test_text_report_surfaces_liveness_and_functions(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      LDA #2\n"
            "      RSUB\n"
            "      END ENTRY\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("LIVENESS", rendered)
        self.assertIn("FUNCTIONS", rendered)
        self.assertIn("dead=A", rendered)
        self.assertIn("F000", rendered)


if __name__ == "__main__":
    unittest.main()
