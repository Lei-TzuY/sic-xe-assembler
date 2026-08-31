import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from control_flow import analyze_control_flow
from range_analysis import SIGNED_MAX, transfer_range_state
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class RangeInterproceduralTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-range-interproc-")
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

    def test_joined_interval_proves_branch_when_exact_constant_is_unknown(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     COMP VALUE\n"
            "     JEQ ONE\n"
            "     LDA #2\n"
            "     J MERGE\n"
            "ONE  LDA #1\n"
            "MERGE COMP #10\n"
            "     JLT DONE\n"
            "DEAD LDA #9\n"
            "DONE RSUB\n"
            "VALUE WORD 0\n"
            "     END MAIN\n"
        )
        merge = next(node for node in report["instructions"] if "MERGE" in node["symbols"])
        self.assertIsNone(merge["registers_in"]["A"])
        self.assertEqual(merge["ranges_in"]["A"], (1, 2))

        branch_node = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JLT"
        )
        self.assertIsNone(branch_node["registers_in"]["CC"])
        self.assertEqual(branch_node["ranges_in"]["CC"], ("LT",))
        branch = next(
            edge for edge in report["edges"]
            if edge["source"] == branch_node["address"] and edge["kind"] == "branch"
        )
        fallthrough = next(
            edge for edge in report["edges"]
            if edge["source"] == branch_node["address"] and edge["kind"] == "fallthrough"
        )
        self.assertTrue(branch["resolved"])
        self.assertFalse(fallthrough["resolved"])
        self.assertEqual(fallthrough["reason"], "condition-false")
        self.assertEqual(fallthrough["resolution"], "abstract-range-condition")
        dead = next(node for node in report["instructions"] if "DEAD" in node["symbols"])
        self.assertFalse(dead["reachable"])

    def test_partial_condition_set_can_rule_out_one_branch_kind(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     COMP VALUE\n"
            "     JEQ TEN\n"
            "     LDA #9\n"
            "     J MERGE\n"
            "TEN  LDA #10\n"
            "MERGE COMP #10\n"
            "     JGT BAD\n"
            "GOOD RSUB\n"
            "BAD  LDA #7\n"
            "     RSUB\n"
            "VALUE WORD 0\n"
            "     END MAIN\n"
        )
        branch_node = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JGT"
        )
        self.assertEqual(branch_node["ranges_in"]["A"], (9, 10))
        self.assertEqual(branch_node["ranges_in"]["CC"], ("LT", "EQ"))
        branch = next(
            edge for edge in report["edges"]
            if edge["source"] == branch_node["address"] and edge["kind"] == "branch"
        )
        self.assertFalse(branch["resolved"])
        self.assertEqual(branch["condition_values"], ["LT", "EQ"])
        self.assertEqual(branch["resolution"], "abstract-range-condition")
        bad = next(node for node in report["instructions"] if "BAD" in node["symbols"])
        self.assertFalse(bad["reachable"])

    def test_singleton_interval_can_resolve_base_target_without_exact_b(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     LDA VALUE\n"
            "     AND #0\n"
            "     +ADD #0x4000\n"
            "     RMO A,B\n"
            "     BASE 0\n"
            "     J FAR\n"
            "VALUE WORD 123\n"
            "     RESB 3000\n"
            "FAR  RSUB\n"
            "     END MAIN\n"
        )
        jump = next(node for node in report["instructions"] if node["base_mnemonic"] == "J")
        self.assertIsNone(jump["registers_in"]["B"])
        self.assertEqual(jump["ranges_in"]["B"], (0x4000, 0x4000))
        self.assertEqual(jump["target_resolution"], "range-singleton-base")
        far = next(node for node in report["instructions"] if "FAR" in node["symbols"])
        self.assertEqual(jump["target"], far["address"])
        edge = next(
            edge for edge in report["edges"]
            if edge["source"] == jump["address"] and edge["kind"] == "jump"
        )
        self.assertTrue(edge["resolved"])
        self.assertEqual(edge["resolution"], "range-singleton-base")

    def test_nested_callee_summaries_compose_without_global_clobber(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     +JSUB OUTER\n"
            "     RSUB\n"
            "OUTER +JSUB INNER\n"
            "     RSUB\n"
            "INNER LDA #1\n"
            "     RSUB\n"
            "     END MAIN\n"
        )
        outer = next(node for node in report["instructions"] if "OUTER" in node["symbols"])
        inner = next(node for node in report["instructions"] if "INNER" in node["symbols"])
        outer_call = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB" and node["target"] == outer["address"]
        )
        inner_call = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "JSUB" and node["target"] == inner["address"]
        )

        outer_summary = outer_call["call_summary"]
        inner_summary = inner_call["call_summary"]
        self.assertIn("A", outer_summary["may_clobber"])
        self.assertIn("L", outer_summary["may_clobber"])
        self.assertIn("B", outer_summary["preserved"])
        self.assertEqual(outer_summary["nested_callees"], [inner["address"]])
        self.assertIn("A", inner_summary["may_clobber"])
        self.assertIn("L", inner_summary["preserved"])

        calls = {call["source"]: call for call in report["calls"]}
        self.assertFalse(calls[outer_call["address"]]["returns_resolved"])
        self.assertTrue(calls[inner_call["address"]]["returns_resolved"])

    def test_leaf_subroutine_gets_proven_return_edge(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     +JSUB ROUTN\n"
            "CONT LDA #2\n"
            "     RSUB\n"
            "ROUTN LDA #1\n"
            "     RSUB\n"
            "     END MAIN\n"
        )
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        continuation = next(node for node in report["instructions"] if "CONT" in node["symbols"])
        routine = next(node for node in report["instructions"] if "ROUTN" in node["symbols"])
        summary = call["call_summary"]
        self.assertTrue(summary["link_register_preserved"])
        self.assertIn("L", summary["preserved"])

        synthetic = [edge for edge in report["edges"] if edge.get("synthetic_return")]
        self.assertEqual(len(synthetic), 1)
        edge = synthetic[0]
        self.assertEqual(edge["target"], continuation["address"])
        self.assertEqual(edge["callee_entry"], routine["address"])
        self.assertEqual(edge["call_source"], call["address"])
        self.assertEqual(edge["resolution"], "link-register-summary")
        call_record = next(item for item in report["calls"] if item["source"] == call["address"])
        self.assertTrue(call_record["returns_resolved"])
        self.assertEqual(call_record["continuation"], continuation["address"])
        self.assertEqual(call_record["return_sites"], [edge["source"]])

    def test_link_register_write_blocks_synthetic_return(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "     +JSUB ROUTN\n"
            "CONT RSUB\n"
            "ROUTN LDL #0\n"
            "     RSUB\n"
            "     END MAIN\n"
        )
        call = next(node for node in report["instructions"] if node["base_mnemonic"] == "JSUB")
        self.assertFalse(call["call_summary"]["link_register_preserved"])
        self.assertIn("L", call["call_summary"]["may_clobber"])
        self.assertFalse(any(edge.get("synthetic_return") for edge in report["edges"]))
        call_record = next(item for item in report["calls"] if item["source"] == call["address"])
        self.assertFalse(call_record["returns_resolved"])

    def test_signed_interval_wrap_degrades_to_unknown(self):
        incoming = {
            "A": (SIGNED_MAX, SIGNED_MAX),
            "X": None,
            "L": None,
            "B": None,
            "S": None,
            "T": None,
            "CC": None,
        }
        node = {
            "base_mnemonic": "ADD",
            "operand": "#1",
            "target": 1,
            "end": 3,
        }
        outgoing = transfer_range_state(node, incoming)
        self.assertIsNone(outgoing["A"])


if __name__ == "__main__":
    unittest.main()
