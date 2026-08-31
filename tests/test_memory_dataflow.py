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


class MemoryDataflowTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-memory-analysis-")
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

    def test_direct_store_load_chain_recovers_constant_and_register_source(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #7\n"
            "      STA SLOT\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        self.assertIsNotNone(store["store_definition_id"])
        self.assertEqual(store["stored_constant"], 7)
        self.assertEqual(load["memory_sources"], [store["store_definition_id"]])
        self.assertEqual(load["load_from_stores"], [store["store_definition_id"]])
        self.assertEqual(load["memory_constant"], 7)
        self.assertEqual(load["loaded_register_constant"], {"register": "B", "value": 7})

        chain = next(
            item for item in report["memory_def_use_chains"]
            if item["id"] == store["store_definition_id"]
        )
        self.assertEqual([site["address"] for site in chain["use_sites"]], [load["address"]])
        self.assertTrue(chain["source_definitions"])

    def test_branch_merge_preserves_multiple_store_definitions(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY COMP FLAG\n"
            "      JEQ LEFT\n"
            "      LDA #1\n"
            "RSTORE STA SLOT\n"
            "      J JOIN\n"
            "LEFT  LDA #2\n"
            "LSTORE STA SLOT\n"
            "JOIN  LDX SLOT\n"
            "      RSUB\n"
            "FLAG  WORD 0\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        stores = [node for node in report["instructions"] if node["base_mnemonic"] == "STA"]
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDX")
        expected = sorted(node["store_definition_id"] for node in stores)
        self.assertEqual(load["memory_sources"], expected)
        self.assertEqual(load["load_from_stores"], expected)
        self.assertIsNone(load["memory_constant"])

    def test_call_summary_preserves_memory_when_callee_has_no_memory_effect(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #5\n"
            "      STA SLOT\n"
            "      +JSUB ROUTN\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "ROUTN CLEAR X\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        call = next(item for item in report["calls"] if item["resolved"])
        self.assertEqual(load["memory_sources"], [store["store_definition_id"]])
        self.assertEqual(load["memory_constant"], 5)
        self.assertFalse(call["memory_effect_summary"]["unknown_write"])
        self.assertEqual(call["memory_effect_summary"]["may_write_cells"], [])
        self.assertFalse(any(
            item["definition_id"] == store["store_definition_id"]
            for item in report["overwritten_stores"]
        ))

    def test_indexed_store_is_may_alias_and_does_not_falsely_kill_precise_store(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "      STA SLOT\n"
            "      CLEAR X\n"
            "      STX SLOT,X\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        precise = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")
        indexed = next(node for node in report["instructions"] if node["base_mnemonic"] == "STX")
        load = next(node for node in report["instructions"] if node["base_mnemonic"] == "LDB")
        self.assertTrue(indexed["unknown_memory_write"])
        self.assertIn(precise["store_definition_id"], load["memory_sources"])
        self.assertTrue(any(definition.startswith("MC") for definition in load["memory_sources"]))
        self.assertIsNone(load["memory_constant"])

    def test_definitely_overwritten_store_is_reported_but_final_store_is_observable(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #1\n"
            "FIRST STA SLOT\n"
            "      LDA #2\n"
            "SECOND STA SLOT\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        first = next(node for node in report["instructions"] if "FIRST" in node["symbols"])
        second = next(node for node in report["instructions"] if "SECOND" in node["symbols"])
        overwritten_ids = {item["definition_id"] for item in report["overwritten_stores"]}
        self.assertIn(first["store_definition_id"], overwritten_ids)
        self.assertNotIn(second["store_definition_id"], overwritten_ids)
        self.assertEqual(report["metrics"]["overwritten_stores"], 1)

    def test_same_value_store_is_only_a_candidate_and_keeps_precise_chain(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY LDA #3\n"
            "FIRST STA SLOT\n"
            "SECOND STA SLOT\n"
            "      LDB SLOT\n"
            "      RSUB\n"
            "SLOT  RESW 1\n"
            "      END ENTRY\n"
        )
        second = next(node for node in report["instructions"] if "SECOND" in node["symbols"])
        candidates = report["same_value_store_candidates"]
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["definition_id"], second["store_definition_id"])
        self.assertEqual(candidates[0]["constant"], 3)
        self.assertEqual(report["metrics"]["same_value_store_candidates"], 1)

    def test_function_memory_contracts_and_text_report(self):
        _, report = self.assemble_and_link(
            "MAIN START 0\n"
            "ENTRY +JSUB ROUTN\n"
            "      RSUB\n"
            "ROUTN LDA INPUT\n"
            "      STA OUTPUT\n"
            "      RSUB\n"
            "INPUT WORD 9\n"
            "OUTPUT RESW 1\n"
            "      END ENTRY\n"
        )
        routn = next(
            function for function in report["functions"]
            if "ROUTN" in function.get("symbols", ())
        )
        self.assertEqual(len(routn["memory_inputs"]), 1)
        self.assertEqual(len(routn["memory_outputs"]), 1)
        self.assertIn(routn["memory_inputs"][0], routn["memory_reads"])
        self.assertIn(routn["memory_outputs"][0], routn["memory_writes"])
        self.assertIn(routn["memory_outputs"][0], routn["memory_overwritten_inputs"])

        rendered = render_control_flow_report(report)
        self.assertIn("MEMORY DATAFLOW", rendered)
        self.assertIn("mem-in=", rendered)
        self.assertIn("mem-out=", rendered)
        self.assertIn("write=", rendered)


if __name__ == "__main__":
    unittest.main()
