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


class ReachingDefinitionTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble_and_link(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-reaching-defs-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        linked = self.run_script(LOADER, source.with_suffix(".obj"), progaddr)
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
        return report

    def test_straight_line_def_use_chain_links_each_register_use(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST LDA #1\n"
            "      ADD #2\n"
            "      STA OUT\n"
            "      RSUB\n"
            "OUT   RESW 1\n"
            "      END FIRST\n"
        )
        load = next(node for node in report["instructions"] if "FIRST" in node["symbols"])
        add = next(node for node in report["instructions"] if node["base_mnemonic"] == "ADD")
        store = next(node for node in report["instructions"] if node["base_mnemonic"] == "STA")

        load_def = load["definition_ids"]["A"]
        add_def = add["definition_ids"]["A"]
        self.assertEqual(add["use_definitions"]["A"], [load_def])
        self.assertEqual(store["use_definitions"]["A"], [add_def])

        chains = {chain["id"]: chain for chain in report["def_use_chains"]}
        self.assertEqual([site["address"] for site in chains[load_def]["use_sites"]], [add["address"]])
        self.assertEqual([site["address"] for site in chains[add_def]["use_sites"]], [store["address"]])

    def test_merge_keeps_multiple_reaching_definitions_instead_of_guessing(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST COMP FLAG\n"
            "      JEQ LEFT\n"
            "      LDA #1\n"
            "      J JOIN\n"
            "LEFT  LDA #2\n"
            "JOIN  STA OUT\n"
            "      RSUB\n"
            "FLAG  WORD 0\n"
            "OUT   RESW 1\n"
            "      END FIRST\n"
        )
        left = next(node for node in report["instructions"] if "LEFT" in node["symbols"])
        right = next(
            node for node in report["instructions"]
            if node["base_mnemonic"] == "LDA" and node["operand"] == "#1"
        )
        join = next(node for node in report["instructions"] if "JOIN" in node["symbols"])
        expected = sorted([left["definition_ids"]["A"], right["definition_ids"]["A"]])
        self.assertEqual(join["use_definitions"]["A"], expected)
        self.assertEqual(join["reaching_in"]["A"], expected)

    def test_dead_overwritten_definition_has_no_use_sites(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST LDA #1\n"
            "      LDA #2\n"
            "      STA OUT\n"
            "      RSUB\n"
            "OUT   RESW 1\n"
            "      END FIRST\n"
        )
        first = next(node for node in report["instructions"] if "FIRST" in node["symbols"])
        definition_id = first["definition_ids"]["A"]
        chain = next(item for item in report["def_use_chains"] if item["id"] == definition_id)
        self.assertEqual(chain["use_sites"], [])
        self.assertIn(
            definition_id,
            [item["definition_id"] for item in report["dead_definitions"]],
        )

    def test_function_contracts_distinguish_inputs_outputs_and_passthrough(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST LDB #7\n"
            "      +JSUB ROUTN\n"
            "      STB OUT\n"
            "      RSUB\n"
            "ROUTN RMO B,A\n"
            "      LDS #1\n"
            "      CLEAR X\n"
            "      RSUB\n"
            "OUT   RESW 1\n"
            "      END FIRST\n"
        )
        routn = next(function for function in report["functions"] if "ROUTN" in function["symbols"])
        self.assertIn("B", routn["required_inputs"])
        self.assertIn("L", routn["required_inputs"])
        self.assertIn("A", routn["produced_outputs"])
        self.assertIn("S", routn["produced_outputs"])
        self.assertIn("X", routn["produced_outputs"])
        self.assertIn("B", routn["passthrough_inputs"])
        self.assertIn("L", routn["passthrough_inputs"])
        self.assertIn("A", routn["overwritten_inputs"])
        self.assertIn("S", routn["overwritten_inputs"])
        self.assertIn("X", routn["overwritten_inputs"])
        self.assertTrue(routn["input_use_sites"]["B"])
        self.assertTrue(routn["output_definitions"]["A"])

    def test_function_entry_pseudo_definition_is_visible_in_use_chain(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST +JSUB ROUTN\n"
            "      RSUB\n"
            "ROUTN RMO B,A\n"
            "      RSUB\n"
            "      END FIRST\n"
        )
        routn_node = next(node for node in report["instructions"] if "ROUTN" in node["symbols"])
        reaching = routn_node["use_definitions"]["B"]
        self.assertEqual(len(reaching), 1)
        self.assertTrue(reaching[0].startswith(f"E{routn_node['address']:05X}:B"))
        chain = next(item for item in report["def_use_chains"] if item["id"] == reaching[0])
        self.assertEqual(chain["kind"], "entry")
        self.assertEqual(chain["value"], "B")
        self.assertEqual(chain["use_sites"][0]["address"], routn_node["address"])

    def test_text_report_surfaces_reaching_definitions_and_contracts(self):
        report = self.assemble_and_link(
            "MAIN START 0\n"
            "FIRST LDA #1\n"
            "      ADD #2\n"
            "      RSUB\n"
            "      END FIRST\n"
        )
        rendered = render_control_flow_report(report)
        self.assertIn("REACHING DEFINITIONS", rendered)
        self.assertIn("A<-D", rendered)
        self.assertIn("required=", rendered)
        self.assertIn("outputs=", rendered)
        self.assertGreater(report["metrics"]["reaching_definitions"], 0)
        self.assertGreater(report["metrics"]["def_use_links"], 0)


if __name__ == "__main__":
    unittest.main()
