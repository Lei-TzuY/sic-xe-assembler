import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from control_flow import (
    analyze_control_flow,
    annotate_typed_disassembly,
    render_control_flow_dot,
    render_control_flow_report,
)
from macro import load_macro_provenance
from source_map import load_linked_debug_map, load_source_map, render_typed_disassembly


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"
TOOLCHAIN = ROOT / "sicxe.py"


class ProvenanceCfgTests(unittest.TestCase):
    def make_macro_program(self, directory, name="program.asm"):
        source = Path(directory) / name
        source.write_text(
            "MAIN START 0\n"
            "INNER MACRO &T\n"
            "      LDA #1\n"
            "      J &T\n"
            "      MEND\n"
            "OUTER MACRO &T\n"
            "      INNER &T\n"
            "      MEND\n"
            "      OUTER TARGET\n"
            "DEAD  LDA #9\n"
            "TARGET RSUB\n"
            "      END MAIN\n",
            encoding="utf-8",
        )
        return source

    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble(self, source):
        result = self.run_script(ASSEMBLER, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        return source.with_suffix(".obj")

    def link(self, obj, progaddr="4000"):
        result = self.run_script(LOADER, obj, progaddr)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nested_macro_provenance_reaches_source_and_debug_maps(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-prov-")
        self.addCleanup(temp.cleanup)
        source = self.make_macro_program(temp.name)
        obj = self.assemble(source)

        provenance_path = Path(str(source.with_suffix(".expanded.asm")).replace(".asm", ".provenance.json"))
        self.assertTrue(provenance_path.exists())
        expanded = source.with_suffix(".expanded.asm")
        provenance = load_macro_provenance(
            provenance_path,
            expanded_sha256=hashlib.sha256(expanded.read_bytes()).hexdigest(),
        )
        macro_body_lines = [item for item in provenance["lines"] if item["kind"] == "macro-body"]
        lda_origin = next(item for item in macro_body_lines if item["source_line"] == 3)
        self.assertEqual(lda_origin["invocation_line"], 9)
        self.assertEqual([frame["name"] for frame in lda_origin["macro_stack"]], ["OUTER", "INNER"])
        self.assertEqual(lda_origin["macro_stack"][0]["body_line"], 7)
        self.assertEqual(lda_origin["macro_stack"][1]["body_line"], 3)

        source_map, _ = load_source_map(source.with_suffix(".sourcemap.json"))
        regions = source_map["sections"][0]["regions"]
        lda_region = next(region for region in regions if region["source_address"] == 0)
        jump_region = next(region for region in regions if region["source_address"] == 3)
        dead_region = next(region for region in regions if region["source_address"] == 6)
        self.assertEqual(lda_region["provenance"]["source_line"], 3)
        self.assertEqual(lda_region["provenance"]["invocation_line"], 9)
        self.assertEqual([frame["name"] for frame in jump_region["provenance"]["macro_stack"]], ["OUTER", "INNER"])
        self.assertEqual(dead_region["provenance"]["source_line"], 10)
        self.assertEqual(dead_region["provenance"]["macro_stack"], [])

        self.link(obj)
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        linked_lda = next(
            region for region in debug["sections"][0]["regions"]
            if region["loaded_address"] == 0x4000
        )
        self.assertEqual(linked_lda["provenance"]["source_line"], 3)
        self.assertEqual(linked_lda["provenance"]["invocation_line"], 9)

    def test_cfg_marks_jump_skipped_typed_instruction_unreachable(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cfg-")
        self.addCleanup(temp.cleanup)
        source = self.make_macro_program(temp.name)
        obj = self.assemble(source)
        self.link(obj)

        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(source.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        report = analyze_control_flow(
            image,
            manifest["image_start"],
            debug,
            manifest["entry"]["address"],
        )

        by_address = {item["address"]: item for item in report["instructions"]}
        self.assertTrue(by_address[0x4000]["reachable"])
        self.assertTrue(by_address[0x4003]["reachable"])
        self.assertFalse(by_address[0x4006]["reachable"])
        self.assertTrue(by_address[0x4009]["reachable"])
        self.assertEqual(report["unreachable_instruction_count"], 1)

        jump = next(edge for edge in report["edges"] if edge["source"] == 0x4003 and edge["kind"] == "jump")
        self.assertEqual(jump["target"], 0x4009)
        self.assertTrue(jump["resolved"])
        self.assertFalse(any(edge["source"] == 0x4003 and edge["kind"] == "fallthrough" for edge in report["edges"]))

        typed = render_typed_disassembly(image, 0x4000, debug)
        annotated = annotate_typed_disassembly(typed, debug, control_flow=report)
        self.assertIn("origin=source:3", annotated)
        self.assertIn("invoke=9", annotated)
        self.assertIn("macro=OUTER#1", annotated)
        dead_line = next(line for line in annotated.splitlines() if line.startswith("04006"))
        self.assertIn("cfg=UNREACHABLE", dead_line)

        text = render_control_flow_report(report)
        self.assertIn("UNREACHABLE", text)
        self.assertIn("--jump-->", text)
        dot = render_control_flow_dot(report)
        self.assertTrue(dot.startswith("digraph sicxe_cfg"))
        self.assertIn("label=\"jump\"", dot)

    def test_cfg_classifies_conditional_call_jump_and_return(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cfg-kinds-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "flow.asm"
        source.write_text(
            "MAIN START 0\n"
            "     JEQ ALT\n"
            "     JSUB ROUTN\n"
            "     J DONE\n"
            "ALT  LDA #1\n"
            "     J DONE\n"
            "ROUTN RSUB\n"
            "DONE RSUB\n"
            "     END MAIN\n",
            encoding="utf-8",
        )
        obj = self.assemble(source)
        self.link(obj, "5000")
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(source.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        report = analyze_control_flow(image, 0x5000, debug, manifest["entry"]["address"])
        kinds = {edge["kind"] for edge in report["edges"]}
        self.assertTrue({"branch", "call", "jump", "return", "fallthrough"}.issubset(kinds))
        self.assertEqual(report["unreachable_instruction_count"], 0)

    def test_cli_cfg_and_disasm_cfg_surface_provenance(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cfg-cli-")
        self.addCleanup(temp.cleanup)
        source = self.make_macro_program(temp.name)
        obj = self.assemble(source)
        linked = self.run_script(TOOLCHAIN, "link", obj, "--progaddr", "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin")
        manifest = source.with_suffix(".manifest.json")

        cfg = self.run_script(TOOLCHAIN, "cfg", image, "--manifest", manifest)
        self.assertEqual(cfg.returncode, 0, cfg.stderr)
        self.assertIn("SIC/XE CONTROL FLOW GRAPH", cfg.stdout)
        self.assertIn("UNREACHABLE", cfg.stdout)
        self.assertIn("origin=source:3", cfg.stdout)

        structured = self.run_script(TOOLCHAIN, "cfg", image, "--manifest", manifest, "--json")
        self.assertEqual(structured.returncode, 0, structured.stderr)
        payload = json.loads(structured.stdout)
        self.assertEqual(payload["unreachable_instruction_count"], 1)

        dot = self.run_script(TOOLCHAIN, "cfg", image, "--manifest", manifest, "--dot")
        self.assertEqual(dot.returncode, 0, dot.stderr)
        self.assertIn("digraph sicxe_cfg", dot.stdout)

        disasm = self.run_script(
            TOOLCHAIN,
            "disasm",
            image,
            "--manifest",
            manifest,
            "--cfg",
        )
        self.assertEqual(disasm.returncode, 0, disasm.stderr)
        self.assertIn("macro=OUTER#1", disasm.stdout)
        self.assertIn("cfg=UNREACHABLE", disasm.stdout)
        self.assertIn("SIC/XE CONTROL FLOW GRAPH", disasm.stdout)

    def test_macro_provenance_is_path_independent(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-prov-paths-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        first_dir = root / "one"
        second_dir = root / "two"
        first_dir.mkdir()
        second_dir.mkdir()
        first = self.make_macro_program(first_dir)
        second = self.make_macro_program(second_dir)
        self.assemble(first)
        self.assemble(second)
        first_prov = Path(str(first.with_suffix(".expanded.asm")).replace(".asm", ".provenance.json"))
        second_prov = Path(str(second.with_suffix(".expanded.asm")).replace(".asm", ".provenance.json"))
        self.assertEqual(first_prov.read_bytes(), second_prov.read_bytes())
        self.assertEqual(
            first.with_suffix(".sourcemap.json").read_bytes(),
            second.with_suffix(".sourcemap.json").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
