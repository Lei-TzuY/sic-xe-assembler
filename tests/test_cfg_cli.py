import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "sicxe.py"


class CfgCliTests(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run(
            [sys.executable, str(TOOLCHAIN), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def make_linked_program(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cfg-cli-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "flow.asm"
        source.write_text(
            "BRANCH MACRO &TARGET\n"
            "       JEQ &TARGET\n"
            "       MEND\n"
            "MAIN   START 0\n"
            "ENTRY  LDA #0\n"
            "       BRANCH ZERO\n"
            "       J DONE\n"
            "ZERO   LDX #1\n"
            "DONE   RSUB\n"
            "       END ENTRY\n",
            encoding="utf-8",
        )
        assembled = self.run_tool("assemble", source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_tool("link", obj, "--progaddr", "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        return source

    def test_cfg_command_emits_text_and_json_graph(self):
        source = self.make_linked_program()
        image = source.with_suffix(".bin")
        manifest = source.with_suffix(".manifest.json")

        text = self.run_tool("cfg", image, "--manifest", manifest)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("SIC/XE CONTROL FLOW GRAPH", text.stdout)
        self.assertIn("BLOCK B0001", text.stdout)
        self.assertIn("-> branch", text.stdout)
        self.assertIn("macro=BRANCH#1", text.stdout)

        structured = self.run_tool("cfg", image, "--manifest", manifest, "--json")
        self.assertEqual(structured.returncode, 0, structured.stderr)
        graph = json.loads(structured.stdout)
        self.assertEqual(graph["kind"], "sicxe-control-flow-graph")
        self.assertEqual(graph["entry_address"], 0x4000)
        self.assertGreaterEqual(graph["block_count"], 3)
        macro_instruction = next(
            item for item in graph["instructions"]
            if item["mnemonic"].lstrip("+") == "JEQ"
        )
        self.assertEqual(macro_instruction["provenance"]["source_line"], 6)
        self.assertEqual(macro_instruction["provenance"]["definition_line"], 2)

    def test_disasm_blocks_shows_block_boundaries_and_original_source(self):
        source = self.make_linked_program()
        result = self.run_tool(
            "disasm",
            source.with_suffix(".bin"),
            "--manifest",
            source.with_suffix(".manifest.json"),
            "--blocks",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("BASIC BLOCK", result.stdout)
        self.assertIn("successors=", result.stdout)
        self.assertIn("source=6", result.stdout)
        self.assertIn("definition=2", result.stdout)
        self.assertIn("macro=BRANCH#1", result.stdout)

    def test_blocks_rejects_forced_linear_mode(self):
        source = self.make_linked_program()
        result = self.run_tool(
            "disasm",
            source.with_suffix(".bin"),
            "--manifest",
            source.with_suffix(".manifest.json"),
            "--linear",
            "--blocks",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("--blocks requires typed debug metadata", result.stderr)


if __name__ == "__main__":
    unittest.main()
