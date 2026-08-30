import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from source_map import load_linked_debug_map, load_source_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class OriginalSourceProvenanceTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def make_program(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-original-provenance-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(
            "LOADV MACRO &VALUE\n"
            "      LDA &VALUE\n"
            "      MEND\n"
            "MAIN  START 0\n"
            "      LOADV #7\n"
            "DIRECT RSUB\n"
            "      END MAIN\n",
            encoding="utf-8",
        )
        return source

    def test_source_map_binds_original_source_and_macro_body(self):
        source = self.make_program()
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)

        source_map, _ = load_source_map(source.with_suffix(".sourcemap.json"))
        self.assertEqual(
            source_map["original_source_sha256"],
            hashlib.sha256(source.read_bytes()).hexdigest(),
        )
        section = source_map["sections"][0]
        instructions = [
            region for region in section["regions"]
            if region["kind"] == "instruction"
        ]
        lda, rsub = instructions

        self.assertEqual(lda["provenance"]["kind"], "macro")
        self.assertEqual(lda["provenance"]["source_line"], 5)
        self.assertEqual(lda["provenance"]["definition_line"], 2)
        self.assertEqual(
            [frame["name"] for frame in lda["provenance"]["macro_stack"]],
            ["LOADV"],
        )
        self.assertEqual(lda["provenance"]["macro_stack"][0]["invocation_line"], 5)
        self.assertEqual(lda["provenance"]["macro_stack"][0]["definition_line"], 1)

        self.assertEqual(rsub["provenance"]["kind"], "direct")
        self.assertEqual(rsub["provenance"]["source_line"], 6)
        self.assertIsNone(rsub["provenance"]["definition_line"])
        self.assertEqual(rsub["provenance"]["macro_stack"], [])

    def test_linked_debug_map_preserves_original_provenance_after_rebase(self):
        source = self.make_program()
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)

        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        instructions = [
            region for region in debug["sections"][0]["regions"]
            if region["kind"] == "instruction"
        ]
        self.assertEqual(instructions[0]["loaded_address"], 0x4000)
        self.assertEqual(instructions[0]["provenance"]["source_line"], 5)
        self.assertEqual(instructions[0]["provenance"]["definition_line"], 2)
        self.assertEqual(instructions[1]["loaded_address"], 0x4003)
        self.assertEqual(instructions[1]["provenance"]["source_line"], 6)


if __name__ == "__main__":
    unittest.main()
