import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import assembler
from assembler_semantics import validate_generated_object_semantics
from errors import AssemblyError


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class AssemblerSemanticTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-assembler-semantics-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(source_text, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ASSEMBLER), str(source)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        return source, result

    def test_org_initialized_overlap_reports_current_source_line(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "A    WORD 1\n"
            "     ORG A\n"
            "B    BYTE X'FF'\n"
            "     END A\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 1 line 4: Initialized storage overlap in MAIN: "
            "000000-000000 conflicts with line 2 range 000000-000002",
            result.stderr,
        )
        for suffix in (".expanded.asm", ".int", ".sym", ".obj", ".lst"):
            self.assertFalse(source.with_suffix(suffix).exists())

    def test_literal_pool_overlap_is_attributed_to_ltorg_line(self):
        _, result = self.assemble(
            "MAIN START 0\n"
            "A    WORD 1\n"
            "     LDA =X'AA'\n"
            "     ORG A\n"
            "     LTORG\n"
            "     END A\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 1 line 5: Initialized storage overlap in MAIN: "
            "000000-000000 conflicts with line 2 range 000000-000002",
            result.stderr,
        )

    def test_org_can_initialize_fields_inside_reserved_storage(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "BUFFER RESB 64\n"
            "       ORG BUFFER+16\n"
            "FIELD  WORD 1\n"
            "       ORG\n"
            "       END MAIN\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        obj = source.with_suffix(".obj").read_text(encoding="utf-8")
        self.assertIn("HMAIN  000000000040", obj)
        self.assertIn("T00001003000001", obj)

    def test_use_blocks_with_equal_block_offsets_do_not_false_positive(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "A    WORD 1\n"
            "     USE DATA\n"
            "B    WORD 2\n"
            "     USE\n"
            "     END A\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        obj = source.with_suffix(".obj").read_text(encoding="utf-8")
        self.assertIn("T00000003000001", obj)
        self.assertIn("T00000303000002", obj)

    def test_generated_object_semantic_validator_rejects_overlap(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-generated-object-semantics-")
        self.addCleanup(temp.cleanup)
        obj = Path(temp.name) / "bad.obj"
        obj.write_text(
            "HMAIN  000000000004\n"
            "T00000002AABB\n"
            "T00000102CCDD\n"
            "E000000\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            AssemblyError,
            "object semantics: Overlapping T records in control section MAIN",
        ):
            validate_generated_object_semantics(obj)

    def test_postflight_semantic_failure_removes_partial_outputs(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-postflight-cleanup-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(
            "MAIN START 0\n"
            "A    WORD 1\n"
            "     END A\n",
            encoding="utf-8",
        )

        error = AssemblyError("forced postflight failure", phase="object semantics")
        with patch("assembler.validate_generated_object_semantics", side_effect=error):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                result = assembler.main([str(source)])

        self.assertEqual(result, 1)
        for suffix in (".expanded.asm", ".int", ".sym", ".obj", ".lst"):
            self.assertFalse(source.with_suffix(suffix).exists())


if __name__ == "__main__":
    unittest.main()
