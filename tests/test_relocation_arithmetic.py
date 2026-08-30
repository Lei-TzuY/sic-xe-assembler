import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import LoaderError, parse_obj_file, pass1 as loader_pass1, pass2 as loader_pass2


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class LoaderRelocationArithmeticTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-relocation-arithmetic-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_repeated_format4_terms_are_grouped_before_range_check(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003000100\n"
            "M00000005+MAIN  \n"
            "M00000005-MAIN  \n"
            "E000000\n"
        )
        estab = loader_pass1([path], 0xFFFF0)
        memory, _ = loader_pass2([path], 0xFFFF0, estab)
        self.assertEqual(bytes(memory[0xFFFF0:0xFFFF3]), bytes.fromhex("000100"))

    def test_format4_relocation_overflow_and_underflow_are_rejected(self):
        overflow = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003000100\n"
            "M00000005+MAIN  \n"
            "E000000\n",
            "overflow.obj",
        )
        estab = loader_pass1([overflow], 0xFFFF0)
        with self.assertRaisesRegex(
            LoaderError,
            "Format-4 relocation result out of unsigned 20-bit range",
        ):
            loader_pass2([overflow], 0xFFFF0, estab)

        underflow = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003000000\n"
            "M00000005-MAIN  \n"
            "E000000\n",
            "underflow.obj",
        )
        estab = loader_pass1([underflow], 0x1000)
        with self.assertRaisesRegex(
            LoaderError,
            "Format-4 relocation result out of unsigned 20-bit range",
        ):
            loader_pass2([underflow], 0x1000, estab)

    def test_word_relocation_uses_signed_addend_and_checks_final_range(self):
        negative_addend = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003FFFFFB\n"
            "M00000006+MAIN  \n"
            "E000000\n",
            "negative.obj",
        )
        estab = loader_pass1([negative_addend], 0x1000)
        memory, _ = loader_pass2([negative_addend], 0x1000, estab)
        self.assertEqual(bytes(memory[0x1000:0x1003]), bytes.fromhex("000FFB"))

        overflow_records = "".join("M00000006+MAIN  \n" for _ in range(9))
        overflow = self.write_object(
            "HMAIN  000000000003\n"
            "T000000037FFFFF\n"
            + overflow_records
            + "E000000\n",
            "word-overflow.obj",
        )
        estab = loader_pass1([overflow], 0xF0000)
        with self.assertRaisesRegex(LoaderError, "WORD relocation result out of 24-bit range"):
            loader_pass2([overflow], 0xF0000, estab)

        underflow = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003800000\n"
            "M00000006-MAIN  \n"
            "E000000\n",
            "word-underflow.obj",
        )
        estab = loader_pass1([underflow], 0x1000)
        with self.assertRaisesRegex(LoaderError, "WORD relocation result out of 24-bit range"):
            loader_pass2([underflow], 0x1000, estab)

    def test_partially_overlapping_modification_fields_are_rejected(self):
        path = self.write_object(
            "HMAIN  000000000004\n"
            "T0000000400000000\n"
            "M00000005+MAIN  \n"
            "M00000106+MAIN  \n"
            "E000000\n"
        )
        with self.assertRaisesRegex(
            LoaderError,
            "Overlapping modification fields in control section MAIN",
        ):
            parse_obj_file(path)


class AssemblerRelocationAddendTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-relocation-addend-")
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

    def test_format4_relocation_addend_must_be_unsigned_20_bit(self):
        _, result = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1\n"
            "     +LDA EXT1-1\n"
            "SEC  CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 2 line 3: Format-4 relocation addend out of unsigned 20-bit range: -1",
            result.stderr,
        )

    def test_word_relocation_addend_must_be_signed_24_bit(self):
        _, result = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1\n"
            "PTR  WORD EXT1+0x800000\n"
            "SEC  CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 2 line 3: WORD relocation addend out of signed 24-bit range: 8388608",
            result.stderr,
        )

    def test_negative_word_relocation_addend_is_unambiguous_end_to_end(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1\n"
            "PTR  WORD EXT1-5\n"
            "SEC  CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "     END MAIN\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        obj_path = source.with_suffix(".obj")
        obj = obj_path.read_text(encoding="utf-8")
        self.assertIn("T00000003FFFFFB", obj)
        self.assertIn("M00000006+EXT1  ", obj)

        estab = loader_pass1([obj_path], 0x4000)
        memory, _ = loader_pass2([obj_path], 0x4000, estab)
        self.assertEqual(bytes(memory[0x4000:0x4003]), bytes.fromhex("003FFE"))


if __name__ == "__main__":
    unittest.main()
