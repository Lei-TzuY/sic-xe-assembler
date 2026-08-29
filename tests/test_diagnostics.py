import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pass1 import encode_byte_operand, parse_line


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
FINAL_SUFFIXES = ("int", "sym", "obj", "lst")


class ParserTests(unittest.TestCase):
    def test_period_inside_character_literal_is_not_a_comment(self):
        self.assertEqual(
            parse_line("MSG BYTE C'HELLO. WORLD' . trailing comment\n"),
            ("MSG", "BYTE", "C'HELLO. WORLD'", False),
        )

    def test_spaces_inside_character_literal_are_preserved(self):
        self.assertEqual(
            parse_line("TEXT BYTE C'HELLO WORLD'\n"),
            ("TEXT", "BYTE", "C'HELLO WORLD'", False),
        )

    def test_indented_unknown_instruction_is_parsed_as_opcode(self):
        self.assertEqual(
            parse_line("    BADOP VALUE\n"),
            (None, "BADOP", "VALUE", False),
        )

    def test_full_line_comment_is_ignored(self):
        self.assertEqual(parse_line("    . comment only\n"), (None, None, None, True))


class ByteOperandTests(unittest.TestCase):
    def test_character_and_hexadecimal_constants(self):
        self.assertEqual(encode_byte_operand("C'A.B'"), "412E42")
        self.assertEqual(encode_byte_operand("C'A B'"), "412042")
        self.assertEqual(encode_byte_operand("X'f1a0'"), "F1A0")

    def test_invalid_hexadecimal_constants_fail(self):
        for operand in ("X'F'", "X'FG'", "Q'12'", "X'12"):
            with self.subTest(operand=operand):
                with self.assertRaises(ValueError):
                    encode_byte_operand(operand)


class AssemblerFailureTests(unittest.TestCase):
    def run_failure_case(self, source_text, expected_error):
        with tempfile.TemporaryDirectory(prefix="sicxe-errors-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            source.write_text(source_text, encoding="utf-8")
            base = source.with_suffix("")

            # Stale artifacts must not survive a failed rebuild.
            for suffix in FINAL_SUFFIXES:
                Path(f"{base}.{suffix}").write_text("stale", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected_error, result.stderr)
            for suffix in FINAL_SUFFIXES:
                self.assertFalse(
                    Path(f"{base}.{suffix}").exists(),
                    f"failed assembly left {suffix} output behind",
                )

    def test_duplicate_label_is_a_hard_error(self):
        self.run_failure_case(
            "COPY START 0\nHERE WORD 1\nHERE WORD 2\n     END COPY\n",
            "pass 1 line 3: Duplicate label HERE",
        )

    def test_undefined_symbol_is_a_hard_error(self):
        self.run_failure_case(
            "COPY START 0\n     LDA MISSING\n     END COPY\n",
            "pass 2 line 2: Undefined symbol MISSING",
        )

    def test_out_of_range_format3_constant_is_a_hard_error(self):
        self.run_failure_case(
            "COPY START 0\n     LDA #4096\n     END COPY\n",
            "pass 2 line 2: Format-3 constant out of 12-bit range",
        )

    def test_missing_end_is_a_hard_error(self):
        self.run_failure_case(
            "COPY START 0\n     RSUB\n",
            "pass 1: Missing END directive",
        )


if __name__ == "__main__":
    unittest.main()
