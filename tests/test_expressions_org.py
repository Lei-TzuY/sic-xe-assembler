import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from expressions import evaluate_expression
from pass1 import run_pass1


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class ExpressionAlgebraTests(unittest.TestCase):
    def setUp(self):
        self.symtab = {
            "ALPHA": 0x1000,
            "BETA": 0x1010,
            "ABS": 7,
        }
        self.relocatable = {"ALPHA", "BETA"}

    def evaluate(self, expression, current=0x1020):
        return evaluate_expression(
            expression,
            current,
            self.symtab,
            self.relocatable,
        )

    def test_relative_minus_relative_is_absolute(self):
        result = self.evaluate("BETA-ALPHA")
        self.assertEqual(result.value, 0x10)
        self.assertFalse(result.relocatable)

    def test_relative_plus_absolute_remains_relocatable(self):
        result = self.evaluate("ALPHA + ABS - 2")
        self.assertEqual(result.value, 0x1005)
        self.assertTrue(result.relocatable)

    def test_balanced_multi_term_expression_can_remain_relocatable(self):
        result = self.evaluate("ALPHA+BETA-ALPHA+3")
        self.assertEqual(result.value, 0x1013)
        self.assertTrue(result.relocatable)

    def test_location_counter_participates_as_relative_term(self):
        result = self.evaluate("*-ALPHA")
        self.assertEqual(result.value, 0x20)
        self.assertFalse(result.relocatable)

    def test_illegal_relative_balances_are_rejected(self):
        for expression in ("ALPHA+BETA", "5-ALPHA", "ALPHA-BETA-ALPHA"):
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ValueError, "Illegal relocatable expression"):
                    self.evaluate(expression)


class OrgDirectiveTests(unittest.TestCase):
    def test_org_restore_and_high_water_mark_define_section_length(self):
        source_text = (
            "COPY START 1000\n"
            "FIRST RESB 4\n"
            "SAVE ORG FIRST+16\n"
            "HIGH WORD 1\n"
            "     ORG\n"
            "LOW  WORD 2\n"
            "SPAN EQU HIGH-LOW\n"
            "DIFF WORD HIGH-LOW\n"
            "PTR  WORD HIGH+3\n"
            "     END FIRST\n"
        )

        with tempfile.TemporaryDirectory(prefix="sicxe-org-") as temp_name:
            temp = Path(temp_name)
            source = temp / "org.asm"
            intermediate = temp / "org.int"
            symbols = temp / "org.sym"
            source.write_text(source_text, encoding="utf-8")

            csects, start = run_pass1(source, intermediate, symbols)
            data = csects["COPY"]

            self.assertEqual(start, 0x1000)
            self.assertEqual(data["symtab"]["SAVE"], 0x1004)
            self.assertEqual(data["symtab"]["HIGH"], 0x1010)
            self.assertEqual(data["symtab"]["LOW"], 0x1004)
            self.assertEqual(data["symtab"]["SPAN"], 0x0C)
            self.assertNotIn("SPAN", data["relocatable"])
            self.assertEqual(data["length"], 0x13)

            intermediate_text = intermediate.read_text(encoding="utf-8")
            self.assertIn("1004\tSAVE ORG FIRST+16", intermediate_text)
            self.assertIn("1010\tHIGH WORD 1", intermediate_text)
            self.assertIn("1013\tORG", intermediate_text)
            self.assertIn("1004\tLOW  WORD 2", intermediate_text)

    def test_org_assembly_emits_absolute_difference_and_relocatable_sum(self):
        source_text = (
            "COPY START 1000\n"
            "FIRST RESB 4\n"
            "     ORG FIRST+16\n"
            "HIGH WORD 1\n"
            "     ORG\n"
            "LOW  WORD 2\n"
            "DIFF WORD HIGH-LOW\n"
            "PTR  WORD HIGH+3\n"
            "     END FIRST\n"
        )

        with tempfile.TemporaryDirectory(prefix="sicxe-org-obj-") as temp_name:
            source = Path(temp_name) / "org.asm"
            source.write_text(source_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            obj = source.with_suffix(".obj").read_text(encoding="utf-8")
            listing = source.with_suffix(".lst").read_text(encoding="utf-8")

            self.assertIn("HCOPY  001000000013", obj)
            self.assertIn("00000C", listing)
            self.assertIn("000013", listing)
            self.assertIn("M00100A06+COPY", obj)

    def test_org_restore_without_saved_location_is_a_hard_error(self):
        source_text = "COPY START 0\n     ORG\n     END COPY\n"
        with tempfile.TemporaryDirectory(prefix="sicxe-org-error-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            source.write_text(source_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "pass 1 line 2: ORG restore requested without a saved location",
                result.stderr,
            )

    def test_org_cannot_move_before_nonzero_section_start(self):
        source_text = "COPY START 1000\n     ORG 5\n     END COPY\n"
        with tempfile.TemporaryDirectory(prefix="sicxe-org-range-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            source.write_text(source_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("ORG target outside control section address range", result.stderr)


if __name__ == "__main__":
    unittest.main()
