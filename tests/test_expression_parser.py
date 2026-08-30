import tempfile
import unittest
from pathlib import Path

from assembler import main as assembler_main
from expressions import evaluate_expression, evaluate_link_expression


class ExpressionParserTests(unittest.TestCase):
    def test_parentheses_precedence_and_absolute_multiplication(self):
        result = evaluate_expression(
            "(A-B) + 3 * (8-4)",
            0,
            {"A": 0x1200, "B": 0x1100},
            {"A", "B"},
        )
        self.assertEqual(result.value, 0x10C)
        self.assertFalse(result.relocatable)

    def test_unary_signs_preserve_relocation_algebra(self):
        result = evaluate_expression(
            "A + -(B-7)",
            0,
            {"A": 0x1200, "B": 0x1100},
            {"A", "B"},
        )
        self.assertEqual(result.value, 0x107)
        self.assertFalse(result.relocatable)

    def test_current_location_remains_primary_star(self):
        result = evaluate_expression("(* + 6) - A", 0x1010, {"A": 0x1000}, {"A"})
        self.assertEqual(result.value, 0x16)
        self.assertFalse(result.relocatable)

    def test_division_truncates_toward_zero(self):
        positive = evaluate_expression("7 / 3", 0, {}, set())
        negative = evaluate_expression("-7 / 3", 0, {}, set())
        self.assertEqual(positive.value, 2)
        self.assertEqual(negative.value, -2)

    def test_relocatable_multiplication_and_division_are_rejected(self):
        for expression in ("A*2", "2*A", "A/2"):
            with self.subTest(expression=expression):
                with self.assertRaisesRegex(ValueError, "requires absolute operands"):
                    evaluate_expression(expression, 0, {"A": 0x1000}, {"A"})

    def test_division_by_zero_and_malformed_parentheses_are_hard_errors(self):
        with self.assertRaisesRegex(ValueError, "Division by zero"):
            evaluate_expression("10/(3-3)", 0, {}, set())
        with self.assertRaisesRegex(ValueError, "Missing '\\)'"):
            evaluate_expression("(1+2", 0, {}, set())

    def test_external_terms_survive_parentheses_and_unary_signs(self):
        result = evaluate_link_expression(
            "EXT1 - (EXT2 - 3*4)",
            0x1000,
            0x1000,
            {},
            set(),
            {"EXT1", "EXT2"},
        )
        self.assertEqual(result.value, 12)
        self.assertEqual(result.local_relocation_factor, 0)
        self.assertEqual(result.external_terms, ((1, "EXT1"), (-1, "EXT2")))

    def test_external_multiplication_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires absolute operands"):
            evaluate_link_expression(
                "EXT1*2", 0, 0, {}, set(), {"EXT1"}
            )

    def test_assembler_accepts_parenthesized_word_and_equ_expressions(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-expression-parser-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "expr.asm"
        source.write_text(
            "MAIN START 0\n"
            "A RESW 1\n"
            "B RESW 1\n"
            "LEN EQU (B-A) * 4\n"
            "VAL WORD (LEN + 2) * 3\n"
            "    END MAIN\n",
            encoding="utf-8",
        )

        self.assertEqual(assembler_main([str(source)]), 0)
        obj = source.with_suffix(".obj").read_text(encoding="utf-8")
        self.assertIn("T0000060300002A", obj)


if __name__ == "__main__":
    unittest.main()
