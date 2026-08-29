import tempfile
import unittest
from pathlib import Path

from errors import AssemblyError
from macro import run_macro_processor


class MacroProcessorTests(unittest.TestCase):
    def run_processor(self, source_text):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-") as temp_name:
            source = Path(temp_name) / "input.asm"
            output = Path(temp_name) / "output.asm"
            source.write_text(source_text, encoding="utf-8")
            run_macro_processor(source, output)
            return output.read_text(encoding="utf-8")

    def test_parameter_substitution_is_token_safe(self):
        output = self.run_processor(
            "PAIR MACRO &A,&AB\n"
            "     LDA &A\n"
            "     ADD &AB\n"
            "     MEND\n"
            "COPY START 0\n"
            "     PAIR ONE,TWO\n"
            "ONE WORD 1\n"
            "TWO WORD 2\n"
            "     END COPY\n"
        )
        self.assertIn("     LDA ONE\n", output)
        self.assertIn("     ADD TWO\n", output)
        self.assertNotIn("ONEB", output)

    def test_argument_split_preserves_commas_inside_quotes(self):
        output = self.run_processor(
            "EMIT MACRO &VALUE\n"
            "DATA BYTE &VALUE\n"
            "     MEND\n"
            "COPY START 0\n"
            "     EMIT C'A,B'\n"
            "     END COPY\n"
        )
        self.assertIn("DATA BYTE C'A,B'\n", output)

    def test_argument_count_mismatch_is_a_hard_error(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            output = Path(temp_name) / "bad.expanded.asm"
            source.write_text(
                "PAIR MACRO &A,&B\n"
                "     LDA &A\n"
                "     ADD &B\n"
                "     MEND\n"
                "COPY START 0\n"
                "     PAIR ONE\n"
                "     END COPY\n",
                encoding="utf-8",
            )
            with self.assertRaises(AssemblyError) as context:
                run_macro_processor(source, output)
            self.assertIn(
                "macro line 6: PAIR expects 2 argument(s), got 1",
                str(context.exception),
            )

    def test_unterminated_macro_is_a_hard_error(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            output = Path(temp_name) / "bad.expanded.asm"
            source.write_text(
                "BROKEN MACRO &VALUE\n"
                "     LDA &VALUE\n",
                encoding="utf-8",
            )
            with self.assertRaises(AssemblyError) as context:
                run_macro_processor(source, output)
            self.assertIn(
                "macro line 1: Unterminated MACRO definition: BROKEN",
                str(context.exception),
            )

    def test_nested_macro_definition_and_expansion(self):
        output = self.run_processor(
            "OUTER MACRO &VALUE\n"
            "INNER MACRO &ARG\n"
            "     LDA &ARG\n"
            "     MEND\n"
            "     INNER &VALUE\n"
            "     MEND\n"
            "COPY START 0\n"
            "     OUTER #7\n"
            "     END COPY\n"
        )
        self.assertIn(". Macro Expansion: OUTER\n", output)
        self.assertIn(". Macro Expansion: INNER\n", output)
        self.assertIn("     LDA #7\n", output)
        self.assertNotIn(" MACRO ", output)

    def test_local_labels_are_unique_per_expansion(self):
        output = self.run_processor(
            "SPIN MACRO &TARGET\n"
            "$LOOP LDA &TARGET\n"
            "      J $LOOP\n"
            "      MEND\n"
            "COPY START 0\n"
            "      SPIN ALPHA\n"
            "      SPIN BETA\n"
            "      END COPY\n"
        )
        self.assertIn("__SPIN_0001_LOOP LDA ALPHA", output)
        self.assertIn("J __SPIN_0001_LOOP", output)
        self.assertIn("__SPIN_0002_LOOP LDA BETA", output)
        self.assertIn("J __SPIN_0002_LOOP", output)

    def test_recursive_macro_expansion_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            output = Path(temp_name) / "bad.expanded.asm"
            source.write_text(
                "SELF MACRO\n"
                "     SELF\n"
                "     MEND\n"
                "COPY START 0\n"
                "     SELF\n"
                "     END COPY\n",
                encoding="utf-8",
            )
            with self.assertRaises(AssemblyError) as context:
                run_macro_processor(source, output)
            self.assertIn(
                "Recursive macro expansion detected: SELF -> SELF",
                str(context.exception),
            )

    def test_undeclared_parameter_reference_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            output = Path(temp_name) / "bad.expanded.asm"
            source.write_text(
                "BAD MACRO &A\n"
                "     LDA &AB\n"
                "     MEND\n",
                encoding="utf-8",
            )
            with self.assertRaises(AssemblyError) as context:
                run_macro_processor(source, output)
            self.assertIn(
                "macro line 2: Macro BAD references undeclared parameter &AB",
                str(context.exception),
            )


if __name__ == "__main__":
    unittest.main()
