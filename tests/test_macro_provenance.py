import tempfile
import unittest
from pathlib import Path

from macro import run_macro_processor


class MacroProvenanceTests(unittest.TestCase):
    def test_nested_expansion_tracks_root_invocation_definition_and_stack(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-provenance-") as temp_name:
            source = Path(temp_name) / "input.asm"
            expanded = Path(temp_name) / "expanded.asm"
            source.write_text(
                "OUTER MACRO &VALUE\n"
                "INNER MACRO &ARG\n"
                "      LDA &ARG\n"
                "      MEND\n"
                "      INNER &VALUE\n"
                "      MEND\n"
                "MAIN  START 0\n"
                "      OUTER #7\n"
                "      END MAIN\n",
                encoding="utf-8",
            )

            trace = run_macro_processor(source, expanded)
            text = expanded.read_text(encoding="utf-8")
            self.assertIn(". Macro Expansion: OUTER\n", text)
            self.assertIn(". Macro Expansion: INNER\n", text)
            self.assertIn("      LDA #7\n", text)

            lines = text.splitlines()
            lda_line = lines.index("      LDA #7") + 1
            item = trace[lda_line - 1]
            self.assertEqual(item["expanded_line"], lda_line)
            self.assertEqual(item["source_line"], 8)
            self.assertEqual(item["definition_line"], 3)
            self.assertIsNone(item["generated"])
            self.assertEqual(
                [frame["name"] for frame in item["macro_stack"]],
                ["OUTER", "INNER"],
            )
            self.assertEqual(
                [frame["expansion_id"] for frame in item["macro_stack"]],
                [1, 2],
            )
            self.assertEqual(item["macro_stack"][0]["invocation_line"], 8)
            self.assertEqual(item["macro_stack"][0]["definition_line"], 1)
            self.assertEqual(item["macro_stack"][1]["invocation_line"], 5)
            self.assertEqual(item["macro_stack"][1]["definition_line"], 2)

    def test_direct_lines_keep_their_original_source_line(self):
        with tempfile.TemporaryDirectory(prefix="sicxe-macro-provenance-direct-") as temp_name:
            source = Path(temp_name) / "input.asm"
            expanded = Path(temp_name) / "expanded.asm"
            source.write_text(
                "MAIN START 0\n"
                "FIRST LDA #1\n"
                "      END FIRST\n",
                encoding="utf-8",
            )
            trace = run_macro_processor(source, expanded)
            self.assertEqual([item["source_line"] for item in trace], [1, 2, 3])
            self.assertTrue(all(not item["macro_stack"] for item in trace))
            self.assertTrue(all(item["definition_line"] is None for item in trace))


if __name__ == "__main__":
    unittest.main()
