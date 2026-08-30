import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from expressions import evaluate_link_expression
from loader import pass1 as loader_pass1, pass2 as loader_pass2


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class LinkExpressionTests(unittest.TestCase):
    def test_external_terms_are_deferred_to_linker(self):
        result = evaluate_link_expression(
            "ALPHA+EXT1-EXT2+5",
            current_location=0x1010,
            csect_start=0x1000,
            symtab={"ALPHA": 0x1004},
            relocatable_symbols={"ALPHA"},
            external_symbols={"EXT1", "EXT2"},
        )

        self.assertEqual(result.value, 9)
        self.assertEqual(result.local_relocation_factor, 1)
        self.assertEqual(result.external_terms, ((1, "EXT1"), (-1, "EXT2")))

    def test_pure_local_illegal_balance_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, "Illegal relocatable expression"):
            evaluate_link_expression(
                "ALPHA+BETA",
                current_location=0x1020,
                csect_start=0x1000,
                symtab={"ALPHA": 0x1004, "BETA": 0x1008},
                relocatable_symbols={"ALPHA", "BETA"},
                external_symbols=set(),
            )


class ExternalExpressionAssemblerTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-ext-expr-")
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

    def test_word_and_format4_external_expressions_relocate_end_to_end(self):
        source, result = self.assemble(
            "MAIN START 1000\n"
            "     EXTREF EXT1,EXT2\n"
            "FIRST +LDA EXT1+7\n"
            "DIFF WORD EXT1-EXT2+5\n"
            "MIX  WORD FIRST+EXT1-EXT2\n"
            "SEC1 CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "SEC2 CSECT\n"
            "     EXTDEF EXT2\n"
            "EXT2 WORD 0\n"
            "     END FIRST\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        obj_path = source.with_suffix(".obj")
        obj = obj_path.read_text(encoding="utf-8")

        self.assertIn("HMAIN  00100000000A", obj)
        self.assertIn("M00100105+EXT1", obj)
        self.assertIn("M00100406+EXT1", obj)
        self.assertIn("M00100406-EXT2", obj)
        self.assertIn("M00100706+MAIN", obj)
        self.assertIn("M00100706+EXT1", obj)
        self.assertIn("M00100706-EXT2", obj)

        estab = loader_pass1([str(obj_path)], 0x4000)
        self.assertEqual(estab["MAIN"], 0x4000)
        self.assertEqual(estab["EXT1"], 0x400A)
        self.assertEqual(estab["EXT2"], 0x400D)

        memory, exec_addr = loader_pass2([str(obj_path)], 0x4000, estab)
        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(bytes(memory[0x4000:0x4004]), bytes.fromhex("03104011"))
        self.assertEqual(bytes(memory[0x4004:0x4007]), bytes.fromhex("000002"))
        self.assertEqual(bytes(memory[0x4007:0x400A]), bytes.fromhex("003FFD"))

    def test_format3_external_expression_requires_format4(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1\n"
            "     LDA EXT1+1\n"
            "SEC  CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "     END MAIN\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 2 line 3: External expression requires Format 4: EXT1+1",
            result.stderr,
        )

    def test_base_rejects_external_expression(self):
        source, result = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1\n"
            "     BASE EXT1+3\n"
            "SEC  CSECT\n"
            "     EXTDEF EXT1\n"
            "EXT1 WORD 0\n"
            "     END MAIN\n"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 2 line 3: BASE cannot use an external reference expression: EXT1+3",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
