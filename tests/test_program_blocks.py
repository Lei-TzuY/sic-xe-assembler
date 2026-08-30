import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import pass1 as loader_pass1
from loader import pass2 as loader_pass2
from pass1 import run_pass1


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class ProgramBlockPass1Tests(unittest.TestCase):
    def test_use_layout_rebases_symbols_by_first_seen_block_order(self):
        source_text = (
            "COPY START 1000\n"
            "FIRST LDA DATA1\n"
            "      USE DATA\n"
            "DATA1 WORD 1\n"
            "BUF   RESB 4\n"
            "      USE CODE\n"
            "CODE1 RSUB\n"
            "      USE\n"
            "LAST  WORD 6\n"
            "      END FIRST\n"
        )

        with tempfile.TemporaryDirectory(prefix="sicxe-use-pass1-") as temp_name:
            temp = Path(temp_name)
            source = temp / "blocks.asm"
            intermediate = temp / "blocks.int"
            symbols = temp / "blocks.sym"
            source.write_text(source_text, encoding="utf-8")

            csects, start = run_pass1(source, intermediate, symbols)
            data = csects["COPY"]

            self.assertEqual(start, 0x1000)
            self.assertEqual(list(data["blocks"]), ["", "DATA", "CODE"])
            self.assertEqual(data["blocks"][""]["start"], 0x1000)
            self.assertEqual(data["blocks"][""]["length"], 6)
            self.assertEqual(data["blocks"]["DATA"]["start"], 0x1006)
            self.assertEqual(data["blocks"]["DATA"]["length"], 7)
            self.assertEqual(data["blocks"]["CODE"]["start"], 0x100D)
            self.assertEqual(data["blocks"]["CODE"]["length"], 3)
            self.assertEqual(data["length"], 0x10)

            self.assertEqual(data["symtab"]["FIRST"], 0x1000)
            self.assertEqual(data["symtab"]["DATA1"], 0x1006)
            self.assertEqual(data["symtab"]["BUF"], 0x1009)
            self.assertEqual(data["symtab"]["CODE1"], 0x100D)
            self.assertEqual(data["symtab"]["LAST"], 0x1003)

            text = intermediate.read_text(encoding="utf-8")
            self.assertIn("1003\tUSE DATA", text)
            self.assertIn("1006\tDATA1 WORD 1", text)
            self.assertIn("100D\tUSE CODE", text)
            self.assertIn("100D\tCODE1 RSUB", text)
            self.assertIn("1010\tUSE", text)
            self.assertIn("1003\tLAST  WORD 6", text)

    def test_label_on_use_binds_before_switch(self):
        source_text = (
            "COPY START 0\n"
            "HERE USE DATA\n"
            "ITEM WORD 1\n"
            "     END HERE\n"
        )
        with tempfile.TemporaryDirectory(prefix="sicxe-use-label-") as temp_name:
            temp = Path(temp_name)
            source = temp / "label.asm"
            intermediate = temp / "label.int"
            symbols = temp / "label.sym"
            source.write_text(source_text, encoding="utf-8")
            csects, _ = run_pass1(source, intermediate, symbols)

            data = csects["COPY"]
            self.assertEqual(data["symtab"]["HERE"], 0)
            self.assertEqual(data["symtab"]["ITEM"], 0)
            self.assertEqual(data["symbol_blocks"]["HERE"][0], "")
            self.assertEqual(data["symbol_blocks"]["ITEM"][0], "DATA")

    def test_org_stack_is_independent_per_program_block(self):
        source_text = (
            "COPY START 0\n"
            "     USE DATA\n"
            "A    RESB 1\n"
            "     ORG A+4\n"
            "B    BYTE X'AA'\n"
            "     ORG\n"
            "C    BYTE X'BB'\n"
            "     END COPY\n"
        )
        with tempfile.TemporaryDirectory(prefix="sicxe-use-org-") as temp_name:
            temp = Path(temp_name)
            source = temp / "org.asm"
            intermediate = temp / "org.int"
            symbols = temp / "org.sym"
            source.write_text(source_text, encoding="utf-8")
            csects, _ = run_pass1(source, intermediate, symbols)

            data = csects["COPY"]
            self.assertEqual(data["blocks"]["DATA"]["length"], 5)
            self.assertEqual(data["symtab"]["A"], 0)
            self.assertEqual(data["symtab"]["B"], 4)
            self.assertEqual(data["symtab"]["C"], 1)

    def test_literal_pool_is_emitted_in_active_program_block(self):
        source_text = (
            "COPY START 0\n"
            "     LDA =X'AA'\n"
            "     USE LIT\n"
            "     LTORG\n"
            "     END COPY\n"
        )
        with tempfile.TemporaryDirectory(prefix="sicxe-use-lit-") as temp_name:
            temp = Path(temp_name)
            source = temp / "literal.asm"
            intermediate = temp / "literal.int"
            symbols = temp / "literal.sym"
            source.write_text(source_text, encoding="utf-8")
            csects, _ = run_pass1(source, intermediate, symbols)

            data = csects["COPY"]
            literal = data["literals"]["=X'AA'"]
            self.assertEqual(data["blocks"][""]["length"], 3)
            self.assertEqual(data["blocks"]["LIT"]["start"], 3)
            self.assertEqual(literal["block"], "LIT")
            self.assertEqual(literal["address"], 3)
            self.assertIn("0003\t=X'AA' BYTE X'AA'", intermediate.read_text(encoding="utf-8"))


class ProgramBlockEndToEndTests(unittest.TestCase):
    def test_source_order_block_switches_assemble_and_load_correctly(self):
        source_text = (
            "COPY START 1000\n"
            "FIRST LDA DATA1\n"
            "      USE DATA\n"
            "DATA1 WORD 1\n"
            "BUF   RESB 4\n"
            "      USE CODE\n"
            "CODE1 RSUB\n"
            "      USE\n"
            "DIFF  WORD DATA1-FIRST\n"
            "      END FIRST\n"
        )

        with tempfile.TemporaryDirectory(prefix="sicxe-use-e2e-") as temp_name:
            source = Path(temp_name) / "blocks.asm"
            source.write_text(source_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            obj_path = source.with_suffix(".obj")
            obj = obj_path.read_text(encoding="utf-8")
            listing = source.with_suffix(".lst").read_text(encoding="utf-8")

            self.assertIn("HCOPY  001000000010", obj)
            self.assertIn("1000\t032003", listing)
            self.assertIn("1003\t000006", listing)
            self.assertIn("1006\t000001", listing)
            self.assertIn("100D\t4F0000", listing)

            estab = loader_pass1([str(obj_path)], 0x4000)
            memory, exec_addr = loader_pass2([str(obj_path)], 0x4000, estab)
            self.assertEqual(exec_addr, 0x4000)
            self.assertEqual(bytes(memory[0x4000:0x4006]).hex().upper(), "032003000006")
            self.assertEqual(bytes(memory[0x4006:0x4009]).hex().upper(), "000001")
            self.assertEqual(bytes(memory[0x400D:0x4010]).hex().upper(), "4F0000")

    def test_invalid_use_block_name_is_a_hard_error(self):
        source_text = "COPY START 0\n     USE BAD NAME\n     END COPY\n"
        with tempfile.TemporaryDirectory(prefix="sicxe-use-error-") as temp_name:
            source = Path(temp_name) / "bad.asm"
            source.write_text(source_text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(ASSEMBLER), str(source)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pass 1 line 2: Invalid USE block name", result.stderr)


if __name__ == "__main__":
    unittest.main()
