import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pass1 import run_pass1


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class ForwardEquPass1Tests(unittest.TestCase):
    def assemble_pass1(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-forward-equ-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        source = root / "program.asm"
        intermediate = root / "program.int"
        symbols = root / "program.sym"
        source.write_text(source_text, encoding="utf-8")
        csects, start = run_pass1(source, intermediate, symbols)
        return csects, start, intermediate.read_text(encoding="utf-8")

    def test_forward_equ_resolves_later_local_symbols(self):
        source = (
            "COPY START 0\n"
            "LEN EQU BUFEND-BUFFER\n"
            "PTR EQU BUFFER+3\n"
            "BUFFER RESB 10\n"
            "BUFEND EQU *\n"
            "VAL WORD LEN\n"
            "REF WORD PTR\n"
            "END COPY\n"
        )
        csects, start, _ = self.assemble_pass1(source)
        data = csects["COPY"]

        self.assertEqual(start, 0)
        self.assertEqual(data["symtab"]["BUFFER"], 0)
        self.assertEqual(data["symtab"]["BUFEND"], 10)
        self.assertEqual(data["symtab"]["LEN"], 10)
        self.assertEqual(data["symtab"]["PTR"], 3)
        self.assertNotIn("LEN", data["relocatable"])
        self.assertIn("PTR", data["relocatable"])
        self.assertIn("BUFEND", data["relocatable"])

    def test_forward_equ_chain_resolves_transitively(self):
        source = (
            "COPY START 0\n"
            "A EQU B+1\n"
            "B EQU C+1\n"
            "C EQU 5\n"
            "END COPY\n"
        )
        csects, _, _ = self.assemble_pass1(source)
        data = csects["COPY"]

        self.assertEqual(data["symtab"]["A"], 7)
        self.assertEqual(data["symtab"]["B"], 6)
        self.assertEqual(data["symtab"]["C"], 5)
        self.assertNotIn("A", data["relocatable"])
        self.assertNotIn("B", data["relocatable"])
        self.assertNotIn("C", data["relocatable"])

    def test_forward_equ_uses_final_program_block_addresses(self):
        source = (
            "COPY START 1000\n"
            "FIRST LDA #0\n"
            "PTR EQU DATA+2\n"
            "DIST EQU CODE-DATA\n"
            "     USE DATA\n"
            "DATA RESB 4\n"
            "     USE CODE\n"
            "CODE RESB 3\n"
            "     USE\n"
            "     END FIRST\n"
        )
        csects, _, intermediate = self.assemble_pass1(source)
        data = csects["COPY"]

        self.assertEqual(data["blocks"][""]["start"], 0x1000)
        self.assertEqual(data["blocks"]["DATA"]["start"], 0x1003)
        self.assertEqual(data["blocks"]["CODE"]["start"], 0x1007)
        self.assertEqual(data["symtab"]["PTR"], 0x1005)
        self.assertEqual(data["symtab"]["DIST"], 4)
        self.assertIn("PTR", data["relocatable"])
        self.assertNotIn("DIST", data["relocatable"])
        self.assertIn("1003\tDATA RESB 4", intermediate)
        self.assertIn("1007\tCODE RESB 3", intermediate)


class ForwardEquAssemblerTests(unittest.TestCase):
    def run_assembler(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-forward-equ-cli-")
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

    def test_forward_equ_drives_word_relocation_correctly(self):
        source_text = (
            "COPY START 1000\n"
            "LEN EQU BUFEND-BUFFER\n"
            "PTR EQU BUFFER+3\n"
            "BUFFER RESB 10\n"
            "BUFEND EQU *\n"
            "VAL WORD LEN\n"
            "REF WORD PTR\n"
            "END COPY\n"
        )
        source, result = self.run_assembler(source_text)
        self.assertEqual(result.returncode, 0, result.stderr)

        obj = source.with_suffix(".obj").read_text(encoding="utf-8")
        listing = source.with_suffix(".lst").read_text(encoding="utf-8")

        self.assertIn("HCOPY  001000000010", obj)
        self.assertIn("00000A", listing)
        self.assertIn("000003", listing)
        self.assertIn("M00100D06+COPY", obj)
        self.assertNotIn("M00100A06+COPY", obj)

    def test_cycle_reports_dependency_path_at_equ_line(self):
        source_text = (
            "COPY START 0\n"
            "A EQU B+1\n"
            "B EQU C+1\n"
            "C EQU A+1\n"
            "END COPY\n"
        )
        _, result = self.run_assembler(source_text)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "pass 1 line 4: Circular EQU dependency: A -> B -> C -> A",
            result.stderr,
        )

    def test_unresolved_symbol_reports_original_equ_line(self):
        source_text = (
            "COPY START 0\n"
            "A EQU MISSING+1\n"
            "END COPY\n"
        )
        _, result = self.run_assembler(source_text)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pass 1 line 2: Undefined symbol MISSING", result.stderr)

    def test_pending_equ_name_reserves_symbol_namespace(self):
        source_text = (
            "COPY START 0\n"
            "A EQU B\n"
            "A RESB 1\n"
            "B RESB 1\n"
            "END COPY\n"
        )
        _, result = self.run_assembler(source_text)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pass 1 line 3: Duplicate label A in COPY", result.stderr)


if __name__ == "__main__":
    unittest.main()
