import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from address_space import SICXE_MAX_ADDRESS, SICXE_MEMORY_SIZE
from loader import LoaderError, pass1 as loader_pass1, pass2 as loader_pass2


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class AddressSpaceAssemblerTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-address-space-")
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

    def test_last_machine_byte_is_a_valid_source_address(self):
        source, result = self.assemble(
            "MAIN START FFFFF\n"
            "LAST BYTE X'AA'\n"
            "     END LAST\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        records = source.with_suffix(".obj").read_text(encoding="utf-8").splitlines()
        self.assertEqual(records[0], "HMAIN  0FFFFF000001")
        self.assertIn("T0FFFFF01AA", records)
        self.assertEqual(records[-1], "E0FFFFF")

    def test_start_above_20_bit_memory_is_rejected_at_source_line(self):
        source, result = self.assemble(
            "MAIN START 100000\n"
            "FIRST BYTE X'00'\n"
            "     END FIRST\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "address contract line 1: START address exceeds 20-bit SIC/XE memory: 100000",
            result.stderr,
        )
        for suffix in (".expanded.asm", ".int", ".sym", ".obj", ".lst"):
            self.assertFalse(source.with_suffix(suffix).exists())

    def test_control_section_cannot_cross_machine_memory_end(self):
        _, result = self.assemble(
            "MAIN START FFFFF\n"
            "FIRST WORD 0\n"
            "     END FIRST\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "address contract: Control section MAIN exceeds 20-bit SIC/XE memory",
            result.stderr,
        )


class AddressSpaceLoaderTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-address-loader-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_loader_uses_full_one_megabyte_memory(self):
        path = self.write_object(
            "HMAIN  000000000004\n"
            "T0000000403100000\n"
            "M00000105+MAIN  \n"
            "E000000\n"
        )
        estab = loader_pass1([path], 0xF0000)
        self.assertEqual(estab["MAIN"], 0xF0000)

        memory, exec_addr = loader_pass2([path], 0xF0000, estab)
        self.assertEqual(len(memory), SICXE_MEMORY_SIZE)
        self.assertEqual(exec_addr, 0xF0000)
        self.assertEqual(bytes(memory[0xF0000:0xF0004]), bytes.fromhex("031F0000"))

    def test_loader_can_write_the_last_addressable_byte(self):
        path = self.write_object(
            "HMAIN  000000000001\n"
            "DEND   000001\n"
            "T00000001AA\n"
            "E000000\n"
        )
        estab = loader_pass1([path], SICXE_MAX_ADDRESS)
        self.assertEqual(estab["MAIN"], SICXE_MAX_ADDRESS)
        # One-past-end labels remain useful as boundary symbols even when the
        # section itself occupies the final addressable byte.
        self.assertEqual(estab["END"], SICXE_MEMORY_SIZE)

        memory, exec_addr = loader_pass2([path], SICXE_MAX_ADDRESS, estab)
        self.assertEqual(memory[SICXE_MAX_ADDRESS], 0xAA)
        self.assertEqual(exec_addr, SICXE_MAX_ADDRESS)

    def test_progaddr_outside_machine_memory_is_rejected(self):
        path = self.write_object(
            "HMAIN  000000000001\n"
            "E\n"
        )
        with self.assertRaisesRegex(LoaderError, "PROGADDR outside 20-bit SIC/XE memory"):
            loader_pass1([path], SICXE_MEMORY_SIZE)
        with self.assertRaisesRegex(LoaderError, "PROGADDR outside 20-bit SIC/XE memory"):
            loader_pass2([path], SICXE_MEMORY_SIZE, {})

    def test_linked_control_sections_cannot_overflow_memory(self):
        path = self.write_object(
            "HONE   000000000010\n"
            "E\n"
            "HTWO   000000000001\n"
            "E\n"
        )
        with self.assertRaisesRegex(
            LoaderError,
            "Loaded control section TWO start outside 20-bit SIC/XE memory",
        ):
            loader_pass1([path], 0xFFFF0)


if __name__ == "__main__":
    unittest.main()
