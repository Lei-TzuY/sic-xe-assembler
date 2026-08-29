import tempfile
import unittest
from pathlib import Path

from loader import pass1 as loader_pass1, pass2 as loader_pass2
from pass1 import run_pass1
from pass2 import run_pass2


class RelocationModelTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix='sicxe-reloc-')
        root = Path(temp.name)
        asm = root / 'program.asm'
        intermediate = root / 'program.int'
        symbols = root / 'program.sym'
        obj = root / 'program.obj'
        listing = root / 'program.lst'
        asm.write_text(source_text, encoding='utf-8')
        csects, start = run_pass1(asm, intermediate, symbols)
        run_pass2(intermediate, obj, listing, csects, start)
        return temp, csects, obj, listing

    def test_nonzero_start_uses_true_section_length(self):
        temp, csects, obj, _ = self.assemble(
            "COPY START 1000\nFIRST RSUB\n     END FIRST\n"
        )
        try:
            self.assertEqual(csects['COPY']['start'], 0x1000)
            self.assertEqual(csects['COPY']['length'], 3)
            self.assertEqual(obj.read_text().splitlines()[0], 'HCOPY  001000000003')
        finally:
            temp.cleanup()

    def test_equ_preserves_relocation_class(self):
        temp, csects, _, _ = self.assemble(
            "COPY START 1000\n"
            "HERE RESW 1\n"
            "REL EQU HERE\n"
            "NEXT EQU *+3\n"
            "ABS EQU 7\n"
            "     END HERE\n"
        )
        try:
            data = csects['COPY']
            self.assertEqual(data['symtab']['REL'], 0x1000)
            self.assertEqual(data['symtab']['NEXT'], 0x1006)
            self.assertEqual(data['symtab']['ABS'], 7)
            self.assertTrue({'HERE', 'REL', 'NEXT'} <= data['relocatable'])
            self.assertNotIn('ABS', data['relocatable'])
        finally:
            temp.cleanup()

    def test_word_and_format4_local_symbols_relocate_from_nonzero_start(self):
        source = (
            "COPY START 1000\n"
            "     EXTDEF TARGET\n"
            "FIRST +LDA TARGET\n"
            "PTR WORD TARGET\n"
            "CONST EQU 7\n"
            "ABS WORD CONST\n"
            "TARGET WORD 1\n"
            "     END FIRST\n"
        )
        temp, _, obj, _ = self.assemble(source)
        try:
            records = obj.read_text().splitlines()
            self.assertEqual(records[0], 'HCOPY  00100000000D')
            self.assertEqual(records[1], 'DTARGET00000A')
            self.assertIn('T0010000D0310000A00000A000007000001', records)
            self.assertIn('M00100105+COPY  ', records)
            self.assertIn('M00100406+COPY  ', records)
            self.assertEqual(records[-1], 'E001000')

            estab = loader_pass1([obj], 0x4000)
            self.assertEqual(estab['COPY'], 0x4000)
            self.assertEqual(estab['TARGET'], 0x400A)
            memory, exec_addr = loader_pass2([obj], 0x4000, estab)
            self.assertEqual(exec_addr, 0x4000)
            self.assertEqual(bytes(memory[0x4000:0x4004]), bytes.fromhex('0310400A'))
            self.assertEqual(bytes(memory[0x4004:0x4007]), bytes.fromhex('00400A'))
            self.assertEqual(bytes(memory[0x4007:0x400A]), bytes.fromhex('000007'))
        finally:
            temp.cleanup()

    def test_location_counter_expression_uses_current_instruction_address(self):
        temp, _, _, listing = self.assemble(
            "COPY START 1000\nHERE JEQ *-3\n     END HERE\n"
        )
        try:
            self.assertIn('332FFA', listing.read_text())
        finally:
            temp.cleanup()

    def test_multisection_execution_address_is_emitted_on_first_section(self):
        temp, _, obj, _ = self.assemble(
            "COPY START 1000\n"
            "FIRST RSUB\n"
            "SEC CSECT\n"
            "     RSUB\n"
            "     END FIRST\n"
        )
        try:
            records = obj.read_text().splitlines()
            e_records = [record for record in records if record.startswith('E')]
            self.assertEqual(e_records, ['E001000', 'E'])
            estab = loader_pass1([obj], 0x4000)
            _, exec_addr = loader_pass2([obj], 0x4000, estab)
            self.assertEqual(exec_addr, 0x4000)
        finally:
            temp.cleanup()


if __name__ == '__main__':
    unittest.main()
