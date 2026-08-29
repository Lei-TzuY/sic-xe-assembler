import unittest

from opcodes import OPCODES
from pass1 import instruction_size
from pass2 import encode_format2


class OpcodeTableTests(unittest.TestCase):
    def test_complete_sicxe_instruction_table(self):
        self.assertEqual(len(OPCODES), 59)
        self.assertEqual(sum(fmt == 1 for _, fmt in OPCODES.values()), 6)
        self.assertEqual(sum(fmt == 2 for _, fmt in OPCODES.values()), 11)
        self.assertEqual(sum(fmt == 3 for _, fmt in OPCODES.values()), 42)

    def test_representative_new_opcodes(self):
        expected = {
            'ADDR': ('90', 2),
            'SHIFTL': ('A4', 2),
            'SVC': ('B0', 2),
            'ADDF': ('58', 3),
            'JGT': ('34', 3),
            'LDF': ('70', 3),
            'STSW': ('E8', 3),
            'TIX': ('2C', 3),
        }
        for opcode, spec in expected.items():
            with self.subTest(opcode=opcode):
                self.assertEqual(OPCODES[opcode], spec)


class Format2EncodingTests(unittest.TestCase):
    def test_register_forms(self):
        cases = {
            ('ADDR', 'A,S'): 0x04,
            ('CLEAR', 'X'): 0x10,
            ('COMPR', 'A,S'): 0x04,
            ('DIVR', 'A,X'): 0x01,
            ('MULR', 'A,X'): 0x01,
            ('RMO', 'A,S'): 0x04,
            ('SUBR', 'S,A'): 0x40,
            ('TIXR', 'T'): 0x50,
        }
        for (opcode, operand), expected in cases.items():
            with self.subTest(opcode=opcode, operand=operand):
                self.assertEqual(encode_format2(opcode, operand), expected)

    def test_shift_count_is_encoded_minus_one(self):
        self.assertEqual(encode_format2('SHIFTL', 'T,16'), 0x5F)
        self.assertEqual(encode_format2('SHIFTR', 'X,1'), 0x10)

    def test_svc_uses_high_nibble(self):
        self.assertEqual(encode_format2('SVC', '0'), 0x00)
        self.assertEqual(encode_format2('SVC', '15'), 0xF0)

    def test_invalid_format2_operands_fail(self):
        bad_cases = (
            ('CLEAR', 'Q'),
            ('ADDR', 'A'),
            ('ADDR', 'A,X,L'),
            ('SHIFTL', 'A,0'),
            ('SHIFTR', 'A,17'),
            ('SVC', '16'),
        )
        for opcode, operand in bad_cases:
            with self.subTest(opcode=opcode, operand=operand):
                with self.assertRaises(ValueError):
                    encode_format2(opcode, operand)


class InstructionSizeTests(unittest.TestCase):
    def test_extended_format_is_four_bytes_for_format3(self):
        self.assertEqual(instruction_size('+LDF'), 4)
        self.assertEqual(instruction_size('+JSUB'), 4)

    def test_extended_format_rejects_format1_and_format2(self):
        for opcode in ('+FIX', '+CLEAR', '+SVC'):
            with self.subTest(opcode=opcode):
                with self.assertRaises(ValueError):
                    instruction_size(opcode)


if __name__ == '__main__':
    unittest.main()
