import unittest

from disassembler import decode_instruction, disassemble, render_disassembly


class DisassemblerTests(unittest.TestCase):
    def test_decodes_format1_and_format2_operands(self):
        fixed = decode_instruction(bytes.fromhex("C4"), 0x1000)
        clear = decode_instruction(bytes.fromhex("B410"), 0x1001)
        shift = decode_instruction(bytes.fromhex("A40F"), 0x1003)
        svc = decode_instruction(bytes.fromhex("B0F0"), 0x1005)

        self.assertEqual((fixed.mnemonic, fixed.size), ("FIX", 1))
        self.assertEqual((clear.mnemonic, clear.operand), ("CLEAR", "X"))
        self.assertEqual((shift.mnemonic, shift.operand), ("SHIFTL", "A,16"))
        self.assertEqual((svc.mnemonic, svc.operand), ("SVC", "15"))

    def test_decodes_format3_addressing_and_pc_target(self):
        immediate = decode_instruction(bytes.fromhex("010005"), 0x1000)
        pc_relative = decode_instruction(bytes.fromhex("032009"), 0x1000)
        rsub = decode_instruction(bytes.fromhex("4F0000"), 0x2000)

        self.assertEqual(immediate.mnemonic, "LDA")
        self.assertEqual(immediate.operand, "#5")
        self.assertEqual(immediate.flags, "010000")
        self.assertEqual(immediate.target, 5)

        self.assertEqual(pc_relative.operand, "0100C")
        self.assertEqual(pc_relative.flags, "110010")
        self.assertEqual(pc_relative.target, 0x100C)

        self.assertEqual(rsub.mnemonic, "RSUB")
        self.assertEqual(rsub.operand, "")
        self.assertIsNone(rsub.target)

    def test_decodes_format4_and_base_relative_targets(self):
        extended = decode_instruction(bytes.fromhex("4B112345"), 0x4000)
        unresolved_base = decode_instruction(bytes.fromhex("034345"), 0x5000)
        resolved_base = decode_instruction(
            bytes.fromhex("034345"),
            0x5000,
            base_register=0x8000,
        )

        self.assertEqual(extended.mnemonic, "+JSUB")
        self.assertEqual(extended.operand, "12345")
        self.assertEqual(extended.target, 0x12345)
        self.assertEqual(extended.flags, "110001")

        self.assertEqual(unresolved_base.operand, "B+345")
        self.assertIsNone(unresolved_base.target)
        self.assertEqual(resolved_base.operand, "08345")
        self.assertEqual(resolved_base.target, 0x8345)

    def test_unknown_or_truncated_bytes_fall_back_without_losing_sync(self):
        records = disassemble(bytes.fromhex("FFB4104B"), start_address=0x3000)
        self.assertEqual(records[0].mnemonic, ".BYTE")
        self.assertEqual(records[0].size, 1)
        self.assertEqual(records[1].mnemonic, "CLEAR")
        self.assertEqual(records[1].address, 0x3001)
        self.assertEqual(records[2].mnemonic, ".BYTE")
        self.assertIn("truncated", records[2].warning)

    def test_linear_sweep_and_rendering_are_deterministic(self):
        payload = bytes.fromhex("C4B4100100050320094F0000")
        records = disassemble(payload, start_address=0x1000)
        text = render_disassembly(records)

        self.assertEqual([item.mnemonic for item in records], ["FIX", "CLEAR", "LDA", "LDA", "RSUB"])
        self.assertIn("01003", text)
        self.assertIn("LDA #5", text)
        self.assertIn("target=0100F", text)
        self.assertTrue(text.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
