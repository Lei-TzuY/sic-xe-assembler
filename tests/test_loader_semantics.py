import tempfile
import unittest
from pathlib import Path

from loader import LoaderError, parse_obj_file, pass1 as loader_pass1, pass2 as loader_pass2


class LoaderSemanticIntegrityTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-loader-semantics-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def assert_parse_rejects(self, text, expected):
        path = self.write_object(text)
        with self.assertRaisesRegex(LoaderError, expected):
            parse_obj_file(path)

    def test_definition_offset_may_equal_length_but_not_exceed_it(self):
        valid = self.write_object(
            "HMAIN  000000000003\n"
            "DEND   000003\n"
            "T00000003000000\n"
            "E000000\n"
        )
        estab = loader_pass1([valid], 0x4000)
        self.assertEqual(estab["END"], 0x4003)

        self.assert_parse_rejects(
            "HMAIN  000000000003\n"
            "DOUT   000004\n"
            "E000000\n",
            "D-record symbol lies outside control section MAIN",
        )

    def test_header_range_must_fit_24_bit_address_space(self):
        self.assert_parse_rejects(
            "HMAIN  FFFFFF000002\n"
            "EFFFFFF\n",
            "Control section exceeds 24-bit address space",
        )

    def test_text_records_may_be_nonmonotonic_but_cannot_overlap(self):
        valid = self.write_object(
            "HMAIN  000000000006\n"
            "T00000303AABBCC\n"
            "T00000003010203\n"
            "E000000\n"
        )
        estab = loader_pass1([valid], 0x4000)
        memory, exec_addr = loader_pass2([valid], 0x4000, estab)
        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(bytes(memory[0x4000:0x4006]), bytes.fromhex("010203AABBCC"))

        self.assert_parse_rejects(
            "HMAIN  000000000006\n"
            "T00000003010203\n"
            "T00000203AABBCC\n"
            "E000000\n",
            "Overlapping T records in control section MAIN",
        )

    def test_modification_field_must_be_loaded_and_declared(self):
        self.assert_parse_rejects(
            "HMAIN  000000000006\n"
            "REXT1  \n"
            "T00000003010203\n"
            "M00000306+EXT1  \n"
            "E000000\n",
            "Modification field is not backed by loaded text in MAIN",
        )

        self.assert_parse_rejects(
            "HMAIN  000000000003\n"
            "T00000003000000\n"
            "M00000006+EXT1  \n"
            "E000000\n",
            "Modification symbol is not declared by R record in MAIN: EXT1",
        )

    def test_modification_can_precede_text_because_loading_is_section_wide(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "REXT1  \n"
            "M00000006+EXT1  \n"
            "T00000003000000\n"
            "E000000\n"
            "HEXT1  000000000000\n"
            "E\n"
        )
        estab = loader_pass1([path], 0x4000)
        self.assertEqual(estab["EXT1"], 0x4003)
        memory, exec_addr = loader_pass2([path], 0x4000, estab)
        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(bytes(memory[0x4000:0x4003]), bytes.fromhex("004003"))

    def test_execution_address_is_end_exclusive(self):
        self.assert_parse_rejects(
            "HMAIN  001000000003\n"
            "T00100003000000\n"
            "E001003\n",
            "Execution address lies outside control section MAIN",
        )

        zero = self.write_object(
            "HZERO  001000000000\n"
            "E001000\n"
        )
        estab = loader_pass1([zero], 0x4000)
        _, exec_addr = loader_pass2([zero], 0x4000, estab)
        self.assertEqual(exec_addr, 0x4000)

    def test_multiple_explicit_execution_addresses_are_rejected(self):
        first = self.write_object(
            "HONE   000000000001\n"
            "T0000000100\n"
            "E000000\n",
            "one.obj",
        )
        second = self.write_object(
            "HTWO   000000000001\n"
            "T0000000100\n"
            "E000000\n",
            "two.obj",
        )
        estab = loader_pass1([first, second], 0x4000)
        with self.assertRaisesRegex(
            LoaderError,
            "Multiple explicit execution addresses across object inputs",
        ):
            loader_pass2([first, second], 0x4000, estab)


if __name__ == "__main__":
    unittest.main()
