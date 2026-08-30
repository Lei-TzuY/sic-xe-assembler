import tempfile
import unittest
from pathlib import Path

from errors import AssemblyError
from loader import pass1 as loader_pass1
from loader import pass2 as loader_pass2
from pass1 import literal_from_operand, parse_literal, run_pass1
from pass2 import run_pass2


class LiteralSyntaxTests(unittest.TestCase):
    def test_literal_canonicalization_and_operand_extraction(self):
        self.assertEqual(parse_literal("=X'f1a0'"), ("=X'F1A0'", "F1A0"))
        self.assertEqual(parse_literal("=C'A,B'"), ("=C'A,B'", "412C42"))
        self.assertEqual(literal_from_operand("=X'f1',X"), ("=X'F1'", "F1"))
        self.assertEqual(literal_from_operand("#=C'EOF'"), ("=C'EOF'", "454F46"))
        self.assertIsNone(literal_from_operand("BUFFER,X"))

    def test_invalid_literals_fail_validation(self):
        for literal in ("X'F1'", "=X'F'", "=X'FG'", "=Q'12'", "="):
            with self.subTest(literal=literal):
                with self.assertRaises(ValueError):
                    parse_literal(literal)


class LiteralPoolTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-literals-")
        root = Path(temp.name)
        source = root / "literal.asm"
        intermediate = root / "literal.int"
        symbols = root / "literal.sym"
        obj = root / "literal.obj"
        listing = root / "literal.lst"
        source.write_text(source_text, encoding="utf-8")

        csects, start = run_pass1(source, intermediate, symbols)
        run_pass2(intermediate, obj, listing, csects, start)
        return temp, csects, intermediate, obj, listing

    def test_ltorg_assigns_pending_literals_once(self):
        temp, csects, intermediate, obj, _ = self.assemble(
            "COPY START 0\n"
            "     LDA =C'EOF'\n"
            "     LDX =C'EOF'\n"
            "     LTORG\n"
            "     LDCH =X'f1'\n"
            "     END COPY\n"
        )
        with temp:
            literals = csects["COPY"]["literals"]
            self.assertEqual(literals["=C'EOF'"]["address"], 0x0006)
            self.assertEqual(literals["=X'F1'"]["address"], 0x000C)
            self.assertEqual(csects["COPY"]["length"], 0x000D)
            self.assertEqual(len(literals), 2)

            intermediate_text = intermediate.read_text(encoding="utf-8")
            self.assertEqual(intermediate_text.count("=C'EOF' BYTE C'EOF'"), 1)
            self.assertIn("0006\t=C'EOF' BYTE C'EOF'", intermediate_text)
            self.assertIn("000C\t=X'F1' BYTE X'F1'", intermediate_text)

            self.assertEqual(
                obj.read_text(encoding="utf-8"),
                "HCOPY  00000000000D\n"
                "T0000000D032003072000454F46532000F1\n"
                "E000000\n",
            )

    def test_end_implicitly_flushes_literal_pool_and_loader_relocates_format4(self):
        temp, csects, _, obj, _ = self.assemble(
            "COPY START 1000\n"
            "     +LDA =X'F1'\n"
            "     END COPY\n"
        )
        with temp:
            self.assertEqual(csects["COPY"]["literals"]["=X'F1'"]["address"], 0x1004)
            self.assertEqual(csects["COPY"]["length"], 5)
            self.assertEqual(
                obj.read_text(encoding="utf-8"),
                "HCOPY  001000000005\n"
                "T0010000503100004F1\n"
                "M00100105+COPY  \n"
                "E001000\n",
            )

            estab = loader_pass1([str(obj)], 0x4000)
            memory, exec_addr = loader_pass2([str(obj)], 0x4000, estab)
            self.assertEqual(estab["COPY"], 0x4000)
            self.assertEqual(exec_addr, 0x4000)
            self.assertEqual(bytes(memory[0x4000:0x4005]), bytes.fromhex("03104004F1"))

    def test_literal_pools_are_independent_per_control_section(self):
        temp, csects, _, _, _ = self.assemble(
            "MAIN START 0\n"
            "     LDA =X'01'\n"
            "SEC  CSECT\n"
            "     LDX =X'01'\n"
            "     END MAIN\n"
        )
        with temp:
            self.assertEqual(csects["MAIN"]["literals"]["=X'01'"]["address"], 3)
            self.assertEqual(csects["SEC"]["literals"]["=X'01'"]["address"], 3)
            self.assertEqual(csects["MAIN"]["length"], 4)
            self.assertEqual(csects["SEC"]["length"], 4)

    def test_invalid_literal_and_ltorg_operand_are_hard_errors(self):
        cases = (
            (
                "COPY START 0\n     LDA =X'F'\n     END COPY\n",
                "BYTE hexadecimal constants must contain an even number of digits",
            ),
            (
                "COPY START 0\n     LTORG EXTRA\n     END COPY\n",
                "LTORG does not take an operand",
            ),
        )

        for source_text, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp_name:
                root = Path(temp_name)
                source = root / "bad.asm"
                source.write_text(source_text, encoding="utf-8")
                with self.assertRaises(AssemblyError) as caught:
                    run_pass1(source, root / "bad.int", root / "bad.sym")
                self.assertIn(expected, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
