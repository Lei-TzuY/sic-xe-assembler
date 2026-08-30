import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from loader import LoaderError, parse_obj_file
from object_format import MAX_OBJECT_RECORD_LENGTH, validate_object_records


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"


class ObjectContractAssemblerTests(unittest.TestCase):
    def assemble(self, source_text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-object-contract-")
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

    def test_rejects_nonrepresentable_control_section_and_external_names(self):
        cases = [
            (
                "TOOLONG START 0\n       END TOOLONG\n",
                "object contract line 1: Control section name must be 1-6 ASCII alphanumeric characters starting with a letter: TOOLONG",
            ),
            (
                "MAIN START 0\n     EXTREF 1BAD\n     END MAIN\n",
                "object contract line 2: EXTREF symbol must be 1-6 ASCII alphanumeric characters starting with a letter: 1BAD",
            ),
            (
                "MAIN START 0\n     EXTDEF TOO_LONG\n     END MAIN\n",
                "object contract line 2: EXTDEF symbol must be 1-6 ASCII alphanumeric characters starting with a letter: TOO_LONG",
            ),
        ]
        for source_text, expected in cases:
            with self.subTest(source=source_text):
                _, result = self.assemble(source_text)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_duplicate_external_directives_are_hard_errors(self):
        _, same_line = self.assemble(
            "MAIN START 0\n"
            "     EXTREF EXT1,EXT1\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(same_line.returncode, 0)
        self.assertIn(
            "object contract line 2: Duplicate EXTREF symbol in directive: EXT1",
            same_line.stderr,
        )

        _, repeated = self.assemble(
            "MAIN START 0\n"
            "     EXTDEF ITEM\n"
            "     EXTDEF ITEM\n"
            "ITEM RESW 1\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(repeated.returncode, 0)
        self.assertIn(
            "object contract line 3: Duplicate EXTDEF symbol in control section: ITEM",
            repeated.stderr,
        )

    def test_extdef_extref_and_local_external_collisions_are_rejected(self):
        _, both = self.assemble(
            "MAIN START 0\n"
            "     EXTDEF ITEM\n"
            "     EXTREF ITEM\n"
            "ITEM RESW 1\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(both.returncode, 0)
        self.assertIn(
            "object contract line 3: Symbol cannot be both EXTDEF and EXTREF in one control section: ITEM",
            both.stderr,
        )

        _, local = self.assemble(
            "MAIN START 0\n"
            "     EXTREF LOCAL\n"
            "LOCAL WORD 0\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(local.returncode, 0)
        self.assertIn(
            "object contract line 2: EXTREF symbol conflicts with a local symbol in MAIN: LOCAL",
            local.stderr,
        )

    def test_global_object_definitions_cannot_collide(self):
        _, result = self.assemble(
            "MAIN START 0\n"
            "     EXTDEF SEC2\n"
            "SEC2 CSECT\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Duplicate object-program definition SEC2", result.stderr)

        _, extdefs = self.assemble(
            "MAIN START 0\n"
            "     EXTDEF ITEM\n"
            "ITEM RESW 1\n"
            "SEC2 CSECT\n"
            "     EXTDEF ITEM\n"
            "ITEM RESW 1\n"
            "     END MAIN\n"
        )
        self.assertNotEqual(extdefs.returncode, 0)
        self.assertIn("Duplicate object-program definition ITEM", extdefs.stderr)

    def test_large_definition_and_reference_sets_are_split_into_bounded_records(self):
        extdefs = [f"D{index:02d}" for index in range(1, 8)]
        extrefs = [f"R{index:02d}" for index in range(1, 14)]
        definitions = "".join(f"{symbol} RESW 1\n" for symbol in extdefs)
        source, result = self.assemble(
            "MAIN START 0\n"
            f"     EXTDEF {','.join(extdefs)}\n"
            f"     EXTREF {','.join(extrefs)}\n"
            + definitions
            + "     END MAIN\n"
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        records = source.with_suffix(".obj").read_text(encoding="utf-8").splitlines()
        d_records = [record for record in records if record.startswith('D')]
        r_records = [record for record in records if record.startswith('R')]

        self.assertEqual([len(record) for record in d_records], [73, 13])
        self.assertEqual([len(record) for record in r_records], [73, 7])
        self.assertTrue(all(len(record) <= MAX_OBJECT_RECORD_LENGTH for record in d_records + r_records))
        validate_object_records(records)

    def test_synthetic_no_start_and_unnamed_csect_names_are_explicitly_valid(self):
        source, result = self.assemble(
            "FIRST WORD 0\n"
            "      END FIRST\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HDEFAUL000000000003", source.with_suffix(".obj").read_text(encoding="utf-8"))

        source, result = self.assemble(
            "MAIN START 0\n"
            "A    WORD 0\n"
            "     CSECT\n"
            "B    WORD 0\n"
            "     END MAIN\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        obj = source.with_suffix(".obj").read_text(encoding="utf-8")
        self.assertIn("HMAIN  000000000003", obj)
        self.assertIn("HUNNAME000000000003", obj)


class LoaderObjectContractTests(unittest.TestCase):
    def write_object(self, text):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-loader-contract-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "bad.obj"
        path.write_text(text, encoding="utf-8")
        return path

    def assert_loader_rejects(self, text, expected):
        path = self.write_object(text)
        with self.assertRaisesRegex(LoaderError, expected):
            parse_obj_file(str(path))

    def test_loader_rejects_malformed_fixed_fields_and_unknown_records(self):
        self.assert_loader_rejects(
            "HMAIN  000000000003X\nE000000\n",
            "Malformed H record",
        )
        self.assert_loader_rejects(
            "H1BAD  000000000003\nE000000\n",
            "H-record control section must be 1-6 ASCII alphanumeric",
        )
        self.assert_loader_rejects(
            "HMAIN  000000000003\nQWHATEVER\nE000000\n",
            "Unknown object record type Q",
        )

    def test_loader_rejects_duplicate_references_and_oversized_records(self):
        self.assert_loader_rejects(
            "HMAIN  000000000003\nREXT1  \nREXT1  \nE000000\n",
            "Duplicate external reference in control section: EXT1",
        )
        oversized = "D" + "".join(f"D{index:02d}".ljust(6) + "000000" for index in range(1, 8))
        self.assertGreater(len(oversized), MAX_OBJECT_RECORD_LENGTH)
        self.assert_loader_rejects(
            f"HMAIN  000000000003\n{oversized}\nE000000\n",
            "Malformed D record",
        )


if __name__ == "__main__":
    unittest.main()
