import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from source_map import (
    LINKED_DEBUG_SCHEMA,
    SOURCE_MAP_SCHEMA,
    load_linked_debug_map,
    load_source_map,
    render_typed_disassembly,
)


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


PROGRAM_TEXT = (
    "MAIN START 1000\n"
    "FIRST LDA #1\n"
    "VALUE WORD 5\n"
    "BYTES BYTE X'ABCD'\n"
    "BUF RESB 8\n"
    "    J FIRST\n"
    "    LDA =X'FF'\n"
    "    LTORG\n"
    "    END FIRST\n"
)


class SourceMapTests(unittest.TestCase):
    def make_program(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-source-map-")
        self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        source = directory / "program.asm"
        source.write_text(PROGRAM_TEXT, encoding="utf-8")
        return directory, source

    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def assemble(self, source):
        result = self.run_script(ASSEMBLER, source)
        self.assertEqual(result.returncode, 0, result.stderr)
        return source.with_suffix(".obj")

    def test_assembler_emits_typed_path_independent_source_map(self):
        _, source = self.make_program()
        obj = self.assemble(source)
        map_path = source.with_suffix(".sourcemap.json")
        self.assertTrue(map_path.exists())

        source_map, _ = load_source_map(map_path)
        self.assertEqual(source_map["schema"], SOURCE_MAP_SCHEMA)
        self.assertNotIn(str(source.parent), map_path.read_text(encoding="utf-8"))
        section = source_map["sections"][0]
        self.assertEqual((section["name"], section["source_start"]), ("MAIN", 0x1000))
        self.assertEqual(
            [region["kind"] for region in section["regions"]],
            [
                "instruction",
                "word",
                "byte",
                "reservation",
                "instruction",
                "instruction",
                "literal",
            ],
        )
        literal = section["regions"][-1]
        self.assertEqual(literal["expanded_line"], 8)
        self.assertIn("FIRST", section["regions"][0]["symbols"])
        self.assertIn("BUF", section["regions"][3]["symbols"])
        self.assertTrue(any(symbol["name"] == "VALUE" for symbol in section["symbols"]))

        object_sha = hashlib.sha256(obj.read_bytes()).hexdigest()
        load_source_map(map_path, object_sha256=object_sha)

    def test_linker_rebases_regions_and_typed_disassembly_preserves_data(self):
        _, source = self.make_program()
        obj = self.assemble(source)
        linked = self.run_script(LOADER, obj, "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)

        image = source.with_suffix(".bin").read_bytes()
        debug_path = source.with_suffix(".debug.json")
        debug, _ = load_linked_debug_map(debug_path)
        self.assertEqual(debug["schema"], LINKED_DEBUG_SCHEMA)
        section = debug["sections"][0]
        self.assertTrue(section["typed"])
        self.assertEqual(section["load_address"], 0x4000)
        self.assertEqual(section["regions"][0]["loaded_address"], 0x4000)
        first = next(symbol for symbol in section["symbols"] if symbol["name"] == "FIRST")
        self.assertEqual(first["loaded_address"], 0x4000)

        text = render_typed_disassembly(image, 0x4000, debug)
        self.assertIn("FIRST:", text)
        self.assertIn(".WORD 0x000005", text)
        self.assertIn(".BYTE X'ABCD'", text)
        self.assertIn(".RESB 8", text)
        self.assertIn(".LITERAL X'FF'", text)
        self.assertIn("target_symbol=FIRST", text)
        self.assertNotIn("01000  ", text)

    def test_stale_source_map_causes_fail_closed_link_and_cleans_artifacts(self):
        _, source = self.make_program()
        obj = self.assemble(source)
        source_map = source.with_suffix(".sourcemap.json")
        payload = json.loads(source_map.read_text(encoding="utf-8"))
        payload["object_sha256"] = "0" * 64
        source_map.write_text(json.dumps(payload), encoding="utf-8")

        for suffix in (".map", ".bin", ".manifest.json", ".debug.json"):
            path = source.with_suffix(suffix)
            path.write_text("stale", encoding="utf-8") if suffix != ".bin" else path.write_bytes(b"stale")

        result = self.run_script(LOADER, obj, "4000")
        self.assertEqual(result.returncode, 1)
        self.assertIn("source-map", result.stderr.lower())
        for suffix in (".map", ".bin", ".manifest.json", ".debug.json"):
            self.assertFalse(source.with_suffix(suffix).exists())

    def test_link_without_source_sidecar_remains_valid_and_untyped(self):
        _, source = self.make_program()
        obj = self.assemble(source)
        source.with_suffix(".sourcemap.json").unlink()

        result = self.run_script(LOADER, obj, "4000")
        self.assertEqual(result.returncode, 0, result.stderr)
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        self.assertFalse(debug["sections"][0]["typed"])

    def test_failed_reassembly_removes_stale_source_map(self):
        _, source = self.make_program()
        self.assemble(source)
        source_map = source.with_suffix(".sourcemap.json")
        self.assertTrue(source_map.exists())
        source.write_text("MAIN START 0\n    BADOP\n    END MAIN\n", encoding="utf-8")
        failed = self.run_script(ASSEMBLER, source)
        self.assertEqual(failed.returncode, 1)
        self.assertFalse(source_map.exists())

    def test_no_start_program_uses_serialized_object_section_identity(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-source-map-no-start-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "nostart.asm"
        source.write_text(
            "FIRST LDA #1\n"
            "      END FIRST\n",
            encoding="utf-8",
        )
        obj = self.assemble(source)
        source_map, _ = load_source_map(source.with_suffix(".sourcemap.json"))
        section = source_map["sections"][0]
        self.assertEqual(section["name"], "DEFAUL")
        self.assertEqual(section["assembler_section_name"], "DEFAULT")

        linked = self.run_script(LOADER, obj, "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        self.assertEqual(debug["sections"][0]["name"], "DEFAUL")
        self.assertTrue(debug["sections"][0]["typed"])

    def test_source_and_debug_maps_are_path_independent(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-source-map-paths-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        maps = []
        debugs = []
        objects = []
        for name in ("left", "right"):
            directory = root / name
            directory.mkdir()
            source = directory / "program.asm"
            source.write_text(PROGRAM_TEXT, encoding="utf-8")
            obj = self.assemble(source)
            objects.append(obj.read_bytes())
            maps.append(source.with_suffix(".sourcemap.json").read_bytes())
            linked = self.run_script(LOADER, obj, "4000")
            self.assertEqual(linked.returncode, 0, linked.stderr)
            debugs.append(source.with_suffix(".debug.json").read_bytes())

        self.assertEqual(objects[0], objects[1])
        self.assertEqual(maps[0], maps[1])
        self.assertEqual(debugs[0], debugs[1])


if __name__ == "__main__":
    unittest.main()
