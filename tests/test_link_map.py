import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from link_map import default_map_path, render_link_map, write_link_map
from load_plan import build_load_plan


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "loader.py"


class LinkMapTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-link-map-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def linked_object(self):
        return self.write_object(
            "HMAIN  000000000006\n"
            "REXT1  UNUSED\n"
            "T00000006000000000000\n"
            "M00000006+EXT1  \n"
            "E000000\n"
            "HSEC2  000000000003\n"
            "DEXT1  000000\n"
            "T00000003000000\n"
            "E\n"
        )

    def test_render_link_map_contains_deterministic_layout_symbols_and_xrefs(self):
        path = self.linked_object()
        plan = build_load_plan([path], 0x4000)

        first = render_link_map(plan)
        second = render_link_map(plan)
        self.assertEqual(first, second)

        self.assertIn("SIC/XE LINK MAP", first)
        self.assertIn("PROGADDR  04000", first)
        self.assertIn("IMAGE     04000-04009 (end-exclusive, length=00009)", first)
        self.assertIn("ENTRY     04000", first)
        self.assertIn("0:0   MAIN    04000  04006  00006", first)
        self.assertIn("0:1   SEC2    04006  04009  00003", first)

        ext1 = first.index("EXT1     EXTDEF  04006")
        main = first.index("MAIN     CSECT   04000")
        sec2 = first.index("SEC2     CSECT   04006")
        self.assertLess(ext1, main)
        self.assertLess(main, sec2)

        self.assertIn("EXT1     1 relocation term(s)", first)
        self.assertIn(
            "+EXT1    from MAIN   source=000000 load=04000 width=06",
            first,
        )
        self.assertIn("MAIN    UNUSED", first)
        self.assertIn(
            "MAIN    source=000000 load=04000 width=06 addend=0 delta=16390 final=16390",
            first,
        )
        self.assertIn("terms: +EXT1", first)
        self.assertIn("SUMMARY sections=2 symbols=3 relocations=1 unused_R=1", first)

    def test_write_link_map_is_atomic_and_uses_first_object_stem(self):
        path = self.linked_object()
        plan = build_load_plan([path], 0x4000)
        target = Path(default_map_path([path]))

        written = write_link_map(plan, target)
        self.assertEqual(Path(written), target)
        self.assertTrue(target.exists())
        self.assertFalse(Path(str(target) + ".tmp").exists())
        self.assertEqual(target.read_text(encoding="utf-8"), render_link_map(plan))

    def test_loader_cli_writes_map_on_success(self):
        path = self.linked_object()
        target = path.with_suffix(".map")
        result = subprocess.run(
            [sys.executable, str(LOADER), str(path), "4000"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(target.exists())
        self.assertIn(f"Link map written: {target}", result.stdout)
        self.assertIn("CROSS REFERENCES", target.read_text(encoding="utf-8"))

    def test_failed_link_removes_stale_map(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "RMISS  \n"
            "T00000003000000\n"
            "M00000006+MISS  \n"
            "E000000\n"
        )
        target = path.with_suffix(".map")
        target.write_text("STALE\n", encoding="utf-8")

        result = subprocess.run(
            [sys.executable, str(LOADER), str(path), "4000"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Undefined external symbol MISS", result.stderr)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
