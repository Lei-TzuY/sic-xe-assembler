import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "sicxe.py"
LOADER = ROOT / "loader.py"


class ToolchainCliTests(unittest.TestCase):
    def make_source(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-cli-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(
            "MAIN START 0\n"
            "VAL WORD (3+4)*6\n"
            "    END MAIN\n",
            encoding="utf-8",
        )
        return source

    def run_tool(self, *args):
        return subprocess.run(
            [sys.executable, str(TOOLCHAIN), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_unified_assemble_link_verify_flow(self):
        source = self.make_source()
        assembled = self.run_tool("assemble", source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)

        obj = source.with_suffix(".obj")
        self.assertTrue(obj.exists())

        linked = self.run_tool("link", obj, "--progaddr", "5000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin")
        manifest = source.with_suffix(".manifest.json")
        link_map = source.with_suffix(".map")
        self.assertTrue(image.exists())
        self.assertTrue(manifest.exists())
        self.assertTrue(link_map.exists())
        self.assertEqual(image.read_bytes(), bytes.fromhex("00002A"))
        metadata = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(metadata["progaddr"], 0x5000)

        verified = self.run_tool("verify", image, manifest, obj)
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.assertIn("Linked artifacts verified reproducible", verified.stdout)

    def test_invalid_progaddr_is_usage_error(self):
        source = self.make_source()
        self.assertEqual(self.run_tool("assemble", source).returncode, 0)
        result = self.run_tool("link", source.with_suffix(".obj"), "--progaddr", "NOPE")
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid hexadecimal address", result.stderr)

    def test_legacy_loader_rejects_unknown_path_instead_of_ignoring_it(self):
        result = subprocess.run(
            [sys.executable, str(LOADER), "missing.obj"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown argument or unreadable object file", result.stderr)

    def test_legacy_loader_rejects_multiple_progaddrs(self):
        source = self.make_source()
        self.assertEqual(self.run_tool("assemble", source).returncode, 0)
        result = subprocess.run(
            [sys.executable, str(LOADER), str(source.with_suffix('.obj')), "4000", "5000"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("PROGADDR may be specified at most once", result.stderr)


if __name__ == "__main__":
    unittest.main()
