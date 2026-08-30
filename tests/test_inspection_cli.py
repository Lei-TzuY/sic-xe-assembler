import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "sicxe.py"


class InspectionCliTests(unittest.TestCase):
    def make_source(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-inspection-cli-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(
            "MAIN START 0\n"
            "     FIX\n"
            "     CLEAR X\n"
            "     LDA #5\n"
            "     +JSUB TARGET\n"
            "TARGET RSUB\n"
            "     END MAIN\n",
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

    def test_assemble_inspect_link_manifest_and_disassemble_flow(self):
        source = self.make_source()
        assembled = self.run_tool("assemble", source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")

        inspected = self.run_tool("inspect", obj, "--disassemble")
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertIn("SIC/XE OBJECT INSPECTION", inspected.stdout)
        self.assertIn("FIX", inspected.stdout)
        self.assertIn("CLEAR X", inspected.stdout)
        self.assertIn("LDA #5", inspected.stdout)
        self.assertIn("+JSUB 0000A", inspected.stdout)
        self.assertIn("M=M00000705+MAIN", inspected.stdout)

        structured = self.run_tool("inspect", obj, "--json")
        self.assertEqual(structured.returncode, 0, structured.stderr)
        report = json.loads(structured.stdout)
        self.assertEqual(report["kind"], "object-program")
        self.assertEqual(report["section_count"], 1)
        self.assertEqual(report["modification_count"], 1)

        linked = self.run_tool("link", obj, "--progaddr", "4000")
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin")
        manifest = source.with_suffix(".manifest.json")

        manifest_inspection = self.run_tool("inspect", manifest)
        self.assertEqual(manifest_inspection.returncode, 0, manifest_inspection.stderr)
        self.assertIn("SIC/XE LINKED IMAGE INSPECTION", manifest_inspection.stdout)
        self.assertIn("LENGTH_OK  yes", manifest_inspection.stdout)
        self.assertIn("SHA256_OK  yes", manifest_inspection.stdout)

        disassembled = self.run_tool("disasm", image, "--manifest", manifest)
        self.assertEqual(disassembled.returncode, 0, disassembled.stderr)
        self.assertIn("04000", disassembled.stdout)
        self.assertIn("FIX", disassembled.stdout)
        self.assertIn("CLEAR X", disassembled.stdout)
        self.assertIn("LDA #5", disassembled.stdout)
        self.assertIn("+JSUB 0400A", disassembled.stdout)
        self.assertIn("RSUB", disassembled.stdout)

    def test_disasm_rejects_start_that_conflicts_with_manifest(self):
        source = self.make_source()
        self.assertEqual(self.run_tool("assemble", source).returncode, 0)
        obj = source.with_suffix(".obj")
        self.assertEqual(self.run_tool("link", obj, "--progaddr", "4000").returncode, 0)

        result = self.run_tool(
            "disasm",
            source.with_suffix(".bin"),
            "--manifest",
            source.with_suffix(".manifest.json"),
            "--start",
            "5000",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match manifest image_start", result.stderr)


if __name__ == "__main__":
    unittest.main()
