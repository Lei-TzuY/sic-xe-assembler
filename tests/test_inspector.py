import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from inspector import (
    InspectionError,
    inspect_image_manifest,
    inspect_object_file,
    render_manifest_inspection,
    render_object_inspection,
)
from linked_image import MANIFEST_SCHEMA


class InspectorTests(unittest.TestCase):
    def make_temp_dir(self):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-inspector-")
        self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def test_object_inspector_reports_sections_records_and_relocation_annotations(self):
        directory = self.make_temp_dir()
        path = directory / "program.obj"
        path.write_text(
            "HMAIN  000000000004\n"
            "REXT1  \n"
            "T000000044B100000\n"
            "M00000105+EXT1  \n"
            "E000000\n",
            encoding="utf-8",
        )

        report = inspect_object_file(path, include_disassembly=True)
        text = render_object_inspection(report)

        self.assertEqual(report["section_count"], 1)
        self.assertEqual(report["text_bytes"], 4)
        self.assertEqual(report["modification_count"], 1)
        section = report["sections"][0]
        self.assertEqual(section["name"], "MAIN")
        self.assertEqual(section["references"], ("EXT1",))
        instruction = section["texts"][0]["disassembly"][0]
        self.assertEqual(instruction["mnemonic"], "+JSUB")
        self.assertEqual(instruction["flags"], "110001")
        self.assertEqual(instruction["modifications"], ("M00000105+EXT1  ",))

        self.assertIn("SIC/XE OBJECT INSPECTION", text)
        self.assertIn("SECTION 0 MAIN", text)
        self.assertIn("+JSUB 00000", text)
        self.assertIn("M=M00000105+EXT1", text)
        self.assertIn("SUMMARY sections=1", text)

    def test_manifest_inspector_compares_adjacent_image_without_relinking(self):
        directory = self.make_temp_dir()
        image = directory / "program.bin"
        manifest = directory / "program.manifest.json"
        payload = bytes.fromhex("01020304")
        image.write_bytes(payload)
        image_sha = hashlib.sha256(payload).hexdigest()
        manifest.write_text(
            json.dumps(
                {
                    "schema": MANIFEST_SCHEMA,
                    "progaddr": 0x4000,
                    "image_start": 0x4000,
                    "image_end_exclusive": 0x4004,
                    "image_length": 4,
                    "image_sha256": image_sha,
                    "input_fingerprint": "a" * 64,
                    "link_fingerprint": "b" * 64,
                    "entry": {"kind": "default-progaddr", "address": 0x4000},
                    "inputs": [
                        {"input_index": 0, "byte_length": 12, "sha256": "c" * 64}
                    ],
                    "sections": [
                        {
                            "input_index": 0,
                            "section_index": 0,
                            "name": "MAIN",
                            "source_start": 0,
                            "load_address": 0x4000,
                            "length": 4,
                        }
                    ],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        report = inspect_image_manifest(manifest, image_path=image)
        text = render_manifest_inspection(report)

        self.assertTrue(report["image"]["length_matches"])
        self.assertTrue(report["image"]["sha256_matches"])
        self.assertIn("LENGTH_OK  yes", text)
        self.assertIn("SHA256_OK  yes", text)
        self.assertIn("MAIN", text)

        image.write_bytes(b"tampered")
        changed = inspect_image_manifest(manifest, image_path=image)
        self.assertFalse(changed["image"]["length_matches"])
        self.assertFalse(changed["image"]["sha256_matches"])

    def test_manifest_inspector_fails_cleanly_on_missing_or_inconsistent_fields(self):
        directory = self.make_temp_dir()
        manifest = directory / "bad.manifest.json"
        manifest.write_text(
            json.dumps({"schema": MANIFEST_SCHEMA, "progaddr": 0x4000}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InspectionError, "missing required field"):
            inspect_image_manifest(manifest)

        manifest.write_text(
            json.dumps(
                {
                    "schema": MANIFEST_SCHEMA,
                    "progaddr": 0x4000,
                    "image_start": 0x4000,
                    "image_end_exclusive": 0x4005,
                    "image_length": 4,
                    "image_sha256": "a" * 64,
                    "input_fingerprint": "b" * 64,
                    "link_fingerprint": "c" * 64,
                    "entry": {"kind": "default-progaddr", "address": 0x4000},
                    "inputs": [],
                    "sections": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(InspectionError, "range is inconsistent"):
            inspect_image_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
