import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from link_map import default_map_path
from linked_image import (
    build_image_manifest,
    default_image_path,
    default_manifest_path,
    extract_linked_image,
    render_image_manifest,
    write_linked_image_artifacts,
)
from load_plan import build_load_plan
from loader import apply_load_plan


ROOT = Path(__file__).resolve().parents[1]
LOADER = ROOT / "loader.py"


class LinkedImageArtifactTests(unittest.TestCase):
    def make_temp_dir(self, prefix="sicxe-linked-image-"):
        temp = tempfile.TemporaryDirectory(prefix=prefix)
        self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def write_object(self, text, name="program.obj", directory=None):
        if directory is None:
            directory = self.make_temp_dir()
        path = Path(directory) / name
        path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def relocatable_object():
        return (
            "HMAIN  000000000006\n"
            "T00000003000001\n"
            "M00000006+MAIN  \n"
            "E000000\n"
        )

    def test_image_is_exact_loaded_range_with_relocation_and_zero_fill(self):
        path = self.write_object(self.relocatable_object())
        plan = build_load_plan([path], 0x4000)
        memory, exec_addr = apply_load_plan(plan)
        image = extract_linked_image(plan, memory)

        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(plan.total_length, 6)
        self.assertEqual(image, bytes.fromhex("004001000000"))
        self.assertEqual(len(image), plan.total_length)

        manifest = build_image_manifest(plan, image)
        self.assertEqual(manifest["image_start"], 0x4000)
        self.assertEqual(manifest["image_end_exclusive"], 0x4006)
        self.assertEqual(manifest["image_length"], 6)
        self.assertEqual(
            manifest["image_sha256"],
            hashlib.sha256(image).hexdigest(),
        )
        self.assertEqual(manifest["entry"]["kind"], "explicit")
        self.assertEqual(manifest["entry"]["section"], "MAIN")
        self.assertEqual(manifest["entry"]["source_address"], 0)

    def test_manifest_rejects_bytes_not_matching_planned_image_length(self):
        path = self.write_object(self.relocatable_object())
        plan = build_load_plan([path], 0x4000)
        with self.assertRaisesRegex(
            ValueError,
            "Linked image length does not match validated load plan",
        ):
            build_image_manifest(plan, b"\x00")

    def test_manifest_and_binary_are_path_independent_and_reproducible(self):
        first_dir = self.make_temp_dir("sicxe-image-first-")
        second_dir = self.make_temp_dir("sicxe-image-second-")
        first = self.write_object(self.relocatable_object(), "one.obj", first_dir)
        second = self.write_object(self.relocatable_object(), "two.obj", second_dir)

        first_plan = build_load_plan([first], 0x5000)
        second_plan = build_load_plan([second], 0x5000)
        first_memory, _ = apply_load_plan(first_plan)
        second_memory, _ = apply_load_plan(second_plan)
        first_image = extract_linked_image(first_plan, first_memory)
        second_image = extract_linked_image(second_plan, second_memory)

        self.assertEqual(first_image, second_image)
        self.assertEqual(
            render_image_manifest(first_plan, first_image),
            render_image_manifest(second_plan, second_image),
        )
        self.assertEqual(first_plan.input_fingerprint, second_plan.input_fingerprint)
        self.assertEqual(first_plan.link_fingerprint, second_plan.link_fingerprint)

        moved_manifest = json.loads(render_image_manifest(first_plan, first_image))
        self.assertNotIn("file_path", moved_manifest)
        self.assertNotIn("canonical_path", moved_manifest)

    def test_progaddr_changes_link_identity_and_relocated_image(self):
        path = self.write_object(self.relocatable_object())
        low_plan = build_load_plan([path], 0x4000)
        high_plan = build_load_plan([path], 0x5000)
        low_memory, _ = apply_load_plan(low_plan)
        high_memory, _ = apply_load_plan(high_plan)
        low_image = extract_linked_image(low_plan, low_memory)
        high_image = extract_linked_image(high_plan, high_memory)

        self.assertNotEqual(low_plan.link_fingerprint, high_plan.link_fingerprint)
        self.assertNotEqual(low_image, high_image)
        self.assertEqual(low_image, bytes.fromhex("004001000000"))
        self.assertEqual(high_image, bytes.fromhex("005001000000"))

    def test_zero_length_link_writes_empty_binary_with_standard_sha256(self):
        path = self.write_object(
            "HMAIN  000000000000\n"
            "E000000\n"
        )
        plan = build_load_plan([path], 0x6000)
        memory, _ = apply_load_plan(plan)
        image = extract_linked_image(plan, memory)
        manifest = build_image_manifest(plan, image)

        self.assertEqual(image, b"")
        self.assertEqual(manifest["image_length"], 0)
        self.assertEqual(manifest["image_start"], 0x6000)
        self.assertEqual(manifest["image_end_exclusive"], 0x6000)
        self.assertEqual(
            manifest["image_sha256"],
            hashlib.sha256(b"").hexdigest(),
        )

    def test_direct_writer_is_atomic_and_manifest_matches_binary(self):
        path = self.write_object(self.relocatable_object())
        plan = build_load_plan([path], 0x4000)
        memory, _ = apply_load_plan(plan)
        image_path = Path(default_image_path([path]))
        manifest_path = Path(default_manifest_path([path]))

        written_image, written_manifest = write_linked_image_artifacts(
            plan,
            memory,
            image_path,
            manifest_path,
        )
        self.assertEqual(Path(written_image), image_path)
        self.assertEqual(Path(written_manifest), manifest_path)
        self.assertFalse(Path(str(image_path) + ".tmp").exists())
        self.assertFalse(Path(str(manifest_path) + ".tmp").exists())

        image = image_path.read_bytes()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["image_sha256"],
            hashlib.sha256(image).hexdigest(),
        )
        self.assertEqual(manifest["link_fingerprint"], plan.link_fingerprint)

    def test_loader_cli_writes_all_reproducible_artifacts(self):
        path = self.write_object(self.relocatable_object())
        map_path = Path(default_map_path([path]))
        image_path = Path(default_image_path([path]))
        manifest_path = Path(default_manifest_path([path]))

        result = subprocess.run(
            [sys.executable, str(LOADER), str(path), "4000"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(map_path.exists())
        self.assertTrue(image_path.exists())
        self.assertTrue(manifest_path.exists())
        self.assertIn(f"Linked image written: {image_path}", result.stdout)
        self.assertIn(f"Image manifest written: {manifest_path}", result.stdout)
        self.assertIn(f"Link map written: {map_path}", result.stdout)
        self.assertEqual(image_path.read_bytes(), bytes.fromhex("004001000000"))

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["image_sha256"],
            hashlib.sha256(image_path.read_bytes()).hexdigest(),
        )

    def test_failed_link_removes_stale_map_image_and_manifest(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "RMISS  \n"
            "T00000003000000\n"
            "M00000006+MISS  \n"
            "E000000\n"
        )
        artifacts = [
            Path(default_map_path([path])),
            Path(default_image_path([path])),
            Path(default_manifest_path([path])),
        ]
        for artifact in artifacts:
            artifact.write_bytes(b"STALE")

        result = subprocess.run(
            [sys.executable, str(LOADER), str(path), "4000"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Undefined external symbol MISS", result.stderr)
        for artifact in artifacts:
            self.assertFalse(artifact.exists())


if __name__ == "__main__":
    unittest.main()
