import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from artifact_verifier import ArtifactVerificationError, verify_linked_artifacts
from linked_image import default_image_path, default_manifest_path, write_linked_image_artifacts
from load_plan import build_load_plan
from loader import apply_load_plan


ROOT = Path(__file__).resolve().parents[1]
VERIFY_LINK = ROOT / "verify_link.py"


class ArtifactVerifierTests(unittest.TestCase):
    def make_artifacts(self, payload="000001"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-artifact-verify-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        obj = root / "program.obj"
        obj.write_text(
            "HMAIN  000000000003\n"
            f"T00000003{payload}\n"
            "M00000006+MAIN  \n"
            "E000000\n",
            encoding="utf-8",
        )
        plan = build_load_plan([obj], 0x4000)
        memory, _ = apply_load_plan(plan)
        image = Path(default_image_path([obj]))
        manifest = Path(default_manifest_path([obj]))
        write_linked_image_artifacts(plan, memory, image, manifest)
        return obj, image, manifest, plan

    def test_valid_artifacts_reproduce_exactly(self):
        obj, image, manifest, plan = self.make_artifacts()
        result = verify_linked_artifacts(image, manifest, [obj])
        self.assertEqual(result.link_fingerprint, plan.link_fingerprint)
        self.assertEqual(result.input_fingerprint, plan.input_fingerprint)
        self.assertEqual(result.progaddr, 0x4000)
        self.assertEqual(result.entry_address, 0x4000)
        self.assertEqual(result.image_length, 3)

    def test_binary_tamper_is_detected_before_relink(self):
        obj, image, manifest, _ = self.make_artifacts()
        altered = bytearray(image.read_bytes())
        altered[-1] ^= 0xFF
        image.write_bytes(altered)
        with self.assertRaisesRegex(ArtifactVerificationError, "SHA-256 mismatch"):
            verify_linked_artifacts(image, manifest, [obj])

    def test_object_input_substitution_is_detected_by_inputset(self):
        obj, image, manifest, _ = self.make_artifacts()
        obj.write_text(
            "HMAIN  000000000003\n"
            "T00000003000002\n"
            "M00000006+MAIN  \n"
            "E000000\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactVerificationError, "INPUTSET mismatch"):
            verify_linked_artifacts(image, manifest, [obj])

    def test_manifest_metadata_tamper_is_detected(self):
        obj, image, manifest, _ = self.make_artifacts()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["entry"]["address"] += 1
        manifest.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactVerificationError, "metadata does not match"):
            verify_linked_artifacts(image, manifest, [obj])

    def test_noncanonical_manifest_format_is_rejected(self):
        obj, image, manifest, _ = self.make_artifacts()
        data = json.loads(manifest.read_text(encoding="utf-8"))
        manifest.write_text(json.dumps(data, sort_keys=False), encoding="utf-8")
        with self.assertRaisesRegex(ArtifactVerificationError, "canonical deterministic form"):
            verify_linked_artifacts(image, manifest, [obj])

    def test_cli_reports_success_and_failure_with_distinct_exit_codes(self):
        obj, image, manifest, _ = self.make_artifacts()
        success = subprocess.run(
            [sys.executable, str(VERIFY_LINK), str(image), str(manifest), str(obj)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertIn("Linked artifacts verified reproducible", success.stdout)
        self.assertIn("LINKID:", success.stdout)

        image.write_bytes(b"tampered")
        failure = subprocess.run(
            [sys.executable, str(VERIFY_LINK), str(image), str(manifest), str(obj)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(failure.returncode, 1)
        self.assertIn("Verification failed:", failure.stderr)


if __name__ == "__main__":
    unittest.main()
