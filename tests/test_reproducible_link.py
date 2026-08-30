import hashlib
import tempfile
import unittest
from pathlib import Path

from link_map import render_link_map
from load_plan import (
    LoadPlanError,
    build_load_plan,
    capture_link_session,
    verify_link_session,
)
from loader import (
    LoaderError,
    apply_load_plan,
    pass1 as loader_pass1,
    pass2 as loader_pass2,
)


class ReproducibleLinkSessionTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-link-session-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    @staticmethod
    def object_text(payload="010203"):
        return (
            "HMAIN  000000000003\n"
            f"T00000003{payload}\n"
            "E000000\n"
        )

    def test_snapshot_hashes_exact_raw_bytes_and_is_path_independent(self):
        text = self.object_text()
        first = self.write_object(text, "one.obj")
        second = self.write_object(text, "two.obj")

        first_session = capture_link_session([first])
        second_session = capture_link_session([second])
        expected = hashlib.sha256(first.read_bytes()).hexdigest()

        self.assertEqual(first_session.inputs[0].sha256, expected)
        self.assertEqual(first_session.inputs[0].byte_length, len(first.read_bytes()))
        self.assertEqual(
            first_session.input_fingerprint,
            second_session.input_fingerprint,
        )

        first_plan = build_load_plan(first_session, 0x4000)
        second_plan = build_load_plan(second_session, 0x4000)
        self.assertEqual(first_plan.link_fingerprint, second_plan.link_fingerprint)
        self.assertNotEqual(
            first_plan.link_fingerprint,
            build_load_plan(first_session, 0x5000).link_fingerprint,
        )

    def test_pass2_uses_exact_pass1_snapshot_after_disk_rewrite(self):
        path = self.write_object(self.object_text("010203"))
        estab = loader_pass1([path], 0x4000)

        path.write_text(self.object_text("AABBCC"), encoding="utf-8")
        memory, exec_addr = loader_pass2([path], 0x4000, estab)

        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(bytes(memory[0x4000:0x4003]), bytes.fromhex("010203"))
        with self.assertRaisesRegex(
            LoadPlanError,
            "Object input changed since snapshot",
        ):
            verify_link_session(estab.link_session)

    def test_plain_dict_estab_intentionally_discards_snapshot_binding(self):
        path = self.write_object(self.object_text("010203"))
        bound_estab = loader_pass1([path], 0x4000)
        legacy_estab = dict(bound_estab)

        path.write_text(self.object_text("AABBCC"), encoding="utf-8")
        memory, _ = loader_pass2([path], 0x4000, legacy_estab)
        self.assertEqual(bytes(memory[0x4000:0x4003]), bytes.fromhex("AABBCC"))

    def test_captured_session_remains_loadable_after_source_is_deleted(self):
        path = self.write_object(self.object_text("112233"))
        session = capture_link_session([path])
        path.unlink()

        plan = build_load_plan(session, 0x6000)
        memory, exec_addr = apply_load_plan(plan)
        self.assertEqual(exec_addr, 0x6000)
        self.assertEqual(bytes(memory[0x6000:0x6003]), bytes.fromhex("112233"))

    def test_bound_estab_cannot_be_reused_with_a_different_input_list(self):
        first = self.write_object(self.object_text(), "first.obj")
        second = self.write_object(self.object_text(), "second.obj")
        estab = loader_pass1([first], 0x4000)

        with self.assertRaisesRegex(
            LoaderError,
            "object input list does not match Pass-1 snapshot",
        ):
            loader_pass2([second], 0x4000, estab)

    def test_plan_exposes_immutable_symbol_and_text_views(self):
        path = self.write_object(self.object_text())
        plan = build_load_plan([path], 0x4000)

        with self.assertRaises(TypeError):
            plan.estab["MAIN"] = 0x5000
        with self.assertRaises(TypeError):
            plan.sections[0].texts[0]['data'] = b"\x00\x00\x00"

    def test_link_map_records_input_and_link_fingerprints(self):
        path = self.write_object(self.object_text())
        plan = build_load_plan([path], 0x4000)
        report = render_link_map(plan)

        self.assertIn(f"INPUTSET  {plan.input_fingerprint}", report)
        self.assertIn(f"LINKID    {plan.link_fingerprint}", report)
        self.assertIn("INPUT SNAPSHOTS", report)
        self.assertIn(plan.inputs[0].sha256, report)
        self.assertIn("SUMMARY sections=1 symbols=1 relocations=0 unused_R=0 inputs=1", report)


if __name__ == "__main__":
    unittest.main()
