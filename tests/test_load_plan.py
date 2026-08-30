import tempfile
import unittest
from pathlib import Path

from load_plan import LoadPlanError, build_load_plan
from loader import LoaderError, apply_load_plan, pass1 as loader_pass1, pass2 as loader_pass2


class LoadPlanIntegrityTests(unittest.TestCase):
    def write_object(self, text, name="program.obj"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-load-plan-")
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_unresolved_external_is_rejected_during_plan_build(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "RMISS  \n"
            "T00000003000000\n"
            "M00000006+MISS  \n"
            "E000000\n"
        )

        # Traditional Pass 1 can still construct the local ESTAB. The complete
        # load plan owns global reference resolution before any memory write.
        self.assertEqual(loader_pass1([path], 0x4000), {"MAIN": 0x4000})
        with self.assertRaisesRegex(
            LoadPlanError,
            "Undefined external symbol MISS referenced by MAIN",
        ):
            build_load_plan([path], 0x4000)

    def test_duplicate_definition_reports_both_provenances(self):
        first = self.write_object(
            "HONE   000000000001\n"
            "DSHARED000000\n"
            "T0000000100\n"
            "E\n",
            "one.obj",
        )
        second = self.write_object(
            "HTWO   000000000001\n"
            "DSHARED000000\n"
            "T0000000100\n"
            "E\n",
            "two.obj",
        )

        with self.assertRaises(LoadPlanError) as caught:
            build_load_plan([first, second], 0x4000)
        message = str(caught.exception)
        self.assertIn("Duplicate external symbol SHARED", message)
        self.assertIn("one.obj", message)
        self.assertIn("two.obj", message)
        self.assertIn("control section ONE", message)
        self.assertIn("control section TWO", message)

    def test_unused_r_declarations_are_legal_plan_metadata(self):
        path = self.write_object(
            "HMAIN  000000000001\n"
            "RUNUSED\n"
            "T0000000100\n"
            "E000000\n"
            "HUNUSED000000000000\n"
            "E\n"
        )
        plan = build_load_plan([path], 0x4000)
        self.assertEqual(plan.sections[0].unused_references, ("UNUSED",))
        memory, exec_addr = apply_load_plan(plan)
        self.assertEqual(exec_addr, 0x4000)
        self.assertEqual(memory[0x4000], 0)

    def test_explicit_entry_point_provenance_is_retained(self):
        path = self.write_object(
            "HMAIN  001000000003\n"
            "T00100003010203\n"
            "E001001\n"
        )
        plan = build_load_plan([path], 0x5000)
        self.assertEqual(plan.execution_address, 0x5001)
        self.assertIn("MAIN", plan.execution_source)
        self.assertIn("E001001", plan.execution_source)
        self.assertEqual(plan.sections[0].loaded_execution_address, 0x5001)

    def test_default_entry_point_has_no_fake_provenance(self):
        path = self.write_object(
            "HMAIN  000000000001\n"
            "T0000000100\n"
            "E\n"
        )
        plan = build_load_plan([path], 0x6000)
        self.assertEqual(plan.execution_address, 0x6000)
        self.assertIsNone(plan.execution_source)

    def test_pass2_rejects_stale_or_tampered_estab_before_loading(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003000000\n"
            "M00000006+MAIN  \n"
            "E000000\n"
        )
        estab = loader_pass1([path], 0x4000)
        tampered = dict(estab)
        tampered["MAIN"] = 0x5000
        with self.assertRaisesRegex(
            LoaderError,
            "ESTAB does not match validated load plan: MAIN expected 04000, received 05000",
        ):
            loader_pass2([path], 0x4000, tampered)

    def test_relocation_is_precomputed_in_plan_then_applied_verbatim(self):
        path = self.write_object(
            "HMAIN  000000000003\n"
            "T00000003000005\n"
            "M00000006+MAIN  \n"
            "E000000\n"
        )
        plan = build_load_plan([path], 0x4000)
        relocation = plan.sections[0].relocations[0]
        self.assertEqual(relocation.addend, 5)
        self.assertEqual(relocation.delta, 0x4000)
        self.assertEqual(relocation.relocated, 0x4005)
        self.assertEqual(relocation.encoded, 0x004005)

        memory, _ = apply_load_plan(plan)
        self.assertEqual(bytes(memory[0x4000:0x4003]), bytes.fromhex("004005"))

    def test_multiple_entry_error_identifies_both_sources(self):
        first = self.write_object(
            "HONE   000000000001\n"
            "T0000000100\n"
            "E000000\n",
            "entry-one.obj",
        )
        second = self.write_object(
            "HTWO   000000000001\n"
            "T0000000100\n"
            "E000000\n",
            "entry-two.obj",
        )
        with self.assertRaises(LoadPlanError) as caught:
            build_load_plan([first, second], 0x4000)
        message = str(caught.exception)
        self.assertIn("Multiple explicit execution addresses across object inputs", message)
        self.assertIn("entry-one.obj", message)
        self.assertIn("entry-two.obj", message)
        self.assertIn("ONE", message)
        self.assertIn("TWO", message)


if __name__ == "__main__":
    unittest.main()
