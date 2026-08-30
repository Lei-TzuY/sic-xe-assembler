import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from emulator import (
    BufferedDevice,
    DeviceBus,
    SicXeMachine,
    resolve_breakpoint,
    s24,
)
from source_map import load_linked_debug_map


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "assembler.py"
LOADER = ROOT / "loader.py"


class EmulatorTests(unittest.TestCase):
    def run_script(self, script, *args):
        return subprocess.run(
            [sys.executable, str(script), *map(str, args)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def build_program(self, text, progaddr="4000"):
        temp = tempfile.TemporaryDirectory(prefix="sicxe-emulator-")
        self.addCleanup(temp.cleanup)
        source = Path(temp.name) / "program.asm"
        source.write_text(text, encoding="utf-8")
        assembled = self.run_script(ASSEMBLER, source)
        self.assertEqual(assembled.returncode, 0, assembled.stderr)
        obj = source.with_suffix(".obj")
        linked = self.run_script(LOADER, obj, progaddr)
        self.assertEqual(linked.returncode, 0, linked.stderr)
        image = source.with_suffix(".bin").read_bytes()
        manifest = json.loads(source.with_suffix(".manifest.json").read_text(encoding="utf-8"))
        debug, _ = load_linked_debug_map(source.with_suffix(".debug.json"))
        machine = SicXeMachine.from_image(
            image,
            manifest["image_start"],
            manifest["entry"]["address"],
            debug_map=debug,
        )
        return source, manifest, debug, machine

    @staticmethod
    def symbol_address(debug, name):
        matches = []
        for section in debug["sections"]:
            for symbol in section["symbols"]:
                if symbol["name"] == name and symbol["relocatable"]:
                    matches.append(symbol["loaded_address"])
        if len(matches) != 1:
            raise AssertionError(f"Expected one symbol {name}, got {matches}")
        return matches[0]

    def test_loop_arithmetic_tix_branch_store_and_svc_stop(self):
        _, _, debug, machine = self.build_program(
            "MAIN START 0\n"
            "      LDA #0\n"
            "      LDX #0\n"
            "LOOP  ADD #1\n"
            "      TIX #5\n"
            "      JLT LOOP\n"
            "      STA RESULT\n"
            "      SVC 0\n"
            "RESULT RESW 1\n"
            "      END MAIN\n"
        )
        result = machine.run(max_steps=100, trace=True)
        self.assertEqual(result.stop_reason, "svc")
        self.assertEqual(result.service_code, 0)
        self.assertEqual(result.executed_steps, 19)
        self.assertEqual(machine.get_register("A"), 5)
        self.assertEqual(machine.get_register("X"), 5)
        result_address = self.symbol_address(debug, "RESULT")
        self.assertEqual(machine.read_word(result_address), 5)

        loop_steps = [
            step for step in result.steps
            if step.context and "LOOP" in step.context["symbols"]
        ]
        self.assertEqual(len(loop_steps), 5)
        self.assertTrue(all(step.context["provenance"]["source_line"] == 4 for step in loop_steps))

    def test_jsub_rsub_format2_and_service_code(self):
        _, _, debug, machine = self.build_program(
            "MAIN START 0\n"
            "      LDA #3\n"
            "      JSUB DOUBLE\n"
            "      STA RESULT\n"
            "      SVC 7\n"
            "DOUBLE ADDR A,A\n"
            "      RSUB\n"
            "RESULT RESW 1\n"
            "      END MAIN\n"
        )
        result = machine.run(max_steps=50, trace=True)
        self.assertEqual((result.stop_reason, result.service_code), ("svc", 7))
        self.assertEqual(machine.get_register("A"), 6)
        self.assertEqual(machine.read_word(self.symbol_address(debug, "RESULT")), 6)
        mnemonics = [step.mnemonic.lstrip("+") for step in result.steps]
        self.assertEqual(mnemonics, ["LDA", "JSUB", "ADDR", "RSUB", "STA", "SVC"])
        jsub = result.steps[1]
        return_address = jsub.pc + len(bytes.fromhex(jsub.bytes_hex))
        self.assertEqual(machine.get_register("L"), return_address)

    def test_indirect_and_indexed_addressing_preserve_ldch_upper_bytes(self):
        _, _, _, machine = self.build_program(
            "MAIN START 0\n"
            "      LDX #1\n"
            "      LDA @PTR\n"
            "      LDCH TABLE,X\n"
            "      SVC 0\n"
            "PTR   WORD VALUE\n"
            "VALUE WORD 1193046\n"
            "TABLE BYTE X'414243'\n"
            "      END MAIN\n"
        )
        result = machine.run(max_steps=20)
        self.assertEqual(result.stop_reason, "svc")
        self.assertEqual(machine.get_register("X"), 1)
        self.assertEqual(machine.get_register("A"), 0x123442)

    def test_register_shift_compare_and_tixr_profile(self):
        _, _, _, machine = self.build_program(
            "MAIN START 0\n"
            "      LDA #1\n"
            "      RMO A,S\n"
            "      SHIFTL S,4\n"
            "      SHIFTR S,2\n"
            "      CLEAR X\n"
            "      TIXR S\n"
            "      COMPR X,S\n"
            "      SVC 0\n"
            "      END MAIN\n"
        )
        result = machine.run(max_steps=20)
        self.assertEqual(result.stop_reason, "svc")
        self.assertEqual(machine.get_register("S"), 4)
        self.assertEqual(machine.get_register("X"), 1)
        self.assertEqual(machine.cc, -1)

    def test_buffered_device_td_rd_wd_flow(self):
        _, _, _, machine = self.build_program(
            "MAIN START 0\n"
            "      TD INDEV\n"
            "      JEQ FAIL\n"
            "      RD INDEV\n"
            "      WD OUTDEV\n"
            "      SVC 0\n"
            "FAIL  SVC 1\n"
            "INDEV BYTE X'F1'\n"
            "OUTDEV BYTE X'05'\n"
            "      END MAIN\n"
        )
        bus = DeviceBus()
        bus.attach(0xF1, BufferedDevice(input_bytes=b"Z", readable=True, writable=False))
        bus.attach(0x05, BufferedDevice(readable=False, writable=True))
        machine.devices = bus

        result = machine.run(max_steps=20, trace=True)
        self.assertEqual((result.stop_reason, result.service_code), ("svc", 0))
        self.assertEqual(machine.get_register("A") & 0xFF, ord("Z"))
        self.assertEqual(result.device_outputs, {"05": "5A"})
        self.assertEqual([step.mnemonic for step in result.steps[:4]], ["TD", "JEQ", "RD", "WD"])

    def test_symbol_breakpoint_stops_before_instruction(self):
        _, _, debug, machine = self.build_program(
            "MAIN START 0\n"
            "      LDA #0\n"
            "      LDX #0\n"
            "LOOP  ADD #1\n"
            "      SVC 0\n"
            "      END MAIN\n"
        )
        loop = resolve_breakpoint("LOOP", debug)
        result = machine.run(max_steps=20, breakpoints=[loop], trace=True)
        self.assertEqual(result.stop_reason, "breakpoint")
        self.assertEqual(result.breakpoint, loop)
        self.assertEqual(result.executed_steps, 2)
        self.assertEqual(result.pc, loop)
        self.assertEqual(machine.get_register("A"), 0)

    def test_division_by_zero_trap_is_transactional(self):
        _, _, debug, machine = self.build_program(
            "MAIN START 0\n"
            "      LDA #5\n"
            "FAULT DIV ZERO\n"
            "      SVC 0\n"
            "ZERO  WORD 0\n"
            "      END MAIN\n"
        )
        fault = self.symbol_address(debug, "FAULT")
        result = machine.run(max_steps=20, trace=True)
        self.assertEqual(result.stop_reason, "trap")
        self.assertEqual(result.executed_steps, 1)
        self.assertEqual(result.pc, fault)
        self.assertEqual(machine.get_register("A"), 5)
        self.assertIn("division by zero", result.error)
        self.assertIn(f"PC {fault:05X}", result.error)

    def test_unsupported_floating_instruction_traps_without_advancing_pc(self):
        _, manifest, _, machine = self.build_program(
            "MAIN START 0\n"
            "      FLOAT\n"
            "      SVC 0\n"
            "      END MAIN\n"
        )
        entry = manifest["entry"]["address"]
        result = machine.run(max_steps=5)
        self.assertEqual(result.stop_reason, "trap")
        self.assertEqual(result.executed_steps, 0)
        self.assertEqual(result.pc, entry)
        self.assertIn("FLOAT", result.error)
        self.assertIn("execution profile", result.error)

    def test_infinite_loop_stops_at_deterministic_step_limit(self):
        _, _, debug, machine = self.build_program(
            "MAIN START 0\n"
            "LOOP  J LOOP\n"
            "      END LOOP\n"
        )
        result = machine.run(max_steps=7)
        self.assertEqual(result.stop_reason, "step-limit")
        self.assertEqual(result.executed_steps, 7)
        self.assertEqual(result.pc, self.symbol_address(debug, "LOOP"))

    def test_signed_24_bit_helpers(self):
        self.assertEqual(s24(0xFFFFFF), -1)
        self.assertEqual(s24(0x800000), -(1 << 23))
        self.assertEqual(s24(0x7FFFFF), (1 << 23) - 1)


if __name__ == "__main__":
    unittest.main()
