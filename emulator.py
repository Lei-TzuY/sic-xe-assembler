from collections import deque
from dataclasses import dataclass

from address_space import SICXE_MAX_ADDRESS, SICXE_MEMORY_SIZE
from disassembler import decode_instruction
from opcodes import OPCODES, REGISTERS


WORD_BITS = 24
WORD_MASK = (1 << WORD_BITS) - 1
WORD_SIGN = 1 << (WORD_BITS - 1)
FLOAT_MASK = (1 << 48) - 1

CC_LT = -1
CC_EQ = 0
CC_GT = 1

_OPCODE_BY_BYTE = {
    int(encoded, 16): (mnemonic, fmt)
    for mnemonic, (encoded, fmt) in OPCODES.items()
}
_REGISTER_BY_NUMBER = {value: name for name, value in REGISTERS.items()}

SUPPORTED_FORMAT1 = frozenset()
SUPPORTED_FORMAT2 = frozenset({
    "ADDR", "CLEAR", "COMPR", "DIVR", "MULR", "RMO", "SHIFTL",
    "SHIFTR", "SUBR", "SVC", "TIXR",
})
SUPPORTED_FORMAT34 = frozenset({
    "ADD", "AND", "COMP", "DIV", "J", "JEQ", "JGT", "JLT", "JSUB",
    "LDA", "LDB", "LDCH", "LDL", "LDS", "LDT", "LDX", "MUL", "OR",
    "RD", "RSUB", "STA", "STB", "STCH", "STL", "STS", "STT", "STX",
    "SUB", "TD", "TIX", "WD",
})


class ExecutionTrap(ValueError):
    def __init__(self, message, pc=None):
        self.pc = pc
        prefix = f"PC {pc:05X}: " if pc is not None else ""
        super().__init__(prefix + message)


@dataclass(frozen=True)
class AddressOperand:
    mode: str
    target_address: object
    effective_address: object
    immediate_value: object


@dataclass(frozen=True)
class ExecutionStep:
    index: int
    pc: int
    next_pc: int
    bytes_hex: str
    mnemonic: str
    operand: str
    register_changes: tuple
    memory_writes: tuple
    cc_before: int
    cc_after: int
    stop_reason: object
    service_code: object
    context: object


@dataclass(frozen=True)
class ExecutionResult:
    stop_reason: str
    steps: tuple
    executed_steps: int
    pc: int
    registers: object
    cc: int
    service_code: object
    breakpoint: object
    error: object
    device_outputs: object


class BufferedDevice:
    """Deterministic byte-oriented device used by RD/WD/TD."""

    def __init__(self, input_bytes=b"", readable=True, writable=True, ready=True):
        self.input = deque(bytes(input_bytes))
        self.output = bytearray()
        self.readable = bool(readable)
        self.writable = bool(writable)
        self.ready = bool(ready)

    def read(self):
        if not self.ready or not self.readable:
            raise ExecutionTrap("device is not ready for input")
        if not self.input:
            raise ExecutionTrap("device input is exhausted")
        return self.input.popleft()

    def write(self, value):
        if not self.ready or not self.writable:
            raise ExecutionTrap("device is not ready for output")
        self.output.append(value & 0xFF)


class DeviceBus:
    def __init__(self):
        self.devices = {}

    def attach(self, device_id, device=None, **kwargs):
        if not 0 <= device_id <= 0xFF:
            raise ValueError(f"Device id must be 00-FF: {device_id}")
        if device is None:
            device = BufferedDevice(**kwargs)
        self.devices[device_id] = device
        return device

    def get(self, device_id):
        return self.devices.get(device_id)

    def test(self, device_id):
        device = self.get(device_id)
        return bool(device is not None and device.ready)

    def read(self, device_id):
        device = self.get(device_id)
        if device is None:
            raise ExecutionTrap(f"unconfigured input device {device_id:02X}")
        return device.read()

    def write(self, device_id, value):
        device = self.get(device_id)
        if device is None:
            raise ExecutionTrap(f"unconfigured output device {device_id:02X}")
        device.write(value)

    def snapshot(self):
        return {
            device_id: (
                tuple(device.input), bytes(device.output), device.readable,
                device.writable, device.ready,
            )
            for device_id, device in self.devices.items()
        }

    def restore(self, snapshot):
        for device_id in list(self.devices):
            if device_id not in snapshot:
                del self.devices[device_id]
        for device_id, state in snapshot.items():
            device = self.devices.get(device_id)
            if device is None:
                device = BufferedDevice()
                self.devices[device_id] = device
            input_bytes, output_bytes, readable, writable, ready = state
            device.input = deque(input_bytes)
            device.output = bytearray(output_bytes)
            device.readable = readable
            device.writable = writable
            device.ready = ready

    def outputs(self):
        return {
            f"{device_id:02X}": bytes(device.output).hex().upper()
            for device_id, device in sorted(self.devices.items())
            if device.output
        }


def u24(value):
    return value & WORD_MASK


def s24(value):
    value &= WORD_MASK
    return value - (1 << WORD_BITS) if value & WORD_SIGN else value


def _trunc_div(dividend, divisor):
    if divisor == 0:
        raise ExecutionTrap("division by zero")
    magnitude = abs(dividend) // abs(divisor)
    return -magnitude if (dividend < 0) ^ (divisor < 0) else magnitude


def _compare(left, right):
    if left < right:
        return CC_LT
    if left > right:
        return CC_GT
    return CC_EQ


def _base_mnemonic(mnemonic):
    return mnemonic[1:] if mnemonic.startswith("+") else mnemonic


def _jsonable(value):
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


class SicXeMachine:
    """Deterministic SIC/XE execution engine for the integer/core ISA profile."""

    def __init__(self, memory=None, entry_address=0, debug_map=None, devices=None,
                 stop_on_zero_return=True):
        self.memory = bytearray(SICXE_MEMORY_SIZE) if memory is None else bytearray(memory)
        if len(self.memory) != SICXE_MEMORY_SIZE:
            raise ValueError(f"Machine memory must be exactly {SICXE_MEMORY_SIZE} bytes")
        self.registers = {
            "A": 0, "X": 0, "L": 0, "B": 0, "S": 0, "T": 0,
            "F": 0, "PC": 0, "SW": 0,
        }
        self.cc = CC_EQ
        self.devices = devices if devices is not None else DeviceBus()
        self.debug_map = debug_map
        self.stop_on_zero_return = bool(stop_on_zero_return)
        self._instruction_context = self._build_instruction_context(debug_map)
        self.set_register("PC", entry_address)

    @classmethod
    def from_image(cls, image, image_start, entry_address, debug_map=None,
                   devices=None, stop_on_zero_return=True):
        raw = bytes(image)
        if image_start < 0 or image_start > SICXE_MAX_ADDRESS:
            raise ValueError(f"Image start outside SIC/XE memory: {image_start:#x}")
        if image_start + len(raw) > SICXE_MEMORY_SIZE:
            raise ValueError(
                f"Image range exceeds SIC/XE memory: {image_start:#x}+{len(raw):#x}"
            )
        memory = bytearray(SICXE_MEMORY_SIZE)
        memory[image_start:image_start + len(raw)] = raw
        return cls(memory=memory, entry_address=entry_address, debug_map=debug_map,
                   devices=devices, stop_on_zero_return=stop_on_zero_return)

    @staticmethod
    def _build_instruction_context(debug_map):
        context = {}
        if not debug_map:
            return context
        for section in debug_map.get("sections", ()):
            if not section.get("typed"):
                continue
            for region in section.get("regions", ()):
                if region.get("kind") != "instruction":
                    continue
                context[region["loaded_address"]] = {
                    "input_index": section.get("input_index"),
                    "section_index": section.get("section_index"),
                    "section": section.get("name"),
                    "symbols": tuple(region.get("symbols") or ()),
                    "expanded_line": region.get("expanded_line"),
                    "provenance": region.get("provenance"),
                    "source_text": region.get("text"),
                }
        return context

    def context_at(self, address):
        item = self._instruction_context.get(address)
        return dict(item) if item is not None else None

    def get_register(self, name):
        register = name.upper()
        if register not in self.registers:
            raise ExecutionTrap(f"unknown register {name}")
        return self.registers[register]

    def set_register(self, name, value):
        register = name.upper()
        if register not in self.registers:
            raise ExecutionTrap(f"unknown register {name}")
        if register == "F":
            if not 0 <= value <= FLOAT_MASK:
                raise ExecutionTrap(f"F register value out of 48-bit range: {value}")
            self.registers[register] = value
            return
        if register == "PC":
            if not 0 <= value <= SICXE_MAX_ADDRESS:
                raise ExecutionTrap(f"PC outside 20-bit SIC/XE memory: {value:#x}")
            self.registers[register] = value
            return
        self.registers[register] = u24(value)

    def _check_range(self, address, length, description="memory access"):
        if length < 0 or address < 0 or address + length > SICXE_MEMORY_SIZE:
            raise ExecutionTrap(
                f"{description} outside SIC/XE memory: address={address:#x}, length={length:#x}",
                pc=self.registers["PC"],
            )

    def read_byte(self, address):
        self._check_range(address, 1)
        return self.memory[address]

    def read_word(self, address):
        self._check_range(address, 3)
        return ((self.memory[address] << 16) | (self.memory[address + 1] << 8)
                | self.memory[address + 2])

    def _write_byte(self, address, value, writes):
        self._check_range(address, 1, "memory write")
        before = self.memory[address]
        after = value & 0xFF
        self.memory[address] = after
        writes.append((address, before, after))

    def _write_word(self, address, value, writes):
        self._check_range(address, 3, "memory write")
        encoded = u24(value)
        for offset, byte in enumerate(((encoded >> 16) & 0xFF,
                                       (encoded >> 8) & 0xFF, encoded & 0xFF)):
            self._write_byte(address + offset, byte, writes)

    def _register_name(self, number, pc):
        name = _REGISTER_BY_NUMBER.get(number)
        if name is None:
            raise ExecutionTrap(f"invalid register number {number:X}", pc=pc)
        return name

    def _integer_register(self, number, pc):
        name = self._register_name(number, pc)
        if name == "F":
            raise ExecutionTrap(
                "48-bit F register is not valid in integer execution profile", pc=pc
            )
        return name

    def _fetch(self, pc):
        self._check_range(pc, 1, "instruction fetch")
        first = self.memory[pc]
        exact = _OPCODE_BY_BYTE.get(first)
        if exact is not None and exact[1] == 1:
            size = 1
        elif exact is not None and exact[1] == 2:
            size = 2
        else:
            decoded_opcode = _OPCODE_BY_BYTE.get(first & 0xFC)
            if decoded_opcode is None or decoded_opcode[1] != 3:
                raise ExecutionTrap(f"unknown opcode byte {first:02X}", pc=pc)
            self._check_range(pc, 3, "instruction fetch")
            n = (first >> 1) & 1
            i = first & 1
            size = 3 if (n, i) == (0, 0) else (4 if (self.memory[pc + 1] >> 4) & 1 else 3)
        self._check_range(pc, size, "instruction fetch")
        raw = bytes(self.memory[pc:pc + size])
        decoded = decode_instruction(raw, address=pc, base_register=self.registers["B"])
        if decoded.mnemonic == ".BYTE":
            raise ExecutionTrap(decoded.warning or "invalid instruction", pc=pc)
        return decoded, raw

    def _address_operand(self, raw, pc, next_pc):
        first = raw[0]
        n = (first >> 1) & 1
        i = first & 1
        second = raw[1]
        x = (second >> 7) & 1
        if (n, i) == (0, 0):
            target = ((second & 0x7F) << 8) | raw[2]
            if x:
                target += self.registers["X"]
            self._check_address(target, pc, "SIC target address")
            return AddressOperand("simple", target, target, None)

        b = (second >> 6) & 1
        p = (second >> 5) & 1
        e = (second >> 4) & 1
        if b and p:
            raise ExecutionTrap("illegal addressing flags: b and p are both set", pc=pc)
        if e and (b or p):
            raise ExecutionTrap("illegal format-4 addressing flags: b/p must be zero", pc=pc)
        if x and (n, i) != (1, 1):
            raise ExecutionTrap("indexed addressing requires simple n=i=1 mode", pc=pc)
        if e:
            field = ((second & 0x0F) << 16) | (raw[2] << 8) | raw[3]
            target = field
        else:
            field = ((second & 0x0F) << 8) | raw[2]
            if p:
                displacement = field if field < 0x800 else field - 0x1000
                target = next_pc + displacement
            elif b:
                target = self.registers["B"] + field
            else:
                target = field
        if x:
            target += self.registers["X"]
        if (n, i) == (0, 1):
            return AddressOperand("immediate", target, None, u24(target))
        self._check_address(target, pc, "target address")
        if (n, i) == (1, 0):
            pointer = self.read_word(target)
            self._check_address(pointer, pc, "indirect target address")
            return AddressOperand("indirect", target, pointer, None)
        if (n, i) == (1, 1):
            return AddressOperand("simple", target, target, None)
        raise ExecutionTrap(f"unsupported n/i addressing combination {n}{i}", pc=pc)

    def _check_address(self, address, pc, description):
        if not 0 <= address <= SICXE_MAX_ADDRESS:
            raise ExecutionTrap(
                f"{description} outside 20-bit SIC/XE memory: {address:#x}", pc=pc
            )

    def _operand_word(self, operand, pc):
        if operand.mode == "immediate":
            return operand.immediate_value
        self._check_range(operand.effective_address, 3, "word operand")
        return self.read_word(operand.effective_address)

    def _operand_byte(self, operand, pc):
        if operand.mode == "immediate":
            return operand.immediate_value & 0xFF
        return self.read_byte(operand.effective_address)

    def _store_address(self, operand, pc):
        if operand.mode == "immediate":
            raise ExecutionTrap("immediate addressing is invalid for store instruction", pc=pc)
        return operand.effective_address

    def _jump_address(self, operand, pc):
        target = operand.immediate_value if operand.mode == "immediate" else operand.effective_address
        self._check_address(target, pc, "branch target")
        return target

    def _set_cc_signed(self, left, right):
        self.cc = _compare(s24(left), s24(right))

    def _execute_format2(self, mnemonic, raw, pc, next_pc):
        operand_byte = raw[1]
        r1 = (operand_byte >> 4) & 0xF
        r2 = operand_byte & 0xF
        if mnemonic == "SVC":
            return next_pc, "svc", r1
        if mnemonic in {"CLEAR", "TIXR"}:
            name1 = self._integer_register(r1, pc)
        else:
            name1 = self._integer_register(r1, pc)
            name2 = self._integer_register(r2, pc)
        if mnemonic == "CLEAR":
            self.set_register(name1, 0)
        elif mnemonic == "RMO":
            self.set_register(name2, self.get_register(name1))
        elif mnemonic == "ADDR":
            self.set_register(name2, s24(self.get_register(name2)) + s24(self.get_register(name1)))
        elif mnemonic == "SUBR":
            self.set_register(name2, s24(self.get_register(name2)) - s24(self.get_register(name1)))
        elif mnemonic == "MULR":
            self.set_register(name2, s24(self.get_register(name2)) * s24(self.get_register(name1)))
        elif mnemonic == "DIVR":
            self.set_register(name2, _trunc_div(s24(self.get_register(name2)), s24(self.get_register(name1))))
        elif mnemonic == "COMPR":
            self._set_cc_signed(self.get_register(name1), self.get_register(name2))
        elif mnemonic == "SHIFTL":
            count = r2 + 1
            value = self.get_register(name1)
            self.set_register(name1, ((value << count) | (value >> (WORD_BITS - count))) & WORD_MASK)
        elif mnemonic == "SHIFTR":
            self.set_register(name1, s24(self.get_register(name1)) >> (r2 + 1))
        elif mnemonic == "TIXR":
            self.set_register("X", self.get_register("X") + 1)
            self._set_cc_signed(self.get_register("X"), self.get_register(name1))
        else:
            raise ExecutionTrap(f"unsupported format-2 instruction {mnemonic}", pc=pc)
        return next_pc, None, None

    def _execute_format34(self, mnemonic, raw, pc, next_pc, writes):
        if mnemonic == "RSUB":
            target = self.get_register("L")
            if target == 0 and self.stop_on_zero_return:
                return 0, "return-zero", None
            self._check_address(target, pc, "RSUB target")
            return target, None, None
        operand = self._address_operand(raw, pc, next_pc)
        if mnemonic in {"LDA", "LDB", "LDL", "LDS", "LDT", "LDX"}:
            self.set_register(mnemonic[2:], self._operand_word(operand, pc))
        elif mnemonic == "LDCH":
            self.set_register("A", (self.get_register("A") & 0xFFFF00) | self._operand_byte(operand, pc))
        elif mnemonic in {"STA", "STB", "STL", "STS", "STT", "STX"}:
            self._write_word(self._store_address(operand, pc), self.get_register(mnemonic[2:]), writes)
        elif mnemonic == "STCH":
            self._write_byte(self._store_address(operand, pc), self.get_register("A") & 0xFF, writes)
        elif mnemonic == "ADD":
            self.set_register("A", s24(self.get_register("A")) + s24(self._operand_word(operand, pc)))
        elif mnemonic == "SUB":
            self.set_register("A", s24(self.get_register("A")) - s24(self._operand_word(operand, pc)))
        elif mnemonic == "MUL":
            self.set_register("A", s24(self.get_register("A")) * s24(self._operand_word(operand, pc)))
        elif mnemonic == "DIV":
            self.set_register("A", _trunc_div(s24(self.get_register("A")), s24(self._operand_word(operand, pc))))
        elif mnemonic == "AND":
            self.set_register("A", self.get_register("A") & self._operand_word(operand, pc))
        elif mnemonic == "OR":
            self.set_register("A", self.get_register("A") | self._operand_word(operand, pc))
        elif mnemonic == "COMP":
            self._set_cc_signed(self.get_register("A"), self._operand_word(operand, pc))
        elif mnemonic == "TIX":
            self.set_register("X", self.get_register("X") + 1)
            self._set_cc_signed(self.get_register("X"), self._operand_word(operand, pc))
        elif mnemonic == "J":
            next_pc = self._jump_address(operand, pc)
        elif mnemonic == "JEQ":
            if self.cc == CC_EQ:
                next_pc = self._jump_address(operand, pc)
        elif mnemonic == "JGT":
            if self.cc == CC_GT:
                next_pc = self._jump_address(operand, pc)
        elif mnemonic == "JLT":
            if self.cc == CC_LT:
                next_pc = self._jump_address(operand, pc)
        elif mnemonic == "JSUB":
            self.set_register("L", next_pc)
            next_pc = self._jump_address(operand, pc)
        elif mnemonic in {"RD", "WD", "TD"}:
            device_id = self._operand_byte(operand, pc)
            if mnemonic == "TD":
                self.cc = CC_LT if self.devices.test(device_id) else CC_EQ
            elif mnemonic == "RD":
                self.set_register("A", (self.get_register("A") & 0xFFFF00) | self.devices.read(device_id))
            else:
                self.devices.write(device_id, self.get_register("A") & 0xFF)
        else:
            raise ExecutionTrap(f"unsupported format-3/4 instruction {mnemonic}", pc=pc)
        return next_pc, None, None

    @staticmethod
    def _register_snapshot(registers):
        return dict(registers)

    @staticmethod
    def _register_changes(before, after):
        return tuple(
            (name, before[name], after[name])
            for name in ("A", "X", "L", "B", "S", "T", "F", "PC", "SW")
            if before[name] != after[name]
        )

    def _rollback(self, registers, cc, writes, device_snapshot):
        self.registers.clear()
        self.registers.update(registers)
        self.cc = cc
        for address, before, _after in reversed(writes):
            self.memory[address] = before
        self.devices.restore(device_snapshot)

    def step(self, index=1):
        pc = self.get_register("PC")
        decoded, raw = self._fetch(pc)
        mnemonic = _base_mnemonic(decoded.mnemonic)
        before = self._register_snapshot(self.registers)
        cc_before = self.cc
        device_snapshot = self.devices.snapshot()
        writes = []
        next_pc = pc + len(raw)
        stop_reason = None
        service_code = None
        try:
            if len(raw) == 1:
                if mnemonic not in SUPPORTED_FORMAT1:
                    raise ExecutionTrap(
                        f"instruction {mnemonic} is outside the implemented execution profile", pc=pc
                    )
            elif len(raw) == 2:
                if mnemonic not in SUPPORTED_FORMAT2:
                    raise ExecutionTrap(
                        f"instruction {mnemonic} is outside the implemented execution profile", pc=pc
                    )
                next_pc, stop_reason, service_code = self._execute_format2(mnemonic, raw, pc, next_pc)
            else:
                if mnemonic not in SUPPORTED_FORMAT34:
                    raise ExecutionTrap(
                        f"instruction {mnemonic} is outside the implemented execution profile", pc=pc
                    )
                next_pc, stop_reason, service_code = self._execute_format34(
                    mnemonic, raw, pc, next_pc, writes
                )
            if stop_reason == "return-zero":
                self.registers["PC"] = 0
            else:
                self.set_register("PC", next_pc)
        except ExecutionTrap as exc:
            self._rollback(before, cc_before, writes, device_snapshot)
            if exc.pc is None:
                raise ExecutionTrap(str(exc), pc=pc) from exc
            raise
        after = self._register_snapshot(self.registers)
        return ExecutionStep(
            index=index, pc=pc, next_pc=self.get_register("PC"),
            bytes_hex=raw.hex().upper(), mnemonic=decoded.mnemonic,
            operand=decoded.operand, register_changes=self._register_changes(before, after),
            memory_writes=tuple(writes), cc_before=cc_before, cc_after=self.cc,
            stop_reason=stop_reason, service_code=service_code, context=self.context_at(pc),
        )

    def run(self, max_steps=100000, breakpoints=(), trace=False):
        if max_steps < 0:
            raise ValueError("max_steps must be non-negative")
        breakpoint_set = set(breakpoints)
        steps = []
        executed = 0
        service_code = None
        breakpoint = None
        error = None
        stop_reason = "step-limit"
        while executed < max_steps:
            pc = self.get_register("PC")
            if pc in breakpoint_set:
                stop_reason = "breakpoint"
                breakpoint = pc
                break
            try:
                step = self.step(index=executed + 1)
            except ExecutionTrap as exc:
                stop_reason = "trap"
                error = str(exc)
                break
            executed += 1
            if trace:
                steps.append(step)
            if step.stop_reason is not None:
                stop_reason = step.stop_reason
                service_code = step.service_code
                break
        return ExecutionResult(
            stop_reason=stop_reason, steps=tuple(steps), executed_steps=executed,
            pc=self.get_register("PC"), registers=self._register_snapshot(self.registers),
            cc=self.cc, service_code=service_code, breakpoint=breakpoint,
            error=error, device_outputs=self.devices.outputs(),
        )


def resolve_breakpoint(token, debug_map=None):
    text = str(token).strip()
    try:
        address = int(text, 16)
    except ValueError:
        address = None
    if address is not None:
        if not 0 <= address <= SICXE_MAX_ADDRESS:
            raise ValueError(f"Breakpoint outside SIC/XE memory: {text}")
        return address
    if debug_map is None:
        raise ValueError(f"Symbol breakpoint requires linked debug metadata: {text}")
    matches = []
    for section in debug_map.get("sections", ()):
        if section.get("name") == text:
            matches.append(section["load_address"])
        for symbol in section.get("symbols", ()):
            if symbol.get("name") == text and symbol.get("relocatable"):
                matches.append(symbol["loaded_address"])
    matches = sorted(set(matches))
    if not matches:
        raise ValueError(f"Unknown breakpoint symbol: {text}")
    if len(matches) > 1:
        rendered = ", ".join(f"{value:05X}" for value in matches)
        raise ValueError(f"Ambiguous breakpoint symbol {text}: {rendered}")
    return matches[0]


def result_to_dict(result):
    return {
        "stop_reason": result.stop_reason,
        "executed_steps": result.executed_steps,
        "pc": result.pc,
        "registers": dict(result.registers),
        "cc": result.cc,
        "service_code": result.service_code,
        "breakpoint": result.breakpoint,
        "error": result.error,
        "device_outputs": dict(result.device_outputs),
        "steps": [
            {
                "index": step.index, "pc": step.pc, "next_pc": step.next_pc,
                "bytes_hex": step.bytes_hex, "mnemonic": step.mnemonic,
                "operand": step.operand,
                "register_changes": [list(change) for change in step.register_changes],
                "memory_writes": [list(write) for write in step.memory_writes],
                "cc_before": step.cc_before, "cc_after": step.cc_after,
                "stop_reason": step.stop_reason, "service_code": step.service_code,
                "context": _jsonable(step.context),
            }
            for step in result.steps
        ],
    }


def _context_text(context):
    if not context:
        return ""
    parts = []
    symbols = context.get("symbols") or ()
    if symbols:
        parts.append("symbols=" + ",".join(symbols))
    expanded_line = context.get("expanded_line")
    if expanded_line is not None:
        parts.append(f"expanded={expanded_line}")
    provenance = context.get("provenance") or {}
    source_line = provenance.get("source_line")
    if source_line is not None:
        parts.append(f"source={source_line}")
    invocation_line = provenance.get("invocation_line")
    if invocation_line is not None and invocation_line != source_line:
        parts.append(f"invocation={invocation_line}")
    stack = provenance.get("macro_stack") or ()
    if stack:
        parts.append("macro=" + ">".join(
            f"{frame.get('name')}#{frame.get('instance')}" for frame in stack
        ))
        body_line = stack[-1].get("body_line")
        if body_line is not None:
            parts.append(f"definition={body_line}")
    return "; ".join(parts)


def render_step(step):
    assembly = step.mnemonic + ((" " + step.operand) if step.operand else "")
    details = []
    context = _context_text(step.context)
    if context:
        details.append(context)
    if step.register_changes:
        details.append("regs=" + ",".join(
            f"{name}:{before:06X}->{after:06X}"
            for name, before, after in step.register_changes
        ))
    if step.cc_before != step.cc_after:
        details.append(f"cc={step.cc_before}->{step.cc_after}")
    if step.memory_writes:
        details.append("mem=" + ",".join(
            f"{address:05X}:{before:02X}->{after:02X}"
            for address, before, after in step.memory_writes
        ))
    if step.stop_reason:
        stop = step.stop_reason
        if step.service_code is not None:
            stop += f"({step.service_code})"
        details.append("stop=" + stop)
    suffix = f" ; {'; '.join(details)}" if details else ""
    return f"{step.index:06d}  {step.pc:05X}  {step.bytes_hex.ljust(8)}  {assembly}{suffix}"


def render_result(result, include_trace=False):
    lines = ["SIC/XE EXECUTION RESULT"]
    if include_trace:
        lines.append("TRACE")
        lines.extend(render_step(step) for step in result.steps)
        lines.append("")
    lines.append(f"STOP       {result.stop_reason}")
    lines.append(f"STEPS      {result.executed_steps}")
    lines.append(f"PC         {result.pc:05X}")
    lines.append(f"CC         {result.cc}")
    if result.service_code is not None:
        lines.append(f"SVC        {result.service_code}")
    if result.breakpoint is not None:
        lines.append(f"BREAKPOINT {result.breakpoint:05X}")
    if result.error:
        lines.append(f"ERROR      {result.error}")
    lines.append("REGISTERS")
    for name in ("A", "X", "L", "B", "S", "T", "PC", "SW"):
        width = 5 if name == "PC" else 6
        lines.append(f"  {name:<2} {result.registers[name]:0{width}X}")
    lines.append(f"  F  {result.registers['F']:012X}")
    if result.device_outputs:
        lines.append("DEVICE OUTPUTS")
        for device_id, data_hex in result.device_outputs.items():
            lines.append(f"  {device_id} {data_hex}")
    return "\n".join(lines) + "\n"
