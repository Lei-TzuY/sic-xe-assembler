from dataclasses import dataclass

from opcodes import FORMAT2_SIGNATURES, OPCODES, REGISTERS


_OPCODE_BY_BYTE = {
    int(encoded, 16): (mnemonic, fmt)
    for mnemonic, (encoded, fmt) in OPCODES.items()
}
_REGISTER_BY_NUMBER = {value: name for name, value in REGISTERS.items()}


@dataclass(frozen=True)
class DecodedInstruction:
    address: int
    size: int
    data: bytes
    mnemonic: str
    operand: str
    format: int
    flags: str = ""
    target: object = None
    warning: object = None

    @property
    def bytes_hex(self):
        return self.data.hex().upper()


def _register_name(number):
    return _REGISTER_BY_NUMBER.get(number, f"R{number:X}")


def _decode_format2_operand(mnemonic, operand_byte):
    signature = FORMAT2_SIGNATURES[mnemonic]
    fields = ((operand_byte >> 4) & 0xF, operand_byte & 0xF)
    values = []
    for index, kind in enumerate(signature):
        field = fields[index]
        if kind == "register":
            values.append(_register_name(field))
        elif kind == "shift_count":
            values.append(str(field + 1))
        elif kind == "nibble":
            values.append(str(field))
        else:
            values.append(f"0x{field:X}")
    return ",".join(values)


def _format_target(value):
    return f"{value:05X}"


def _addressing_prefix(n, i):
    if (n, i) == (0, 1):
        return "#"
    if (n, i) == (1, 0):
        return "@"
    if (n, i) == (1, 1):
        return ""
    return "?"


def _byte_fallback(raw, address, warning):
    first = raw[0]
    return DecodedInstruction(
        address=address,
        size=1,
        data=raw[:1],
        mnemonic=".BYTE",
        operand=f"X'{first:02X}'",
        format=0,
        warning=warning,
    )


def decode_instruction(data, address=0, base_register=None):
    """Decode one SIC/XE instruction from the beginning of *data*.

    Unknown opcodes are represented as a one-byte `.BYTE` pseudo-instruction so
    callers can perform a deterministic linear sweep across arbitrary data.
    """
    raw = bytes(data)
    if not raw:
        raise ValueError("At least one byte is required for disassembly")

    first = raw[0]
    exact = _OPCODE_BY_BYTE.get(first)
    if exact is not None and exact[1] in (1, 2):
        mnemonic, fmt = exact
        if fmt == 1:
            return DecodedInstruction(
                address=address,
                size=1,
                data=raw[:1],
                mnemonic=mnemonic,
                operand="",
                format=1,
            )
        if len(raw) < 2:
            return _byte_fallback(
                raw,
                address,
                f"truncated format-2 instruction {mnemonic}",
            )
        return DecodedInstruction(
            address=address,
            size=2,
            data=raw[:2],
            mnemonic=mnemonic,
            operand=_decode_format2_operand(mnemonic, raw[1]),
            format=2,
        )

    opcode = first & 0xFC
    decoded = _OPCODE_BY_BYTE.get(opcode)
    if decoded is None or decoded[1] != 3:
        return _byte_fallback(raw, address, "unknown opcode")

    mnemonic, _ = decoded
    if len(raw) < 3:
        return _byte_fallback(
            raw,
            address,
            f"truncated format-3 instruction {mnemonic}",
        )

    n = (first >> 1) & 1
    i = first & 1
    second = raw[1]
    x = (second >> 7) & 1

    # n=i=0 selects original SIC compatibility encoding. In this mode the
    # lower 15 address bits are not XE b/p/e flags and the instruction is
    # always exactly three bytes long.
    if (n, i) == (0, 0):
        target = ((second & 0x7F) << 8) | raw[2]
        operand = _format_target(target)
        if x:
            operand += ",X"
        return DecodedInstruction(
            address=address,
            size=3,
            data=raw[:3],
            mnemonic=mnemonic,
            operand=operand,
            format=3,
            flags=f"00{x}---",
            target=target,
            warning="SIC compatibility mode",
        )

    b = (second >> 6) & 1
    p = (second >> 5) & 1
    e = (second >> 4) & 1
    size = 4 if e else 3
    if len(raw) < size:
        return _byte_fallback(
            raw,
            address,
            f"truncated format-{size} instruction {mnemonic}",
        )

    flags = f"{n}{i}{x}{b}{p}{e}"
    prefix = _addressing_prefix(n, i)
    warnings = []
    if b and p:
        warnings.append("both base-relative and PC-relative flags are set")
    if x and (n, i) != (1, 1):
        warnings.append("indexed flag used with non-simple addressing")

    if e:
        field = ((second & 0x0F) << 16) | (raw[2] << 8) | raw[3]
        target = field
        if b or p:
            warnings.append("format-4 instruction has b/p set")
        operand = prefix + _format_target(field)
        mnemonic_text = "+" + mnemonic
    else:
        field = ((second & 0x0F) << 8) | raw[2]
        mnemonic_text = mnemonic
        if p:
            signed_disp = field if field < 0x800 else field - 0x1000
            target = address + 3 + signed_disp
            operand = prefix + _format_target(target)
        elif b:
            if base_register is None:
                target = None
                operand = prefix + f"B+{field:03X}"
            else:
                target = base_register + field
                operand = prefix + _format_target(target)
        else:
            target = field
            operand = prefix + (str(field) if (n, i) == (0, 1) else _format_target(field))

    if x:
        operand += ",X"
    if mnemonic == "RSUB" and n == 1 and i == 1 and x == b == p == e == 0 and field == 0:
        operand = ""
        target = None

    return DecodedInstruction(
        address=address,
        size=size,
        data=raw[:size],
        mnemonic=mnemonic_text,
        operand=operand,
        format=size,
        flags=flags,
        target=target,
        warning="; ".join(warnings) if warnings else None,
    )


def disassemble(data, start_address=0, base_register=None, max_instructions=None):
    """Deterministically linear-sweep a byte sequence into decoded records."""
    raw = bytes(data)
    offset = 0
    decoded = []
    while offset < len(raw):
        if max_instructions is not None and len(decoded) >= max_instructions:
            break
        instruction = decode_instruction(
            raw[offset:],
            address=start_address + offset,
            base_register=base_register,
        )
        decoded.append(instruction)
        offset += instruction.size
    return tuple(decoded)


def render_disassembly(records):
    lines = []
    for record in records:
        raw = record.bytes_hex.ljust(8)
        assembly = record.mnemonic
        if record.operand:
            assembly += " " + record.operand
        details = []
        if record.flags:
            details.append(f"nixbpe={record.flags}")
        if record.target is not None:
            details.append(f"target={record.target:05X}")
        if record.warning:
            details.append(record.warning)
        suffix = f" ; {'; '.join(details)}" if details else ""
        lines.append(f"{record.address:05X}  {raw}  {assembly}{suffix}")
    return "\n".join(lines) + ("\n" if lines else "")
