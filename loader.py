import os
import sys

from address_space import (
    SICXE_MEMORY_SIZE,
    validate_machine_address,
    validate_machine_range,
)
from loader_semantics import analyze_object_records
from relocation import (
    FORMAT4_RELOCATION_HALF_BYTES,
    decode_object_addend,
    encode_relocated_value,
)


class LoaderError(Exception):
    pass


def _load_object(filepath):
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                records.append(line.strip('\n'))
    try:
        sections = analyze_object_records(records)
    except ValueError as exc:
        raise LoaderError(f"Invalid object program {filepath}: {exc}") from exc
    return records, sections


def parse_obj_file(filepath):
    """Read an object file after validating both framing and loader semantics."""
    records, _ = _load_object(filepath)
    return records


def _validate_progaddr(progaddr):
    try:
        validate_machine_address(progaddr, "PROGADDR")
    except ValueError as exc:
        raise LoaderError(str(exc)) from exc


def _validate_section_placement(csaddr, length, name):
    try:
        validate_machine_range(csaddr, length, f"Loaded control section {name}")
    except ValueError as exc:
        raise LoaderError(str(exc)) from exc


def pass1(obj_files, progaddr):
    _validate_progaddr(progaddr)
    estab = {}
    csaddr = progaddr

    for file in obj_files:
        _, sections = _load_object(file)
        for section in sections:
            csect_name = section['name']
            _validate_section_placement(csaddr, section['length'], csect_name)

            if csect_name in estab:
                raise LoaderError(f"Duplicate external symbol {csect_name}")
            estab[csect_name] = csaddr

            for sym_name, sym_offset in section['definitions']:
                if sym_name in estab:
                    raise LoaderError(f"Duplicate external symbol {sym_name}")
                estab[sym_name] = csaddr + sym_offset

            csaddr += section['length']

    return estab


def _check_memory_range(memory, start, length, description):
    if start < 0 or length < 0 or start + length > len(memory):
        raise LoaderError(f"{description} exceeds loader memory")


def _group_modifications(modifications):
    """Preserve first-seen field order while grouping repeated M terms."""
    groups = {}
    order = []
    for modification in modifications:
        key = (modification['offset'], modification['half_bytes'])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(modification)
    return [groups[key] for key in order]


def _apply_modification_group(memory, csaddr, section, group, estab):
    first = group[0]
    mod_addr = csaddr + first['offset']
    _check_memory_range(memory, mod_addr, 3, "Modification record")

    raw_value = (
        (memory[mod_addr] << 16)
        | (memory[mod_addr + 1] << 8)
        | memory[mod_addr + 2]
    )
    try:
        addend = decode_object_addend(raw_value, first['half_bytes'])
    except ValueError as exc:
        raise LoaderError(str(exc)) from exc

    delta = 0
    for modification in group:
        sym_name = modification['symbol']
        if sym_name not in estab:
            raise LoaderError(f"Undefined external symbol {sym_name}")
        sym_value = estab[sym_name]
        delta += sym_value if modification['sign'] == '+' else -sym_value

    relocated = addend + delta
    try:
        encoded = encode_relocated_value(relocated, first['half_bytes'])
    except ValueError as exc:
        raise LoaderError(
            f"{exc} in {section['name']} at {first['address']:06X} "
            f"(addend={addend}, delta={delta})"
        ) from exc

    if first['half_bytes'] == FORMAT4_RELOCATION_HALF_BYTES:
        encoded |= raw_value & 0xF00000

    memory[mod_addr] = (encoded >> 16) & 0xFF
    memory[mod_addr + 1] = (encoded >> 8) & 0xFF
    memory[mod_addr + 2] = encoded & 0xFF


def pass2(obj_files, progaddr, estab):
    _validate_progaddr(progaddr)
    csaddr = progaddr
    exec_addr = progaddr
    explicit_execution_seen = False
    memory = bytearray(SICXE_MEMORY_SIZE)

    for file in obj_files:
        _, sections = _load_object(file)
        for section in sections:
            current_cslth = section['length']
            _validate_section_placement(csaddr, current_cslth, section['name'])
            _check_memory_range(memory, csaddr, current_cslth, "Control section")

            for text in section['texts']:
                start_addr = csaddr + text['offset']
                _check_memory_range(memory, start_addr, text['length'], "Text record")
                memory[start_addr:start_addr + text['length']] = text['data']

            # Every repeated M record for the same field is one relocation
            # expression. Sum the exact signed symbol deltas first, validate the
            # final 20/24-bit result once, then write the field once. This avoids
            # record-order-dependent modular wraparound.
            for group in _group_modifications(section['modifications']):
                _apply_modification_group(memory, csaddr, section, group, estab)

            source_exec = section['execution_address']
            if source_exec is not None:
                if explicit_execution_seen:
                    raise LoaderError(
                        "Multiple explicit execution addresses across object inputs"
                    )
                explicit_execution_seen = True
                exec_addr = csaddr + (source_exec - section['start'])

            csaddr += current_cslth

    return memory, exec_addr


def print_estab(estab):
    print("\n" + "=" * 30)
    print("External Symbol Table (ESTAB)")
    print("-" * 30)
    print(f"{'Symbol Name':<15} {'Address':<10}")
    print("-" * 30)
    for sym, addr in estab.items():
        print(f"{sym:<15} {addr:05X}")
    print("=" * 30 + "\n")


def dump_memory(memory, start_addr, length):
    print("=" * 65)
    print(f"Memory Dump ({start_addr:05X} - {start_addr + length - 1:05X})")
    print("-" * 65)

    end_addr = min(start_addr + length, len(memory))
    dump_start = start_addr & ~0x0F
    dump_end = min((end_addr + 15) & ~0x0F, len(memory))

    for addr in range(dump_start, dump_end, 16):
        row = memory[addr:min(addr + 16, len(memory))]
        hex_data = " ".join(f"{byte:02X}" for byte in row).ljust(47)
        ascii_data = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
        print(f"{addr:05X}  {hex_data}  |{ascii_data}|")
    print("=" * 65 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python loader.py <obj_file1> [obj_file2 ...] [PROGADDR]")
        return 1

    args = sys.argv[1:]
    progaddr = 0x4000
    obj_files = []

    for arg in args:
        if os.path.exists(arg):
            obj_files.append(arg)
        else:
            try:
                progaddr = int(arg, 16)
            except ValueError:
                pass

    if not obj_files:
        print("Error: No valid object files provided.", file=sys.stderr)
        return 1

    try:
        print(f"Loading {len(obj_files)} object files starting at PROGADDR {progaddr:05X}...")
        estab = pass1(obj_files, progaddr)
        print_estab(estab)
        memory, exec_addr = pass2(obj_files, progaddr, estab)
        print(f"Load complete. Execution start address: {exec_addr:05X}\n")

        total_len = 0
        for file in obj_files:
            _, sections = _load_object(file)
            total_len += sum(section['length'] for section in sections)
        dump_memory(memory, progaddr, total_len)
        return 0
    except (LoaderError, OSError, ValueError) as exc:
        print(f"Load failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
