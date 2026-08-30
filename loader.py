import os
import sys

from address_space import SICXE_MEMORY_SIZE
from load_plan import LoadPlanError, build_estab, build_load_plan
from loader_semantics import analyze_object_records


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
    """Read an object file after validating framing and section semantics."""
    records, _ = _load_object(filepath)
    return records


def _as_loader_error(callable_, *args):
    try:
        return callable_(*args)
    except LoadPlanError as exc:
        raise LoaderError(str(exc)) from exc


def pass1(obj_files, progaddr):
    """Traditional loader Pass 1: placement and ESTAB construction."""
    return _as_loader_error(build_estab, obj_files, progaddr)


def _estab_mismatch(expected, actual):
    keys = sorted(set(expected) | set(actual))
    for key in keys:
        if key not in actual:
            return f"missing {key}={expected[key]:05X}"
        if key not in expected:
            return f"unexpected {key}={actual[key]:05X}"
        if actual[key] != expected[key]:
            return (
                f"{key} expected {expected[key]:05X}, "
                f"received {actual[key]:05X}"
            )
    return "unknown mismatch"


def apply_load_plan(plan):
    """Materialize one fully validated plan into SIC/XE memory.

    All parsing, placement, symbol resolution, entry-point selection, and exact
    relocation arithmetic have already succeeded before this function allocates
    and mutates memory.
    """
    memory = bytearray(SICXE_MEMORY_SIZE)

    for section in plan.sections:
        for text in section.texts:
            start = section.load_address + text['offset']
            memory[start:start + text['length']] = text['data']

        for relocation in section.relocations:
            address = section.load_address + relocation.offset
            encoded = relocation.encoded
            memory[address] = (encoded >> 16) & 0xFF
            memory[address + 1] = (encoded >> 8) & 0xFF
            memory[address + 2] = encoded & 0xFF

    return memory, plan.execution_address


def pass2(obj_files, progaddr, estab):
    """Validate a complete load plan before performing any memory mutation."""
    plan = _as_loader_error(build_load_plan, obj_files, progaddr)
    if dict(estab) != plan.estab:
        raise LoaderError(
            "ESTAB does not match validated load plan: "
            + _estab_mismatch(plan.estab, dict(estab))
        )
    return apply_load_plan(plan)


def print_estab(estab):
    print("\n" + "=" * 30)
    print("External Symbol Table (ESTAB)")
    print("-" * 30)
    print(f"{'Symbol Name':<15} {'Address':<10}")
    print("-" * 30)
    for sym, addr in estab.items():
        print(f"{sym:<15} {addr:05X}")
    print("=" * 30 + "\n")


def print_load_map(plan):
    print("=" * 65)
    print("Validated Load Plan")
    print("-" * 65)
    for section in plan.sections:
        end = section.load_address + section.length
        print(
            f"[{section.input_index}:{section.section_index}] "
            f"{section.name:<6} {section.load_address:05X}-{end:05X} "
            f"len={section.length:05X}  {section.file_path}"
        )
        if section.unused_references:
            print(
                "    unused R declarations: "
                + ", ".join(section.unused_references)
            )
    if plan.execution_source is None:
        print(f"Entry: {plan.execution_address:05X} (default PROGADDR)")
    else:
        print(
            f"Entry: {plan.execution_address:05X} from "
            f"{plan.execution_source}"
        )
    print("=" * 65 + "\n")


def dump_memory(memory, start_addr, length):
    print("=" * 65)
    if length:
        print(f"Memory Dump ({start_addr:05X} - {start_addr + length - 1:05X})")
    else:
        print(f"Memory Dump ({start_addr:05X}, empty image)")
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
        print(f"Planning {len(obj_files)} object files at PROGADDR {progaddr:05X}...")
        plan = _as_loader_error(build_load_plan, obj_files, progaddr)
        print_load_map(plan)
        print_estab(plan.estab)

        memory, exec_addr = apply_load_plan(plan)
        print(f"Load complete. Execution start address: {exec_addr:05X}\n")
        dump_memory(memory, progaddr, plan.total_length)
        return 0
    except (LoaderError, OSError, ValueError) as exc:
        print(f"Load failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
