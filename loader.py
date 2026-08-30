import os
import sys
from pathlib import Path

from address_space import SICXE_MEMORY_SIZE
from link_map import default_map_path, write_link_map
from linked_image import (
    default_image_path,
    default_manifest_path,
    write_linked_image_artifacts,
)
from load_plan import (
    LoadPlanError,
    build_estab,
    build_load_plan,
    capture_link_session,
)
from loader_semantics import analyze_object_records


class LoaderError(Exception):
    pass


class SessionEstab(dict):
    """ESTAB compatible with dict, plus the immutable Pass-1 input session."""

    def __init__(self, values, link_session):
        super().__init__(values)
        self.link_session = link_session


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
    """Traditional Pass 1, with an immutable input snapshot bound to ESTAB."""
    session = _as_loader_error(capture_link_session, obj_files)
    estab = _as_loader_error(build_estab, session, progaddr)
    return SessionEstab(estab, session)


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


def _session_input_mismatch(session, obj_files):
    expected = tuple(snapshot.canonical_path for snapshot in session.inputs)
    actual = tuple(str(Path(filepath).resolve()) for filepath in obj_files)
    if expected == actual:
        return None
    return (
        "object input list does not match Pass-1 snapshot: "
        f"expected {expected}, received {actual}"
    )


def apply_load_plan(plan):
    """Materialize one fully validated plan into SIC/XE memory.

    All parsing, placement, symbol resolution, entry-point selection, exact
    relocation arithmetic, and input capture have already succeeded before
    this function allocates and mutates memory.
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
    """Plan and load from the exact Pass-1 snapshot when one is available."""
    if isinstance(estab, SessionEstab):
        mismatch = _session_input_mismatch(estab.link_session, obj_files)
        if mismatch is not None:
            raise LoaderError(mismatch)
        session = estab.link_session
    else:
        # Compatibility path for callers that intentionally pass a plain dict.
        # Such callers have discarded the Pass-1 snapshot, so capture the
        # current files once and still perform the complete load-plan preflight.
        session = _as_loader_error(capture_link_session, obj_files)

    plan = _as_loader_error(build_load_plan, session, progaddr)
    if dict(estab) != dict(plan.estab):
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
    print(f"Input fingerprint: {plan.input_fingerprint}")
    print(f"Link fingerprint:  {plan.link_fingerprint}")
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


def _remove_stale_artifacts(paths):
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


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

    map_path = default_map_path(obj_files)
    image_path = default_image_path(obj_files)
    manifest_path = default_manifest_path(obj_files)
    artifact_paths = (map_path, image_path, manifest_path)
    _remove_stale_artifacts(artifact_paths)

    try:
        print(f"Capturing {len(obj_files)} object files for reproducible link...")
        session = _as_loader_error(capture_link_session, obj_files)
        print(f"Planning at PROGADDR {progaddr:05X}...")
        plan = _as_loader_error(build_load_plan, session, progaddr)

        # Materialize first. Persistent artifacts are emitted only after the
        # complete validated plan has produced the exact final image bytes.
        memory, exec_addr = apply_load_plan(plan)
        written_image, written_manifest = write_linked_image_artifacts(
            plan,
            memory,
            image_path,
            manifest_path,
        )
        write_link_map(plan, map_path)

        print(f"Linked image written: {written_image}")
        print(f"Image manifest written: {written_manifest}")
        print(f"Link map written: {map_path}")
        print_load_map(plan)
        print_estab(plan.estab)
        print(f"Load complete. Execution start address: {exec_addr:05X}\n")
        dump_memory(memory, progaddr, plan.total_length)
        return 0
    except (LoaderError, OSError, ValueError) as exc:
        _remove_stale_artifacts(artifact_paths)
        print(f"Load failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
