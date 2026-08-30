import os
import sys

from errors import AssemblyError
from macro import run_macro_processor
from object_format import canonicalize_object_file, validate_source_object_contracts
from pass1 import parse_line, run_pass1
from pass2 import run_pass2
from pass2_compat import prepare_pass2_inputs


def _remove_files(paths):
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("Usage: python assembler.py <source.asm>", file=sys.stderr)
        return 1

    asm_file = args[0]
    base_name = os.path.splitext(asm_file)[0]

    expanded_file = f"{base_name}.expanded.asm"
    int_file = f"{base_name}.int"
    sym_file = f"{base_name}.sym"
    obj_file = f"{base_name}.obj"
    lst_file = f"{base_name}.lst"
    generated_outputs = [expanded_file, int_file, sym_file, obj_file, lst_file]

    # Do not leave stale or partially generated output from a failed assembly.
    _remove_files(generated_outputs)

    try:
        print("Starting Macro Processor (Pass 0)...")
        run_macro_processor(asm_file, expanded_file)
        print(f"Macro Processor completed. Generated: {expanded_file}")

        print("Validating object-program contracts...")
        validate_source_object_contracts(expanded_file, parse_line)

        print("Starting Pass 1...")
        csects, start_addr = run_pass1(expanded_file, int_file, sym_file)
        print(f"Pass 1 completed. Found {len(csects)} CSECT(s).")

        print("Starting Pass 2...")
        pass2_int_file, pass2_csects, transient_file = prepare_pass2_inputs(
            int_file,
            csects,
            parse_line,
        )
        try:
            run_pass2(pass2_int_file, obj_file, lst_file, pass2_csects, start_addr)
        finally:
            if transient_file:
                _remove_files([transient_file])
        canonicalize_object_file(obj_file)
        print(
            f"Pass 2 completed. Outputs generated: "
            f"{int_file}, {sym_file}, {obj_file}, {lst_file}"
        )
        return 0
    except AssemblyError as exc:
        _remove_files(generated_outputs)
        print(f"Assembly failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        _remove_files(generated_outputs)
        print(f"Assembly failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
