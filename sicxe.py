import argparse
import hashlib
import json
import sys
from pathlib import Path

import assembler
import loader
from artifact_verifier import ArtifactVerificationError, verify_linked_artifacts
from control_flow import (
    ControlFlowError,
    analyze_control_flow,
    annotate_typed_disassembly,
    render_control_flow_dot,
    render_control_flow_report,
)
from disassembler import disassemble, render_disassembly
from emulator import (
    BufferedDevice,
    DeviceBus,
    SicXeMachine,
    render_result,
    resolve_breakpoint,
    result_to_dict,
)
from inspector import (
    InspectionError,
    inspect_image_manifest,
    inspect_object_file,
    render_manifest_inspection,
    render_object_inspection,
)
from source_map import (
    SourceMapError,
    load_linked_debug_map,
    load_source_map,
    render_linked_debug_inspection,
    render_source_map_inspection,
    render_typed_disassembly,
)


def _parse_hex_address(value):
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hexadecimal address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("address must be non-negative")
    return parsed


def _parse_nonnegative_int(value):
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid decimal integer: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def _parse_register_assignment(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("register assignment must use REG=HEX")
    name, raw_value = value.split("=", 1)
    name = name.strip().upper()
    if name not in {"A", "X", "L", "B", "S", "T", "F", "PC", "SW"}:
        raise argparse.ArgumentTypeError(f"unknown register: {name}")
    try:
        parsed = int(raw_value.strip(), 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hexadecimal register value: {raw_value}") from exc
    return name, parsed


def _parse_device_id(value):
    try:
        device_id = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hexadecimal device id: {value}") from exc
    if not 0 <= device_id <= 0xFF:
        raise argparse.ArgumentTypeError("device id must be between 00 and FF")
    return device_id


def _parse_device_input(value):
    if "=" not in value:
        raise argparse.ArgumentTypeError("device input must use ID=HEXBYTES")
    raw_id, raw_data = value.split("=", 1)
    device_id = _parse_device_id(raw_id.strip())
    data_text = raw_data.strip()
    if len(data_text) % 2:
        raise argparse.ArgumentTypeError("device HEXBYTES must contain an even number of digits")
    try:
        data = bytes.fromhex(data_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid device HEXBYTES: {raw_data}") from exc
    return device_id, data


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sicxe.py",
        description=(
            "SIC/XE assembler, reproducible linker, artifact verifier, inspector, "
            "source-aware disassembler, control-flow analyzer, and integer emulator"
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    assemble = subcommands.add_parser("assemble", help="assemble one SIC/XE source file")
    assemble.add_argument("source", help="assembly source (.asm)")

    link = subcommands.add_parser("link", help="link object files and emit .map/.bin/manifest/debug")
    link.add_argument("objects", nargs="+", help="object inputs in link order")
    link.add_argument(
        "--progaddr", type=_parse_hex_address, default=0x4000, metavar="HEX",
        help="load address in hexadecimal (default: 4000)",
    )

    verify = subcommands.add_parser("verify", help="rebuild and verify linked image artifacts")
    verify.add_argument("image", help="linked .bin image")
    verify.add_argument("manifest", help="linked .manifest.json")
    verify.add_argument("objects", nargs="+", help="original object inputs in link order")

    inspect = subcommands.add_parser(
        "inspect", help="inspect .obj, .manifest.json, .sourcemap.json, or .debug.json artifacts"
    )
    inspect.add_argument("artifact", help="artifact to inspect")
    inspect.add_argument("--image", help="linked .bin image to compare with a manifest (auto-detected when adjacent)")
    inspect.add_argument("--disassemble", action="store_true", help="linear-sweep T-record bytes when inspecting an object program")
    inspect.add_argument("--base", type=_parse_hex_address, metavar="HEX", help="optional B-register value for base-relative object disassembly")
    inspect.add_argument("--json", action="store_true", help="emit the structured inspection result as JSON")

    disasm = subcommands.add_parser("disasm", help="decode a linked image, using typed source metadata when available")
    disasm.add_argument("image", help="raw linked .bin image")
    disasm.add_argument("--start", type=_parse_hex_address, metavar="HEX", help="address corresponding to the first byte (default: 0 unless metadata is used)")
    disasm.add_argument("--manifest", help="linked-image manifest from which to derive/validate image start and CFG entry")
    disasm.add_argument("--debug", help="linked .debug.json source map (auto-detected beside the image when present)")
    disasm.add_argument("--linear", action="store_true", help="ignore typed debug metadata and force the historical linear sweep")
    disasm.add_argument("--cfg", action="store_true", help="annotate reachability/basic blocks and append a CFG report (requires manifest + debug metadata)")
    disasm.add_argument("--base", type=_parse_hex_address, metavar="HEX", help="optional B-register value for base-relative target resolution")
    disasm.add_argument("--offset", type=_parse_nonnegative_int, default=0, metavar="N", help="byte offset into the image (default: 0)")
    disasm.add_argument("--length", type=_parse_nonnegative_int, metavar="N", help="maximum number of image bytes to decode")
    disasm.add_argument("--max-instructions", type=_parse_nonnegative_int, metavar="N", help="stop after at most N decoded instruction records")

    cfg = subcommands.add_parser("cfg", help="build basic blocks and control-flow edges from typed linked debug metadata")
    cfg.add_argument("image", help="raw linked .bin image")
    cfg.add_argument("--manifest", required=True, help="linked-image manifest supplying LINKID, image origin, and execution entry")
    cfg.add_argument("--debug", help="linked .debug.json source map (auto-detected beside the image when present)")
    cfg.add_argument("--base", type=_parse_hex_address, metavar="HEX", help="optional B-register value for base-relative target resolution")
    cfg_output = cfg.add_mutually_exclusive_group()
    cfg_output.add_argument("--json", action="store_true", help="emit structured CFG JSON")
    cfg_output.add_argument("--dot", action="store_true", help="emit Graphviz DOT")

    run = subcommands.add_parser(
        "run",
        help="execute a linked image with deterministic integer/core SIC/XE semantics",
    )
    run.add_argument("image", help="linked .bin image")
    run.add_argument(
        "--manifest", required=True,
        help="linked-image manifest supplying image origin, SHA, LINKID, and execution entry",
    )
    run.add_argument("--debug", help="linked .debug.json source map (auto-detected beside the image when present)")
    run.add_argument("--max-steps", type=_parse_nonnegative_int, default=100000, metavar="N", help="maximum executed instructions before step-limit stop (default: 100000)")
    run.add_argument("--breakpoint", action="append", default=[], metavar="HEX_OR_SYMBOL", help="stop before executing this address/symbol; repeatable")
    run.add_argument("--set", dest="registers", type=_parse_register_assignment, action="append", default=[], metavar="REG=HEX", help="set initial register value after loading; repeatable")
    run.add_argument("--device-input", type=_parse_device_input, action="append", default=[], metavar="ID=HEXBYTES", help="attach/read input bytes for an 8-bit device id; repeatable")
    run.add_argument("--device-output", type=_parse_device_id, action="append", default=[], metavar="ID", help="attach a writable output device; repeatable")
    run.add_argument("--trace", action="store_true", help="include each successfully executed instruction with register/memory/source diffs")
    run.add_argument("--json", action="store_true", help="emit structured execution result JSON")
    run.add_argument("--no-return-halt", action="store_true", help="execute RSUB with L=0 literally instead of treating it as a host return stop")

    return parser


def _run_verify(args):
    try:
        result = verify_linked_artifacts(args.image, args.manifest, args.objects)
    except ArtifactVerificationError as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1
    print("Linked artifacts verified reproducible.")
    print(f"Image SHA-256: {result.image_sha256}")
    print(f"INPUTSET:       {result.input_fingerprint}")
    print(f"LINKID:         {result.link_fingerprint}")
    print(f"PROGADDR:       {result.progaddr:05X}")
    print(f"ENTRY:          {result.entry_address:05X}")
    return 0


def _default_image_for_manifest(path):
    text = str(path)
    suffix = ".manifest.json"
    if not text.endswith(suffix):
        return None
    candidate = Path(text[:-len(suffix)] + ".bin")
    return str(candidate) if candidate.exists() else None


def _adjacent_object_for_source_map(path):
    text = str(path)
    suffix = ".sourcemap.json"
    if not text.endswith(suffix):
        return None
    candidate = Path(text[:-len(suffix)] + ".obj")
    return candidate if candidate.exists() else None


def _run_inspect(args):
    artifact = str(args.artifact)
    try:
        if artifact.endswith(".obj"):
            report = inspect_object_file(artifact, include_disassembly=args.disassemble, base_register=args.base)
            output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_object_inspection(report)
        elif artifact.endswith(".manifest.json"):
            if args.disassemble:
                raise InspectionError("--disassemble applies to object inspection; use `sicxe.py disasm` for .bin images")
            image = args.image or _default_image_for_manifest(artifact)
            report = inspect_image_manifest(artifact, image_path=image)
            output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_manifest_inspection(report)
        elif artifact.endswith(".sourcemap.json"):
            if args.disassemble or args.image or args.base is not None:
                raise InspectionError("source-map inspection does not use --image/--base/--disassemble")
            adjacent = _adjacent_object_for_source_map(artifact)
            object_sha = hashlib.sha256(adjacent.read_bytes()).hexdigest() if adjacent else None
            report, _ = load_source_map(artifact, object_sha256=object_sha)
            output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_source_map_inspection(report)
        elif artifact.endswith(".debug.json"):
            if args.disassemble or args.image or args.base is not None:
                raise InspectionError("linked-debug inspection does not use --image/--base/--disassemble")
            report, _ = load_linked_debug_map(artifact)
            output = json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else render_linked_debug_inspection(report)
        else:
            raise InspectionError("inspect expects .obj, .manifest.json, .sourcemap.json, or .debug.json")
    except (InspectionError, SourceMapError, OSError) as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 1
    print(output, end="")
    return 0


def _manifest_report(path):
    try:
        return inspect_image_manifest(path)
    except InspectionError as exc:
        raise ValueError(str(exc)) from exc


def _default_debug_for_image(image_path):
    candidate = Path(image_path).with_suffix(".debug.json")
    return str(candidate) if candidate.exists() else None


def _load_debug_map(debug_path, manifest_report=None):
    try:
        return load_linked_debug_map(
            debug_path,
            link_fingerprint=(manifest_report["link_fingerprint"] if manifest_report is not None else None),
        )[0]
    except SourceMapError as exc:
        raise ValueError(str(exc)) from exc


def _entry_address(manifest_report):
    entry = manifest_report.get("entry") or {}
    address = entry.get("address")
    if not isinstance(address, int):
        raise ValueError("Manifest does not contain a valid execution entry address")
    return address


def _run_disasm(args):
    try:
        image = Path(args.image).read_bytes()
    except OSError as exc:
        print(f"Disassembly failed: {exc}", file=sys.stderr)
        return 1
    if args.linear and args.cfg:
        print("Disassembly failed: --cfg cannot be combined with --linear", file=sys.stderr)
        return 1
    start = args.start
    manifest_report = None
    if args.manifest:
        try:
            manifest_report = _manifest_report(args.manifest)
        except ValueError as exc:
            print(f"Disassembly failed: {exc}", file=sys.stderr)
            return 1
        manifest_start = manifest_report["image_start"]
        if start is not None and start != manifest_start:
            print(f"Disassembly failed: --start {start:05X} does not match manifest image_start {manifest_start:05X}", file=sys.stderr)
            return 1
        start = manifest_start
    debug_path = None if args.linear else (args.debug or _default_debug_for_image(args.image))
    debug_map = None
    if debug_path:
        try:
            debug_map = _load_debug_map(debug_path, manifest_report=manifest_report)
        except ValueError as exc:
            print(f"Disassembly failed: {exc}", file=sys.stderr)
            return 1
        debug_start = debug_map["progaddr"]
        if start is not None and start != debug_start:
            print(f"Disassembly failed: image start {start:05X} does not match debug PROGADDR {debug_start:05X}", file=sys.stderr)
            return 1
        start = debug_start
    if args.cfg and manifest_report is None:
        print("Disassembly failed: --cfg requires --manifest to establish the execution entry", file=sys.stderr)
        return 1
    if args.cfg and debug_map is None:
        print("Disassembly failed: --cfg requires linked debug metadata", file=sys.stderr)
        return 1
    if start is None:
        start = 0
    offset = args.offset
    if offset > len(image):
        print(f"Disassembly failed: offset {offset} exceeds image length {len(image)}", file=sys.stderr)
        return 1
    if debug_map is not None:
        try:
            output = render_typed_disassembly(
                image, start, debug_map, base_register=args.base, offset=offset,
                length=args.length, max_instructions=args.max_instructions,
            )
            cfg_report = None
            if args.cfg:
                cfg_report = analyze_control_flow(
                    image, start, debug_map, _entry_address(manifest_report), base_register=args.base,
                )
            output = annotate_typed_disassembly(output, debug_map, control_flow=cfg_report)
        except (SourceMapError, ControlFlowError, ValueError) as exc:
            print(f"Disassembly failed: {exc}", file=sys.stderr)
            return 1
        print(output, end="")
        if cfg_report is not None:
            print("\n" + render_control_flow_report(cfg_report), end="")
        return 0
    end = len(image) if args.length is None else min(len(image), offset + args.length)
    payload = image[offset:end]
    records = disassemble(payload, start_address=start + offset, base_register=args.base, max_instructions=args.max_instructions)
    print(render_disassembly(records), end="")
    return 0


def _run_cfg(args):
    try:
        image = Path(args.image).read_bytes()
        manifest_report = _manifest_report(args.manifest)
        debug_path = args.debug or _default_debug_for_image(args.image)
        if debug_path is None:
            raise ValueError("CFG analysis requires linked .debug.json metadata")
        debug_map = _load_debug_map(debug_path, manifest_report=manifest_report)
        if debug_map["progaddr"] != manifest_report["image_start"]:
            raise ValueError("Debug PROGADDR does not match manifest image_start")
        report = analyze_control_flow(
            image, manifest_report["image_start"], debug_map,
            _entry_address(manifest_report), base_register=args.base,
        )
    except (OSError, ValueError, ControlFlowError) as exc:
        print(f"CFG analysis failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.dot:
        print(render_control_flow_dot(report), end="")
    else:
        print(render_control_flow_report(report), end="")
    return 0


def _build_device_bus(args):
    bus = DeviceBus()
    for device_id in args.device_output:
        device = bus.get(device_id)
        if device is None:
            bus.attach(device_id, BufferedDevice(readable=False, writable=True))
        else:
            device.writable = True
    for device_id, data in args.device_input:
        device = bus.get(device_id)
        if device is None:
            bus.attach(device_id, BufferedDevice(input_bytes=data, readable=True, writable=False))
        else:
            device.input.extend(data)
            device.readable = True
    return bus


def _run_emulator(args):
    try:
        image = Path(args.image).read_bytes()
        manifest_report = inspect_image_manifest(args.manifest, image_path=args.image)
        image_check = manifest_report.get("image")
        if not image_check or not image_check["length_matches"] or not image_check["sha256_matches"]:
            raise ValueError("linked image does not match manifest length/SHA-256")
        debug_path = args.debug or _default_debug_for_image(args.image)
        debug_map = _load_debug_map(debug_path, manifest_report=manifest_report) if debug_path else None
        if debug_map is not None and debug_map["progaddr"] != manifest_report["image_start"]:
            raise ValueError("Debug PROGADDR does not match manifest image_start")
        machine = SicXeMachine.from_image(
            image,
            manifest_report["image_start"],
            _entry_address(manifest_report),
            debug_map=debug_map,
            devices=_build_device_bus(args),
            stop_on_zero_return=not args.no_return_halt,
        )
        for register, value in args.registers:
            machine.set_register(register, value)
        breakpoints = [resolve_breakpoint(token, debug_map) for token in args.breakpoint]
        result = machine.run(max_steps=args.max_steps, breakpoints=breakpoints, trace=args.trace)
    except (OSError, ValueError) as exc:
        print(f"Execution failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result_to_dict(result), indent=2, sort_keys=True))
    else:
        print(render_result(result, include_trace=args.trace), end="")
    return 1 if result.stop_reason in {"trap", "step-limit"} else 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))
    if args.command == "assemble":
        return assembler.main([args.source])
    if args.command == "link":
        return loader.main(list(args.objects) + [f"{args.progaddr:X}"])
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "inspect":
        return _run_inspect(args)
    if args.command == "disasm":
        return _run_disasm(args)
    if args.command == "cfg":
        return _run_cfg(args)
    if args.command == "run":
        return _run_emulator(args)
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
