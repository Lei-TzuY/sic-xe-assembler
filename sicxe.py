import argparse
import json
import sys
from pathlib import Path

import assembler
import loader
from artifact_verifier import ArtifactVerificationError, verify_linked_artifacts
from disassembler import disassemble, render_disassembly
from inspector import (
    InspectionError,
    inspect_image_manifest,
    inspect_object_file,
    render_manifest_inspection,
    render_object_inspection,
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


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sicxe.py",
        description=(
            "SIC/XE assembler, reproducible linker, artifact verifier, inspector, "
            "and disassembler"
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    assemble = subcommands.add_parser("assemble", help="assemble one SIC/XE source file")
    assemble.add_argument("source", help="assembly source (.asm)")

    link = subcommands.add_parser("link", help="link object files and emit .map/.bin/manifest")
    link.add_argument("objects", nargs="+", help="object inputs in link order")
    link.add_argument(
        "--progaddr",
        type=_parse_hex_address,
        default=0x4000,
        metavar="HEX",
        help="load address in hexadecimal (default: 4000)",
    )

    verify = subcommands.add_parser(
        "verify",
        help="rebuild and verify linked image artifacts",
    )
    verify.add_argument("image", help="linked .bin image")
    verify.add_argument("manifest", help="linked .manifest.json")
    verify.add_argument("objects", nargs="+", help="original object inputs in link order")

    inspect = subcommands.add_parser(
        "inspect",
        help="inspect a validated .obj or linked .manifest.json artifact",
    )
    inspect.add_argument("artifact", help="object file or linked-image manifest")
    inspect.add_argument(
        "--image",
        help="linked .bin image to compare with a manifest (auto-detected when adjacent)",
    )
    inspect.add_argument(
        "--disassemble",
        action="store_true",
        help="linear-sweep T-record bytes when inspecting an object program",
    )
    inspect.add_argument(
        "--base",
        type=_parse_hex_address,
        metavar="HEX",
        help="optional B-register value for base-relative disassembly",
    )
    inspect.add_argument(
        "--json",
        action="store_true",
        help="emit the structured inspection result as JSON",
    )

    disasm = subcommands.add_parser(
        "disasm",
        help="linear-sweep a raw linked image as SIC/XE instructions",
    )
    disasm.add_argument("image", help="raw linked .bin image")
    disasm.add_argument(
        "--start",
        type=_parse_hex_address,
        metavar="HEX",
        help="address corresponding to the first byte (default: 0 unless --manifest is used)",
    )
    disasm.add_argument(
        "--manifest",
        help="linked-image manifest from which to derive/validate the image start",
    )
    disasm.add_argument(
        "--base",
        type=_parse_hex_address,
        metavar="HEX",
        help="optional B-register value for base-relative target resolution",
    )
    disasm.add_argument(
        "--offset",
        type=_parse_nonnegative_int,
        default=0,
        metavar="N",
        help="byte offset into the image (default: 0)",
    )
    disasm.add_argument(
        "--length",
        type=_parse_nonnegative_int,
        metavar="N",
        help="maximum number of image bytes to decode",
    )
    disasm.add_argument(
        "--max-instructions",
        type=_parse_nonnegative_int,
        metavar="N",
        help="stop after at most N decoded records",
    )

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


def _run_inspect(args):
    artifact = str(args.artifact)
    try:
        if artifact.endswith(".obj"):
            report = inspect_object_file(
                artifact,
                include_disassembly=args.disassemble,
                base_register=args.base,
            )
            output = (
                json.dumps(report, indent=2, sort_keys=True) + "\n"
                if args.json
                else render_object_inspection(report)
            )
        elif artifact.endswith(".manifest.json"):
            if args.disassemble:
                raise InspectionError(
                    "--disassemble applies to object inspection; use `sicxe.py disasm` for .bin images"
                )
            image = args.image or _default_image_for_manifest(artifact)
            report = inspect_image_manifest(artifact, image_path=image)
            output = (
                json.dumps(report, indent=2, sort_keys=True) + "\n"
                if args.json
                else render_manifest_inspection(report)
            )
        else:
            raise InspectionError(
                "inspect expects a .obj or .manifest.json artifact"
            )
    except InspectionError as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 1

    print(output, end="")
    return 0


def _manifest_image_start(path):
    try:
        report = inspect_image_manifest(path)
    except InspectionError as exc:
        raise ValueError(str(exc)) from exc
    return report["image_start"]


def _run_disasm(args):
    try:
        image = Path(args.image).read_bytes()
    except OSError as exc:
        print(f"Disassembly failed: {exc}", file=sys.stderr)
        return 1

    start = args.start
    if args.manifest:
        try:
            manifest_start = _manifest_image_start(args.manifest)
        except ValueError as exc:
            print(f"Disassembly failed: {exc}", file=sys.stderr)
            return 1
        if start is not None and start != manifest_start:
            print(
                f"Disassembly failed: --start {start:05X} does not match "
                f"manifest image_start {manifest_start:05X}",
                file=sys.stderr,
            )
            return 1
        start = manifest_start
    if start is None:
        start = 0

    offset = args.offset
    if offset > len(image):
        print(
            f"Disassembly failed: offset {offset} exceeds image length {len(image)}",
            file=sys.stderr,
        )
        return 1
    end = len(image) if args.length is None else min(len(image), offset + args.length)
    payload = image[offset:end]
    records = disassemble(
        payload,
        start_address=start + offset,
        base_register=args.base,
        max_instructions=args.max_instructions,
    )
    print(render_disassembly(records), end="")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else list(argv))

    if args.command == "assemble":
        return assembler.main([args.source])
    if args.command == "link":
        legacy_args = list(args.objects) + [f"{args.progaddr:X}"]
        return loader.main(legacy_args)
    if args.command == "verify":
        return _run_verify(args)
    if args.command == "inspect":
        return _run_inspect(args)
    if args.command == "disasm":
        return _run_disasm(args)

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
