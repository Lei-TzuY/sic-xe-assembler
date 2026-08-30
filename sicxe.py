import argparse
import sys

import assembler
import loader
from artifact_verifier import ArtifactVerificationError, verify_linked_artifacts


def _parse_hex_address(value):
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid hexadecimal address: {value}") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("address must be non-negative")
    return parsed


def build_parser():
    parser = argparse.ArgumentParser(
        prog="sicxe.py",
        description="SIC/XE assembler, linking loader, and reproducibility verifier",
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

    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
