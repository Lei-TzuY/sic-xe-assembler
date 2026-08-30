import sys

from artifact_verifier import ArtifactVerificationError, verify_linked_artifacts


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if len(args) < 3:
        print(
            "Usage: python verify_link.py <image.bin> <manifest.json> <obj_file1> [obj_file2 ...]",
            file=sys.stderr,
        )
        return 2

    image_path, manifest_path, *obj_files = args
    try:
        result = verify_linked_artifacts(image_path, manifest_path, obj_files)
    except ArtifactVerificationError as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1

    print("Linked artifacts verified reproducible.")
    print(f"Image SHA-256: {result.image_sha256}")
    print(f"INPUTSET:       {result.input_fingerprint}")
    print(f"LINKID:         {result.link_fingerprint}")
    print(f"PROGADDR:       {result.progaddr:05X}")
    print(f"ENTRY:          {result.entry_address:05X}")
    print(f"IMAGE LENGTH:   {result.image_length}")
    print(f"INPUTS:         {result.input_count}")
    print(f"SECTIONS:       {result.section_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
