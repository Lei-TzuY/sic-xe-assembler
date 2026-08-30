# Reproducible linked-image artifacts

A successful loader CLI invocation emits the final linked bytes as a deterministic binary image plus a path-independent JSON manifest. These artifacts prove the output side of the reproducible-link contract: the same ordered object bytes at the same `PROGADDR` must produce the same `.bin` and `.manifest.json` byte-for-byte.

## Files

For:

```powershell
python loader.py program.obj 4000
```

the loader writes:

- `program.bin` — the exact final bytes in `[PROGADDR, PROGADDR + total_length)`;
- `program.manifest.json` — deterministic metadata and the SHA-256 of `program.bin`;
- `program.map` — the human-readable link map and cross-reference report.

With multiple object inputs, the first input owns the output stem because one invocation produces one linked image.

## Binary image range

The binary is not a 1 MiB memory dump. It contains exactly the contiguous linked-image range from `PROGADDR` through the end-exclusive sum of all control-section lengths. Its byte length is therefore exactly `LoadPlan.total_length`.

Text bytes are copied from validated T records and relocation fields contain their final precomputed values. Bytes inside the linked range that were reserved but never initialized by a T record remain the loader's deterministic initial value `0x00`. A zero-length linked image is represented by an empty `.bin` file.

## Manifest

The JSON manifest uses the schema identifier `sicxe-linked-image-v1` and records:

- `PROGADDR`, image start/end-exclusive range, and byte length;
- SHA-256 of the exact `.bin` bytes;
- the ordered path-independent `input_fingerprint` (`INPUTSET`);
- the `PROGADDR`-sensitive `link_fingerprint` (`LINKID`);
- entry-point provenance without host paths;
- each input's ordered index, raw byte length, and SHA-256;
- each control section's input/section indices, name, source origin, final load address, and length.

Host file paths and canonical paths are deliberately excluded. Copying identical object bytes to another directory therefore does not change either the binary image or the manifest. Input bytes, input order, or `PROGADDR` changes do change the reproducibility identity; relocation may also change the final image bytes.

The manifest is rendered as stable UTF-8 JSON with sorted keys and a trailing newline, making it suitable for byte-for-byte regression tests and source-control diffs.

## Output integrity

The CLI captures immutable object snapshots, builds and validates the complete load plan, and materializes memory before emitting persistent artifacts. `.bin` and `.manifest.json` are each written through temporary sibling files followed by atomic replacement. The `.map` writer follows the same pattern.

Before a link starts, stale `.map`, `.bin`, and `.manifest.json` files for that output stem are removed. If planning, materialization, or artifact generation fails, all three final artifacts are removed so a previous successful output cannot be mistaken for the current run.

`linked_image.extract_linked_image(plan, memory)` returns the exact binary slice.

`linked_image.build_image_manifest(plan, image_bytes)` returns the path-independent manifest data.

`linked_image.render_image_manifest(plan, image_bytes)` returns its deterministic JSON representation.

`linked_image.write_linked_image_artifacts(...)` writes the binary and manifest atomically per file.
