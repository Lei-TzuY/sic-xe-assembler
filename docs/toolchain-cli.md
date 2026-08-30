# Unified toolchain CLI and verification

The historical entry points remain supported:

```text
python assembler.py program.asm
python loader.py program.obj 4000
python verify_link.py program.bin program.manifest.json program.obj
```

For normal use, `sicxe.py` exposes the complete workflow through one command surface.

## Assemble

```text
python sicxe.py assemble program.asm
```

Assembly keeps the existing fail-closed output policy: stale generated files are removed before work begins and partial outputs are removed if macro expansion, Pass 1, Pass 2, object canonicalization, address-space checks, overlap checks, or generated-object semantic validation fails.

## Link

```text
python sicxe.py link program.obj --progaddr 4000
python sicxe.py link main.obj io.obj math.obj --progaddr 8000
```

`--progaddr` is hexadecimal. The default remains `4000` for compatibility with the standalone loader.

One successful link emits three persistent artifacts beside the first object input:

- `.map` — human-readable section layout, ESTAB, cross-references, relocation arithmetic, provenance, INPUTSET, and LINKID;
- `.bin` — exact contiguous linked image for `[PROGADDR, PROGADDR + total_length)` after relocation;
- `.manifest.json` — canonical, path-independent output attestation containing the image SHA-256, ordered object hashes, section layout, entry point, INPUTSET, and LINKID.

The legacy `loader.py` parser is now strict. Unknown/unreadable object arguments and multiple positional PROGADDR values are usage errors instead of being silently ignored or overwritten.

## Verify

```text
python sicxe.py verify program.bin program.manifest.json program.obj
python verify_link.py program.bin program.manifest.json program.obj
```

Verification does not trust a previous `.map` or an earlier in-memory load plan. It independently:

1. reads the binary and canonical JSON manifest;
2. verifies the manifest schema and binary SHA-256;
3. captures the supplied object files again as an immutable link session;
4. recomputes INPUTSET and LINKID using the manifest PROGADDR;
5. rebuilds the complete load plan and ESTAB;
6. re-executes relocation and materializes fresh SIC/XE memory;
7. compares the reproduced linked range byte-for-byte with the supplied `.bin`;
8. reconstructs the expected manifest and requires semantic equality;
9. requires the persisted JSON bytes to equal the canonical deterministic serialization.

This detects binary tampering, substituted/reordered object inputs, changed PROGADDR/link identity, modified manifest metadata, and noncanonical manifest serialization.

## Inspect

```text
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.obj --json
python sicxe.py inspect program.manifest.json
```

Object inspection runs the same structural/semantic object analyzer as the loader before displaying CSECT, D/R/T/M/E, raw SHA-256, text bytes, relocation sites, and entry data. `--disassemble` linear-sweeps T-record payloads and attaches overlapping M records to decoded instructions/data fields.

Manifest inspection shows PROGADDR, image range/SHA, INPUTSET, LINKID, input identities, section placement, and entry provenance. If the adjacent `.bin` exists it is auto-detected and its current length/SHA are compared against the manifest. Use `--image` to select a different binary explicitly.

`--json` exposes object/manifest inspection as machine-readable structured output.

Inspection explains persisted state; it intentionally does not replace `verify`, which independently re-links the supplied object inputs.

## Disassemble

```text
python sicxe.py disasm program.bin --start 4000
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --manifest program.manifest.json --base 8000
python sicxe.py disasm program.bin --manifest program.manifest.json --offset 32 --length 64
```

The disassembler decodes SIC/XE formats 1–4, format-2 operand signatures, `nixbpe`, addressing prefixes, PC-relative targets, optional base-relative targets, indexed addressing, and format-4 20-bit targets. Unknown/truncated bytes fall back to one-byte `.BYTE` records so linear sweep remains deterministic.

When a manifest is supplied, its `image_start` becomes the disassembly origin. Supplying a conflicting `--start` is a hard error.

Flat SIC/XE images do not carry a general code/data map, so disassembly is deliberately described as linear sweep rather than source reconstruction. Valid data bytes can resemble valid instructions. See [`inspection-disassembly.md`](inspection-disassembly.md) for the exact contract and limitations.

## Expression language

Assembler expressions use a real precedence parser rather than additive string splitting.

Supported operators, from highest to lowest precedence:

1. parentheses: `( ... )`
2. unary `+` and `-`
3. binary `*` and `/`
4. binary `+` and `-`

`*` remains the current location when it appears where a primary expression is expected; between two operands it is multiplication. Division is integer division truncated toward zero.

Examples:

```asm
LEN      EQU     (BUFEND-BUFFER) * 4
OFFSET   EQU     -(A-B) + 20
VALUE    WORD    (LEN + 2) * 3
MIX      WORD    EXT1 - (EXT2 - 12)
```

Relocation algebra remains strict. Multiplication and division require both operands to be absolute. Expressions such as `BUFFER*2`, `EXT1/4`, or `(EXT1-EXT2)*2` are rejected because SIC/XE object modification records do not encode general scaled relocation terms. Parentheses and unary signs may freely rearrange additive local/external relocation terms.

## Exit status

The command-line convention is:

- `0` — operation completed successfully;
- `1` — source/object/artifact validation or execution failed;
- `2` — command-line usage error.

This makes the tools straightforward to use from CI scripts and larger build systems.
