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

Assembly keeps the fail-closed output policy: stale generated files are removed before work begins and partial outputs are removed if macro expansion, Pass 1, Pass 2, object canonicalization, address-space checks, overlap checks, generated-object semantic validation, provenance generation, or source-map generation fails.

Alongside `.expanded.asm/.int/.sym/.obj/.lst`, successful assembly emits:

- `program.expanded.provenance.json` — path-independent original-source/macro expansion ancestry for every physical expanded line;
- `program.sourcemap.json` — object-SHA-bound typed regions, symbols, expanded-source lines, and original-source/macro provenance.

## Link

```text
python sicxe.py link program.obj --progaddr 4000
python sicxe.py link main.obj io.obj math.obj --progaddr 8000
```

`--progaddr` is hexadecimal. The default remains `4000` for compatibility with the standalone loader.

One successful link emits four persistent artifacts beside the first object input:

- `.map` — human-readable section layout, ESTAB, cross-references, relocation arithmetic, provenance, INPUTSET, and LINKID;
- `.bin` — exact contiguous linked image for `[PROGADDR, PROGADDR + total_length)` after relocation;
- `.manifest.json` — canonical, path-independent output attestation containing image SHA-256, ordered object hashes, section layout, entry point, INPUTSET, and LINKID;
- `.debug.json` — LINKID-bound, path-independent linked source/debug metadata with rebased typed regions, loaded symbols, original-source/macro ancestry, and separate DEBUGID.

For each object input, the linker auto-detects an adjacent `.sourcemap.json`. Missing source maps are legal and produce an untyped section. Present source maps are trusted only after self-fingerprint, object-SHA, and section-layout validation; a stale sidecar fails the link instead of silently attaching incorrect provenance.

The legacy `loader.py` parser remains strict. Unknown/unreadable object arguments and multiple positional PROGADDR values are usage errors instead of being silently ignored or overwritten.

## Verify

```text
python sicxe.py verify program.bin program.manifest.json program.obj
python verify_link.py program.bin program.manifest.json program.obj
```

Verification does not trust a previous `.map`, `.debug.json`, or earlier in-memory load plan. It independently:

1. reads the binary and canonical JSON manifest;
2. verifies the manifest schema and binary SHA-256;
3. captures the supplied object files again as an immutable link session;
4. recomputes INPUTSET and LINKID using the manifest PROGADDR;
5. rebuilds the complete load plan and ESTAB;
6. re-executes relocation and materializes fresh SIC/XE memory;
7. compares the reproduced linked range byte-for-byte with the supplied `.bin`;
8. reconstructs the expected manifest and requires semantic equality;
9. requires the persisted JSON bytes to equal canonical deterministic serialization.

This executable reproducibility proof intentionally does not require source/debug maps. DEBUGID and macro-provenance identity remain separate metadata identities from LINKID.

## Inspect

```text
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.manifest.json
python sicxe.py inspect program.debug.json --json
```

Object inspection runs the same structural/semantic object analyzer as the loader before displaying CSECT, D/R/T/M/E, raw SHA-256, text bytes, relocation sites, and entry data. `--disassemble` linear-sweeps T-record payloads and attaches overlapping M records.

Source-map inspection displays MAPID, object/source hashes, final typed regions, expanded-source lines, and symbols. JSON output additionally exposes original-source lines and nested macro provenance. If the adjacent `.obj` exists, its current SHA is checked against the sidecar.

Linked-debug inspection displays LINKID, DEBUGID, loaded CSECT ranges, typed/untyped status, rebased regions, and loaded symbols.

Manifest inspection shows PROGADDR, image range/SHA, INPUTSET, LINKID, input identities, section placement, and entry provenance. If the adjacent `.bin` exists it is auto-detected and its current length/SHA are compared against the manifest.

`--json` exposes every inspection report as machine-readable structured output.

Inspection explains persisted state; it intentionally does not replace `verify`, which independently re-links object inputs.

## Disassemble

```text
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --manifest program.manifest.json --base 8000
python sicxe.py disasm program.bin --manifest program.manifest.json --offset 32 --length 64
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

When an adjacent `.debug.json` exists, source-aware rendering is the default. The debug LINKID must match the manifest and its PROGADDR must match the image origin.

Typed regions render according to assembler intent:

- instructions are decoded;
- `WORD` becomes `.WORD`;
- `BYTE` becomes `.BYTE`;
- literal pools become `.LITERAL`;
- reservations become `.RESB` metadata;
- exact loaded symbol starts become labels;
- instruction targets matching known symbols get `target_symbol=`;
- expanded-source line provenance is printed;
- original-source line and nested macro invocation/definition ancestry are appended.

CSECTs from third-party objects without source-map sidecars fall back to the raw linear decoder. `--linear` forces raw decoding for the entire image even when debug metadata is available.

`--cfg` additionally annotates typed instructions with reachability/basic-block identity and appends the control-flow report. It requires `--manifest` so analysis starts from the true execution entry and cannot be combined with `--linear`.

The underlying decoder handles formats 1–4, original SIC compatibility mode, format-2 operand signatures, `nixbpe`, addressing prefixes, PC-relative targets, optional base-relative targets, indexed addressing, and format-4 20-bit targets. Unknown/truncated bytes fall back to one-byte `.BYTE` records.

## Control flow

```text
python sicxe.py cfg program.bin --manifest program.manifest.json
python sicxe.py cfg program.bin --manifest program.manifest.json --json
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
python sicxe.py cfg program.bin --manifest program.manifest.json --base 8000
```

CFG analysis requires LINKID-matching typed debug metadata. The adjacent `.debug.json` is auto-detected unless `--debug` is supplied.

The analyzer uses only regions explicitly typed as instructions. It models direct `J`, conditional `JEQ/JGT/JLT`, `JSUB`, `RSUB`, and ordinary same-CSECT fallthrough; builds deterministic basic blocks; and computes a conservative reachable closure from the manifest execution entry.

Indirect/indexed transfers and unresolved base-relative targets remain unresolved rather than being fabricated into static edges. `UNREACHABLE` therefore means not reachable through the statically provable graph, not that dynamic execution can never reach the address.

`--json` exposes the complete instruction/block/edge model. `--dot` emits deterministic Graphviz DOT.

See [`inspection-disassembly.md`](inspection-disassembly.md), [`source-maps.md`](source-maps.md), and [`control-flow.md`](control-flow.md) for exact contracts and limitations.

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
