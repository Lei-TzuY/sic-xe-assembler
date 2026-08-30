# SIC/XE Assembler and Linking Loader

A dependency-free Python implementation of a SIC/XE macro assembler and linking loader, with unusually strict semantic validation, deterministic linking, reproducible output artifacts, independent artifact verification, structured inspection, source maps, original-source macro provenance, disassembly, and typed control-flow analysis.

The project started as a conventional two-pass assembler and now covers the complete SIC/XE instruction table, macros, literals, program blocks, control sections, relocation expressions, a validated load-plan model, a 1 MiB machine-memory model, persistent link maps, deterministic linked images, end-to-end reproducibility checks, typed source/debug metadata, formats 1–4 disassembly, and conservative basic-block/CFG analysis.

## Quick start

Use the unified CLI for new workflows:

```powershell
python sicxe.py assemble program.asm
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.obj --disassemble
python sicxe.py link program.obj --progaddr 4000
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.manifest.json
python sicxe.py verify program.bin program.manifest.json program.obj
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
```

The historical entry points remain supported:

```powershell
python assembler.py program.asm
python loader.py program.obj 4000
python verify_link.py program.bin program.manifest.json program.obj
```

No third-party runtime packages are required.

## What is implemented

| Area | Support |
| --- | --- |
| Instructions | Complete SIC/XE instruction table; formats 1, 2, 3, and 4 |
| Addressing | immediate, indirect, indexed, PC-relative, base-relative, extended |
| Macros | parameters, quoted arguments, nested expansion, recursion detection, unique local labels, original-source invocation/definition provenance |
| Literals | `=C'..'`, `=X'..'`, deduplication, `LTORG`, automatic pool flush |
| Expressions | parentheses, unary `+/-`, `*`/`/` precedence, relocation-aware `+/-` |
| Symbols | `EQU`, forward `EQU` dependencies, cycle detection, `*` current location |
| Layout | `ORG`, `USE` program blocks, independent block LOCCTRs, high-water lengths |
| Linking | `CSECT`, `EXTDEF`, `EXTREF`, D/R/M/E records, grouped relocation arithmetic |
| Validation | fixed-field object contracts, initialized-storage overlap checks, shared object semantics |
| Machine model | 20-bit SIC/XE address space / 1 MiB memory; independent 24-bit WORD values |
| Reproducibility | immutable object snapshots, INPUTSET, LINKID, deterministic `.map/.bin/manifest` |
| Verification | independent re-link and byte-for-byte artifact reproduction |
| Source maps | object-SHA-bound typed regions, expanded/original source lines, nested macro ancestry, symbols, linked rebasing, DEBUGID |
| Inspection | validated CSECT/D/R/T/M/E reports, source/debug map reports, manifest/image SHA checks, JSON output |
| Disassembly | formats 1–4, SIC compatibility, format-2 signatures, nixbpe, PC/base targets, typed data-aware rendering |
| Control flow | manifest-entry reachability, typed basic blocks, branch/jump/call/return edges, JSON and Graphviz DOT |

## Assembly pipeline

For `program.asm`, assembly produces:

```text
program.expanded.asm
program.expanded.provenance.json
program.int
program.sym
program.obj
program.lst
program.sourcemap.json
```

The successful pipeline is deliberately fail-closed:

1. macro expansion plus deterministic line-provenance capture;
2. object-name/source-contract preflight;
3. source START address validation;
4. Pass 1 symbol/layout construction;
5. finalized program-block/CSECT address validation;
6. initialized-storage overlap detection;
7. Pass 2 object generation;
8. object-record canonicalization;
9. generated-object semantic validation using the same analyzer as the loader;
10. deterministic source-map generation bound to the exact canonical object SHA-256 and macro-provenance fingerprint.

If any stage fails, stale and partial generated outputs, including provenance/source-map sidecars, are removed.

### Macro processor and original-source provenance

Macros use positional `&NAME` parameters. Arguments may contain quoted commas, macro bodies may invoke other macros, recursive expansion is rejected, and `$LOCAL` labels are rewritten into deterministic unique labels for each invocation.

```asm
SPIN     MACRO   &TARGET
$LOOP    LDA     &TARGET
         J       $LOOP
         MEND
```

The historical `program.expanded.asm` bytes remain unchanged. A separate `program.expanded.provenance.json` records every physical expanded line, its original source line, the outermost invocation line, and the full nested macro stack. Each frame includes macro name, deterministic invocation instance, definition line, body line, and immediate call-site line. The sidecar is path-independent and self-fingerprinted.

That provenance is then copied onto typed regions in `program.sourcemap.json` and survives rebasing into `program.debug.json`, so linked instructions can be traced back through macro expansion history without modifying executable identity.

### Literals and program blocks

Format-3/4 operands may use `=C'..'` and `=X'..'` literals. Pools are deduplicated per CSECT and emitted by `LTORG`, `CSECT`, or `END`.

`USE` gives each program block an independent location counter and `ORG` restore stack. Final block addresses are assigned only after Pass 1, with the unnamed block first and named blocks in first-seen order.

### Expressions and relocation algebra

Expressions use normal precedence:

1. parentheses;
2. unary `+` / `-`;
3. multiplication / division;
4. addition / subtraction.

Examples:

```asm
LENGTH   EQU     (BUFEND-BUFFER) * 4
OFFSET   EQU     -(A-B) + 20
VALUE    WORD    (LENGTH + 2) * 3
MIX      WORD    EXT1 - (EXT2 - 12)
```

`*` is the current location when used as a primary expression and multiplication when used between operands. Division truncates toward zero.

Relocation rules remain strict: multiplication and division require absolute operands. Relocatable local symbols and external symbols may participate in additive algebra, but expressions such as `BUFFER*2` or `EXT1/4` are rejected because SIC/XE modification records cannot represent arbitrary scaled relocation terms.

Forward `EQU` definitions are resolved transitively after final program-block layout. Circular dependencies are rejected with the dependency path.

## Object-program and address contracts

Object names used by control sections, `EXTDEF`, and `EXTREF` must fit the six-character SIC/XE fixed field: 1–6 ASCII alphanumeric characters beginning with a letter. D/R records are split to the standard record-length bound, and H/D/R/T/M/E framing is structurally validated.

SIC/XE machine memory is 20-bit: `0x00000`–`0xFFFFF` (1 MiB). Six hexadecimal address digits in object records are a serialization field, not permission to address 16 MiB of machine memory. `START`, final section layout, `PROGADDR`, and linked-image placement obey the 20-bit limit; 24-bit `WORD` data remains independent.

Initialized instructions, `WORD`, `BYTE`, and literal bytes may not overlap after final layout. `RESB`/`RESW` remain reservations, so using `ORG` to define initialized fields inside a reserved buffer remains legal.

See [`docs/address-space.md`](docs/address-space.md).

## Linking and relocation

The loader first captures every object input exactly once into an immutable link session. It then validates and resolves the entire link before allocating or mutating SIC/XE memory.

The load plan contains:

- ordered object snapshots and raw SHA-256 digests;
- complete CSECT placement;
- ESTAB plus definition provenance;
- resolved R/M references;
- grouped exact relocation arithmetic;
- unused-but-legal R declarations;
- execution-entry provenance;
- path-independent INPUTSET and PROGADDR-sensitive LINKID.

Repeated M records over the exact same field are one relocation expression: all signed symbol deltas are summed with exact integers, then the final field is range-checked once and written once. Partially overlapping modification fields and mixed 5/6-half-byte fields over the same bytes are rejected as ambiguous.

The loader allocates the full 1 MiB SIC/XE memory image. A normal `pass1() -> pass2()` API sequence binds the Pass-1 ESTAB to the immutable input session, removing file-reopen TOCTOU: changing or deleting an object file after Pass 1 cannot change the bytes materialized by that link operation.

See [`docs/load-plan.md`](docs/load-plan.md) and [`docs/relocation-arithmetic.md`](docs/relocation-arithmetic.md).

## Persistent linked artifacts

A successful link emits four files beside the first object input:

```text
program.map
program.bin
program.manifest.json
program.debug.json
```

`program.map` is a deterministic human-readable link report containing CSECT layout, ESTAB, definition provenance, cross-references, unused R declarations, relocation sites/arithmetic, input hashes, INPUTSET, LINKID, and entry provenance.

`program.bin` is the exact contiguous linked address range `[PROGADDR, PROGADDR + total_length)` after relocation. Reserved gaps inside that range are deterministic zero bytes.

`program.manifest.json` uses schema `sicxe-linked-image-v1` and attests the binary SHA-256, ordered input hashes, section layout, entry point, INPUTSET, and LINKID. It intentionally contains no host paths, so moving identical object bytes to another directory does not change the manifest.

`program.debug.json` is a separate optional-metadata identity layer. For assembler-produced inputs, the linker verifies adjacent `.sourcemap.json` files against immutable object SHA-256 snapshots, validates section layout, rebases relocatable symbols/typed regions to loaded addresses, preserves original-source/macro ancestry, and records a separate DEBUGID. Inputs without a source-map sidecar remain linkable and are marked `typed=false`; a present-but-invalid sidecar fails closed.

Keeping DEBUGID separate from LINKID means source metadata never changes executable identity or the independent `.bin/.manifest/.obj` reproducibility proof.

See [`docs/link-map.md`](docs/link-map.md), [`docs/linked-image.md`](docs/linked-image.md), and [`docs/source-maps.md`](docs/source-maps.md).

## Independent artifact verification

The verifier does not trust the previous `.map`, `.debug.json`, or an earlier in-memory plan:

```powershell
python sicxe.py verify program.bin program.manifest.json program.obj
```

It reads the persisted binary/manifest, captures the supplied objects again, recomputes INPUTSET/LINKID, rebuilds the complete load plan, re-applies relocation, rematerializes memory, and requires both the binary and canonical manifest to reproduce exactly.

This detects binary tampering, substituted or reordered object inputs, manifest metadata changes, wrong PROGADDR/link identity, and noncanonical manifest serialization. Source/debug maps are deliberately outside this executable proof.

## Inspection and disassembly

Every persistent metadata layer is inspectable without mutation:

```powershell
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.manifest.json
```

Object inspection first runs the shared object semantic analyzer, then reports raw SHA-256, CSECT ranges, D/R/T/M/E records, exact text bytes, relocation fields, entry data, and summary counts. `--disassemble` additionally linear-sweeps each T payload and attaches any intersecting M records to the decoded record.

Source-map JSON contains object/source hashes, MAPID, final source addresses, region types, expanded-source lines, original-source lines, nested macro ancestry, and symbols. When the adjacent `.obj` is present, its current SHA is checked against the sidecar.

Linked-debug inspection reports LINKID, DEBUGID, loaded section placement, typed/untyped status, rebased regions, and symbol starts.

Manifest inspection reports image range/SHA, INPUTSET, LINKID, ordered input identities, section placement, and entry provenance. An adjacent `.bin` is auto-detected and compared for current length/SHA. This is deliberately lighter than `verify`: inspection observes persisted state; verification independently re-links it.

### Source-aware disassembly

For assembler-produced linked images, the adjacent `.debug.json` is auto-detected:

```powershell
python sicxe.py disasm program.bin --manifest program.manifest.json
```

Typed rendering uses assembler intent rather than treating every byte as probable code:

- instructions are decoded normally;
- `WORD` data renders as `.WORD`;
- `BYTE` data renders as `.BYTE`;
- literal-pool bytes render as `.LITERAL`;
- reservations render as `.RESB` metadata rather than decoding deterministic zero-filled image bytes as instructions;
- loaded labels are printed at exact symbol starts;
- instruction targets that equal known symbols gain `target_symbol=` annotations;
- expanded-source line provenance remains visible;
- original-source line and nested macro invocation/definition ancestry are appended to each typed record.

A linked image can mix typed assembler inputs and untyped third-party object inputs; untyped CSECTs fall back to the normal linear decoder.

Force the historical raw mode explicitly with:

```powershell
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

The underlying decoder still handles formats 1–4, original SIC compatibility mode, register/shift/SVC format-2 signatures, `nixbpe`, immediate/indirect/indexed syntax, PC-relative targets, optional base-relative target resolution, and 20-bit format-4 targets. Unknown/truncated bytes fall back to one-byte `.BYTE` records so a raw sweep remains deterministic.

### Control-flow analysis

Typed instructions can also be organized into a conservative static CFG:

```powershell
python sicxe.py cfg program.bin --manifest program.manifest.json
python sicxe.py cfg program.bin --manifest program.manifest.json --json
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
```

The analyzer starts from the **actual execution entry in the manifest**, not merely PROGADDR. It models direct `J`, conditional `JEQ/JGT/JLT`, `JSUB`, `RSUB`, and ordinary fallthrough; builds deterministic basic blocks; and marks typed instructions outside the statically provable entry closure as `UNREACHABLE`.

Indirect (`@`) and indexed (`,X`) transfers are not pretended to be resolved static targets. Untyped bytes and data regions never become CFG nodes. Therefore `UNREACHABLE` means "not reachable through the statically provable edges represented by this analysis", not "the CPU can never execute this address".

See [`docs/control-flow.md`](docs/control-flow.md) for the exact edge and reachability contract.

See [`docs/toolchain-cli.md`](docs/toolchain-cli.md), [`docs/inspection-disassembly.md`](docs/inspection-disassembly.md), and [`docs/source-maps.md`](docs/source-maps.md).

## Testing

Run everything locally:

```powershell
python -m compileall -q .
python -m unittest discover -s tests -v
python verify.py
```

`verify.py` assembles the four checked-in fixture programs in an isolated temporary directory and byte-compares `.expanded.asm`, `.int`, `.sym`, `.obj`, and `.lst` against the tracked golden outputs. Provenance/source/debug/CFG metadata has independent deterministic regression coverage so the historical golden artifact contract remains unchanged.

GitHub Actions runs the unit suite across Ubuntu and Windows on Python 3.10 and 3.13. Byte-for-byte golden fixture verification runs on Linux, while the cross-platform matrix exercises filesystem behavior, atomic artifact writes, the unified CLI, linking, reproducibility verification, source/debug maps, original-source provenance, source-aware disassembly, and CFG analysis.

## Documentation

- [`docs/address-space.md`](docs/address-space.md) — machine vs object-field address model
- [`docs/relocation-arithmetic.md`](docs/relocation-arithmetic.md) — 20/24-bit relocation addend contracts
- [`docs/load-plan.md`](docs/load-plan.md) — deterministic planning and immutable link sessions
- [`docs/link-map.md`](docs/link-map.md) — stable linker map / cross-reference format
- [`docs/linked-image.md`](docs/linked-image.md) — binary image and manifest contract
- [`docs/source-maps.md`](docs/source-maps.md) — macro provenance, assembler source maps, linked DEBUGID, typed regions
- [`docs/control-flow.md`](docs/control-flow.md) — conservative typed CFG, basic blocks, reachability, DOT output
- [`docs/toolchain-cli.md`](docs/toolchain-cli.md) — unified CLI, verifier, and expression grammar
- [`docs/inspection-disassembly.md`](docs/inspection-disassembly.md) — inspectors, decoder, and raw code/data limitation

## Scope

This remains an educational SIC/XE implementation rather than a production-system linker, but correctness is treated as a first-class goal: malformed inputs fail hard, relocation is explicit, address-space limits are enforced, executable and debug provenance are separately recorded, final linked artifacts can be independently reproduced and verified, macro-generated machine code can be traced back to original source/call stacks, and assembler-produced images can be disassembled and structurally analyzed without silently pretending every byte or every dynamic edge is statically known.
