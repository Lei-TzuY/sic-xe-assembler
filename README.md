# SIC/XE Assembler and Linking Loader

A dependency-free Python implementation of a SIC/XE macro assembler and linking loader, with unusually strict semantic validation, deterministic linking, reproducible output artifacts, independent artifact verification, structured inspection, and instruction disassembly.

The project started as a conventional two-pass assembler and now covers the complete SIC/XE instruction table, macros, literals, program blocks, control sections, relocation expressions, a validated load-plan model, a 1 MiB machine-memory model, persistent link maps, deterministic linked images, end-to-end reproducibility checks, object/manifest inspection, and formats 1–4 disassembly.

## Quick start

Use the unified CLI for new workflows:

```powershell
python sicxe.py assemble program.asm
python sicxe.py inspect program.obj --disassemble
python sicxe.py link program.obj --progaddr 4000
python sicxe.py inspect program.manifest.json
python sicxe.py verify program.bin program.manifest.json program.obj
python sicxe.py disasm program.bin --manifest program.manifest.json
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
| Macros | parameters, quoted arguments, nested expansion, recursion detection, unique local labels |
| Literals | `=C'..'`, `=X'..'`, deduplication, `LTORG`, automatic pool flush |
| Expressions | parentheses, unary `+/-`, `*`/`/` precedence, relocation-aware `+/-` |
| Symbols | `EQU`, forward `EQU` dependencies, cycle detection, `*` current location |
| Layout | `ORG`, `USE` program blocks, independent block LOCCTRs, high-water lengths |
| Linking | `CSECT`, `EXTDEF`, `EXTREF`, D/R/M/E records, grouped relocation arithmetic |
| Validation | fixed-field object contracts, initialized-storage overlap checks, shared object semantics |
| Machine model | 20-bit SIC/XE address space / 1 MiB memory; independent 24-bit WORD values |
| Reproducibility | immutable object snapshots, INPUTSET, LINKID, deterministic `.map/.bin/manifest` |
| Verification | independent re-link and byte-for-byte artifact reproduction |
| Inspection | validated CSECT/D/R/T/M/E reports, manifest/image SHA checks, JSON output |
| Disassembly | formats 1–4, format-2 signatures, nixbpe, PC/base targets, deterministic fallback |

## Assembly pipeline

For `program.asm`, assembly produces:

```text
program.expanded.asm
program.int
program.sym
program.obj
program.lst
```

The successful pipeline is deliberately fail-closed:

1. macro expansion;
2. object-name/source-contract preflight;
3. source START address validation;
4. Pass 1 symbol/layout construction;
5. finalized program-block/CSECT address validation;
6. initialized-storage overlap detection;
7. Pass 2 object generation;
8. object-record canonicalization;
9. generated-object semantic validation using the same analyzer as the loader.

If any stage fails, stale and partial generated outputs are removed.

### Macro processor

Macros use positional `&NAME` parameters. Arguments may contain quoted commas, macro bodies may invoke other macros, recursive expansion is rejected, and `$LOCAL` labels are rewritten into deterministic unique labels for each invocation.

```asm
SPIN     MACRO   &TARGET
$LOOP    LDA     &TARGET
         J       $LOOP
         MEND
```

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

A successful link emits three files beside the first object input:

```text
program.map
program.bin
program.manifest.json
```

`program.map` is a deterministic human-readable link report containing CSECT layout, ESTAB, definition provenance, cross-references, unused R declarations, relocation sites/arithmetic, input hashes, INPUTSET, LINKID, and entry provenance.

`program.bin` is the exact contiguous linked address range `[PROGADDR, PROGADDR + total_length)` after relocation. Reserved gaps inside that range are deterministic zero bytes.

`program.manifest.json` uses schema `sicxe-linked-image-v1` and attests the binary SHA-256, ordered input hashes, section layout, entry point, INPUTSET, and LINKID. It intentionally contains no host paths, so moving identical object bytes to another directory does not change the manifest.

See [`docs/link-map.md`](docs/link-map.md) and [`docs/linked-image.md`](docs/linked-image.md).

## Independent artifact verification

The verifier does not trust the previous `.map` or an earlier in-memory plan:

```powershell
python sicxe.py verify program.bin program.manifest.json program.obj
```

It reads the persisted binary/manifest, captures the supplied objects again, recomputes INPUTSET/LINKID, rebuilds the complete load plan, re-applies relocation, rematerializes memory, and requires both the binary and canonical manifest to reproduce exactly.

This detects binary tampering, substituted or reordered object inputs, manifest metadata changes, wrong PROGADDR/link identity, and noncanonical manifest serialization.

## Inspection and disassembly

Inspection makes object/link state explainable without mutating it:

```powershell
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.obj --json
python sicxe.py inspect program.manifest.json
```

Object inspection first runs the shared object semantic analyzer, then reports raw SHA-256, CSECT ranges, D/R/T/M/E records, exact text bytes, relocation fields, entry data, and summary counts. `--disassemble` additionally linear-sweeps each T payload and attaches any intersecting M records to the decoded record.

Manifest inspection reports image range/SHA, INPUTSET, LINKID, ordered input identities, section placement, and entry provenance. An adjacent `.bin` is auto-detected and compared for current length/SHA. This is deliberately lighter than `verify`: inspection observes persisted state; verification independently re-links it.

Raw linked images can be decoded directly:

```powershell
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --start 4000 --base 8000
```

The disassembler handles formats 1–4, register/shift/SVC format-2 signatures, `nixbpe`, immediate/indirect/indexed syntax, PC-relative targets, optional base-relative target resolution, and 20-bit format-4 targets. Unknown/truncated bytes fall back to one-byte `.BYTE` records so the sweep remains deterministic.

A flat SIC/XE image does not carry a general code/data map, so disassembly is intentionally a linear-sweep decoder rather than a claim to reconstruct original source. `WORD`, `BYTE`, literals, and tables may coincidentally resemble valid instructions.

See [`docs/toolchain-cli.md`](docs/toolchain-cli.md) and [`docs/inspection-disassembly.md`](docs/inspection-disassembly.md).

## Testing

Run everything locally:

```powershell
python -m compileall -q .
python -m unittest discover -s tests -v
python verify.py
```

`verify.py` assembles the four checked-in fixture programs in an isolated temporary directory and byte-compares `.expanded.asm`, `.int`, `.sym`, `.obj`, and `.lst` against the tracked golden outputs.

GitHub Actions runs the unit suite across Ubuntu and Windows on Python 3.10 and 3.13. Byte-for-byte golden fixture verification runs on Linux, while the cross-platform matrix exercises filesystem behavior, atomic artifact writes, the unified CLI, linking, reproducibility verification, inspection, and disassembly.

## Documentation

- [`docs/address-space.md`](docs/address-space.md) — machine vs object-field address model
- [`docs/relocation-arithmetic.md`](docs/relocation-arithmetic.md) — 20/24-bit relocation addend contracts
- [`docs/load-plan.md`](docs/load-plan.md) — deterministic planning and immutable link sessions
- [`docs/link-map.md`](docs/link-map.md) — stable linker map / cross-reference format
- [`docs/linked-image.md`](docs/linked-image.md) — binary image and manifest contract
- [`docs/toolchain-cli.md`](docs/toolchain-cli.md) — unified CLI, verifier, and expression grammar
- [`docs/inspection-disassembly.md`](docs/inspection-disassembly.md) — inspectors, disassembler, and code/data limitation

## Scope

This remains an educational SIC/XE implementation rather than a production-system linker, but correctness is treated as a first-class goal: malformed inputs fail hard, relocation is explicit, address-space limits are enforced, output provenance is recorded, final linked artifacts can be independently reproduced and verified, and every persistent stage can be inspected without hiding the limits of flat-image disassembly.
