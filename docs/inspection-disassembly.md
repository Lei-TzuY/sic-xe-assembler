# Inspection and disassembly

The toolchain can inspect every persistent stage without changing it. Inspection is intentionally separate from verification: inspection explains an artifact, while `sicxe.py verify` independently re-links object inputs and proves that the persisted binary and manifest are reproducible.

## Object inspection

```text
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.obj --disassemble --base 8000
python sicxe.py inspect program.obj --json
```

Before reporting anything, object inspection runs the same H/D/R/T/M/E structural and semantic analyzer used by the assembler postflight and linking loader. A malformed object program therefore cannot be presented as a valid inspection report.

The report includes raw object SHA-256 and byte/record counts, control-section source ranges, D/R/T/M/E structure, exact text bytes, relocation fields, execution data, and aggregate counts.

With `--disassemble`, each T payload is linear-swept as SIC/XE instructions. Any M record whose three-byte field intersects a decoded record is attached to that record as an annotation. This view deliberately describes the object payload itself and does not use assembler source-map type information.

## Source-map inspection

Assembler-produced object programs have a path-independent sidecar:

```text
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.sourcemap.json --json
```

The report exposes the canonical object SHA, expanded-source SHA, source-map fingerprint, final CSECT ranges, typed regions, expanded-source lines, and symbols. If the adjacent `.obj` exists, inspection also requires its current SHA to match the map.

See [`source-maps.md`](source-maps.md) for the binding and DEBUGID contracts.

## Linked-image manifest inspection

```text
python sicxe.py inspect program.manifest.json
python sicxe.py inspect program.manifest.json --image program.bin
python sicxe.py inspect program.manifest.json --json
```

When a manifest is inspected, an adjacent `program.bin` is auto-detected when present. The report shows schema, PROGADDR, linked image range, image SHA-256, INPUTSET, LINKID, entry provenance, ordered input identities, and section layout.

If a binary is supplied or auto-detected, inspection additionally computes its current byte length and SHA-256 and reports whether each matches the manifest. This is a lightweight persisted-artifact check only; it does not replace independent re-link verification.

## Linked-debug inspection

A successful link also emits:

```text
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.debug.json --json
```

The linked-debug report shows LINKID, DEBUGID, PROGADDR, typed/untyped input status, rebased CSECT ranges, loaded symbol addresses, region kinds, and expanded-source line provenance.

A debug map is optional metadata. Inputs without source-map sidecars are represented as `typed=false`. A present source map must match its object SHA and section layout or the link fails rather than attaching stale provenance.

## Source-aware linked-image disassembly

```text
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --manifest program.manifest.json --base 8000
python sicxe.py disasm program.bin --manifest program.manifest.json --offset 32 --length 64
```

When adjacent `program.debug.json` metadata exists, it is auto-detected. Its LINKID must agree with the supplied manifest and its PROGADDR must agree with the image origin.

Typed CSECTs are rendered according to assembler intent:

- `instruction` regions are decoded as SIC/XE instructions;
- `word` regions render as `.WORD`;
- `byte` regions render as `.BYTE`;
- `literal` regions render as `.LITERAL`;
- `reservation` regions render as `.RESB` metadata instead of decoding zero-filled image bytes;
- exact loaded symbols appear as labels;
- decoded instruction targets that exactly match known symbols gain `target_symbol=` annotations;
- every typed region reports its expanded-source line.

For a linked image containing both assembler-produced and third-party objects, source-aware rendering is mixed: typed CSECTs use source metadata and untyped CSECTs fall back to the raw decoder.

Force the historical linear sweep with:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

A manifest supplies the correct image start automatically. If both `--manifest` and `--start` are given, their addresses must match. Likewise, a debug map from a different link is rejected through LINKID/PROGADDR checks rather than silently producing wrong annotations.

## Raw decoder

The underlying decoder supports:

- format 1 opcodes;
- all format 2 signatures, register names, shift counts, and SVC nibble values;
- format 3/4 opcode decoding;
- original SIC compatibility mode (`n=i=0`);
- `nixbpe` reporting;
- immediate, indirect, simple, and indexed syntax;
- PC-relative target recovery;
- base-relative `B+disp` reporting, or concrete target recovery when `--base` is supplied;
- 20-bit format-4 target decoding;
- RSUB special handling;
- deterministic `.BYTE X'..'` fallback for unknown or truncated opcodes.

## Code/data boundary behavior

Raw SIC/XE object files and flat linked images do not inherently encode a complete code-vs-data map. A pure raw disassembler must therefore linear-sweep and can mistake ordinary data for valid opcodes.

Assembler source maps remove that ambiguity for assembler-produced regions without pretending to infer unavailable information for third-party objects. `WORD`, `BYTE`, literal pools, and reservations are explicitly typed only when source provenance is available; otherwise the tool remains transparent about falling back to linear decoding.

## Cross-layer invariant

The integration suite now exercises the complete typed path:

1. assemble source containing code, `WORD`, `BYTE`, reservations, symbols, and literals;
2. require a source map bound to the exact canonical object SHA;
3. inspect object and source-map metadata;
4. link at a nonzero PROGADDR;
5. require source regions/symbols to rebase into a LINKID-bound debug map;
6. inspect manifest and debug metadata;
7. source-aware disassemble the relocated binary;
8. require data to remain data, reservations to remain reservations, and a branch target to resolve to the rebased symbol;
9. force `--linear` and confirm the historical raw decoder remains available.

This ties assembler layout, source provenance, object relocation, loader placement, executable identity, debug identity, and disassembly semantics into one regression.
