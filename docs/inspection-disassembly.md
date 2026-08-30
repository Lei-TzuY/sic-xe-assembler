# Inspection, source-aware disassembly, and control flow

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

Assembler-produced object programs have path-independent source/provenance sidecars:

```text
program.expanded.provenance.json
program.sourcemap.json
```

Inspect the source map with:

```text
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.sourcemap.json --json
```

The source-map report exposes canonical object SHA, source-map identity, final CSECT ranges, typed regions, expanded-source lines, and symbols. JSON output additionally exposes original-source SHA, macro-provenance fingerprint, original source line, outermost invocation line, and each nested macro definition/body/call-site frame.

If the adjacent `.obj` exists, inspection requires its current SHA to match the map.

See [`source-maps.md`](source-maps.md) for the provenance, binding, and DEBUGID contracts.

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

The linked-debug report shows LINKID, DEBUGID, PROGADDR, typed/untyped input status, rebased CSECT ranges, loaded symbol addresses, region kinds, and expanded-source line provenance. JSON retains the complete original-source/macro ancestry on each typed region.

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
- every typed region reports its expanded-source line;
- every typed region also reports original-source provenance;
- macro-generated lines show the outer invocation and complete nested macro stack.

For a linked image containing both assembler-produced and third-party objects, source-aware rendering is mixed: typed CSECTs use source metadata and untyped CSECTs fall back to the raw decoder.

Force the historical linear sweep with:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

A manifest supplies the correct image start automatically. If both `--manifest` and `--start` are given, their addresses must match. Likewise, a debug map from a different link is rejected through LINKID/PROGADDR checks rather than silently producing wrong annotations.

## CFG-aware disassembly

Add `--cfg` to annotate each typed instruction with its basic block and conservative reachability state, then append the full graph report:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
```

CFG mode requires both manifest entry provenance and linked debug metadata. It cannot be combined with `--linear` because raw bytes do not provide trusted code boundaries.

Standalone graph output is also available:

```text
python sicxe.py cfg program.bin --manifest program.manifest.json
python sicxe.py cfg program.bin --manifest program.manifest.json --json
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
```

See [`control-flow.md`](control-flow.md) for branch/call/fallthrough semantics and the conservative meaning of `UNREACHABLE`.

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

## Code/data and control-flow boundaries

Raw SIC/XE object files and flat linked images do not inherently encode a complete code-vs-data type map. A pure raw disassembler must therefore linear-sweep and can mistake ordinary data for valid opcodes.

Assembler source maps remove that ambiguity for assembler-produced regions without pretending to infer unavailable information for third-party objects. CFG analysis is stricter still: only typed instruction regions become graph nodes.

Dynamic behavior remains dynamic. Indirect/indexed jumps, computed returns, runtime register values, and self-modifying behavior are not fabricated into resolved static edges.

## Cross-layer invariant

The integration suite exercises the path from original source through graph analysis:

1. expand nested macros without changing historical expanded-source bytes;
2. bind every expanded line to original source and macro invocation/definition ancestry;
3. assemble typed final-address regions and bind them to canonical object SHA;
4. link at a nonzero PROGADDR and rebase regions/symbols into DEBUGID-bound metadata;
5. source-aware disassemble the relocated binary while preserving data/reservations;
6. recover labels and direct branch targets;
7. start reachability from the manifest execution entry;
8. build deterministic basic blocks and branch/jump/call/return/fallthrough edges;
9. identify typed instructions outside the statically provable closure;
10. retain `--linear` as the explicit raw fallback.

This ties macro expansion, original-source provenance, assembler layout, relocation, loader placement, executable identity, debug identity, disassembly, and static control flow into one regression surface.
