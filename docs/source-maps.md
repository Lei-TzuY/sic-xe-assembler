# Source maps and typed linked debug metadata

The assembler and linker intentionally keep executable reproducibility separate from optional debug/source metadata.

The executable identity remains defined by the object input bytes and `PROGADDR`:

- `INPUTSET` identifies the ordered raw `.obj` inputs;
- `LINKID` identifies `INPUTSET + PROGADDR`;
- `.bin` and `.manifest.json` remain unchanged by source-map availability.

Debug metadata is layered beside that contract rather than folded into it.

## Assembler source map

A successful assembly emits:

```text
program.sourcemap.json
```

with schema:

```text
sicxe-source-map-v1
```

The source map is path-independent. It stores hashes and semantic content, not host absolute paths.

Top-level fields include:

- canonical object SHA-256;
- expanded-source SHA-256;
- deterministic source-map fingerprint;
- ordered control sections.

Each section records:

- section index/name;
- final source origin and length;
- local symbols, including whether they are relocatable and whether they came from a label, `EQU`, or literal;
- typed final-address regions.

The region types are:

- `instruction`;
- `word`;
- `byte`;
- `literal`;
- `reservation`.

Every region stores its final source-object address, section-relative offset, byte length, expanded-source line, source statement text, and any relocatable symbols beginning at that address.

Addresses are collected after Pass 1 finalizes program-block layout. Consequently `USE`, `ORG`, and literal-pool placement are represented by their actual final addresses rather than provisional virtual block addresses.

`RESB`/`RESW` regions are retained even though initialized fields may legally overlap a reservation through `ORG`. The source map describes source intent; it does not reinterpret the existing initialized-storage overlap policy.

Synthetic literal rows are attributed to the `LTORG`, `CSECT`, or `END` source statement that caused the pool to materialize, using the same expanded-source mapping semantics as assembler overlap diagnostics.

## Object binding

A source map is valid only for the exact canonical `.obj` bytes from which it was produced.

The linker checks:

1. source-map self fingerprint;
2. source-map `object_sha256` against the immutable object input snapshot;
3. section count/order;
4. section name, source origin, and length against parsed object semantics.

If a sidecar is absent, linking remains valid and that input is marked untyped.

If a sidecar exists but is stale, tampered, or structurally inconsistent, linking fails. Silently ignoring a present-but-invalid debug file would allow incorrect source provenance to be attached to a valid executable image.

## Linked debug map

A successful link emits:

```text
program.debug.json
```

with schema:

```text
sicxe-linked-debug-v1
```

The linked debug map contains:

- the executable `LINKID` it describes;
- `PROGADDR`;
- per-input object/source-map identities;
- a separate deterministic `DEBUGID`;
- every planned CSECT placement;
- source symbols rebased to loaded addresses;
- typed source regions rebased to loaded addresses.

Relocatable symbols are rebased as:

```text
loaded = section.load_address + (source_address - section.source_start)
```

Absolute `EQU` values are not rebased.

The debug map is path-independent for the same reason as the executable manifest. Moving an identical object/source-map set to another directory does not change its semantic debug identity.

## Why DEBUGID is separate from LINKID

Debug metadata does not affect the executable bytes. Two links may therefore have the same `LINKID` and `.bin` while one has source metadata and the other does not.

Keeping a separate `DEBUGID` preserves two useful statements independently:

- `LINKID`: these are the same executable link inputs and placement;
- `DEBUGID`: these are the same executable identity plus the same available source/debug metadata.

The independent artifact verifier continues to prove `.bin + .manifest.json + .obj` reproducibility without requiring source maps.

## Source-aware disassembly

When `program.debug.json` is adjacent to `program.bin`, the unified CLI uses it automatically:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json
```

Typed rendering changes the meaning of disassembly:

- `instruction` regions are decoded as SIC/XE instructions;
- `word` regions render as `.WORD` rather than being guessed as opcodes;
- `byte` regions render as `.BYTE`;
- `literal` regions render as `.LITERAL`;
- `reservation` regions render as `.RESB` metadata without pretending the zero-filled linked-image bytes were source instructions;
- exact loaded symbol matches are printed as labels;
- instruction targets that exactly match known relocatable symbols gain `target_symbol=` annotations;
- expanded-source line provenance is printed on typed records.

Use:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

to force the historical raw linear sweep.

For inputs without source maps, typed disassembly falls back to linear decoding for those CSECTs only, so linked images may mix source-aware and untyped third-party object inputs.

## Inspection

Both metadata layers are directly inspectable:

```text
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.sourcemap.json --json
python sicxe.py inspect program.debug.json --json
```

When the adjacent `.obj` exists, source-map inspection additionally verifies its current object SHA against the sidecar.

## Limits

The source map currently tracks **expanded-source** line provenance. Macro-generated statements therefore point into `program.expanded.asm`, which is deterministic and exactly what Pass 1/Pass 2 consumed. Mapping macro-expanded statements all the way back through invocation/definition stacks to original pre-expansion source is a separate provenance layer and is not fabricated here.

Likewise, source maps describe assembler-produced objects. Hand-written or third-party object programs remain valid but untyped unless accompanied by a conforming source map.
