# Source maps, macro provenance, and typed linked debug metadata

The assembler and linker intentionally keep executable reproducibility separate from optional debug/source metadata.

The executable identity remains defined by the object input bytes and `PROGADDR`:

- `INPUTSET` identifies the ordered raw `.obj` inputs;
- `LINKID` identifies `INPUTSET + PROGADDR`;
- `.bin` and `.manifest.json` remain unchanged by source-map availability.

Debug metadata is layered beside that contract rather than folded into it.

## Macro-expansion provenance

A successful assembly now emits both:

```text
program.expanded.asm
program.expanded.provenance.json
```

The expanded source bytes remain exactly the historical macro-processor output. The provenance sidecar is a separate path-independent layer with schema `sicxe-macro-provenance-v1`.

For every physical expanded-source line it records:

- the expanded line number;
- the original `.asm` line that supplied the statement text;
- the outermost source-level macro invocation line, when applicable;
- whether the line is direct source, a macro marker, an invocation label, or macro body output;
- the complete nested macro stack.

Each macro-stack frame records the macro name, deterministic invocation instance, definition line, body line, and immediate call-site line. Nested expansion therefore preserves ancestry such as:

```text
source line 3
invoked from original line 9
OUTER#1(def=6, body=7, call=9)
  -> INNER#2(def=2, body=3, call=7)
```

The sidecar stores SHA-256 for both the original and expanded source plus a deterministic provenance fingerprint. Moving identical source to another directory does not change the sidecar bytes.

## Assembler source map

A successful assembly emits:

```text
program.sourcemap.json
```

with schema `sicxe-source-map-v1`.

The source map is path-independent. It stores hashes and semantic content, not host absolute paths.

Top-level fields include:

- canonical object SHA-256;
- expanded-source SHA-256;
- original-source SHA-256 when macro provenance is available;
- macro-provenance fingerprint;
- deterministic source-map fingerprint (MAPID);
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

Every region stores its final source-object address, section-relative offset, byte length, expanded-source line, source statement text, any relocatable symbols beginning at that address, and the original-source/macro ancestry for the expanded statement.

Addresses are collected after Pass 1 finalizes program-block layout. Consequently `USE`, `ORG`, and literal-pool placement are represented by their actual final addresses rather than provisional virtual block addresses.

`RESB`/`RESW` regions are retained even though initialized fields may legally overlap a reservation through `ORG`. The source map describes source intent; it does not reinterpret the existing initialized-storage overlap policy.

Synthetic literal rows are attributed to the `LTORG`, `CSECT`, or `END` expanded statement that caused the pool to materialize; that statement's own provenance then carries the mapping back to the original source or enclosing macro invocation.

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

with schema `sicxe-linked-debug-v1`.

The linked debug map contains:

- the executable `LINKID` it describes;
- `PROGADDR`;
- per-input object/source-map identities;
- a separate deterministic `DEBUGID`;
- every planned CSECT placement;
- source symbols rebased to loaded addresses;
- typed source regions rebased to loaded addresses;
- original-source and nested macro ancestry copied with each typed region.

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

The independent artifact verifier continues to prove `.bin + .manifest.json + .obj` reproducibility without requiring source maps or macro provenance.

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
- expanded-source lines remain visible;
- each typed line also carries original-source and macro-stack provenance.

Use:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --linear
```

to force the historical raw linear sweep.

For inputs without source maps, typed disassembly falls back to linear decoding for those CSECTs only, so linked images may mix source-aware and untyped third-party object inputs.

Control-flow annotations build on the same typed regions. See [`control-flow.md`](control-flow.md).

## Inspection

Both metadata layers are directly inspectable:

```text
python sicxe.py inspect program.sourcemap.json
python sicxe.py inspect program.debug.json
python sicxe.py inspect program.sourcemap.json --json
python sicxe.py inspect program.debug.json --json
```

When the adjacent `.obj` exists, source-map inspection additionally verifies its current object SHA against the sidecar. JSON inspection exposes the complete original-source and macro ancestry stored on each region.

## Limits

Source provenance identifies original file lines and macro definition/invocation stacks, but it does not attempt to reconstruct a source-level AST after macro substitution. A generated line can therefore be traced precisely to its textual origin and call ancestry without claiming that the post-substitution operand text is identical to the macro-definition text.

Source maps describe assembler-produced objects. Hand-written or third-party object programs remain valid but untyped unless accompanied by a conforming source map.
