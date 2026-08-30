# Inspection and disassembly

The toolchain can inspect every persistent link stage without changing it. Inspection is intentionally separate from verification: inspection explains an artifact, while `sicxe.py verify` independently re-links object inputs and proves that the persisted binary and manifest are reproducible.

## Object inspection

```text
python sicxe.py inspect program.obj
python sicxe.py inspect program.obj --disassemble
python sicxe.py inspect program.obj --disassemble --base 8000
python sicxe.py inspect program.obj --json
```

Before reporting anything, object inspection runs the same H/D/R/T/M/E structural and semantic analyzer used by the assembler postflight and linking loader. A malformed object program therefore cannot be presented as a valid inspection report.

The report includes:

- raw object SHA-256 and byte/record counts;
- control-section source ranges;
- D-record definitions and section-relative values;
- sorted R-record external references;
- T-record addresses, lengths, and exact payload bytes;
- M-record addresses, widths, signs, and symbols;
- E-record execution address;
- aggregate text-byte and modification counts.

With `--disassemble`, each T payload is also linear-swept as SIC/XE instructions. Any M record whose three-byte field intersects a decoded record is attached to that record as an annotation, making relocation sites visible beside the bytes they modify.

`--json` emits the same structured report as deterministic JSON for scripts and external analysis.

## Linked-image manifest inspection

```text
python sicxe.py inspect program.manifest.json
python sicxe.py inspect program.manifest.json --image program.bin
python sicxe.py inspect program.manifest.json --json
```

When a manifest is inspected, an adjacent `program.bin` is auto-detected from `program.manifest.json` when present. The report shows schema, PROGADDR, linked image range, image SHA-256, INPUTSET, LINKID, entry provenance, ordered input identities, and section layout.

If a binary is supplied or auto-detected, inspection additionally computes its current byte length and SHA-256 and reports whether each matches the manifest. This is a lightweight persisted-artifact check only; it does not replace independent re-link verification.

## Raw linked-image disassembly

```text
python sicxe.py disasm program.bin --start 4000
python sicxe.py disasm program.bin --manifest program.manifest.json
python sicxe.py disasm program.bin --manifest program.manifest.json --base 8000
python sicxe.py disasm program.bin --manifest program.manifest.json --offset 32 --length 64
```

A manifest supplies the correct image start automatically. If both `--manifest` and `--start` are given, their addresses must match or the command fails rather than silently producing incorrect address annotations.

The disassembler supports:

- format 1 opcodes;
- all format 2 signatures, register names, shift counts, and SVC nibble values;
- format 3/4 opcode decoding;
- `nixbpe` flag reporting;
- immediate, indirect, simple, and indexed syntax;
- PC-relative target recovery;
- base-relative `B+disp` reporting, or concrete target recovery when `--base` is supplied;
- 20-bit format-4 target decoding;
- RSUB special handling;
- deterministic `.BYTE X'..'` fallback for unknown or truncated opcodes.

## Important limitation: code/data boundaries

SIC/XE object files and flat linked images do not encode a general code-vs-data type map. The disassembler therefore uses deterministic **linear sweep**. It decodes valid instruction encodings but does not claim that every decodable byte sequence was intended as executable code.

This is especially important for `WORD`, `BYTE`, literal pools, reserved gaps, and embedded tables. Unknown bytes fall back to `.BYTE`, but ordinary data can coincidentally resemble valid opcodes. Object inspection keeps T/M structure visible so a reviewer can distinguish encoding facts from code/data interpretation.

## Cross-layer invariant

The integration suite exercises the complete path:

1. assemble source containing formats 1/2/3/4;
2. inspect the generated object program;
3. confirm a local format-4 reference carries its M record;
4. link at a nonzero PROGADDR;
5. inspect the generated manifest and binary hash;
6. disassemble the relocated binary;
7. require the format-4 target to equal the final loaded address.

This ties assembler encoding, object relocation metadata, loader arithmetic, persistent image generation, and decoder semantics into one regression instead of testing each layer in isolation.
