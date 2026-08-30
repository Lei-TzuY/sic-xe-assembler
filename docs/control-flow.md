# Control-flow analysis and basic blocks

The toolchain can build a conservative control-flow graph (CFG) from linked images when typed debug metadata is available.

```text
python sicxe.py cfg program.bin --manifest program.manifest.json
python sicxe.py cfg program.bin --manifest program.manifest.json --json
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
```

The same analysis can annotate source-aware disassembly:

```text
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
```

## Inputs and trust boundary

CFG analysis requires:

- the linked `.bin` image;
- its `.manifest.json`, which supplies LINKID, image origin, and the actual execution entry point;
- a LINKID-matching `.debug.json`, normally auto-detected beside the image.

Only regions explicitly typed as `instruction` are nodes in the graph. `WORD`, `BYTE`, literals, reservations, and untyped third-party CSECT bytes are never promoted to code merely because their bytes happen to decode as opcodes.

This is deliberately stricter than raw linear disassembly.

## Control-transfer model

The static analyzer recognizes:

- `J` / `+J` — unconditional jump, no fallthrough;
- `JEQ`, `JGT`, `JLT` — conditional branch plus fallthrough;
- `JSUB` / `+JSUB` — call edge plus fallthrough continuation;
- `RSUB` — dynamic return terminator;
- ordinary instructions — fallthrough to the immediately adjacent typed instruction when one exists.

A direct control target is resolved only when it lands exactly on another typed instruction region.

Indirect (`@`) and indexed (`,X`) control transfers are intentionally not converted into static resolved edges. Base-relative branches can be resolved only when a concrete B-register value is supplied with `--base`.

## Reachability

Reachability starts at the execution address recorded by the linked-image manifest, not merely at PROGADDR.

The analyzer follows only resolved static edges. Instructions outside that proven closure are marked `UNREACHABLE`.

This is a conservative statement:

> `UNREACHABLE` means "not reachable from the known entry through the statically provable edges represented by this analysis."

It does **not** mean the CPU can never execute that address. Dynamic indirect jumps, indexed jumps, computed return addresses, self-modifying code, or other runtime behavior may add edges that a static SIC/XE image cannot prove.

## Basic blocks

A new basic block begins at:

- the typed execution entry;
- a resolved jump/branch/call target;
- the fallthrough continuation after a conditional branch or call;
- the first typed instruction in each section;
- any instruction following a control-transfer terminator;
- any instruction separated from the previous typed instruction by a non-code gap.

Blocks are assigned deterministic IDs (`B000`, `B001`, ...), ordered by input, section, and loaded address.

The text report includes block ranges, section identity, reachability, decoded instructions, original-source provenance, and graph edges.

## Edge model

Instruction-level edges carry:

- source address;
- optional target address;
- kind (`fallthrough`, `branch`, `jump`, `call`, `return`);
- whether the target resolves to typed code;
- source/target basic-block IDs where available;
- a reason for unresolved edges (`indirect`, `indexed`, `unresolved-addressing`, `outside-typed-code`, or `dynamic-return`).

This structure is also available through `--json`.

## Graphviz output

`--dot` emits deterministic Graphviz DOT with one node per basic block and resolved block-to-block edges:

```text
python sicxe.py cfg program.bin --manifest program.manifest.json --dot > program.dot
```

The DOT output is intentionally presentation-light; the JSON report remains the complete machine-readable representation.

## Provenance integration

CFG instruction records inherit the same provenance as typed disassembly:

- original source line;
- outermost macro invocation line;
- nested macro definition/body/call-site stack;
- expanded-source line;
- symbols at the instruction address.

This makes a graph edge traceable not only to a loaded address but back through assembler and macro expansion history.

## Scope

The CFG is a static structural aid, not an emulator and not a full decompiler. It does not model register values in general, execute conditions, infer indirect targets from dataflow, or synthesize return edges from the L register. Those would require a separate abstract-interpreter/emulator layer.
