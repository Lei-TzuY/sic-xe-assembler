# Control-flow, static dataflow, and graph analysis

The toolchain builds a conservative control-flow graph (CFG) from linked images when typed debug metadata is available, then enriches it with must-constant register propagation, dominators, natural loops, call sites, and structural complexity metrics.

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

Only regions explicitly typed as `instruction` are nodes. `WORD`, `BYTE`, literals, reservations, and untyped third-party CSECT bytes are never promoted to code merely because their bytes happen to decode as opcodes.

## Control-transfer model

The analyzer recognizes:

- `J` / `+J` — unconditional jump, no fallthrough;
- `JEQ`, `JGT`, `JLT` — conditional branch plus fallthrough;
- `JSUB` / `+JSUB` — call edge plus fallthrough continuation;
- `RSUB` — dynamic return terminator;
- ordinary instructions — fallthrough to the immediately adjacent typed instruction in the same CSECT.

A direct target is resolved only when it lands exactly on another typed instruction region. Fallthrough never crosses a control-section boundary.

Indirect (`@`) and indexed (`,X`) control transfers are intentionally not fabricated as static edges.

## Must-constant register dataflow

The analysis tracks provable 24-bit constants for:

```text
A X L B S T
```

The lattice is deliberately strict: at a merge, a register remains constant only when **every reachable predecessor proves the same value**. A conflicting value or any unknown predecessor makes the merged value unknown.

Supported transfer facts include:

- immediate `LDA/LDB/LDL/LDS/LDT/LDX`;
- `CLEAR`;
- `RMO`;
- constant `ADDR/SUBR/MULR/DIVR`;
- immediate `ADD/SUB/MUL/DIV/AND/OR` when A is already known;
- `TIX/TIXR` increment of a known X;
- `JSUB` setting L to the return address.

Memory-dependent loads and arithmetic become unknown. Shift operations are conservatively treated as clobbering their destination rather than baking an uncertain shift-semantics assumption into the analyzer. `SVC` and `LPS` invalidate all tracked register constants.

A call edge receives the state at the call site. The synthetic caller fallthrough used to model possible return continuation is deliberately clobbered to unknown, because the toolchain assumes no calling convention that would preserve registers across an arbitrary subroutine.

### Runtime B-register resolution

This dataflow closes a major gap in static SIC/XE disassembly: base-relative control transfers no longer require a global manually supplied B value when the program itself proves B.

For example:

```asm
     +LDB #FAR
     BASE FAR
     J FAR
     RESB 4096
FAR  RSUB
```

The linked extended `LDB` proves the runtime B value. The analyzer then re-decodes the b-relative `J`, resolves its actual loaded target, rebuilds CFG edges, recomputes dataflow, and iterates until target resolution reaches a fixed point.

A target resolved this way is marked:

```text
target-resolution=dataflow-base
```

The assembler `BASE` directive itself is **not** treated as runtime register state; it only controls encoding. Static resolution depends on machine instructions that actually establish B, or on an explicit initial `--base` assumption.

If two paths establish different B values before a merge, B becomes unknown and the later b-relative target remains unresolved.

## Reachability

Reachability starts at the execution address recorded by the linked-image manifest, not merely at PROGADDR.

The analyzer follows only resolved static edges. Instructions outside that proven closure are marked `UNREACHABLE`.

This is a conservative statement:

> `UNREACHABLE` means "not reachable from the known entry through the statically provable edges represented by this analysis."

It does **not** mean the CPU can never execute that address. Dynamic indirect/indexed jumps, computed returns, self-modifying code, or other runtime behavior may add edges that a static image cannot prove.

## Basic blocks

A new basic block begins at:

- the typed execution entry;
- a resolved jump/branch/call target;
- the fallthrough continuation after a conditional branch or call;
- the first typed instruction in each section;
- any instruction following a control-transfer terminator;
- any instruction separated from the previous typed instruction by a non-code gap.

Blocks receive deterministic IDs (`B000`, `B001`, ...), ordered by input, section, and loaded address.

Each block records predecessor/successor block IDs and its dominator set.

## Dominators

Dominators are computed over the complete resolved reachable block graph rooted at the manifest entry block. Call edges participate in this whole-program dominance relation.

For every reachable block `B`, the JSON report exposes the blocks that dominate `B`. The entry block dominates every reachable block in an ordinary single-entry graph.

## Back edges and natural loops

A resolved non-call edge `U -> H` is a back edge when `H` dominates `U`.

For each back edge, the analyzer constructs the corresponding natural loop by walking non-call predecessors backward from the latch to the header. The report includes:

- loop header block;
- latch block;
- member blocks;
- the underlying back edge.

Call edges are excluded from loop formation.

## Call graph

Every `JSUB/+JSUB` produces a call-site record containing:

- caller address/block/CSECT;
- target address/block when statically resolved;
- callee CSECT;
- symbols beginning at the target;
- unresolved reason when the target cannot be proved;
- whether target recovery depended on dataflow-resolved B.

Return edges remain dynamic because `RSUB` obtains its destination from L; the analyzer does not invent a return target.

## Structural metrics

The report exposes:

- reachable basic-block count;
- resolved intraprocedural edge count;
- weak component count after excluding call edges;
- decision-point count;
- natural-loop count;
- McCabe-style cyclomatic complexity.

For reachable blocks, complexity is:

```text
M = E - N + 2P
```

where `E` is the number of resolved non-call block edges, `N` is reachable block count, and `P` is the number of weakly connected components in that non-call graph. Excluding call edges avoids counting a subroutine invocation itself as a branch decision; disconnected caller/callee components contribute their own baseline complexity.

## Edge model

Instruction-level edges carry:

- source address;
- optional target address;
- kind (`fallthrough`, `branch`, `jump`, `call`, `return`);
- whether the target resolves to typed code;
- source/target basic-block IDs where available;
- unresolved reason (`indirect`, `indexed`, `unresolved-addressing`, `outside-typed-code`, or `dynamic-return`);
- target-resolution provenance such as `dataflow-base`.

This structure, register facts, dominators, loops, calls, and metrics are all available through `--json`.

## Graphviz output

`--dot` emits deterministic Graphviz DOT with one node per basic block and resolved block-to-block edges:

```text
python sicxe.py cfg program.bin --manifest program.manifest.json --dot > program.dot
```

Loop-member blocks are annotated in their labels. Edges resolved from a proven B constant retain `dataflow-base` in the edge label. The JSON report remains the complete machine-readable representation.

## Provenance integration

CFG instruction records inherit the same provenance as typed disassembly:

- original source line;
- outermost macro invocation line;
- nested macro definition/body/call-site stack;
- expanded-source line;
- symbols at the instruction address.

Source-aware disassembly with `--cfg` additionally prints proven incoming register constants and target-resolution annotations beside the machine instruction.

## Scope

This remains a static abstract interpretation, not an emulator or decompiler. It proves a narrow set of constant register facts and structural edges; it does not model memory contents, evaluate branch conditions, infer arbitrary indirect/indexed targets, assume a calling convention, or synthesize dynamic RSUB return edges. Unknown information stays unknown rather than being guessed.
