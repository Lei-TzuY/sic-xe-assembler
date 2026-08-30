# Control-flow, static dataflow, and graph analysis

The toolchain builds a conservative control-flow graph (CFG) from linked images when typed debug metadata is available, then enriches it with must-constant register and condition-code propagation, condition-sensitive branch pruning, conservative subroutine summaries, dominators, natural loops, call sites, and structural complexity metrics.

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
- `JEQ`, `JGT`, `JLT` — conditional branch plus fallthrough unless condition analysis proves one edge impossible;
- `JSUB` / `+JSUB` — call edge plus possible return continuation;
- `RSUB` — dynamic return terminator;
- ordinary instructions — fallthrough to the immediately adjacent typed instruction in the same CSECT.

A direct target is resolved only when it lands exactly on another typed instruction region. Fallthrough never crosses a control-section boundary.

Indirect (`@`) and indexed (`,X`) control transfers are intentionally not fabricated as static edges.

## Must-constant register and condition dataflow

The analysis tracks provable 24-bit constants for:

```text
A X L B S T
```

and an abstract SIC/XE condition code:

```text
LT EQ GT unknown
```

The lattice is deliberately strict: at a merge, a register or condition remains known only when **every reachable predecessor proves the same value**. A conflicting value or any unknown predecessor makes the merged value unknown.

Supported register transfer facts include:

- immediate `LDA/LDB/LDL/LDS/LDT/LDX`;
- `CLEAR`;
- `RMO`;
- constant `ADDR/SUBR/MULR/DIVR`;
- immediate `ADD/SUB/MUL/DIV/AND/OR` when A is already known;
- `TIX/TIXR` increment of a known X;
- `JSUB` setting L to the return address.

Condition-code facts are produced conservatively by:

- immediate `COMP` when A and the immediate operand are known;
- `COMPR` when both compared registers are known;
- immediate `TIX` when the incremented X and immediate operand are known;
- `TIXR` when incremented X and the compared register are known.

The comparison uses 24-bit two's-complement ordering. Memory-dependent comparisons remain unknown. `TD` and floating compare state are treated as unknown rather than guessed.

Memory-dependent loads and arithmetic become unknown. Shift operations are conservatively treated as clobbering their destination rather than baking an uncertain shift-semantics assumption into the analyzer. `SVC` and `LPS` invalidate the tracked abstract state.

### Condition-sensitive branch pruning

When a conditional branch receives a proven condition code, impossible edges are removed from the resolved graph:

```asm
     LDA  #5
     COMP #5
     JEQ  TAKEN
DEAD LDA  #9
TAKEN RSUB
```

The abstract state before `JEQ` proves `CC=EQ`. The branch edge remains feasible and the fallthrough edge is marked:

```text
reason=condition-false
resolution=abstract-condition
```

`DEAD` therefore becomes unreachable, and dominators/loops/complexity consume the pruned graph.

The reverse case is handled too: if `CC=LT` or `CC=GT`, a `JEQ` branch itself is pruned while its fallthrough remains feasible.

No pruning occurs when the condition is unknown. A memory-based `COMP`, conflicting predecessor conditions, or any unsupported comparison leaves both conditional edges in the graph.

## Conservative subroutine summaries

Resolved `JSUB/+JSUB` targets receive a local may-write summary. Starting at the callee entry, the analyzer follows resolved non-call control flow until visible `RSUB` sites and records which tracked registers may be written.

A register is listed as **preserved** only if no visited callee instruction may write it. Registers with any possible write are listed under `may_clobber`.

For example, a subroutine containing only:

```asm
ROUTN LDA #1
      RSUB
```

may clobber A but preserves X/L/B/S/T. A caller with a previously proven B value can therefore retain B across that call and continue resolving later base-relative control transfers.

A subroutine that executes `CLEAR B` cannot preserve B, so the caller's post-return B fact becomes unknown.

Nested calls are deliberately treated as opaque by this local summary model: encountering a nested `JSUB` marks every tracked caller-visible register as potentially clobbered. This avoids inventing a calling convention or recursively assuming preservation that has not been proven.

Condition-code preservation is never claimed by these summaries; caller continuation receives unknown CC after a call.

The structured CFG JSON exposes each resolved call node's `call_summary`, including:

- callee entry address and symbols;
- `preserved` registers;
- `may_clobber` registers;
- visible `RSUB` return sites;
- visited instruction addresses;
- whether a visible return was found.

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

The assembler `BASE` directive itself is **not** treated as runtime register state; it only controls encoding. Static resolution depends on machine instructions that actually establish B, on a conservative post-call preservation summary, or on an explicit initial `--base` assumption.

If two paths establish different B values before a merge, B becomes unknown and the later b-relative target remains unresolved.

## Reachability

Reachability starts at the execution address recorded by the linked-image manifest, not merely at PROGADDR.

The analyzer follows only resolved and condition-feasible static edges. Instructions outside that proven closure are marked `UNREACHABLE`.

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

Dominators are computed over the condition-pruned resolved reachable block graph rooted at the manifest entry block. Call edges participate in this whole-program dominance relation.

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

The separate local `call_summary` attached to the call instruction controls only which proven register constants can safely survive into the caller's synthetic return continuation.

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

where `E` is the number of resolved non-call block edges, `N` is reachable block count, and `P` is the number of weakly connected components in that non-call graph. Condition-proven impossible edges are excluded automatically. Excluding call edges avoids counting a subroutine invocation itself as a branch decision; disconnected caller/callee components contribute their own baseline complexity.

## Edge model

Instruction-level edges carry:

- source address;
- optional target address;
- kind (`fallthrough`, `branch`, `jump`, `call`, `return`);
- whether the target resolves to typed code;
- source/target basic-block IDs where available;
- unresolved reason (`indirect`, `indexed`, `unresolved-addressing`, `outside-typed-code`, `dynamic-return`, or `condition-false`);
- target-resolution provenance such as `dataflow-base` or `abstract-condition`;
- proven condition metadata when branch feasibility is known.

This structure, register/CC facts, call summaries, dominators, loops, calls, and metrics are all available through `--json`.

## Graphviz output

`--dot` emits deterministic Graphviz DOT with one node per basic block and resolved block-to-block edges:

```text
python sicxe.py cfg program.bin --manifest program.manifest.json --dot > program.dot
```

Loop-member blocks are annotated in their labels. Edges resolved from a proven B constant retain `dataflow-base` in the edge label. Condition-pruned edges are absent from the resolved block graph. The JSON report remains the complete machine-readable representation.

## Provenance integration

CFG instruction records inherit the same provenance as typed disassembly:

- original source line;
- outermost macro invocation line;
- nested macro definition/body/call-site stack;
- expanded-source line;
- symbols at the instruction address.

Source-aware disassembly with `--cfg` additionally prints proven incoming register constants and target-resolution annotations beside the machine instruction. Structured JSON retains the full condition-code state and call summaries.

## Scope

This remains a static abstract interpretation, not an emulator or decompiler. It proves a narrow set of constant register/condition facts and structural edges; it does not model arbitrary memory contents, infer arbitrary indirect/indexed targets, assume a calling convention, recursively solve nested-call summaries, or synthesize dynamic RSUB return edges. Unknown information stays unknown rather than being guessed.
