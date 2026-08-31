# Control-flow, abstract values, and interprocedural analysis

The toolchain builds a conservative typed control-flow graph (CFG) from linked images, then layers exact constants, signed 24-bit intervals, condition reasoning, runtime base recovery, compositional subroutine summaries, proven return edges, dominators, loops, call metadata, and structural metrics on top.

```text
python sicxe.py cfg program.bin --manifest program.manifest.json
python sicxe.py cfg program.bin --manifest program.manifest.json --json
python sicxe.py cfg program.bin --manifest program.manifest.json --dot
python sicxe.py disasm program.bin --manifest program.manifest.json --cfg
```

Only `.debug.json` regions explicitly typed as instructions become CFG nodes. Data, literals, reservations, and untyped third-party bytes are never promoted to code merely because they decode as opcodes.

## Control-transfer model

The structural graph recognizes direct `J`, `JEQ/JGT/JLT`, `JSUB`, `RSUB`, and ordinary same-CSECT fallthrough. Indirect (`@`) and indexed (`,X`) transfers remain unresolved rather than being guessed. Fallthrough never crosses a control-section boundary.

`RSUB` always retains its hardware-level unresolved `dynamic-return` edge. Later interprocedural analysis may add additional context-specific resolved return edges without deleting that dynamic truth.

## Exact must-constant domain

The exact domain tracks 24-bit constants for:

```text
A X L B S T
```

plus condition code:

```text
LT EQ GT unknown
```

A value survives a merge only when every reachable predecessor proves the same value. Supported transfer facts include immediate loads, `CLEAR`, `RMO`, selected register arithmetic, selected immediate accumulator arithmetic, `TIX/TIXR`, and `JSUB` setting L to the continuation address. Memory-dependent or unsupported writes degrade to unknown.

`COMP`, `COMPR`, `TIX`, and `TIXR` can prove CC when their operands are provable. Impossible `JEQ/JLT/JGT` branch or fallthrough edges are then marked `condition-false` with `abstract-condition` provenance.

## Signed 24-bit interval domain

The second domain keeps a conservative convex interval for each tracked register. It uses signed two's-complement bounds:

```text
-8388608 .. 8388607
```

The exact API remains unchanged: `registers_in/out` still contain either an exact raw 24-bit value or `None`. Interval information is exposed separately as `ranges_in/out`.

At a merge, two known ranges join by convex hull. For example two paths that establish `A=1` and `A=2` produce:

```text
exact A = unknown
range A = [1,2]
```

That range can still prove:

```asm
COMP #10
JLT  TARGET
```

because every possible A value is less than 10. The fallthrough becomes `condition-false` with `abstract-range-condition` provenance even though no exact A constant exists.

The interval CC may also be a proper subset such as `{LT,EQ}`. A later `JGT` can therefore be ruled out while `JEQ` cannot.

### Arithmetic safety

Intervals are propagated only when the result is representable as one sound signed 24-bit convex interval. If arithmetic may cross two's-complement wrap, the result becomes unknown instead of inventing a misleading range.

This rule is intentionally strict. For example `[0x7FFFFF,0x7FFFFF] + 1` does not become `[-8388608,-8388608]` in the interval domain; it becomes unknown because the current domain does not model modular non-convex wrap sets.

`AND #mask` can narrow an unknown A to `[0,mask]` when the mask does not set the sign bit. This allows useful facts to emerge even after a memory-dependent load.

## Runtime B recovery from either domain

Exact B constants continue to resolve b-relative instructions with:

```text
target-resolution=dataflow-base
```

A singleton interval can now resolve the same target even when the exact lattice is unknown:

```asm
LDA VALUE      ; exact/range A unknown
AND #0         ; exact A unknown, range A=[0,0]
RMO A,B        ; exact B unknown, range B=[0,0]
BASE MAIN
J FAR
```

The resulting target is marked:

```text
target-resolution=range-singleton-base
```

Only a singleton interval is usable as an address. A wider interval never uses its midpoint or endpoints as a guessed B value. Range-owned target resolutions are revoked if a later fixed-point iteration widens B.

The assembler `BASE` directive is never treated as runtime register state; it only explains the chosen encoding.

## Compositional subroutine summaries

Every resolved call target receives a may-write summary. The analyzer first records direct writes in the callee, then composes resolved nested-callee summaries to a monotone fixed point.

Each summary exposes:

- `direct_clobbers`;
- transitive `may_clobber`;
- `preserved` registers;
- `nested_callees`;
- unresolved nested call sites;
- visible `RSUB` sites;
- visited instruction addresses;
- `may_return`;
- `link_register_preserved`.

A nested `JSUB` directly writes only L. Its callee's proven clobbers are then added transitively. Thus an outer routine calling an inner routine that only modifies A can still prove B preserved instead of falling back to global clobber.

Unknown/unresolved calls remain fully opaque and may clobber every tracked register. Recursive call cycles converge because may-clobber sets only grow.

CC preservation is never claimed across calls.

## Proven interprocedural return edges

A resolved call has a known continuation because `JSUB` writes L to the address following the call. A callee summary can therefore prove a particular `RSUB` returns to that continuation when all of the following hold:

1. the call target is resolved typed code;
2. the callee exposes an `RSUB` return site;
3. no reachable callee instruction may write L;
4. the caller continuation is a typed instruction.

The graph then keeps the original unresolved edge:

```text
RSUB --return--> ? [dynamic-return]
```

and adds a context-specific edge:

```text
RSUB --return--> CONT [resolved/link-register-summary]
```

Synthetic return edges contain `synthetic_return=true`, `call_source`, and `callee_entry` metadata. They participate in whole-program predecessor/successor and DOT output, but **do not feed context-free register/range propagation**. Caller continuation state is already propagated through the call summary, so mixing raw callee state into every caller would be unsound.

Synthetic returns are also excluded from intraprocedural natural-loop and McCabe calculations, just like call edges. A callee that writes L, performs a nested `JSUB`, or otherwise cannot prove the link register untouched does not receive a synthetic return edge.

## Condition-sensitive fixed point

Exact CC pruning, interval CC pruning, and base-target recovery are iterated until stable. Removing an impossible edge can tighten later joins; tighter joins can prove additional constants/ranges; those facts can in turn resolve more control targets.

The process is monotone and fail-conservative: unknown information stays unknown, and target/condition provenance records which domain supplied each proof.

## Reachability and basic blocks

Reachability begins at the manifest's real execution entry. Only resolved feasible edges are followed. `UNREACHABLE` therefore means "not reachable through the statically provable graph represented by this analysis", not "physically impossible at runtime"; unresolved indirect jumps, self-modifying code, and other dynamic behavior can still add paths.

Basic blocks use deterministic IDs (`B000`, `B001`, ...). Blocks record predecessors, successors, reachability, and dominators. Instruction-level sequential fallthrough inside one block is retained for dataflow but is not counted as a separate block-graph edge.

## Dominators, loops, calls, and complexity

Dominators operate over the resolved reachable whole-program graph. Natural-loop detection excludes call and synthetic-return edges. A non-call/non-synthetic-return edge `U -> H` is a back edge when H dominates U.

Call records include target symbols, continuation address, callee summary, proven return sites, and whether interprocedural returns were resolved.

McCabe-style complexity uses only reachable resolved intraprocedural block edges:

```text
M = E - N + 2P
```

Calls and synthetic returns are excluded so procedure linkage itself is not counted as a branch decision.

## Reports

Text output includes exact and range facts, edge proof provenance, subroutine summaries, calls, loops, and metrics. JSON retains all structures directly. DOT renders resolved block edges, including proven interprocedural returns.

Source-aware `disasm --cfg` annotates exact incoming register constants, non-singleton incoming ranges, possible CC sets, reachability/basic-block identity, and base-target proof provenance beside each typed instruction.

## Scope

This is a static abstract interpreter, not an emulator or decompiler. The interval domain is intentionally convex and signed-24-bit; it does not model arbitrary modular sets or memory contents. Return resolution is intentionally proof-based and context-limited; dynamic `RSUB` semantics are never erased. Unknown indirect/indexed targets, untyped bytes, opaque calls, and unsupported machine effects remain unknown rather than being guessed.
