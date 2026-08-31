# Liveness and function analysis

The typed CFG now exposes compiler-style backward liveness and conservative function objects without changing assembler, linker, object, image, manifest, or golden-output contracts.

## Register/value liveness

The liveness domain contains:

```text
A X L B S T CC
```

Each typed instruction receives:

- `uses` — tracked values read by the instruction;
- `defs` — tracked values overwritten by the instruction;
- `live_in` / `live_out` — backward fixed-point liveness sets;
- `dead_writes` — general-register definitions whose produced value is not live after the instruction;
- `dead_condition_write` — the analogous condition-code fact;
- `memory_read`, `memory_write`, `side_effects`, and `opaque_liveness` annotations.

A `dead_writes` result does **not** mean the whole instruction can be removed. Stores, I/O, calls, control transfers, traps, and other side effects remain semantically relevant even when one produced register value is dead.

The analysis is deliberately conservative at unknown exits. `RSUB`, unresolved control transfers, and typed dead ends expose every tracked value to an unknown external observer. Therefore a reported dead write must be killed before any represented successor can use it; the analyzer never assumes an ABI or invisible caller behavior.

Calls are summarized as single caller-side operations for liveness. A resolved callee summary limits which registers may be overwritten, but without a calling convention the callee may consume any incoming general register. Unresolved calls use and define the full tracked domain.

Addressing dependencies are explicit: indexed instructions use X and base-relative instructions use B. Conditional branches use CC. `RSUB` uses L.

## Function objects

Function entries are:

1. the linked manifest execution entry when it is typed code; and
2. every statically resolved `JSUB/+JSUB` target.

A function body is the resolved **non-call** CFG closure from that entry. Nested calls remain call sites inside the caller rather than pulling the callee body into the caller. Synthetic call-context return edges are structural interprocedural evidence and are excluded from body traversal.

The analyzer intentionally permits shared tails. If two resolved function entries jump into the same typed tail, those instructions may belong to both function objects. This is safer than forcing an arbitrary unique partition.

Each function object exposes:

- stable ID (`F000`, `F001`, ...);
- entry address/block, section, and symbols;
- `instruction_addresses` and block IDs;
- `call_sites`, `return_sites`, callers, and callees;
- transitive `may_clobber` and complementary `preserved` general registers;
- entry `live_in` requirements;
- dead-write sites;
- per-function block/edge/component counts, decision points, and cyclomatic complexity.

Call records are enriched with `caller_functions` and `callee_function`, and instruction/block records expose their function ownership.

## Trust boundary

This is static machine-code analysis, not ABI inference or decompilation. In particular:

- indirect/indexed unresolved control targets are not invented;
- no parameter/return-register convention is assumed;
- unknown privileged operations conservatively use/define all tracked values;
- floating-point, PC, SW, device, and arbitrary memory values remain outside the general-register liveness domain except for side-effect annotations;
- shared-tail ownership is allowed rather than guessed away;
- dead-register-write evidence is not automatically promoted into source rewriting or binary optimization.
