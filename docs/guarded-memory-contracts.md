# Guarded memory contracts

Guarded call summaries now distinguish three memory outcomes for every cell in a function's guarded memory contract:

```text
identity        the return value is exactly the call-entry value of this cell
unknown         the return value is not representable safely
symbolic-linear the return value is a bounded sparse linear expression
```

The summary field `memory_contract_cells` is the finite set of tracked cells that the function may write.  Every guarded return case carries one explicit `memory_outputs[cell]` entry for each of these cells.  Cells outside the contract remain structurally preserved by the existing memory-effect summary.

This removes the older ambiguity where an omitted memory output could mean either "unchanged" or "unknown".  In particular, a conditional write such as:

```asm
MAYSET COMP #0
       JEQ KEEP
       LDX #7
       STX SLOT
KEEP   RSUB
```

can be represented as:

```text
A_in == 0  -> MEM[SLOT]_out = identity
A_in != 0  -> MEM[SLOT]_out = 7
```

A caller that proves `A=0` can therefore retain its incoming `SLOT` constant.  A caller for which both cases remain feasible joins the identity value with `7`; no exact fact is invented unless all feasible cases agree.

An `unknown` case is different from identity.  If a selected path performs an unrepresentable write, the caller receives no exact/range postcondition for that cell and the existing may-write summary remains authoritative.

## Nested guarded composition

A guarded function may consume another guarded callee during summary inference when all of the following hold:

- the nested call target is resolved;
- the callee has a supported bounded guarded summary;
- the callee has `link_register_preserved=true`;
- every callee guard can be substituted into the caller's current symbolic register/memory state.

The analyzer then forks only over the callee's already-bounded guarded cases.  It does **not** inline the callee CFG.  Callee guards are rewritten in terms of the outer function's entry roots, and register/memory case outputs are substituted into the outer symbolic state.

Each resulting outer case records `nested_cases` provenance containing the call source, callee entry, and selected callee case id.  The outer summary also reports `guarded_nested_composed_calls`.

Composition remains subject to the global guarded bounds:

- at most 8 retained return cases per function;
- at most 128 explored path states per function;
- loops/revisits disable guarded summarization for that function;
- failed nested guard substitution falls back to the existing must-summary;
- unproven link-register preservation blocks guarded nested consumption;
- range wrap, unknown aliases, and unrepresentable symbolic operations remain fail-conservative.

Nested composition does not change the structural return proof.  An outer function containing `JSUB` can therefore gain a precise guarded summary for reporting/composition while still remaining unconsumable by its own callers when `link_register_preserved=false`.

This layer changes only static-analysis metadata.  Assembly, object records, relocation, linking, linked images, manifests, INPUTSET/LINKID, and historical golden artifacts are unchanged.
