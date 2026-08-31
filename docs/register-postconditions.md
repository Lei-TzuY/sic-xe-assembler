# Register return postconditions

The CFG enrichment layer now infers caller-independent register facts at resolved subroutine returns and feeds those facts back into caller dataflow.

This is an analysis-only capability. It does not alter assembler output, object records, linked image bytes, manifests, INPUTSET, LINKID, DEBUGID, or the historical CFG core.

## Summary domain

For each resolved callee entry the analyzer may publish:

- `return_constants`: exact 24-bit register values that agree at every represented `RSUB`.
- `return_ranges`: signed 24-bit interval hulls when all represented returns have a known interval but exact values disagree.
- `return_conditions`: a condition-code set when every represented return has known CC information.
- `return_value_registers`: the registers with an exact or interval postcondition.

The existing structural fields such as `may_clobber`, `preserved`, `return_sites`, and `link_register_preserved` remain authoritative for control-transfer safety.

## Caller-independent inference

A function summary starts with all ordinary registers and CC unknown at the callee entry. The summary therefore cannot accidentally capture a value that happens to be true at one caller.

For example:

```asm
ROUTN LDA #7
      RSUB
```

can prove `A=7` at return, while:

```asm
ROUTN LDA SLOT
      RSUB
```

cannot become `A=7` merely because one caller stored 7 into `SLOT` before the call.

The local summary pass intentionally uses register/immediate transfer semantics rather than caller-specific reaching-memory facts. Linked-image initialized-memory reasoning remains a separate trust domain.

## Exact and range returns

If all represented returns agree exactly:

```text
return_constants: A=000007
return_ranges:    A=[7,7]
```

If exact values differ but every return has a bounded interval, the analyzer keeps the interval hull:

```text
return_constants: -
return_ranges:    A=[1,2]
```

If one represented return leaves a register unknown, no postcondition is invented for that register.

## Nested composition

Resolved nested callees participate in a fixed point. If an inner callee proves `A=9`, an outer body can use that fact for subsequent register-only arithmetic and may infer a stronger outer return summary.

Nested composition does not by itself prove that the outer callee returns normally. A nested `JSUB` directly writes `L`, so the existing structural `link_register_preserved` proof remains required before a caller consumes the outer return postcondition.

## Link-register gate

A represented `RSUB` means the instruction exists; it does not prove that its `L` value still points at the caller continuation.

Caller-side return constants/ranges are therefore consumed only when the structural summary also reports:

```text
link_register_preserved=true
```

This keeps value reasoning subordinate to the established synthetic-return proof.

## Caller feedback

After summaries converge, they are applied to the existing memory-aware exact/range analysis. This enables patterns such as:

```asm
      +JSUB ROUTN
      COMP #7
      JEQ GOOD
```

when `ROUTN` proves `A=7`. The compare yields `CC=EQ` and the impossible conditional edge can be pruned with explicit `register-postcondition-condition` provenance.

Range-only facts similarly use `register-postcondition-range-condition`.

A proven returned `B` value may also re-decode an unresolved base-relative instruction. Exact and singleton-range resolutions are reported as:

```text
register-postcondition-base
register-postcondition-range-base
```

If such a target changes, instruction edges and proof-based synthetic returns are rebuilt and the register-postcondition fixed point runs again.

## Conservatism

The analysis intentionally degrades to unknown instead of guessing when:

- any represented return lacks a register/range fact,
- a caller-specific memory load is the only source of a value,
- a nested callee does not have a usable return proof,
- a base-relative operand cannot be decoded from a proven B value,
- or a return path cannot be represented safely.

May-clobber summaries, liveness, reaching definitions, memory provenance, and return-value summaries remain separate evidence layers.
