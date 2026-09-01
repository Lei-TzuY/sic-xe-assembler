# Guarded register contracts

Guarded summaries now give conditionally clobbered registers the same explicit output semantics already used for guarded memory cells.

## Why explicit register modes are needed

A path-specific register output used to be omitted both when the register was unchanged and when its symbolic value became unknown. Those meanings are not interchangeable. Consider:

```asm
MAYSET COMP #0
       JEQ KEEP
       LDB #7
KEEP   RSUB
```

The structural summary correctly says that `B` may be clobbered, because one path writes it. But the `KEEP` path has a stronger fact: `B_out = B_in`. A caller that proves the `KEEP` guard should retain its incoming B value rather than degrading it to unknown.

## Contract register set

Each guarded function exposes `register_contract_registers`, the tracked registers in its pristine structural `may_clobber` set. Globally preserved registers remain governed by the existing structural summary and are not redundantly expanded into every guarded case.

Every guarded case contains an explicit output for every contract register:

```json
{
  "register_outputs": {
    "B": {"kind": "identity"}
  }
}
```

The three output forms are:

- `identity`: `R_out = R_in` on this guarded path;
- `unknown`: the path may return but no safe symbolic value for R survives;
- `symbolic-linear`: the existing bounded sparse symbolic expression over entry registers/memory.

Constants are represented by zero-term `symbolic-linear` expressions as before.

## Call-site instantiation

For each feasible guarded case, the caller evaluates register outputs against its own incoming exact/range register and direct-memory facts.

- selected `identity` reuses the caller's incoming exact/range value;
- selected `unknown` removes any exact/range claim for that register;
- selected symbolic output is evaluated with the existing 24-bit exact and signed-range rules.

If multiple cases remain feasible, exact values survive only when every case agrees and intervals use the existing sound hull rule. The call-site record exposes `register_modes` alongside `exact_registers` and `range_registers`.

This matters directly for control flow. If a caller has `B=0x4000`, selects an identity-B case, and then executes a base-relative jump, guarded refinement can retain B and resolve that target. Conversely, an unknown-B case cannot reuse the pre-call base.

## Nested guarded composition

Nested guarded callees use the same explicit register modes. During outer-summary construction:

- identity restores the nested call's incoming symbolic register expression;
- unknown kills that expression;
- symbolic output substitutes the outer symbolic state into the callee formula.

The existing `nested_cases` provenance, case/state budgets, and `link_register_preserved` gate remain unchanged. In particular, deriving an outer guarded value does not prove that an outer function with an unpreserved L register safely returns to its caller.

## Compatibility and safety

This change is additive to the guarded schema. Existing symbolic register outputs keep their existing serialization. The new `identity` and `unknown` kinds only make previously ambiguous missing outputs explicit for conditionally clobbered registers.

Structural `may_clobber`/`preserved` information is still derived from the pristine CFG, later analysis layers still preserve earlier proof ownership, and all alias, wrap, case-budget, path-budget, and loop fail-conservative rules continue to apply.

The assembler, object format, linker, linked image, manifest, INPUTSET/LINKID, and historical golden artifacts are outside this analysis-only change.
