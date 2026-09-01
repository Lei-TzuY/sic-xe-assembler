# Guarded condition-code contracts

The guarded interprocedural layer now treats the SIC/XE condition code as an
explicit per-case return postcondition, alongside guarded register and memory
outputs.

## Case schema

Each supported `guarded_case` carries `condition_values`:

- `["EQ"]`, `["LT"]`, or `["GT"]` means the return path proves one condition.
- A proper subset such as `["LT", "GT"]` means the path proves a bounded set.
- `null` means the path's final condition code is unknown.

The order is deterministic: `LT`, `EQ`, `GT`.

The condition belongs to the final represented state at the case's `RSUB`.
`COMP` and `COMPR` establish a symbolic comparison. A following `JEQ`, `JLT`,
or `JGT` narrows the path's condition set. Instructions whose CC effect is not
represented precisely (`TIX`, `TIXR`, `TD`, `COMPF`, `LPS`, `SVC`) invalidate
the condition contract instead of reusing an older comparison.

## Call-site instantiation

After the caller's exact/range register and direct-memory facts filter the
guarded cases, the remaining condition postconditions are joined:

- one value -> `condition_mode="exact"`, `exact_condition`, and a singleton
  `range_conditions`;
- multiple known values -> `condition_mode="set"` and `range_conditions`;
- any unknown selected case -> `condition_mode="unknown"` and no CC fact.

These fields live in `guarded_transfer_instantiation`.

The selected postcondition is fed into the same whole-program exact/range
fixed point as guarded register and memory outputs. Therefore a condition
returned by a callee may safely prune the caller's immediately following
`JEQ`/`JLT`/`JGT`. Exact pruning keeps the
`guarded-transfer-condition` provenance; set/range pruning keeps
`guarded-transfer-range-condition`.

## Nested guarded calls

When a resolved nested callee has a bounded guarded summary and preserves the
link register, each nested case carries its `condition_values` into the outer
path. The outer function can therefore branch on the returned CC without
inventing a symbolic comparison. The existing case/state budgets and
link-register gate still apply.

If the nested condition is unknown, the outer analysis fails conservative:
it cannot use that CC to choose an edge.

## Safety boundary

This layer changes static-analysis metadata only. It does not change assembly,
object records, relocation, linking, linked images, manifests, debug-map
identity, INPUTSET/LINKID, or historical golden outputs.
