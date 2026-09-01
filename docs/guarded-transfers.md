# Guarded transfer summaries

The analyzer can preserve a bounded set of path-specific return transfers instead of immediately joining different return paths to unknown.

## Why this layer exists

Earlier interprocedural layers intentionally use must summaries: a return constant or symbolic formula is reusable only when all represented returns agree. That is sound, but a small helper such as:

```asm
CHOOSE COMP #0
       JEQ ZERO
       LDA #2
       RSUB
ZERO   LDA #1
       RSUB
```

has no single `A_out` formula. The guarded layer records two bounded cases instead:

```text
if A_in == 0  -> A_out = 1
if A_in != 0  -> A_out = 2
```

A concrete `JSUB` evaluates the guards using its own exact/range register and direct-memory must-state. Cases that are provably impossible are removed. The remaining outputs are then joined soundly.

## Guard representation

A guard is stored as two existing `symbolic-linear` expressions plus an allowed condition-code set:

```json
{
  "left": {
    "kind": "symbolic-linear",
    "register_coefficients": {"A": 1},
    "memory_coefficients": {},
    "offset": 0,
    "modulus": 16777216
  },
  "right": {
    "kind": "symbolic-linear",
    "register_coefficients": {},
    "memory_coefficients": {},
    "offset": 0,
    "modulus": 16777216
  },
  "allowed": ["EQ"]
}
```

`JEQ`, `JLT`, and `JGT` branch/fallthrough edges become complementary allowed sets. For example the `JEQ` fallthrough is `{LT,GT}`, not an invented single relation.

The comparison operands can themselves depend on direct entry-memory roots, so a function that performs `LDA FLAG; COMP #0` can produce cases guarded by `MEM[FLAG]_in`.

## Case outputs

Each case can contain register and direct-memory outputs expressed in the same generic sparse symbolic domain used by memory-input summaries:

```text
C0 if A_in == 0 -> A_out=1, MEM[SLOT]_out=7
C1 if A_in != 0 -> A_out=2, MEM[SLOT]_out=9
```

Constants are represented as zero-term symbolic expressions, while register/memory-dependent outputs retain their sparse coefficients.

## Call-site evaluation

For each resolved `JSUB` with `link_register_preserved=true`, the analyzer evaluates every guard with:

1. exact register facts;
2. signed 24-bit register ranges;
3. exact direct-memory must values; and
4. direct-memory must ranges.

An exact comparison can choose one case immediately. Interval comparison can also remove impossible cases. Unknown comparisons keep the case feasible rather than guessing.

When multiple cases remain:

- an exact output is retained only when every feasible case produces the same exact value;
- a range output is the sound hull of every feasible case when every case has a representable interval;
- a missing/unknown output in any feasible case prevents an exact claim.

This allows an input range to select a branch even when the caller has no exact constant. For example `A_in in [0,1]` proves `A_in < 10`, so only the `<10` return case remains.

## CFG feedback

Selected guarded outputs are merged with the already established symbolic-memory-input call-site instantiation, then fed through the existing memory-aware exact/range passes. They can therefore:

- prove caller comparisons and prune impossible branches;
- return path-specific direct-memory values that later loads consume; and
- recover a path-specific B value for base-relative target resolution.

New proof provenance is used only when this layer is the first owner:

```text
guarded-transfer-condition
guarded-transfer-range-condition
guarded-transfer-base
guarded-transfer-range-base
```

Older target/edge proof ownership is snapshotted and restored. A later guarded pass never relabels a fact already proven by an earlier layer.

## Bounds and fail-conservative rules

This is deliberately not an unrestricted symbolic executor.

- At most eight distinct guarded return cases are retained.
- At most 128 path states are explored per function.
- A control-flow revisit/loop disables guarded summarization for that function.
- Guards are currently derived from symbolic `COMP`/`COMPR` state feeding `JEQ/JLT/JGT`.
- `TIX/TIXR` comparisons are not represented as guarded symbolic relations in this layer.
- If a conditional branch has no representable symbolic comparison, the guarded summary is disabled rather than made unconditional.
- All underlying symbolic expressions still obey the combined four-root sparse term budget.
- Signed 24-bit range wrap degrades to unknown.
- Indexed/indirect/unresolved aliases retain the previous fail-conservative memory behavior.
- Call-site consumption remains gated by the existing structural `link_register_preserved` proof.

Loops, richer boolean/path constraint simplification, and guarded nested-callee composition can be added later without changing the public meaning of the existing must-summary layers.

## Public report fields

The new layer is additive:

```text
guarded_transfer_summaries
guarded_transfer_instantiations
guarded_transfers
```

Existing register, memory, sparse-linear, and symbolic-memory-input summary schemas remain unchanged.

The assembler, object format, linker, linked image, manifest, INPUTSET/LINKID, and historical golden artifacts are outside this analysis-only layer.