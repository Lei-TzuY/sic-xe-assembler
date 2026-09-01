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

## Structural path authority

Reusable guarded cases are inferred from a pristine structural CFG rebuilt from the decoded instructions. Their path existence, return sites, `may_return`, and `link_register_preserved` facts are never inherited from a caller-specialized summary produced by an earlier exact/range pass.

This separation is essential. Earlier layers are allowed to prune a callee path when a particular caller proves a condition. Reusing that pruned return shape as a caller-independent function contract would silently erase valid return cases for other callers. Guarded inference therefore treats earlier summaries only as value-transfer hints; pristine structural control-flow facts are authoritative.

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

The first public case schema deliberately omits both unchanged identity outputs and unknown outputs. Consequently a missing memory cell is ambiguous: it may mean `MEM[X]_out = MEM[X]_in`, or it may mean that the path cannot represent a precise value. Until those states have distinct serialization, a guarded memory postcondition is written back into caller must-memory only when that cell has an explicit output formula on every guarded return case. Partial conditional writes therefore remain conservative.

## Call-site evaluation

For each resolved `JSUB` with `link_register_preserved=true`, the analyzer evaluates every guard with:

1. exact register facts;
2. signed 24-bit register ranges;
3. exact direct-memory must values; and
4. direct-memory must ranges.

An exact comparison can choose one case immediately. Interval comparison can also remove impossible cases. Unknown comparisons keep the case feasible rather than guessing.

When multiple cases remain:

- an exact register output is retained only when every feasible case produces the same exact value;
- a register range output is the sound hull of every feasible case when every case has a representable interval;
- a direct-memory output is consumable only when that cell is explicitly represented on every guarded return case, in addition to the same exact/range agreement rules;
- an unknown or ambiguous output prevents a must-value claim.

This allows an input range to select a branch even when the caller has no exact constant. For example `A_in in [0,1]` proves `A_in < 10`, so only the `<10` return case remains.

## CFG feedback

Selected guarded outputs are merged with the already established symbolic-memory-input call-site instantiation, then fed through the existing memory-aware exact/range passes. They can therefore:

- prove caller comparisons and prune impossible branches;
- return path-specific direct-memory values when every guarded return explicitly defines the cell, allowing later loads to consume the selected value; and
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
- Structural path facts always come from the pristine instruction CFG, never from caller-specific pruning.
- All underlying symbolic expressions still obey the combined four-root sparse term budget.
- Signed 24-bit range wrap degrades to unknown.
- Indexed/indirect/unresolved aliases retain the previous fail-conservative memory behavior.
- A guarded memory cell is written back only when every guarded return case explicitly represents that cell.
- Call-site consumption remains gated by the existing structural `link_register_preserved` proof.

Loops, richer boolean/path constraint simplification, explicit identity-vs-unknown memory outputs, and guarded nested-callee composition can be added later without changing the public meaning of the existing must-summary layers.

## Public report fields

The new layer is additive:

```text
guarded_transfer_summaries
guarded_transfer_instantiations
guarded_transfers
```

Existing register, memory, sparse-linear, and symbolic-memory-input summary schemas remain unchanged.

The assembler, object format, linker, linked image, manifest, INPUTSET/LINKID, and historical golden artifacts are outside this analysis-only layer.
