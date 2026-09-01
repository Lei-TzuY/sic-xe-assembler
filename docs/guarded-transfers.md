# Guarded transfer summaries

The analyzer can preserve a bounded set of path-specific return transfers instead of immediately joining different return paths to unknown.

## Why this layer exists

Earlier interprocedural layers intentionally use must summaries: a return constant or symbolic formula is reusable only when all represented returns agree. That is sound, but a helper such as:

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

A concrete `JSUB` evaluates the guards using its own exact/range register and direct-memory must-state. Cases that are provably impossible are removed. Remaining outputs are joined soundly.

## Structural authority

Reusable guarded cases are inferred from a pristine structural CFG rebuilt from decoded instructions. Path existence, return sites, `may_return`, and `link_register_preserved` are never inherited from caller-specialized pruning.

The same rule applies to memory effects. `may_read_cells`, `may_write_cells`, `unknown_read`, `unknown_write`, and preserved-cell shape are rebuilt from the pristine structural CFG before guarded memory contracts are inferred. Earlier layers may contribute value hints, but they cannot erase a valid path or shrink a reusable function's write set merely because one caller proves a condition.

## Guard representation

A guard stores two `symbolic-linear` expressions plus an allowed condition-code set. `JEQ`, `JLT`, and `JGT` branch/fallthrough edges become complementary allowed sets, and comparison operands may depend on entry registers or direct entry-memory roots.

## Register and memory case outputs

Register outputs retain the existing sparse symbolic representation. Guarded memory contracts additionally expose `memory_contract_cells`, the finite set of tracked cells that the function may write. Every guarded return case explicitly represents every contract cell with one of three states:

```text
identity         MEM[X]_out = MEM[X]_in
unknown          MEM[X]_out cannot be represented safely
symbolic-linear  MEM[X]_out is a sparse symbolic expression
```

For example:

```asm
MAYSET COMP #0
       JEQ KEEP
       LDX #7
       STX SLOT
KEEP   RSUB
```

can produce:

```text
A_in == 0 -> MEM[SLOT]_out = identity
A_in != 0 -> MEM[SLOT]_out = 7
```

This removes the older ambiguity where an omitted cell could mean either unchanged or unknown. See `guarded-memory-contracts.md` for the complete contract.

## Call-site evaluation

For each resolved `JSUB` with `link_register_preserved=true`, the analyzer evaluates guards with exact register facts, signed 24-bit register ranges, exact direct-memory must values, and direct-memory must ranges.

For memory outputs, `identity` evaluates to the caller's incoming value/range, `unknown` contributes no exact/range postcondition, and `symbolic-linear` is evaluated from caller register/memory facts. An exact result survives only when every feasible case agrees exactly; a range survives only when every feasible case has a representable interval, joined by sound hull. Instantiations expose `memory_modes` so reports distinguish selected identity, unknown, symbolic, or joined behavior.

## Nested guarded composition

A guarded function may compose another guarded callee when the target is resolved, the callee has a supported bounded guarded summary, and `link_register_preserved=true`.

The analyzer does not inline the callee CFG. It forks only over the callee's already-bounded cases, substitutes each callee guard into the outer function's current symbolic register/memory state, applies the selected case outputs, and continues through the outer CFG. Resulting outer cases record `nested_cases` provenance containing call source, callee entry, and case id.

Composition is a monotone summary fixed point: leaf guarded summaries become available first, then callers may consume them on later inference iterations. An outer function may gain a precise guarded summary for reporting/composition while still remaining unconsumable by its own callers if its structural `link_register_preserved` proof is false.

## CFG feedback and proof ownership

Selected guarded outputs are merged with established symbolic-memory-input call-site instantiations and fed through the existing memory-aware exact/range passes. They can prove caller comparisons, prune branches, return direct-memory facts, and recover B for base-relative target resolution.

New proof provenance is used only when this layer is the first owner. Older target/edge proof ownership is snapshotted and restored. A later guarded pass never relabels a fact already proven by an earlier layer. Likewise, an older must-summary can remain intentionally conservative while the later guarded call-site layer proves a caller-specific postcondition.

## Bounds and fail-conservative rules

- At most eight distinct guarded return cases are retained per function.
- At most 128 path states are explored per function.
- A control-flow revisit/loop disables guarded summarization for that function.
- Guards currently come from symbolic `COMP`/`COMPR` feeding `JEQ/JLT/JGT`.
- `TIX/TIXR` comparisons are not represented as guarded symbolic relations here.
- Failed nested guard substitution falls back to the existing must-summary.
- Nested guarded consumption requires proven link-register preservation.
- All symbolic expressions obey the existing sparse root budget.
- Signed 24-bit wrap degrades to unknown.
- Indexed/indirect/unresolved aliases retain fail-conservative memory behavior.
- Pristine structural CFG and pristine memory-effect shape are authoritative for reusable summaries.

## Public report fields

The guarded layer remains additive:

```text
guarded_transfer_summaries
guarded_transfer_instantiations
guarded_transfers
```

Additional guarded fields include:

```text
memory_contract_cells
guarded_nested_composed_calls
nested_cases
memory_modes
```

Existing register, memory, sparse-linear, symbolic-memory-input, assembler, object, linker, linked-image, manifest, INPUTSET/LINKID, and historical golden contracts remain unchanged.
