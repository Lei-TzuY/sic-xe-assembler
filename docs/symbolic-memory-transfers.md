# Symbolic memory return transfers

The CFG analyzer can infer caller-independent linear relations between a callee's entry registers and direct memory cells that are guaranteed to hold those values when the callee returns.

This layer builds on the bounded sparse register-transfer domain. It does not replace reaching-store provenance or the existing memory constant/range postconditions.

## Example

```asm
SETVAL ADDR X,A
       STA SLOT
       RSUB
```

For a three-byte direct `SLOT` cell, the analyzer can infer:

```text
MEM[SLOT]_out = A_in + X_in
```

At a call site where `A=1` and `X=2`, the summary is instantiated as `SLOT=3`. A later `LDA SLOT` can therefore recover `A=3`, feed that value into `COMP`, and prune a provably impossible conditional edge.

## Domain

Memory formulas reuse the sparse linear register domain:

```text
c1*R1 + c2*R2 + ... + offset   (mod 2^24)
```

The domain is intentionally bounded:

- at most four non-zero symbolic register terms;
- deterministic normalized register ordering;
- nonlinear symbolic multiplication/division is rejected;
- exact call-site substitution uses SIC/XE 24-bit modular arithmetic;
- range substitution is kept only when the signed 24-bit interval does not wrap.

Single-source formulas retain the existing `kind=affine` representation. Genuine multivariate formulas use `kind=linear` with a sparse coefficient map.

## Memory trust boundary

A symbolic memory formula is created only by a direct, statically resolved store to a tracked cell. Indexed and indirect stores, unresolved addresses, and opaque memory barriers invalidate affected symbolic memory facts conservatively.

A direct WORD-width store such as `STA`, `STB`, or `STX` can transfer the complete symbolic register expression into the memory cell. `STCH` only preserves a symbolic value when the source is already a constant because taking the low byte of an unknown 24-bit linear expression is not represented by this domain.

Overlapping direct stores invalidate overlapping cells unless the write exactly matches the tracked cell.

## Function-local inference

Every function is analyzed from caller-independent entry state:

- each tracked register starts as its own symbolic input;
- tracked memory starts unknown;
- direct stores can establish symbolic memory formulas;
- resolved nested callees can contribute their proven memory formulas by symbolic substitution;
- CFG joins preserve a formula only when every represented predecessor agrees exactly.

A return memory formula is published only when every represented `RSUB` has the same non-unknown expression for that cell.

This means a conditional store does not invent a postcondition:

```asm
MAYSET COMP FLAG
       JEQ DONE
       STA SLOT
DONE   RSUB
```

Because one return path leaves `SLOT` unknown, no symbolic `SLOT` return formula is published.

## Nested calls and return proof

Nested symbolic memory summaries can compose. However, a caller may consume the resulting formula only when the existing control-flow analysis proves `link_register_preserved=true` for that callee.

This separates two obligations:

1. what value a cell has at represented return sites;
2. whether the call is proven to return to the caller continuation.

A value proof never substitutes for the link-register/control-flow proof.

## Call-site instantiation

For every resolved `JSUB`, the analyzer evaluates the callee's memory formulas using the call site's current exact/range register facts. Results are exposed independently as:

```text
symbolic_memory_transfer_summaries
symbolic_memory_instantiations
symbolic_memory_transfers
```

The established fields remain unchanged:

```text
memory_effect_summaries
register_transfer_summaries
sparse_linear_transfer_summaries
```

This keeps may-write provenance, must-value constants/ranges, register relations, and symbolic memory relations as separate evidence layers.

## Feedback into CFG analysis

Instantiated memory facts are fed into the existing memory-aware register/range engine. They can therefore enable:

- `LDA/LDB/...` constant recovery;
- interval recovery through memory;
- condition-code inference;
- branch pruning (`symbolic-memory-condition` / `symbolic-memory-range-condition`);
- B-register recovery through `LDB`;
- base-relative target resolution (`symbolic-memory-base` / `symbolic-memory-range-base`).

After an edge or target changes, the higher-level CFG wrapper rebuilds structural products and reruns downstream liveness, reaching-definition, memory provenance, function, ownership, dominator, loop, and complexity analyses.

## Non-goals

This is not a general symbolic heap or alias solver. The current layer intentionally does not model:

- symbolic memory addresses;
- indexed or indirect cell identities;
- arbitrary memory-to-memory symbolic formulas;
- nonlinear register formulas;
- more than four symbolic register terms;
- caller-specific memory inputs promoted into reusable function summaries.

Unsupported cases degrade to unknown rather than fabricating precision.
