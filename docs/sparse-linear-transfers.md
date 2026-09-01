# Sparse multivariate register transfers

The call-site transfer layer now includes a bounded sparse multivariate linear domain on top of the existing single-source affine analysis.

## Domain

A symbolic register value is represented as

```text
c1*R1 + c2*R2 + ... + cn*Rn + k   (mod 2^24)
```

where each `Ri` is one function-entry register from `A/X/L/B/S/T`. The implementation keeps at most four non-zero source terms. Expressions that exceed the term budget become unknown rather than growing without bound.

Serialization remains backward compatible:

- constants use `kind=constant`;
- one-source formulas keep the established `kind=affine` schema;
- genuine multivariate formulas use `kind=linear` with a deterministic sparse `coefficients` mapping.

For example:

```json
{
  "kind": "linear",
  "coefficients": {"A": 1, "X": 1},
  "offset": 4,
  "modulus": 16777216
}
```

means `A_in + X_in + 4 (mod 2^24)`.

## Supported transfer composition

The domain safely composes operations that remain linear:

- register copies with `RMO`;
- `CLEAR` and immediate loads as constants;
- immediate `ADD`/`SUB`;
- multiplication by a proven constant;
- division by `1` or `-1`;
- `ADDR` and `SUBR`, including different symbolic source registers;
- `MULR` when one side is constant;
- `DIVR` under the same safe division restrictions;
- `TIX`/`TIXR` as `X_out = X_in + 1`;
- identity bit operations such as `AND #0xFFFFFF` and `OR #0`.

Memory-dependent loads, opaque operations, unsupported division, non-linear products, and expressions exceeding the sparse-term budget degrade to unknown.

## Function summaries and nested calls

Every represented return must agree on the same symbolic expression before it becomes a reusable function summary. Join points therefore keep a formula only when all represented incoming paths produce exactly the same normalized expression.

Resolved nested callees are composed by substitution. For example, if

```text
INNER: A_out = A_in + X_in
OUTER: call INNER; ADD #1
```

then OUTER can infer

```text
A_out = A_in + X_in + 1
```

The existing link-register proof remains mandatory before a caller consumes any return formula. A callee may have a mathematically valid return-state expression at its `RSUB` sites while still lacking proof that `L` reaches those sites unchanged.

## Call-site instantiation

At each concrete `JSUB`, the analyzer substitutes the caller's current facts into the reusable formula.

Exact facts use SIC/XE 24-bit modular arithmetic. For example:

```text
A_in = 1
X_in = 2
A_out = A_in + X_in
```

instantiates to `A_out = 3`.

Range facts use signed 24-bit interval arithmetic. Each term is bounded independently and the resulting interval is retained only when the complete sum remains inside `[-8388608, 8388607]`. Potential two's-complement wrap degrades to unknown. This can lose precision because correlations between input registers are intentionally not modeled, but it does not under-approximate the represented values.

## CFG feedback

Instantiated exact/range values flow through the existing memory-aware register transfer functions. They can therefore:

- prove `COMP`/`COMPR` results;
- prune impossible `JEQ/JLT/JGT` edges;
- propagate into later arithmetic;
- establish a returned `B` value;
- resolve base-relative control-flow targets.

Edges pruned only because of this layer use `sparse-linear-condition` or `sparse-linear-range-condition`. Base targets owned by this layer use `sparse-linear-base` or `sparse-linear-range-base`.

After refinement, the wrapper reuses the existing structural refresh path so reachability, blocks, dominators, loops, liveness, reaching definitions, memory provenance, functions, callers, and callees all reflect the refined graph.

## Compatibility

The previous single-source public fields remain intact:

```text
register_transfer_summaries
callsite_transfer_instantiations
callsite_transfers
```

The new layer is exposed separately as:

```text
sparse_linear_transfer_summaries
sparse_linear_instantiations
sparse_linear_transfers
```

Single-source formulas inside the new layer still serialize as `kind=affine`. Existing executable artifacts, object records, linked-image manifests, INPUTSET, LINKID, DEBUGID, and assembler golden outputs are unchanged.

## Trust boundary

This is bounded linear abstract interpretation, not general symbolic execution. In particular it does not claim to model arbitrary memory expressions, symbolic multiplication, non-linear bitwise transformations, alias-dependent values, or unbounded symbolic formula growth. When a proof leaves the supported domain, the result becomes unknown.
