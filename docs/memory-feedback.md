# Integrated memory feedback and callee effects

The analyzer now closes a conservative fixed point between register facts and memory facts. The historical CFG core still runs first. A second analysis layer then iterates:

1. alias-aware reaching memory definitions,
2. direct-memory constants and signed 24-bit intervals,
3. register/condition-code propagation using those memory facts,
4. condition-feasibility pruning,
5. memory analysis again on the refined graph.

The loop stops only when register states, range states, memory definitions, and edge feasibility are stable. It is an analysis-only refinement: assembler output, object records, linked-image bytes, INPUTSET, LINKID, DEBUGID, and the historical CFG core are unchanged.

## Memory-backed register and condition facts

A direct statically resolved memory read may feed the abstract register domains when every reaching memory definition proves the same value or compatible interval.

Example:

```asm
LDA  #5
STA  TEMP
LDA  TEMP
COMP #5
JEQ  TAKEN
```

The store records `5`, the second `LDA` recovers `A=5`, `COMP` proves `CC=EQ`, and the impossible `JEQ` fallthrough is removed. The edge is annotated with `resolution=memory-feedback-condition`.

The same feedback works for intervals. For example, an unknown value constrained by `AND #1`, stored, and loaded again carries the interval `[0,1]`. A later `COMP #10` can therefore prove `LT` even though no exact constant exists. Range-only pruning is annotated `memory-feedback-range-condition`.

Supported memory-backed integer operations are conservative versions of the existing register/range transfer functions: direct `LDA/LDB/LDL/LDS/LDT/LDX`, `LDCH` when the rest of A is already known, direct `ADD/SUB/MUL/DIV/AND/OR`, direct `COMP`, and direct `TIX`. Indexed, indirect, or unresolved accesses never supply a precise value.

## Callee memory-effect summaries

Resolved subroutines now receive compositional memory summaries over the finite tracked-cell domain:

- `may_read_cells`
- `may_write_cells`
- `unknown_read`
- `unknown_write`
- `preserved_cells`
- `nested_callees`

A call no longer weakly clobbers every tracked cell by default. If a callee is proven to write only `OTHER`, a previously known `SLOT` value survives across the call. If the callee directly writes `SLOT`, only `SLOT` is weakly clobbered. Nested resolved callees compose by fixed point.

Any unresolved call, indexed/indirect store, or opaque operation that may touch arbitrary memory sets the corresponding unknown flag and falls back to the conservative all-cell effect.

Call memory summaries are may-effects, not ABI declarations. A preserved cell means only that no represented path in the analyzed callee is known to write that tracked cell and no unknown write was encountered.

## Strong and weak updates

Direct exact stores retain the existing strong-update rule. An exact store to a tracked cell replaces the old full-cell definitions. Differently sized overlapping exact stores replace the old value with a partial-overlap clobber.

Unknown aliases and call effects remain weak updates. They add a clobber definition but preserve older definitions as alternatives. Therefore a possible alias cannot create a false dead-store proof.

## Structural recomputation

Memory feedback can remove condition edges. After convergence the wrapper recomputes reachability, basic blocks, predecessors/successors, dominators, natural loops, call graph, and complexity before liveness, reaching definitions, and function contracts run. Downstream analyses therefore consume the refined graph instead of stale structural metadata.

## Trust boundary

The analysis deliberately does not:

- infer arbitrary pointer aliases,
- treat object-file data bytes as initialized semantic constants unless a represented store proves them,
- assume unresolved calls preserve memory,
- infer memory-mapped I/O purity,
- treat same-value stores as automatically removable,
- modify executable artifacts based on analysis results.

Unknown information stays unknown. Precision is gained only when every represented reaching definition or callee effect supports the claim.
