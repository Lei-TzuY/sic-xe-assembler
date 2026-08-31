# Cross-domain register / memory / CFG fixed point

The typed analyzer no longer treats memory dataflow as a report-only pass. Proven
memory constants now feed back into exact register constants, signed intervals,
condition-code reasoning, and base-relative target recovery. At the same time,
resolved subroutines expose compositional memory-effect summaries so calls only
weakly clobber cells the callee may write.

## Iteration

The refinement loop is intentionally finite and conservative:

1. rebuild typed instruction edges from the current decoded targets;
2. compute alias-aware reaching memory definitions with callee summaries;
3. feed proven direct-memory constants into exact register transfer functions;
4. feed the same constants into singleton signed intervals;
5. prune condition-impossible branch/fallthrough edges;
6. use proven exact/range B values to re-decode base-relative instructions;
7. add proof-based synthetic return edges;
8. recompute memory with the refined register states and control flow;
9. repeat until targets, edges, register/range states, and memory facts stabilize.

Failure to converge within the finite guard is a hard analysis error rather than
silently returning partially stable facts.

## Memory-to-register feedback

Only a direct statically resolved memory cell whose reaching definitions all
carry the same constant can seed value reasoning. Supported feedback includes:

- `LDA/LDB/LDL/LDS/LDT/LDX cell` -> exact register constant + singleton range;
- `LDCH cell` -> exact A only when the incoming A value is already exact;
- `ADD/SUB/MUL/DIV/AND/OR cell` -> exact/range A when operands are provable;
- `COMP cell` -> exact/range CC facts;
- `TIX cell` -> X update plus exact/range CC facts.

If a load has multiple reaching stores with different constants, an initial
memory pseudo-definition, an alias clobber, or any other unknown source, no
constant is invented.

## CFG consequences

Memory feedback is allowed to affect control flow. For example:

```asm
      LDA  #5
      STA  TEMP
      LDA  TEMP
      COMP #5
      JEQ  TAKEN
DEAD  LDA  #9
TAKEN RSUB
TEMP  RESW 1
```

The store/load chain proves `A=5`, then `CC=EQ`, so the `JEQ` fallthrough is
removed by the normal exact-condition rule and `DEAD` becomes unreachable.
Existing edge reason/resolution strings remain compatible (`condition-false`,
`abstract-condition` / `abstract-range-condition`); `memory_feedback` on the
instruction records where memory supplied the value identifies the additional
proof source.

A memory-loaded B value can likewise resolve a base-relative control transfer.
The normal `dataflow-base` / `range-singleton-base` resolution ownership rules
still apply, including revocation if a later join makes B unknown.

## Interprocedural memory effects

Each resolved call target gets a monotone may-effect summary over the finite set
of tracked direct cells:

- `direct_reads` / `direct_writes`;
- transitive `may_read_cells` / `may_write_cells`;
- `preserved_cells` when no unknown write exists;
- `unknown_read` / `unknown_write`;
- nested callees and unresolved call sites.

At a resolved call, a known callee causes weak clobbers only for its
`may_write_cells`. A memory-free callee therefore preserves precise reaching
stores. If the callee may write `OTHER` but not `SLOT`, only `OTHER` receives a
call-clobber definition. Nested resolved calls compose through a fixed point.

Unknown/indirect/unresolved calls and opaque operations remain full memory
barriers. A call summary is may-effect information: a listed cell is not assumed
to be definitely overwritten, so call updates remain weak rather than strong.

Read summaries also refine observability used by overwritten-store diagnostics.
A store is considered observable at a known call only when the callee may read
that cell (or has unknown reads); a memory-free callee no longer keeps unrelated
stores artificially alive.

## Compatibility boundary

This is analysis-only. It does not change assembly, object records, relocation,
linked image bytes, manifest schema, INPUTSET, LINKID, DEBUGID, source maps, or
historical golden outputs. `control_flow_core.py` remains the historical CFG
implementation; the cross-domain fixed point runs in the enrichment layer and
then rebuilds derived graph structures from the refined edges.
