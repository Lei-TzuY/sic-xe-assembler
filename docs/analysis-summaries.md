# Condition pruning and subroutine summaries

This note summarizes the two interprocedural refinements layered on top of the typed CFG.

## Condition-code abstraction

The abstract state tracks `CC` as one of `LT`, `EQ`, `GT`, or unknown. Exact facts are produced only by comparisons whose operands are provably constant (`COMP #imm`, `COMPR`, immediate `TIX`, and `TIXR`). Conditional jumps are pruned only when the required condition is known to be impossible. Unknown conditions preserve both branch and fallthrough edges.

Pruned edges remain visible in structured CFG output with `reason=condition-false` and `resolution=abstract-condition`, but they no longer participate in reachability, dominators, loops, or complexity.

## Local subroutine summaries

For every resolved `JSUB/+JSUB` target, the analyzer walks reachable non-call control flow from the callee entry and builds a local may-write summary. A tracked register is `preserved` only if no visited instruction may write it; otherwise it appears in `may_clobber`.

Nested calls are opaque and therefore may clobber all tracked registers. Condition-code preservation is never inferred. This makes summaries conservative enough to reuse caller constants only when preservation is actually proven.

The summary is attached to the call instruction in structured CFG JSON as `call_summary`, including callee symbols, preserved/may-clobber sets, visible return sites, visited instruction addresses, and `may_return`.

These summaries are analysis metadata only. They do not alter object code, LINKID, DEBUGID, or linked-image reproducibility.
