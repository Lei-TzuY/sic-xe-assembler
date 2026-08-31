# Interprocedural CFG design note

The structural CFG keeps ordinary `JSUB` call edges, summarized caller continuations, and hardware-level unresolved `RSUB` returns. It may additionally add context-specific synthetic return edges when a call target and continuation are known, the callee exposes an `RSUB`, and the callee summary proves that L is never written before that return.

Synthetic return edges are marked `synthetic_return=true` with `resolution=link-register-summary`, `call_source`, and `callee_entry`. They enrich predecessor/successor relationships, call reports, JSON, and DOT output without erasing the original `dynamic-return` edge.

They are excluded from exact/range state propagation because caller continuation state is already transferred through the call summary. They are also excluded from natural-loop and intraprocedural McCabe calculations so procedure linkage is not mistaken for loop structure or branch complexity.

Subroutine summaries are compositional. Direct may-writes are collected per resolved callee, then transitive may-writes from resolved nested callees are unioned to a monotone fixed point. Unknown calls remain fully opaque. Recursive call cycles converge because may-clobber sets only grow.
