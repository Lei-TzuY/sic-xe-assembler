# Static-analysis trust boundary

The analyzer consumes linked bytes plus LINKID-matching typed debug metadata. It never changes executable artifacts and never contributes to INPUTSET, LINKID, image SHA-256, or relocation semantics.

All proofs are conservative. Exact constants require agreement across all reachable predecessors. Intervals are convex signed 24-bit ranges and degrade to unknown on unsupported wrap behavior. Conditional edges are removed only when the abstract condition set proves them impossible. Indirect/indexed control transfers remain unresolved. Unknown callees remain fully opaque.

Interprocedural return resolution is additive: the original dynamic RSUB edge remains present even when a call-context return edge can be proven from an untouched L register. Context-specific return edges do not feed context-free register/range propagation.
