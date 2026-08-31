# Interval analysis design note

The CFG analyzer keeps exact constants and signed 24-bit intervals as separate abstract domains. Exact results continue to use the historical `registers_in/out` fields; interval results use `ranges_in/out` so existing consumers do not need to reinterpret integer values.

Intervals are convex signed ranges over `[-8388608, 8388607]`. Merge uses convex hull. Arithmetic that could cross two's-complement wrap degrades to unknown instead of forcing a wrapped set into an unsound interval.

This domain is intentionally small but useful: path merges retain bounds even when exact constants disagree, bit masks such as `AND #0` can manufacture a singleton from an otherwise unknown value, and comparison operations derive a subset of `{LT, EQ, GT}`. Conditional branches are pruned only when their required relation is impossible for that set.

A singleton B interval may resolve a base-relative control transfer with `range-singleton-base` provenance. Wider ranges never guess an address.

The interval analyzer uses the same compositional subroutine preserve/clobber summaries as exact dataflow. Synthetic `RSUB` return edges are structural-only and are excluded from interval propagation because caller continuation state is already represented by the summarized call fallthrough.
