# Analysis documentation

- `control-flow.md` — end-user CFG, exact/range dataflow, calls, returns, dominators, loops, metrics.
- `range-analysis.md` — signed 24-bit interval-domain design and safety rules.
- `interprocedural-cfg.md` — compositional call summaries and proof-based synthetic return edges.
- `liveness-functions.md` — register/CC liveness, dead-write evidence, function discovery, ownership, callers/callees, and per-function metrics.
- `reaching-definitions.md` — GEN/KILL reaching definitions, def-use chains, entry pseudo-definitions, and function input/output contracts.
- `memory-dataflow.md` — alias-aware reaching stores, store-to-load chains, memory constants, overwritten-store evidence, and function memory contracts.
- `memory-feedback.md` — integrated memory→register/range/CC fixed point, structural reanalysis after branch pruning, and compositional callee memory-effect summaries.
- `memory-postconditions.md` — typed linked-image initializer seeding, callee return constants/ranges, and memory-derived B target resolution.
- `analysis-contract.md` — trust boundary and fail-conservative guarantees.
