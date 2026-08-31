# Analysis documentation

- `control-flow.md` — end-user CFG, exact/range dataflow, calls, returns, dominators, loops, metrics.
- `range-analysis.md` — signed 24-bit interval-domain design and safety rules.
- `interprocedural-cfg.md` — compositional call summaries and proof-based synthetic return edges.
- `liveness-functions.md` — register/CC liveness, dead-write evidence, function discovery, ownership, callers/callees, and per-function metrics.
- `reaching-definitions.md` — GEN/KILL reaching definitions, def-use chains, entry pseudo-definitions, and function input/output contracts.
- `analysis-contract.md` — trust boundary and fail-conservative guarantees.
