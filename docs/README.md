# Analysis documentation

- `control-flow.md` — end-user CFG, exact/range dataflow, calls, returns, dominators, loops, metrics.
- `range-analysis.md` — signed 24-bit interval-domain design and safety rules.
- `interprocedural-cfg.md` — compositional call summaries and proof-based synthetic return edges.
- `liveness-functions.md` — register/CC liveness, dead-write evidence, function discovery, ownership, callers/callees, and per-function metrics.
- `reaching-definitions.md` — GEN/KILL reaching definitions, def-use chains, entry pseudo-definitions, and function input/output contracts.
- `memory-dataflow.md` — alias-aware reaching stores, store-to-load chains, memory constants, overwritten-store evidence, and function memory contracts.
- `memory-feedback.md` — integrated memory→register/range/CC fixed point, structural reanalysis after branch pruning, and compositional callee memory-effect summaries.
- `memory-postconditions.md` — typed linked-image initializer seeding, callee return constants/ranges, and memory-derived B target resolution.
- `register-postconditions.md` — caller-independent register/CC return constants and ranges, nested composition, link-register gating, caller branch pruning, and returned-B target recovery.
- `callsite-transfers.md` — single-source affine register return formulas, call-site exact/range substitution, symbolic CFG feedback, and returned-B target recovery.
- `sparse-linear-transfers.md` — bounded multivariate linear register formulas, sparse coefficient vectors, nested substitution, call-site exact/range instantiation, and CFG feedback.
- `symbolic-memory-transfers.md` — caller-independent memory-cell formulas over entry registers, nested substitution, call-site exact/range memory instantiation, and memory→register/CFG feedback.
- `symbolic-memory-inputs.md` — direct memory cells as symbolic function inputs, memory↔register sparse formulas, nested composition, per-call memory/register substitution, and CFG feedback.
- `analysis-contract.md` — trust boundary and fail-conservative guarantees.
