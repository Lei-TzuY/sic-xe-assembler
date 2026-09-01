# Guarded returnability contracts

The guarded interprocedural layer can now describe whether a call returns to its
continuation under a path guard, independently from its register, memory, and
condition-code postconditions.

## Case schema

Each inferred `returnability_case` contains:

- `guards`: symbolic register/memory predicates inherited from the function path;
- `returns`: `true`, `false`, or `null`;
- `terminal_kind`: why the path is classified;
- `terminal_address` / `terminal_nodes`: proof provenance for the terminal;
- `nested_cases`: nested guarded-call provenance.

`true` means the represented path reaches an `RSUB` and preservation of the SIC/XE
link register `L` is proven. `false` means the analyzer has a closed no-return
proof. `null` means return behavior is unknown.

## Closed-cycle proof

Version 1 intentionally recognizes only a narrow no-return terminal: a closed
function-local strongly connected component.

A cycle is classified `no-return` only when all of the following hold:

1. it is cyclic (a self-loop or a multi-node SCC);
2. it contains no represented `RSUB`;
3. it contains no `JSUB`;
4. every structural control edge is resolved;
5. every such edge remains inside the SCC.

An indirect jump, an unresolved or outside-image target, an unresolved call, an
unproven `RSUB`, or any other opaque terminal remains `returns=null`. The analyzer
does not equate "outside typed code" with program termination.

## Call-site instantiation

The caller's exact/range register and direct-memory facts filter the returnability
cases with the same guarded-case feasibility rules used for value contracts.
The resulting `guarded_transfer_instantiation` exposes:

- `return_mode`: `returns`, `no-return`, `mixed`, or `unknown`;
- `returnability_known`;
- `must_return`, `may_return`, and `must_not_return`;
- `return_feasible_cases` and `return_ruled_out_cases`.

When every feasible case is proven `no-return`, the call's fallthrough edge is
marked infeasible with `resolution="guarded-returnability"` and
`reason="guarded-no-return"`. Context-specific synthetic return edges belonging
to that call site are removed. The normal CFG refresh then recomputes reachability,
basic blocks, dominators, loops, liveness, reaching definitions, memory provenance,
and function objects from the refined graph.

Mixed or unknown returnability never prunes the continuation.

## Nested calls

A nested callee's returnability cases may be substituted into an outer function.
A proven nested no-return case terminates that outer path even when the outer
function cannot prove normal return because its link register is not preserved.
A nested returning case only continues through the caller when it is itself
proven to return.

The existing guarded limits still apply: at most eight terminal cases and 128
explored path states. Unrepresentable guards or excessive path structure degrade
conservatively.

## Compatibility boundary

Returnability is a separate control-state contract. Existing guarded register,
memory, and CC schemas retain their meanings. This layer changes static-analysis
metadata and CFG reachability only; it does not change assembly, object records,
relocation, linking, linked images, manifests, debug-map identity, INPUTSET/LINKID,
or historical golden outputs.
