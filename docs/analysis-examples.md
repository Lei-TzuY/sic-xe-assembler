# Static analysis examples

## Range-only branch proof

Two feasible predecessors that assign `A=1` and `A=2` merge to exact `A=unknown`, interval `A=[1,2]`. `COMP #10` therefore yields possible CC `{LT}` and a following `JLT` has only its branch edge feasible.

## Range-only base recovery

`LDA VALUE; AND #0; RMO A,B` leaves exact B unknown but proves interval B `[0,0]`. A b-relative control transfer can therefore be re-decoded with base 0 and is annotated `range-singleton-base`.

## Proven return edge

For `JSUB ROUTN` followed by continuation `CONT`, a leaf `ROUTN` that reaches `RSUB` without any write to L retains the normal unresolved `dynamic-return` edge and gains a context-specific resolved `RSUB -> CONT` edge annotated `link-register-summary`.
