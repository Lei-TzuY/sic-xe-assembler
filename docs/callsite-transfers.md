# Call-site symbolic register transfers

The register postcondition layer can prove caller-independent return constants and ranges. This layer handles the complementary case where a callee's output is a deterministic function of its input, but no caller-independent value exists.

## Domain

A symbolic register value is intentionally limited to a single-source affine formula:

```text
scale * R_in + offset  (mod 2^24)
```

Examples:

```text
A_out = A_in + 1
B_out = A_in
X_out = 2 * X_in - 3
```

The JSON representation is deterministic:

```json
{
  "kind": "affine",
  "source": "A",
  "scale": 1,
  "offset": 1,
  "modulus": 16777216
}
```

Constants remain the responsibility of the existing register-return postcondition layer and are composed with symbolic transfers when a call is instantiated.

## Supported transfer operations

The analysis safely models:

- immediate loads as constants;
- `CLEAR`;
- `RMO` copies;
- immediate `ADD`, `SUB`, and `MUL`;
- division by `1` or `-1` (and constant-only division);
- `ADDR`, `SUBR`, and `MULR` only when the result stays single-source affine;
- `TIX`/`TIXR` as `X + 1`;
- identity-safe special cases such as `AND #0`, `AND #0xFFFFFF`, and `OR #0`.

Memory-dependent loads, opaque operations, unsupported shifts, and expressions requiring multiple independent input registers become unknown rather than being approximated as affine.

For example, `ADDR X,A` means `A_out = A_in + X_in`; because that needs two independent symbolic sources, the current domain deliberately refuses to summarize it.

## Caller-independent summary inference

Each resolved function entry starts with symbolic input variables for `A/X/L/B/S/T`. Function-local control flow is analyzed independently of any concrete caller. A formula is published only when every represented return site has the same symbolic expression for that register.

Nested resolved callees are composed to a fixed point. As with exact/range return postconditions, a nested summary can be used only to the degree justified by its structural preserve/clobber information.

The resulting function summary exposes:

```text
return_transfers
transfer_input_registers
symbolic_return_registers
```

## Link-register gate

A symbolic formula is not enough to prove that execution returns to the caller continuation. A call site consumes `return_transfers` only when structural analysis also proves `link_register_preserved=true` for the callee.

This intentionally keeps the following two questions separate:

1. What value would a represented `RSUB` return with?
2. Is the link-register discipline strong enough to prove that this call actually returns there?

A nested `JSUB` that overwrites `L` can therefore allow an outer symbolic formula to be inferred for reporting while still preventing callers from consuming it.

## Call-site instantiation

At each concrete `JSUB`, the reusable formula is substituted with that call site's incoming facts.

Example:

```asm
LDA   #4
+JSUB INC
...
INC   ADD #1
      RSUB
```

The function summary is:

```text
A_out = A_in + 1
```

and this call site instantiates it as:

```text
A_out = 5
```

A second call with `A=9` uses the same summary but instantiates to `A=10`.

Exact instantiation follows the machine's 24-bit modular arithmetic. Range instantiation is stricter: an affine image is kept only when the full signed interval remains inside `[-8388608, 8388607]`; a possible wrap degrades to unknown.

## CFG feedback

Instantiated values feed the existing memory-aware register/range transfer functions. This can prove post-call `COMP`, `COMPR`, or `TIX*` conditions and prune impossible `JLT/JEQ/JGT` edges.

Edges pruned by this layer use explicit provenance:

```text
call-transfer-condition
call-transfer-range-condition
```

A returned `B` exact value or singleton interval can also re-decode a base-relative control target using:

```text
call-transfer-base
call-transfer-range-base
```

If that changes a target, instruction edges and proof-based return edges are rebuilt and the analysis repeats to a fixed point.

## Report surface

CFG JSON exposes:

- `register_transfer_summaries`;
- `callsite_transfer_instantiations`;
- per-function `register_transfer_summary`;
- per-call `register_transfer_summary` and `transfer_instantiation`;
- per-`JSUB` `call_transfer_instantiation`.

The text CFG report adds a `CALL-SITE SYMBOLIC TRANSFERS` section, including formulas and concrete exact/range instantiations.

## Trust boundary

This layer is deliberately not general symbolic execution. It does not:

- invent multivariate formulas;
- read caller-specific memory while deriving a reusable callee formula;
- assume an ABI or calling convention;
- infer a return solely from the presence of `RSUB`;
- approximate signed 24-bit wrap with an unsound convex interval.

Unsupported facts become unknown and fall back to the previous preserve/clobber, constant, range, memory, and CFG analyses.
