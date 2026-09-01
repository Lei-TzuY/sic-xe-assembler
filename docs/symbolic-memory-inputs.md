# Symbolic memory-input transfers

The control-flow analyzer can now use direct memory cells as caller-independent symbolic function inputs, closing the previous one-way register→memory transfer model into a bounded memory↔register domain.

## Examples

A direct load can define a returned register in terms of entry memory:

```asm
GET    LDA SLOT
       RSUB
```

```text
A_out = MEM[SLOT]_in
```

A function can also transform one input cell into another output cell:

```asm
MIX    LDA INVAL
       ADDR X,A
       ADD #1
       STA OUTVAL
       RSUB
```

```text
MEM[OUTVAL]_out = MEM[INVAL]_in + X_in + 1
```

The summary is caller-independent. Each concrete `JSUB` substitutes its own register facts and direct-memory must-state, so two calls to the same function can produce different exact/range results without widening the reusable function contract.

## Symbolic roots

At each function entry the domain creates two kinds of roots:

```text
register:<name>
memory:<loaded-cell-id>
```

A public formula is serialized as `kind=symbolic-linear` with independent sparse maps:

```json
{
  "kind": "symbolic-linear",
  "register_coefficients": {"X": 1},
  "memory_coefficients": {"04042+3": 1},
  "offset": 1,
  "modulus": 16777216
}
```

The total number of non-zero register + memory terms is bounded to four. A fifth symbolic root degrades the expression to unknown.

## Supported symbolic operations

The domain preserves direct WORD-width loads and stores, register moves/arithmetic, immediate add/subtract, constant scaling, and nested proven calls when the result remains sparse linear.

Nonlinear multiplication/division of two symbolic expressions is not represented. Division is retained only for ±1 scaling or fully constant expressions. Bitwise operations preserve only sound constant/identity cases.

`STCH` does not preserve an unknown symbolic 24-bit expression because extracting the low byte is outside this linear domain.

## Memory trust boundary

Only direct, statically resolved tracked cells can become symbolic memory inputs. Indexed loads/stores, indirect addressing, unresolved targets, unknown alias writes, overlapping partial writes, and opaque memory barriers invalidate the affected facts conservatively.

This remains a direct-cell abstraction, not a symbolic pointer or heap model.

## Nested composition

Resolved nested callees can substitute both register and memory roots into the caller's symbolic state. For example, an inner summary

```text
MEM[OUT]_out = MEM[IN]_in + 1
```

can feed an outer `LDA OUT`, producing

```text
A_out = MEM[IN]_in + 1
```

The resulting value is consumable at an outer call site only when the existing control-flow proof establishes `link_register_preserved=true`. Memory/value evidence never replaces return-control evidence.

## Call-site instantiation

At every resolved `JSUB`, the analyzer evaluates memory-dependent formulas using:

1. the call site's exact/range register state; and
2. the call site's direct-memory must-state immediately before the call.

Results are exposed as:

```text
symbolic_memory_input_summaries
symbolic_memory_input_instantiations
symbolic_memory_inputs
```

Each instantiation separates:

```text
exact_registers
range_registers
exact_memory
range_memory
```

The older evidence layers remain unchanged and keep ownership of proofs they already established.

## CFG feedback

Memory-dependent register returns can feed directly into comparisons and base-relative addressing. Memory-dependent cell returns are inserted into the concrete must-memory analysis and can subsequently flow through `LDA/LDB/...`.

New proof provenance is used only when this layer is the first owner:

```text
symbolic-memory-input-condition
symbolic-memory-input-range-condition
symbolic-memory-input-base
symbolic-memory-input-range-base
```

Previously established target/edge provenance is restored rather than relabeled by this later analysis layer.

## Safety rules

The implementation deliberately degrades to unknown when:

- more than four symbolic roots survive normalization;
- a direct cell cannot be identified exactly;
- an indexed/indirect/unknown alias participates;
- a signed 24-bit range substitution would wrap;
- nonlinear symbolic arithmetic is required;
- represented return paths disagree; or
- link-register preservation is not proven at the consuming call site.

The assembler, object format, linker, image, manifest, INPUTSET/LINKID, and historical golden artifacts are outside this analysis-only layer and remain unchanged.
