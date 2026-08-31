# Alias-aware memory dataflow

The memory analysis layer extends the typed CFG with conservative store/load provenance without changing assembler, object, linker, linked-image, manifest, LINKID, DEBUGID, or historical CFG semantics.

## Tracked cells

Only statically resolved direct memory accesses are tracked. A cell is identified by `(loaded address, access width)` and rendered as `AAAAA+W`, for example `04030+3`.

The current width model covers SIC/XE word loads/stores and arithmetic, byte `LDCH/STCH`, and six-byte floating-memory instructions. Immediate operands are not memory accesses.

Indexed (`...,X`), indirect (`@...`), unresolved addressing, calls, and opaque machine operations are deliberately not converted into precise cells.

## Memory definitions

Three deterministic definition families are emitted:

- `MI<entry>:<cell>` — function-entry memory pseudo-definition, representing the value supplied by the caller/environment.
- `MS<address>:<cell>` — a precise direct store.
- `MC<address>:<cell>` — an unknown clobber caused by a may-alias write, call/opaque operation, or differently-sized overlapping store.

A precise direct store performs a strong update for its exact cell. A proven overlapping store of a different width invalidates the old full-cell value with a clobber definition.

## May-alias safety

Unknown aliasing uses weak updates.

For example, after:

```text
STA SLOT
STX SLOT,X
LDB SLOT
```

`STX SLOT,X` may overwrite `SLOT`, but it is not proven to do so for the runtime X value. Therefore the load may receive both the old precise `MS...` definition and a new `MC...` clobber. The analysis must not erase the precise store merely because an alias is possible.

Calls and opaque operations follow the same principle: they may read or write tracked memory, so incoming definitions are treated as externally observable and an unknown clobber is added rather than replacing the old definition.

## Store-to-load chains

Each exact direct read reports:

- `memory_sources` — all reaching memory definitions;
- `load_from_stores` — the precise `MS...` subset;
- `memory_constant` — a value only when every reaching definition proves the same constant;
- `loaded_register_constant` — recovered full-word load result for A/B/L/S/T/X when the memory constant is proven.

Each precise store definition records the source register, the register reaching-definitions feeding that store, and an exact constant when the pre-store register state proves one.

This creates a cross-domain evidence chain:

```text
register definition -> store -> memory definition -> load
```

## Overwritten stores

A store is reported as an `overwritten_store` only if all of the following hold in represented control flow:

1. no exact load uses the store definition;
2. the value is not observable by an unknown/opaque memory reader such as a call;
3. the definition does not survive to a represented exit.

This is intentionally stricter than simply checking whether a store has no direct load use.

`same_value_store_candidates` are weaker diagnostics. They identify a direct store whose proven constant equals the proven constant already reaching that exact cell. The word *candidate* is intentional: the analyzer does not claim arbitrary memory addresses are free of device or externally visible write effects.

## Function memory contracts

Function objects gain represented-flow memory facts:

- `memory_reads` / `memory_writes`;
- `memory_inputs` and use sites;
- `memory_passthrough_inputs`;
- `memory_partially_preserved_inputs`;
- `memory_overwritten_inputs`;
- `memory_outputs` and output store definitions.

These are not ABI declarations. They are facts over the typed CFG and represented `RSUB` returns. Functions without represented returns do not claim return-state memory contracts.

## Trust boundary

The analysis does not invent alias proofs. Indexed, indirect, unresolved, cross-call, and opaque memory behavior always degrades precision. Memory constants are recovered only when every reaching definition proves the same value. The analysis currently reports recovered load constants but does not feed them back into the historical control-flow pruning engine; executable CFG semantics remain unchanged by this enrichment layer.
