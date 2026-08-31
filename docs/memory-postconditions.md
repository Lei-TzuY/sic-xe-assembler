# Initialized memory and return postconditions

This layer sits above the reaching-store analysis. It never changes object files, relocation, linked-image bytes, manifest identities, or the historical CFG core.

## Typed initialized-memory seeds

The analyzer may seed a tracked memory cell from the linked image only when all of the following are true:

1. linked debug metadata marks the section as typed;
2. one `word`, `byte`, or `literal` region wholly covers the cell;
3. the cell lies inside the persisted linked image;
4. there is exactly one covering initialized region.

The linked image bytes are authoritative, so relocation has already been applied. `reservation` regions never seed a value, even when an ORG overlay intentionally shares their address range with initialized storage.

A 3-byte cell also receives a signed 24-bit singleton range. Other widths may carry an exact byte-string value without pretending that it is a signed SIC/XE word interval.

## Must-value memory domain

Reaching stores answer **which definitions may reach a load**. The must-value domain asks a different question: **do all represented executions agree on the same memory value or range?**

At a merge:

- exact constants survive only when both incoming values are the same;
- intervals are joined by their convex hull only when both sides have known intervals;
- any unknown side makes the interval unknown.

Direct stores strongly replace the abstract value of the exact tracked cell. Partial overlap, indexed/indirect writes, unresolved calls, and opaque writers conservatively destroy must-value certainty.

## Initialized values and register feedback

A direct load may feed an initialized or post-call memory value back into the existing register/range transfer functions. Therefore code such as:

```asm
INIT  WORD 5
      ...
      LDA INIT
      COMP #5
      JEQ TAKEN
```

can prove `A=5`, `CC=EQ`, and prune the impossible fallthrough without any runtime `STA` first.

The same feedback works for `LDCH` when the rest of A is already known and for a 3-byte literal that is read as a word.

## Memory-derived base targets

When a memory-backed load proves incoming `B`, a b-relative instruction can be decoded again with that value. These resolutions are marked separately:

- `memory-feedback-base` for an exact B value;
- `memory-feedback-range-base` for a singleton interval.

If a memory-owned B proof disappears, its target is revoked. Historical `dataflow-base` and `range-singleton-base` resolutions remain owned by the older core analysis.

Whenever a memory-derived target changes, instruction edges and proof-based synthetic returns are rebuilt before the fixed point continues.

## Callee return-memory postconditions

Resolved callees first receive structural may-read/may-write summaries. A separate function-local must-value analysis starts each callee with unknown memory and examines every represented `RSUB`.

A cell receives a return constant only if every represented return has the same exact value. It receives a return range only if every represented return has a known interval; the summary stores the hull across those returns.

Thus:

```asm
SETVAL LDA #7
       STA SLOT
       RSUB
```

may prove `SLOT=7` on return, while:

```asm
MAYSET JEQ SKIP
       LDA #7
       STA SLOT
SKIP   RSUB
```

cannot prove any SLOT postcondition because one represented path preserves the unknown incoming value.

Nested resolved callees compose by fixed point. If an inner callee proves a return value, an outer callee may use that fact when computing its own returns. Unknown or aliased writes still collapse the affected must-value state to unknown.

## Separation from reaching-store provenance

Return postconditions do not rewrite reaching-store IDs. A load may still report conservative `MI/MS/MC` sources while the must-value layer proves that all represented outcomes agree on one value. The report exposes the proof origin through `memory_value_resolution` so provenance and abstract value evidence remain distinguishable.

## Convergence and structural refresh

The analysis iterates:

1. tracked-cell discovery and initialized-image seeding;
2. function-local memory must values;
3. callee return-memory summaries;
4. memory-aware exact/range register propagation;
5. condition pruning;
6. memory-derived B target resolution;
7. edge rebuild when a target changes.

After convergence, reachability, basic blocks, dominators, loops, call graph, complexity, liveness, reaching definitions, and function contracts are rebuilt from the refined graph.

The analysis is fail-conservative: uncertainty removes facts; it never fabricates a constant, range, alias target, or return postcondition.