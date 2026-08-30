# Deterministic load-plan contract

The loader separates **planning** from **memory mutation**. `build_load_plan()` must complete successfully before `apply_load_plan()` allocates the 1 MiB SIC/XE memory image or writes any byte.

## Planning phases

1. Parse every object file and run the shared H/D/R/T/M/E structural + semantic validator.
2. Lay out every control section sequentially from `PROGADDR` and validate each 20-bit machine-memory range.
3. Build one global ESTAB from control-section names and D-record definitions. Duplicate definitions are rejected with both definition provenances.
4. Resolve every M-record symbol against the complete ESTAB. R declarations that are never used by an M record are legal and are retained as `unused_references` metadata.
5. Group repeated M records by exact relocation field, decode the original addend, sum the complete signed ESTAB delta, validate the final result, and precompute the encoded field bytes.
6. Resolve the execution entry point. At most one explicit E-record address is allowed across all linked inputs; otherwise `PROGADDR` is the default entry.

Only after all six phases succeed can the plan be applied.

## Planned section data

Each `PlannedSection` records:

- input file and deterministic input/section indices;
- source H-record origin and control-section length;
- final load address;
- D definitions and R references;
- text records;
- prevalidated relocation fields;
- unused R declarations;
- source and loaded execution addresses when that section owns the explicit entry point.

Each `PlannedRelocation` records the original addend, exact accumulated delta, final relocated integer, encoded field value, source M records, and signed symbol terms. `apply_load_plan()` therefore does not repeat symbol lookup or relocation arithmetic.

## ESTAB integrity

The legacy `pass1()` / `pass2()` API remains supported. `pass1()` returns the placement-derived ESTAB. Before `pass2()` writes memory it rebuilds the complete load plan and requires the caller-provided ESTAB to match exactly. This detects stale or tampered ESTAB data instead of silently loading with a different symbol map.

## Failure atomicity

Planning failures include:

- malformed object programs;
- control-section placement overflow;
- duplicate external definitions;
- undefined external symbols used by M records;
- relocation overflow/underflow;
- ambiguous multiple explicit entry points.

These failures happen before `apply_load_plan()` allocates or mutates the memory image. The materialization phase is intentionally simple: copy validated T bytes, write precomputed relocation fields, and return the validated execution address.
