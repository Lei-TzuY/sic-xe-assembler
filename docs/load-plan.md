# Deterministic load-plan contract

The loader separates **input capture**, **planning**, and **memory mutation**. Object files are captured into an immutable `LinkSession`; `build_load_plan()` must then complete successfully before `apply_load_plan()` allocates the 1 MiB SIC/XE memory image or writes any byte.

## Immutable input capture

`capture_link_session()` reads every object file exactly once. Each `ObjectInputSnapshot` retains:

- deterministic input index;
- display path and canonical path;
- the exact raw bytes read for this link invocation;
- byte length;
- SHA-256 of those raw bytes;
- immutable parsed record strings.

The session computes one order-sensitive, path-independent `input_fingerprint` from the ordered raw-input digests. Moving identical object bytes to different paths therefore does not change the content identity, while changing bytes or input order does.

`build_load_plan()` also computes a `link_fingerprint` from the input fingerprint plus `PROGADDR`. With no other linker options today, identical ordered object bytes linked at the same `PROGADDR` produce the same link ID.

Planning from a `LinkSession` never reopens the object files. A captured session can still be planned and materialized if an input is later modified, replaced, or deleted; the transaction remains bound to the bytes that were actually captured. `verify_link_session()` is an explicit optional check that rereads the current paths and fails if their SHA-256 values no longer match the session.

## Planning phases

1. Analyze every frozen object snapshot and run the shared H/D/R/T/M/E structural + semantic validator.
2. Lay out every control section sequentially from `PROGADDR` and validate each 20-bit machine-memory range.
3. Build one global ESTAB from control-section names and D-record definitions. Duplicate definitions are rejected with both definition provenances.
4. Resolve every M-record symbol against the complete ESTAB. R declarations that are never used by an M record are legal and are retained as `unused_references` metadata.
5. Group repeated M records by exact relocation field, decode the original addend, sum the complete signed ESTAB delta, validate the final result, and precompute the encoded field bytes.
6. Resolve the execution entry point. At most one explicit E-record address is allowed across all linked inputs; otherwise `PROGADDR` is the default entry.
7. Freeze the public ESTAB, symbol-source map, and T-record views exposed by the resulting `LoadPlan`.

Only after all phases succeed can the plan be applied.

## Planned section data

Each `PlannedSection` records:

- input file and deterministic input/section indices;
- source H-record origin and control-section length;
- final load address;
- D definitions and R references;
- immutable text-record views;
- prevalidated relocation fields;
- unused R declarations;
- source and loaded execution addresses when that section owns the explicit entry point.

Each `PlannedRelocation` records the original addend, exact accumulated delta, final relocated integer, encoded field value, source M records, and signed symbol terms. `apply_load_plan()` therefore does not repeat file I/O, symbol lookup, or relocation arithmetic.

## Traditional pass1/pass2 compatibility

The legacy `pass1()` / `pass2()` API remains supported without reopening the TOCTOU window. `pass1()` returns a `SessionEstab`, which is a normal `dict` subclass plus the immutable `LinkSession` used to construct it. A normal sequence:

```python
estab = pass1(obj_files, progaddr)
memory, entry = pass2(obj_files, progaddr, estab)
```

causes Pass 2 to build the complete plan from the exact Pass-1 snapshot, not from the current files on disk. Pass 2 also requires the object-file list to identify the same paths and requires the ESTAB values to match the plan exactly.

Code that explicitly converts the result with `dict(estab)` intentionally discards the session binding. For backward compatibility, Pass 2 then captures the current files once and performs the full preflight against that new snapshot. This legacy path preserves the old plain-dictionary API but cannot provide Pass-1/Pass-2 snapshot continuity because the caller removed the metadata that proves it.

## Failure atomicity

Planning failures include:

- malformed object programs;
- control-section placement overflow;
- duplicate external definitions;
- undefined external symbols used by M records;
- relocation overflow/underflow;
- ambiguous multiple explicit entry points;
- stale or tampered ESTAB data;
- reuse of a bound ESTAB with a different input-file list.

These failures happen before `apply_load_plan()` allocates or mutates the memory image. The materialization phase is intentionally simple: copy frozen validated T bytes, write precomputed relocation fields, and return the validated execution address.

## Reproducible artifacts

The persistent `.map` report records the ordered input snapshots, each raw SHA-256, the aggregate `INPUTSET` fingerprint, and the final `LINKID`. These values make a successful link independently auditable without trusting file modification times or reconstructing which bytes happened to be on disk between Pass 1 and Pass 2.