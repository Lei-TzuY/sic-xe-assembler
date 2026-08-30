# Unified toolchain CLI and verification

The historical entry points remain supported:

```text
python assembler.py program.asm
python loader.py program.obj 4000
python verify_link.py program.bin program.manifest.json program.obj
```

For normal use, `sicxe.py` exposes the complete workflow through one command surface.

## Assemble

```text
python sicxe.py assemble program.asm
```

Assembly keeps the existing fail-closed output policy: stale generated files are removed before work begins and partial outputs are removed if macro expansion, Pass 1, Pass 2, object canonicalization, address-space checks, overlap checks, or generated-object semantic validation fails.

## Link

```text
python sicxe.py link program.obj --progaddr 4000
python sicxe.py link main.obj io.obj math.obj --progaddr 8000
```

`--progaddr` is hexadecimal. The default remains `4000` for compatibility with the standalone loader.

One successful link emits three persistent artifacts beside the first object input:

- `.map` — human-readable section layout, ESTAB, cross-references, relocation arithmetic, provenance, INPUTSET, and LINKID;
- `.bin` — exact contiguous linked image for `[PROGADDR, PROGADDR + total_length)` after relocation;
- `.manifest.json` — canonical, path-independent output attestation containing the image SHA-256, ordered object hashes, section layout, entry point, INPUTSET, and LINKID.

The legacy `loader.py` parser is now strict. Unknown/unreadable object arguments and multiple positional PROGADDR values are usage errors instead of being silently ignored or overwritten.

## Verify

```text
python sicxe.py verify program.bin program.manifest.json program.obj
python verify_link.py program.bin program.manifest.json program.obj
```

Verification does not trust a previous `.map` or an earlier in-memory load plan. It independently:

1. reads the binary and canonical JSON manifest;
2. verifies the manifest schema and binary SHA-256;
3. captures the supplied object files again as an immutable link session;
4. recomputes INPUTSET and LINKID using the manifest PROGADDR;
5. rebuilds the complete load plan and ESTAB;
6. re-executes relocation and materializes fresh SIC/XE memory;
7. compares the reproduced linked range byte-for-byte with the supplied `.bin`;
8. reconstructs the expected manifest and requires semantic equality;
9. requires the persisted JSON bytes to equal the canonical deterministic serialization.

This detects binary tampering, substituted/reordered object inputs, changed PROGADDR/link identity, modified manifest metadata, and noncanonical manifest serialization.

## Expression language

Assembler expressions now use a real precedence parser rather than additive string splitting.

Supported operators, from highest to lowest precedence:

1. parentheses: `( ... )`
2. unary `+` and `-`
3. binary `*` and `/`
4. binary `+` and `-`

`*` remains the current location when it appears where a primary expression is expected; between two operands it is multiplication. Division is integer division truncated toward zero.

Examples:

```asm
LEN      EQU     (BUFEND-BUFFER) * 4
OFFSET   EQU     -(A-B) + 20
VALUE    WORD    (LEN + 2) * 3
MIX      WORD    EXT1 - (EXT2 - 12)
```

Relocation algebra remains strict. Multiplication and division require both operands to be absolute. Expressions such as `BUFFER*2`, `EXT1/4`, or `(EXT1-EXT2)*2` are rejected because SIC/XE object modification records do not encode general scaled relocation terms. Parentheses and unary signs may freely rearrange additive local/external relocation terms.

## Exit status

The command-line convention is:

- `0` — operation completed successfully;
- `1` — source/object/artifact validation or execution failed;
- `2` — command-line usage error.

This makes the tools straightforward to use from CI scripts and larger build systems.
