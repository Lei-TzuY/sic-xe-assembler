# SIC/XE Assembler and Linking Loader

A small systems-programming project that implements macro expansion, a two-pass SIC/XE assembler, control sections, program blocks, external definitions/references, relocation records, literal pools, expression algebra, forward `EQU`, `ORG`, object-program contract validation, and a linking loader.

## Run the assembler

```powershell
python assembler.py test_xe.asm
```

For `program.asm`, the assembler writes `program.expanded.asm`, `program.int`, `program.sym`, `program.obj`, and `program.lst` beside the source file.

Object-program names used by control sections, `EXTDEF`, and `EXTREF` must fit the SIC/XE six-character fixed field: 1–6 ASCII alphanumeric characters beginning with a letter. Duplicate or colliding external namespaces are rejected instead of being silently truncated. Large D/R records are split to the standard 73-character record bound, and generated H/D/R/T/M/E framing is validated before assembly succeeds.

## Macro processor

Macros use positional `&NAME` parameters and are validated before expansion. Arguments may contain quoted commas, macro bodies may invoke other macros, and recursive expansion is rejected. Labels beginning with `$` are macro-local and are rewritten to deterministic unique symbols for each expansion, so repeated invocations do not create duplicate assembler labels.

Example:

```asm
SPIN     MACRO   &TARGET
$LOOP    LDA     &TARGET
         J       $LOOP
         MEND
```

Two `SPIN` invocations receive different expanded `$LOOP` symbols. Missing/extra arguments, duplicate or undeclared parameters, unexpected `MEND`, and unterminated definitions are hard assembly errors.

## Program blocks

`USE` switches among independent location counters inside one control section. The unnamed default block is laid out first; named blocks follow in first-seen order. Pass 1 records block-relative locations and rebases symbols, literals, and intermediate addresses only after all block lengths are known.

```asm
COPY     START   1000
FIRST    LDA     TABLE
         USE     DATA
TABLE    RESW    16
         USE     CODE
ROUTINE  RSUB
         USE
NEXT     WORD    TABLE-FIRST
         END     FIRST
```

`USE DATA` and `USE CODE` preserve the previous location of each block, while operand-less `USE` returns to the default block. Source order therefore does not need to match final memory order. Labels on a `USE` statement bind to the current block before the switch. Literal pools emitted by `LTORG` are placed in whichever block is active at that point. Each program block also owns an independent `ORG` restore stack.

## Literal pools

Format 3/4 instructions may reference character and hexadecimal literals with `=C'..'` and `=X'..'`. Literals are deduplicated within each control section. `LTORG` emits all currently pending literals at the current location; any remaining literals are emitted automatically before `CSECT` or `END`.

```asm
COPY     START   0
         LDA     =C'EOF'
         LDX     =C'EOF'
         LTORG
         LDCH    =X'F1'
         END     COPY
```

The two `=C'EOF'` references share one pool entry. Literal addresses participate in normal PC/base-relative addressing, and format-4 literal references generate the same control-section relocation records as local symbols.

## Expressions, forward EQU, and ORG

Assembler expressions support additive terms made from local symbols, `*`, decimal/hexadecimal integers, and `+` / `-`. Relocation legality follows SIC/XE relative-term algebra: `relative-relative` is absolute, `relative+absolute` remains relocatable, while expressions such as `relative+relative` or `absolute-relative` are rejected.

`EQU` definitions may refer to local symbols or other `EQU` symbols that appear later in the same control section. Definitions that can be evaluated immediately remain available to following statements; unresolved forward definitions are completed after program-block layout, so their final values use rebased block addresses. Dependency chains are resolved transitively and circular definitions are rejected with the dependency path.

```asm
LENGTH   EQU     BUFEND-BUFFER
PTR      EQU     BUFFER+3
BUFFER   RESB    64
BUFEND   EQU     *
```

The example resolves `LENGTH` as an absolute value and `PTR` as relocatable even though both reference later symbols. Undefined symbols are reported at the original `EQU` line. Forward `EQU` does not make layout-changing directives speculative: an `ORG` expression must still be resolvable when the `ORG` statement is encountered.

```asm
         ORG     BUFFER+16
FIELD    RESW    1
         ORG
```

`ORG expression` saves the current location and moves LOCCTR to the evaluated address; operand-less `ORG` restores the most recently saved location. With program blocks, `ORG` must resolve within the currently active block. Block length uses the highest location reached, so moving LOCCTR backward cannot truncate the final block or H-record length.

## External relocation expressions

`WORD` and format-4 instructions may combine `EXTREF` symbols with constants and local relocatable terms. The assembler stores the section-relative/absolute part in the object field and emits one signed modification record for every deferred relocation term.

```asm
         EXTREF  EXT1,EXT2
FIRST    +LDA    EXT1+7
DIFF     WORD    EXT1-EXT2+5
MIX      WORD    FIRST+EXT1-EXT2
```

For `DIFF`, the initial WORD value is `5`, followed by `+EXT1` and `-EXT2` modification records. `MIX` additionally emits a `+<current CSECT>` modification for the local relocatable `FIRST` term. Format-3 instructions reject expressions containing external symbols because they cannot be resolved with 12-bit PC/base-relative addressing, and `BASE` likewise rejects external expressions.

## Run the loader

```powershell
python loader.py program.obj 4000
```

Object programs retain their assembled control-section origin. The loader translates H/T/M/E record addresses to the requested `PROGADDR`, so sources with a non-zero `START` address relocate correctly instead of being loaded at `PROGADDR + START`.

Before ESTAB construction or memory mutation, the loader validates the complete section semantics: H ranges must stay within 24-bit source space; D offsets may denote the one-past-end location but not beyond it; T records may arrive out of address order but may not overlap; every M field must lie inside the section, be fully backed by loaded T bytes, and name either the current control section or a symbol declared by R; execution addresses are end-exclusive for non-empty sections. Across all linked inputs only one explicit execution address is accepted, preventing later object files from silently overriding the program entry point.

## Verify the checked-in fixtures

```powershell
python verify.py
```

The verifier assembles `test.asm`, `test_macro.asm`, `test_csect.asm`, and `test_xe.asm` in a temporary directory and byte-compares all generated outputs with the checked-in golden files.

## Scope

This is an educational SIC/XE implementation, not a production toolchain. The fixtures cover the complete SIC/XE instruction table, format 1–4 encoding, PC/base-relative addressing, SIC/XE relocation expressions including forward `EQU` dependencies and signed external modification terms, `ORG`, `USE` program blocks, literal pools and `LTORG`, validated/nested macro expansion, control sections, fixed-field object-program contracts, external symbols, local/external relocation records, semantic loader validation, and loader relocation.
