# SIC/XE Assembler and Linking Loader

A small systems-programming project that implements macro expansion, a two-pass SIC/XE assembler, control sections, external definitions/references, relocation records, and a linking loader.

## Run the assembler

```powershell
python assembler.py test_xe.asm
```

For `program.asm`, the assembler writes `program.expanded.asm`, `program.int`, `program.sym`, `program.obj`, and `program.lst` beside the source file.

## Run the loader

```powershell
python loader.py program.obj 4000
```

Object programs retain their assembled control-section origin. The loader translates H/T/M/E record addresses to the requested `PROGADDR`, so sources with a non-zero `START` address relocate correctly instead of being loaded at `PROGADDR + START`.

## Verify the checked-in fixtures

```powershell
python verify.py
```

The verifier assembles `test.asm`, `test_macro.asm`, `test_csect.asm`, and `test_xe.asm` in a temporary directory and byte-compares all generated outputs with the checked-in golden files.

## Scope

This is an educational SIC/XE implementation, not a production toolchain. The fixtures cover the complete SIC/XE instruction table, format 1–4 encoding, PC/base-relative addressing, location-counter expressions, macros, control sections, external symbols, local/external relocation records, and loader relocation.
