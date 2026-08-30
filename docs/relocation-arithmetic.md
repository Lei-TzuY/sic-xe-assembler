# Relocation arithmetic contract

SIC/XE modification records identify a field by source address and half-byte width. This implementation treats all M records with the same `(address, half_bytes)` as terms of one relocation expression rather than as independent modular writes.

## Object addends

The object field contains the expression portion known at assembly time. To make that addend unambiguous at load time:

- 5-half-byte format-4 fields use an **unsigned 20-bit** addend (`0..0xFFFFF`).
- 6-half-byte `WORD` fields use a **signed 24-bit two's-complement** addend (`-0x800000..0x7FFFFF`).

The assembler rejects relocatable expressions whose pre-link value does not fit the corresponding addend contract. Non-relocatable `WORD` constants retain the wider existing data contract (`-0x800000..0xFFFFFF`).

## Link-time evaluation

For one field, the loader computes:

```text
final = decoded_addend + sum(+ESTAB[symbol]) - sum(ESTAB[symbol])
```

using normal unbounded integer arithmetic. It does not truncate after each M record.

The final value must satisfy:

- format-4 field: `0..0xFFFFF`;
- `WORD` field: `-0x800000..0xFFFFFF`.

Only after the final range check succeeds is the value encoded back into memory. For a 5-half-byte field, the upper flag nibble of the containing three bytes is preserved.

This means a sequence whose intermediate terms would exceed the field width can still be valid when the complete expression cancels back into range. Conversely, a true final overflow or underflow is a loader error rather than silent modular wraparound.

## Modification-field overlap

Repeated M records over exactly the same address and width are valid and are grouped. Different relocation fields may not partially overlap the same three bytes, and the same address may not mix 5- and 6-half-byte widths. Such object programs are rejected as ambiguous before memory mutation.
