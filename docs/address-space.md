# Address-space contract

SIC/XE uses two different widths that must not be conflated:

| Concept | Width | Range | Meaning |
| --- | ---: | ---: | --- |
| Object-program address field | 24 bits | `000000`-`FFFFFF` | Fixed six-hex-digit H/D/T/M/E serialization field |
| Machine byte address | 20 bits | `00000`-`FFFFF` | Addressable SIC/XE memory |
| Loader memory | 1 MiB | `0x00000`-`0xFFFFF` | Concrete byte array used by the linking loader |
| Format-4 address field | 20 bits | `0x00000`-`0xFFFFF` | Extended instruction address/displacement field |
| WORD data field | 24 bits | three bytes | Data value; not itself a machine-address-width declaration |

A six-digit object record therefore does **not** imply a 16 MiB machine. The extra object-field width is a serialization convention; assembler and loader placement still have to fit the 20-bit SIC/XE address space.

## Assembler rules

- `START` must be at most `0xFFFFF`.
- After `USE`, `ORG`, literal-pool placement, and program-block rebasing are finalized, every control section must satisfy `start + length <= 0x100000`.
- A control section may occupy the last addressable byte. For example, `START FFFFF` plus one `BYTE` is valid; a three-byte `WORD` there is not.
- Object framing remains six hexadecimal digits even when the represented machine address needs only five.
- `WORD` constants continue to use their independent 24-bit data range.

## Loader rules

- `PROGADDR` must be a real machine byte address (`0x00000`-`0xFFFFF`).
- ESTAB construction validates placement before any memory mutation. A single section or the aggregate of multiple linked sections may end exactly at `0x100000`, but may not cross it.
- The loader allocates the full SIC/XE memory size (`1 << 20` bytes), so high addresses such as `0xF0000` are first-class load locations rather than artificial overflow cases.
- Text and modification writes are checked against the same memory limit after relocation.

## One-past-end symbols

An `EXTDEF` may denote a section boundary such as `BUFEND EQU *`. Its section-relative offset may equal the control-section length. Consequently, if a section occupies the final machine byte, its one-past-end boundary symbol can have ESTAB value `0x100000`.

That value is a **boundary value, not a dereferenceable byte address**. It remains useful for lengths, differences, and 24-bit data expressions. Code that needs a concrete machine byte address must remain within `0x00000`-`0xFFFFF`.
