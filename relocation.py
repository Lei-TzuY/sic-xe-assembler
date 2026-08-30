FORMAT4_RELOCATION_BITS = 20
FORMAT4_RELOCATION_HALF_BYTES = 5
FORMAT4_RELOCATION_MAX = (1 << FORMAT4_RELOCATION_BITS) - 1

WORD_RELOCATION_BITS = 24
WORD_RELOCATION_HALF_BYTES = 6
WORD_SIGNED_MIN = -(1 << (WORD_RELOCATION_BITS - 1))
WORD_SIGNED_MAX = (1 << (WORD_RELOCATION_BITS - 1)) - 1
WORD_UNSIGNED_MAX = (1 << WORD_RELOCATION_BITS) - 1


def _sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    mask = (1 << bits) - 1
    value &= mask
    return value - (1 << bits) if value & sign_bit else value


def has_relocation_terms(result):
    return bool(result.local_relocation_factor or result.external_terms)


def validate_object_addend(value, half_bytes):
    """Validate the unrelocated addend encoded by the assembler.

    Five-half-byte SIC/XE relocation fields are unsigned 20-bit address
    addends. Six-half-byte WORD relocation fields use a signed 24-bit addend,
    which gives the loader an unambiguous two's-complement interpretation.
    """
    if half_bytes == FORMAT4_RELOCATION_HALF_BYTES:
        if not 0 <= value <= FORMAT4_RELOCATION_MAX:
            raise ValueError(
                f"Format-4 relocation addend out of unsigned 20-bit range: {value}"
            )
        return value

    if half_bytes == WORD_RELOCATION_HALF_BYTES:
        if not WORD_SIGNED_MIN <= value <= WORD_SIGNED_MAX:
            raise ValueError(
                f"WORD relocation addend out of signed 24-bit range: {value}"
            )
        return value

    raise ValueError(f"Unsupported relocation field length: {half_bytes}")


def decode_object_addend(raw_value, half_bytes):
    if half_bytes == FORMAT4_RELOCATION_HALF_BYTES:
        return raw_value & FORMAT4_RELOCATION_MAX
    if half_bytes == WORD_RELOCATION_HALF_BYTES:
        return _sign_extend(raw_value, WORD_RELOCATION_BITS)
    raise ValueError(f"Unsupported relocation field length: {half_bytes}")


def validate_relocated_value(value, half_bytes):
    """Validate an exact post-link value before encoding it back into memory."""
    if half_bytes == FORMAT4_RELOCATION_HALF_BYTES:
        if not 0 <= value <= FORMAT4_RELOCATION_MAX:
            raise ValueError(
                f"Format-4 relocation result out of unsigned 20-bit range: {value}"
            )
        return value

    if half_bytes == WORD_RELOCATION_HALF_BYTES:
        # WORD is a 24-bit data field: negative results use signed
        # two's-complement, while non-negative data may use the full unsigned
        # 24-bit range.
        if not WORD_SIGNED_MIN <= value <= WORD_UNSIGNED_MAX:
            raise ValueError(
                f"WORD relocation result out of 24-bit range: {value}"
            )
        return value

    raise ValueError(f"Unsupported relocation field length: {half_bytes}")


def encode_relocated_value(value, half_bytes):
    validate_relocated_value(value, half_bytes)
    if half_bytes == FORMAT4_RELOCATION_HALF_BYTES:
        return value
    return value & WORD_UNSIGNED_MAX
