OBJECT_ADDRESS_BITS = 24
OBJECT_ADDRESS_SIZE = 1 << OBJECT_ADDRESS_BITS
OBJECT_ADDRESS_MAX = OBJECT_ADDRESS_SIZE - 1

SICXE_ADDRESS_BITS = 20
SICXE_MEMORY_SIZE = 1 << SICXE_ADDRESS_BITS
SICXE_MAX_ADDRESS = SICXE_MEMORY_SIZE - 1


def validate_machine_address(address, description="Address"):
    """Validate one addressable SIC/XE byte address."""
    if not 0 <= address <= SICXE_MAX_ADDRESS:
        raise ValueError(
            f"{description} outside {SICXE_ADDRESS_BITS}-bit SIC/XE memory: {address:#x}"
        )
    return address


def validate_machine_range(start, length, description="Range"):
    """Validate a SIC/XE memory interval [start, start + length)."""
    validate_machine_address(start, f"{description} start")
    if length < 0:
        raise ValueError(f"{description} length must be non-negative: {length}")
    if start + length > SICXE_MEMORY_SIZE:
        raise ValueError(
            f"{description} exceeds {SICXE_ADDRESS_BITS}-bit SIC/XE memory: "
            f"start={start:#x}, length={length:#x}"
        )
    return start, length
