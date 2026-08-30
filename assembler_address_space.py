from address_space import SICXE_MAX_ADDRESS, validate_machine_range
from errors import AssemblyError


def validate_source_start_address(source_path, parse_line):
    """Reject a source START that cannot denote a SIC/XE machine address."""
    with open(source_path, 'r') as source:
        for line_number, line in enumerate(source, 1):
            _, opcode, operand, is_comment = parse_line(line)
            if is_comment:
                continue
            if opcode != 'START':
                return
            if not operand:
                return
            try:
                start = int(operand, 16)
            except ValueError:
                # Pass 1 owns malformed START diagnostics.
                return
            if start > SICXE_MAX_ADDRESS:
                raise AssemblyError(
                    f"START address exceeds 20-bit SIC/XE memory: {operand}",
                    phase="address contract",
                    line_number=line_number,
                )
            return


def validate_finalized_csect_ranges(csects):
    """Require every finalized control section to fit the 1 MiB machine space."""
    for name, data in csects.items():
        try:
            validate_machine_range(
                data['start'],
                data['length'],
                f"Control section {name}",
            )
        except ValueError as exc:
            raise AssemblyError(str(exc), phase="address contract") from exc
