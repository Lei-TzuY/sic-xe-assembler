from errors import AssemblyError
from expressions import evaluate_expression
from opcodes import DIRECTIVES, OPCODES


def _strip_comment(line):
    """Strip SIC/XE comments without treating periods inside literals as comments."""
    in_quote = False
    for index, char in enumerate(line):
        if char == "'":
            in_quote = not in_quote
        elif char == '.' and not in_quote and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip('\n')


def parse_line(line):
    had_leading_whitespace = bool(line[:1].isspace())
    code = _strip_comment(line).strip()
    if not code:
        return None, None, None, True

    first_parts = code.split(None, 1)
    first = first_parts[0]
    remainder = first_parts[1].strip() if len(first_parts) > 1 else ""

    def is_opcode(token):
        raw = token[1:] if token.startswith('+') else token
        return raw in OPCODES or token in DIRECTIVES

    if is_opcode(first) or had_leading_whitespace:
        return None, first, remainder or None, False

    if not remainder:
        return first, None, None, False

    opcode_parts = remainder.split(None, 1)
    opcode = opcode_parts[0]
    operand = opcode_parts[1].strip() if len(opcode_parts) > 1 else None
    return first, opcode, operand, False


def instruction_size(opcode):
    """Return the encoded size for an instruction, validating extended format use."""
    raw_opcode = opcode[1:] if opcode.startswith('+') else opcode
    if raw_opcode not in OPCODES:
        return None

    fmt = OPCODES[raw_opcode][1]
    if opcode.startswith('+'):
        if fmt != 3:
            raise ValueError(
                f"Extended format is only valid for format 3/4 instructions: {opcode}"
            )
        return 4
    return fmt


def encode_byte_operand(operand):
    """Validate a BYTE operand and return its hexadecimal object representation."""
    if not operand or len(operand) < 3 or operand[1] != "'" or not operand.endswith("'"):
        raise ValueError(f"Invalid BYTE operand: {operand}")

    kind = operand[0].upper()
    payload = operand[2:-1]

    if kind == 'C':
        if any(ord(char) > 0xFF for char in payload):
            raise ValueError("BYTE character constants must contain single-byte characters")
        return "".join(f"{ord(char):02X}" for char in payload)

    if kind == 'X':
        if len(payload) % 2:
            raise ValueError("BYTE hexadecimal constants must contain an even number of digits")
        try:
            int(payload or '0', 16)
        except ValueError as exc:
            raise ValueError(f"Invalid hexadecimal BYTE constant: {payload}") from exc
        return payload.upper()

    raise ValueError(f"BYTE operand must use C'..' or X'..': {operand}")


def parse_literal(literal):
    """Return canonical literal spelling and object bytes for =C'..' / =X'..'."""
    if not literal or not literal.startswith('='):
        raise ValueError(f"Invalid literal: {literal}")

    body = literal[1:]
    object_code = encode_byte_operand(body)
    kind = body[0].upper()
    payload = body[2:-1]
    if kind == 'X':
        canonical = f"=X'{object_code}'"
    else:
        canonical = f"=C'{payload}'"
    return canonical, object_code


def literal_from_operand(operand):
    """Extract and validate a literal reference from an instruction operand."""
    if not operand:
        return None

    token = operand.strip()
    if token.startswith(('#', '@')):
        token = token[1:].strip()
    if token.upper().endswith(',X'):
        token = token[:-2].strip()
    if not token.startswith('='):
        return None
    return parse_literal(token)


def _parse_nonnegative_decimal(operand, directive):
    if operand is None:
        raise ValueError(f"{directive} requires an operand")
    try:
        value = int(operand, 10)
    except ValueError as exc:
        raise ValueError(f"{directive} requires a decimal integer: {operand}") from exc
    if value < 0:
        raise ValueError(f"{directive} operand must be non-negative: {operand}")
    return value


def _new_csect(start):
    return {
        'symtab': {},
        'relocatable': set(),
        'extdef': [],
        'extref': [],
        'literals': {},
        'pending_literals': [],
        'start': start,
        'length': 0,
    }


def _finish_csect(csect, locctr):
    length = locctr - csect['start']
    if length < 0:
        raise ValueError("Location counter moved before control-section start")
    csect['length'] = length


def run_pass1(asm_file, int_file, sym_file):
    csects = {}
    current_csect = ""
    locctr = 0
    start_address = 0
    saw_end = False

    def fail(line_number, message):
        raise AssemblyError(message, phase="pass 1", line_number=line_number)

    with open(asm_file, 'r') as f_in, open(int_file, 'w') as f_out:
        lines = f_in.readlines()
        first_line = True

        def register_literal(csect, operand, line_number):
            try:
                parsed = literal_from_operand(operand)
            except ValueError as exc:
                fail(line_number, str(exc))
            if parsed is None:
                return

            canonical, object_code = parsed
            if canonical not in csect['literals']:
                csect['literals'][canonical] = {
                    'address': None,
                    'object_code': object_code,
                }
                csect['pending_literals'].append(canonical)

        def flush_literals(csect, line_number):
            nonlocal locctr
            pending = csect['pending_literals']
            for canonical in pending:
                entry = csect['literals'][canonical]
                if entry['address'] is not None:
                    continue
                entry['address'] = locctr
                body = canonical[1:]
                f_out.write(f"{locctr:04X}\t{canonical} BYTE {body}\n")
                locctr += len(entry['object_code']) // 2
                if locctr > 0x1000000:
                    fail(line_number, "Location counter exceeds 24-bit address space")
            pending.clear()

        for line_number, line in enumerate(lines, 1):
            label, opcode, operand, is_comment = parse_line(line)
            if is_comment:
                continue

            if first_line and opcode == 'START':
                try:
                    start_address = int(operand, 16) if operand else 0
                except ValueError:
                    fail(line_number, f"Invalid START address: {operand}")
                if not 0 <= start_address <= 0xFFFFFF:
                    fail(line_number, f"START address out of range: {operand}")
                locctr = start_address
                current_csect = label if label else "DEFAULT"
                csects[current_csect] = _new_csect(start_address)
                f_out.write(f"{locctr:04X}\t{line.strip()}\n")
                first_line = False
                continue

            first_line = False

            if not current_csect:
                current_csect = "DEFAULT"
                csects[current_csect] = _new_csect(0)

            if opcode == 'START':
                fail(line_number, "START must be the first non-comment statement")

            if opcode == 'CSECT':
                current_data = csects[current_csect]
                flush_literals(current_data, line_number)
                try:
                    _finish_csect(current_data, locctr)
                except ValueError as exc:
                    fail(line_number, str(exc))
                new_csect = label if label else "UNNAMED"
                if new_csect in csects:
                    fail(line_number, f"Duplicate control section: {new_csect}")
                current_csect = new_csect
                csects[current_csect] = _new_csect(0)
                locctr = 0
                f_out.write(f"{locctr:04X}\t{line.strip()}\n")
                continue

            if opcode == 'END':
                current_data = csects[current_csect]
                flush_literals(current_data, line_number)
                try:
                    _finish_csect(current_data, locctr)
                except ValueError as exc:
                    fail(line_number, str(exc))
                f_out.write(f"\t\t{line.strip()}\n")
                saw_end = True
                break

            f_out.write(f"{locctr:04X}\t{line.strip()}\n")
            csect = csects[current_csect]

            if opcode == 'EXTDEF':
                if not operand:
                    fail(line_number, "EXTDEF requires at least one symbol")
                symbols = [part.strip() for part in operand.split(',')]
                if any(not symbol for symbol in symbols):
                    fail(line_number, "EXTDEF contains an empty symbol")
                csect['extdef'].extend(symbols)
                continue

            if opcode == 'EXTREF':
                if not operand:
                    fail(line_number, "EXTREF requires at least one symbol")
                symbols = [part.strip() for part in operand.split(',')]
                if any(not symbol for symbol in symbols):
                    fail(line_number, "EXTREF contains an empty symbol")
                csect['extref'].extend(symbols)
                continue

            if opcode == 'EQU':
                if not label:
                    fail(line_number, "EQU requires a label")
                if label in csect['symtab']:
                    fail(line_number, f"Duplicate label {label} in {current_csect}")
                try:
                    result = evaluate_expression(
                        operand,
                        locctr,
                        csect['symtab'],
                        csect['relocatable'],
                    )
                except ValueError as exc:
                    fail(line_number, str(exc))
                if not 0 <= result.value <= 0xFFFFFF:
                    fail(line_number, f"EQU value out of range: {result.value}")
                csect['symtab'][label] = result.value
                if result.relocatable:
                    csect['relocatable'].add(label)
                continue

            if opcode == 'LTORG':
                if operand:
                    fail(line_number, "LTORG does not take an operand")
                if label:
                    if label in csect['symtab']:
                        fail(line_number, f"Duplicate label {label} in {current_csect}")
                    csect['symtab'][label] = locctr
                    csect['relocatable'].add(label)
                flush_literals(csect, line_number)
                continue

            if label:
                if label in csect['symtab']:
                    fail(line_number, f"Duplicate label {label} in {current_csect}")
                csect['symtab'][label] = locctr
                csect['relocatable'].add(label)

            try:
                size = instruction_size(opcode) if opcode else None
            except ValueError as exc:
                fail(line_number, str(exc))

            if size is not None:
                if OPCODES[opcode[1:] if opcode.startswith('+') else opcode][1] == 3:
                    register_literal(csect, operand, line_number)
                locctr += size
            elif opcode == 'WORD':
                if operand is None:
                    fail(line_number, "WORD requires an operand")
                locctr += 3
            elif opcode == 'RESW':
                try:
                    locctr += 3 * _parse_nonnegative_decimal(operand, 'RESW')
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode == 'RESB':
                try:
                    locctr += _parse_nonnegative_decimal(operand, 'RESB')
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode == 'BYTE':
                try:
                    locctr += len(encode_byte_operand(operand)) // 2
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode in ['BASE', 'NOBASE']:
                pass
            elif opcode:
                fail(line_number, f"Invalid opcode {opcode}")

            if locctr > 0x1000000:
                fail(line_number, "Location counter exceeds 24-bit address space")

    if not saw_end:
        raise AssemblyError("Missing END directive", phase="pass 1")

    with open(sym_file, 'w') as f_sym:
        for cs_name, cs_data in csects.items():
            f_sym.write(f"CS: {cs_name}\n")
            for lbl, addr in cs_data['symtab'].items():
                f_sym.write(f"  {lbl}\t{addr:04X}\n")
            for literal, entry in cs_data['literals'].items():
                if entry['address'] is not None:
                    f_sym.write(f"  {literal}\t{entry['address']:04X}\n")

    return csects, start_address
