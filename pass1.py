from errors import AssemblyError
from expressions import evaluate_expression
from opcodes import DIRECTIVES, OPCODES


PROGRAM_BLOCK_STRIDE = 1 << 28


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


def _new_block(name, order, virtual_base):
    return {
        'name': name,
        'order': order,
        'virtual_base': virtual_base,
        'locctr': 0,
        'max_locctr': 0,
        'org_stack': [],
        'start': None,
        'length': 0,
    }


def _new_csect(start):
    default_block = _new_block('', 0, start)
    return {
        'symtab': {},
        'relocatable': set(),
        'extdef': [],
        'extref': [],
        'literals': {},
        'pending_literals': [],
        'symbol_blocks': {},
        'equ_defs': {},
        'equ_order': [],
        'blocks': {'': default_block},
        'start': start,
        'length': 0,
        'finalized': False,
    }


def _block_location(block):
    return block['virtual_base'] + block['locctr']


def _note_block_location(block):
    if block['locctr'] > block['max_locctr']:
        block['max_locctr'] = block['locctr']


def _ensure_block(csect, block_name):
    if block_name not in csect['blocks']:
        order = len(csect['blocks'])
        virtual_base = csect['start'] + PROGRAM_BLOCK_STRIDE * order
        csect['blocks'][block_name] = _new_block(block_name, order, virtual_base)
    return csect['blocks'][block_name]


def _resolve_equ_definitions(csect):
    """Resolve EQU symbols after program-block addresses have been finalized."""
    resolved_symtab = {
        symbol: csect['symtab'][symbol]
        for symbol in csect['symbol_blocks']
    }
    resolved_relocatable = set(csect['symbol_blocks'])
    resolved = set()
    resolving = []

    def resolve(symbol):
        if symbol in resolved:
            return

        if symbol in resolving:
            cycle_start = resolving.index(symbol)
            cycle = resolving[cycle_start:] + [symbol]
            current_symbol = resolving[-1]
            definition = csect['equ_defs'][current_symbol]
            raise AssemblyError(
                f"Circular EQU dependency: {' -> '.join(cycle)}",
                phase="pass 1",
                line_number=definition['line_number'],
            )

        definition = csect['equ_defs'][symbol]
        block = csect['blocks'][definition['block']]
        current_location = block['start'] + definition['offset']
        resolving.append(symbol)

        while True:
            try:
                result = evaluate_expression(
                    definition['expression'],
                    current_location,
                    resolved_symtab,
                    resolved_relocatable,
                )
            except ValueError as exc:
                message = str(exc)
                prefix = "Undefined symbol "
                if message.startswith(prefix):
                    dependency = message[len(prefix):]
                    if dependency in csect['equ_defs']:
                        resolve(dependency)
                        continue
                raise AssemblyError(
                    message,
                    phase="pass 1",
                    line_number=definition['line_number'],
                ) from exc
            break

        if not 0 <= result.value <= 0xFFFFFF:
            raise AssemblyError(
                f"EQU value out of range: {result.value}",
                phase="pass 1",
                line_number=definition['line_number'],
            )

        resolved_symtab[symbol] = result.value
        if result.relocatable:
            resolved_relocatable.add(symbol)
        else:
            resolved_relocatable.discard(symbol)
        resolving.pop()
        resolved.add(symbol)

    for symbol in csect['equ_order']:
        resolve(symbol)

    for symbol in csect['equ_order']:
        csect['symtab'][symbol] = resolved_symtab[symbol]
    csect['relocatable'] = resolved_relocatable


def _finalize_csect(csect):
    if csect['finalized']:
        return

    next_start = csect['start']
    for block in csect['blocks'].values():
        _note_block_location(block)
        block['length'] = block['max_locctr']
        block['start'] = next_start
        next_start += block['length']

    csect['length'] = next_start - csect['start']
    if next_start > 0x1000000:
        raise ValueError("Control section exceeds 24-bit address space")

    for symbol, (block_name, offset) in csect['symbol_blocks'].items():
        block = csect['blocks'][block_name]
        csect['symtab'][symbol] = block['start'] + offset

    _resolve_equ_definitions(csect)

    for entry in csect['literals'].values():
        if entry['block'] is not None:
            block = csect['blocks'][entry['block']]
            entry['address'] = block['start'] + entry['offset']

    csect['finalized'] = True


def run_pass1(asm_file, int_file, sym_file):
    csects = {}
    current_csect = ""
    current_block = ''
    start_address = 0
    saw_end = False
    intermediate_records = []

    def fail(line_number, message):
        raise AssemblyError(message, phase="pass 1", line_number=line_number)

    def emit_record(csect_name, block_name, offset, text, addressed=True):
        intermediate_records.append({
            'csect': csect_name,
            'block': block_name,
            'offset': offset,
            'text': text,
            'addressed': addressed,
        })

    with open(asm_file, 'r') as f_in:
        lines = f_in.readlines()
        first_line = True

        def current_data():
            return csects[current_csect]

        def current_block_data():
            return current_data()['blocks'][current_block]

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
                    'block': None,
                    'offset': None,
                }
                csect['pending_literals'].append(canonical)

        def flush_literals(csect, line_number):
            block = current_block_data()
            pending = csect['pending_literals']
            for canonical in pending:
                entry = csect['literals'][canonical]
                if entry['block'] is not None:
                    continue
                entry['block'] = current_block
                entry['offset'] = block['locctr']
                body = canonical[1:]
                emit_record(
                    current_csect,
                    current_block,
                    block['locctr'],
                    f"{canonical} BYTE {body}",
                )
                block['locctr'] += len(entry['object_code']) // 2
                _note_block_location(block)
                if block['locctr'] > 0x1000000:
                    fail(line_number, "Program block exceeds 24-bit address space")
            pending.clear()

        def define_label(csect, label, line_number):
            if not label:
                return
            if label in csect['symtab'] or label in csect['equ_defs']:
                fail(line_number, f"Duplicate label {label} in {current_csect}")
            block = current_block_data()
            csect['symtab'][label] = _block_location(block)
            csect['relocatable'].add(label)
            csect['symbol_blocks'][label] = (current_block, block['locctr'])

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
                current_csect = label if label else "DEFAULT"
                csects[current_csect] = _new_csect(start_address)
                current_block = ''
                emit_record(current_csect, current_block, 0, line.strip())
                first_line = False
                continue

            first_line = False

            if not current_csect:
                current_csect = "DEFAULT"
                csects[current_csect] = _new_csect(0)
                current_block = ''

            if opcode == 'START':
                fail(line_number, "START must be the first non-comment statement")

            if opcode == 'CSECT':
                csect = current_data()
                flush_literals(csect, line_number)
                try:
                    _finalize_csect(csect)
                except ValueError as exc:
                    fail(line_number, str(exc))

                new_csect = label if label else "UNNAMED"
                if new_csect in csects:
                    fail(line_number, f"Duplicate control section: {new_csect}")
                current_csect = new_csect
                csects[current_csect] = _new_csect(0)
                current_block = ''
                emit_record(current_csect, current_block, 0, line.strip())
                continue

            if opcode == 'END':
                csect = current_data()
                flush_literals(csect, line_number)
                try:
                    _finalize_csect(csect)
                except ValueError as exc:
                    fail(line_number, str(exc))
                emit_record(current_csect, current_block, 0, line.strip(), addressed=False)
                saw_end = True
                break

            csect = current_data()
            block = current_block_data()
            source_offset = block['locctr']
            emit_record(current_csect, current_block, source_offset, line.strip())

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
                if not operand:
                    fail(line_number, "Expression is required")
                if label in csect['symtab'] or label in csect['equ_defs']:
                    fail(line_number, f"Duplicate label {label} in {current_csect}")

                csect['equ_defs'][label] = {
                    'expression': operand,
                    'block': current_block,
                    'offset': block['locctr'],
                    'line_number': line_number,
                }
                csect['equ_order'].append(label)

                try:
                    result = evaluate_expression(
                        operand,
                        _block_location(block),
                        csect['symtab'],
                        csect['relocatable'],
                    )
                except ValueError as exc:
                    if not str(exc).startswith("Undefined symbol "):
                        fail(line_number, str(exc))
                else:
                    if not 0 <= result.value <= 0xFFFFFF:
                        fail(line_number, f"EQU value out of range: {result.value}")
                    csect['symtab'][label] = result.value
                    if result.relocatable:
                        csect['relocatable'].add(label)
                    else:
                        csect['relocatable'].discard(label)
                continue

            if opcode == 'ORG':
                define_label(csect, label, line_number)
                if operand:
                    try:
                        result = evaluate_expression(
                            operand,
                            _block_location(block),
                            csect['symtab'],
                            csect['relocatable'],
                        )
                    except ValueError as exc:
                        fail(line_number, str(exc))
                    target_offset = result.value - block['virtual_base']
                    if not 0 <= target_offset <= 0xFFFFFF:
                        if current_block == '':
                            fail(
                                line_number,
                                f"ORG target outside control section address range: {result.value}",
                            )
                        fail(
                            line_number,
                            "ORG target must resolve within the current program block",
                        )
                    block['org_stack'].append(block['locctr'])
                    block['locctr'] = target_offset
                    _note_block_location(block)
                else:
                    if not block['org_stack']:
                        fail(line_number, "ORG restore requested without a saved location")
                    block['locctr'] = block['org_stack'].pop()
                continue

            if opcode == 'USE':
                define_label(csect, label, line_number)
                target_block = operand.strip() if operand else ''
                if target_block and (
                    any(char.isspace() for char in target_block) or ',' in target_block
                ):
                    fail(line_number, f"Invalid USE block name: {operand}")
                _ensure_block(csect, target_block)
                current_block = target_block
                continue

            if opcode == 'LTORG':
                if operand:
                    fail(line_number, "LTORG does not take an operand")
                define_label(csect, label, line_number)
                flush_literals(csect, line_number)
                continue

            define_label(csect, label, line_number)

            try:
                size = instruction_size(opcode) if opcode else None
            except ValueError as exc:
                fail(line_number, str(exc))

            if size is not None:
                if OPCODES[opcode[1:] if opcode.startswith('+') else opcode][1] == 3:
                    register_literal(csect, operand, line_number)
                block['locctr'] += size
            elif opcode == 'WORD':
                if operand is None:
                    fail(line_number, "WORD requires an operand")
                block['locctr'] += 3
            elif opcode == 'RESW':
                try:
                    block['locctr'] += 3 * _parse_nonnegative_decimal(operand, 'RESW')
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode == 'RESB':
                try:
                    block['locctr'] += _parse_nonnegative_decimal(operand, 'RESB')
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode == 'BYTE':
                try:
                    block['locctr'] += len(encode_byte_operand(operand)) // 2
                except ValueError as exc:
                    fail(line_number, str(exc))
            elif opcode in ['BASE', 'NOBASE']:
                pass
            elif opcode:
                fail(line_number, f"Invalid opcode {opcode}")

            _note_block_location(block)
            if block['locctr'] > 0x1000000:
                fail(line_number, "Program block exceeds 24-bit address space")

    if not saw_end:
        raise AssemblyError("Missing END directive", phase="pass 1")

    with open(int_file, 'w') as f_out:
        for record in intermediate_records:
            if not record['addressed']:
                f_out.write(f"\t\t{record['text']}\n")
                continue
            csect = csects[record['csect']]
            block = csect['blocks'][record['block']]
            address = block['start'] + record['offset']
            f_out.write(f"{address:04X}\t{record['text']}\n")

    with open(sym_file, 'w') as f_sym:
        for cs_name, cs_data in csects.items():
            f_sym.write(f"CS: {cs_name}\n")
            for lbl, addr in cs_data['symtab'].items():
                f_sym.write(f"  {lbl}\t{addr:04X}\n")
            for literal, entry in cs_data['literals'].items():
                if entry['address'] is not None:
                    f_sym.write(f"  {literal}\t{entry['address']:04X}\n")

    return csects, start_address