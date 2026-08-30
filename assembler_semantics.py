from errors import AssemblyError
from loader_semantics import analyze_object_records
from pass1 import encode_byte_operand, instruction_size


def _source_statements(source_path, parse_line):
    statements = []
    with open(source_path, 'r') as source:
        for line_number, line in enumerate(source, 1):
            _, _, _, is_comment = parse_line(line)
            if is_comment:
                continue
            statements.append({
                'line_number': line_number,
                'text': line.strip(),
            })
    return statements


def _intermediate_records(int_path):
    records = []
    with open(int_path, 'r') as intermediate:
        for raw_line in intermediate:
            raw = raw_line.rstrip('\n')
            parts = raw.split('\t', 1)
            if len(parts) != 2:
                continue
            address_text = parts[0].strip()
            records.append({
                'address': int(address_text, 16) if address_text else None,
                'text': parts[1].strip(),
            })
    return records


def _object_size(opcode, operand):
    if not opcode:
        return 0
    size = instruction_size(opcode)
    if size is not None:
        return size
    if opcode == 'WORD':
        return 3
    if opcode == 'BYTE':
        return len(encode_byte_operand(operand)) // 2
    return 0


def _is_synthetic_literal(text, parse_line):
    label, opcode, _, is_comment = parse_line(text)
    return not is_comment and opcode == 'BYTE' and bool(label and label.startswith('='))


def _map_source_lines(source_path, int_path, parse_line):
    """Map intermediate statements back to expanded-source line numbers.

    Literal-pool rows are synthetic. LTORG emits them after its own row, while
    CSECT/END flushes place them immediately before the boundary row. Assign
    those rows to the source statement that caused the pool to materialize.
    """
    source = _source_statements(source_path, parse_line)
    records = _intermediate_records(int_path)
    source_index = 0
    last_matched = None

    for record in records:
        text = record['text']
        line_number = None

        if source_index < len(source) and text == source[source_index]['text']:
            line_number = source[source_index]['line_number']
            last_matched = source[source_index]
            source_index += 1
        elif _is_synthetic_literal(text, parse_line):
            if last_matched is not None:
                _, last_opcode, _, _ = parse_line(last_matched['text'])
            else:
                last_opcode = None

            if last_opcode == 'LTORG':
                line_number = last_matched['line_number']
            elif source_index < len(source):
                _, next_opcode, _, _ = parse_line(source[source_index]['text'])
                if next_opcode in ('CSECT', 'END'):
                    line_number = source[source_index]['line_number']

        record['line_number'] = line_number

    return records


def validate_initialized_storage(source_path, int_path, parse_line):
    """Reject overlapping initialized bytes using Pass-1 final addresses.

    RESB/RESW ranges are deliberately not claimed: ORG is commonly used to
    define initialized fields inside a reserved buffer. Instructions, WORD,
    BYTE, and emitted literals do claim bytes and may not overwrite each other.
    """
    records = _map_source_lines(source_path, int_path, parse_line)
    current_csect = None
    initialized = {}

    for record in records:
        text = record['text']
        label, opcode, operand, is_comment = parse_line(text)
        if is_comment:
            continue

        if opcode == 'START':
            current_csect = label or 'DEFAULT'
            initialized.setdefault(current_csect, [])
            continue

        if current_csect is None:
            current_csect = 'DEFAULT'
            initialized.setdefault(current_csect, [])

        if opcode == 'CSECT':
            current_csect = label or 'UNNAMED'
            initialized.setdefault(current_csect, [])
            continue

        if record['address'] is None:
            continue

        try:
            size = _object_size(opcode, operand)
        except ValueError:
            # Pass 1 already owns syntax/size diagnostics. Do not shadow them
            # with a secondary semantic-check error.
            continue
        if size <= 0:
            continue

        start = record['address']
        end = start + size
        ranges = initialized[current_csect]
        for previous in ranges:
            if max(start, previous['start']) < min(end, previous['end']):
                previous_line = previous['line_number']
                previous_where = (
                    f"line {previous_line}" if previous_line is not None else "an earlier statement"
                )
                line_number = record['line_number']
                raise AssemblyError(
                    f"Initialized storage overlap in {current_csect}: "
                    f"{start:06X}-{end - 1:06X} conflicts with {previous_where} "
                    f"range {previous['start']:06X}-{previous['end'] - 1:06X}",
                    phase="pass 1",
                    line_number=line_number,
                )

        ranges.append({
            'start': start,
            'end': end,
            'line_number': record['line_number'],
            'text': text,
        })


def validate_generated_object_semantics(obj_path):
    """Require assembler output to satisfy the same semantics as loader input."""
    with open(obj_path, 'r') as object_file:
        records = [line.rstrip('\n') for line in object_file if line.strip()]
    try:
        return analyze_object_records(records)
    except ValueError as exc:
        raise AssemblyError(str(exc), phase="object semantics") from exc
