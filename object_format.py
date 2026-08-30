import re

from errors import AssemblyError


OBJECT_NAME_WIDTH = 6
MAX_OBJECT_RECORD_LENGTH = 73
MAX_TEXT_BYTES = 30
SYNTHETIC_DEFAULT_CSECT = "DEFAUL"
SYNTHETIC_UNNAMED_CSECT = "UNNAME"
_OBJECT_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,5}$")


def validate_object_name(name, description="Object symbol"):
    """Validate a fixed-field SIC/XE object-program name and return it unchanged."""
    if not isinstance(name, str) or not _OBJECT_NAME_RE.fullmatch(name):
        raise ValueError(
            f"{description} must be 1-6 ASCII alphanumeric characters starting with a letter: {name}"
        )
    return name


def format_object_name(name, description="Object symbol"):
    """Return a validated six-character object-program name field."""
    return validate_object_name(name, description).ljust(OBJECT_NAME_WIDTH)


def parse_object_name_field(field, description="Object symbol"):
    """Validate one exact six-character object-program name field."""
    if len(field) != OBJECT_NAME_WIDTH:
        raise ValueError(f"{description} field must be exactly 6 characters")
    name = field.rstrip(" ")
    if field != name.ljust(OBJECT_NAME_WIDTH):
        raise ValueError(f"{description} field may only use trailing padding spaces")
    return validate_object_name(name, description)


def build_fixed_entry_records(record_type, entries, entry_width):
    """Split fixed-width entries across standard 73-character object records."""
    if len(record_type) != 1:
        raise ValueError("Object record type must be one character")
    if entry_width <= 0:
        raise ValueError("Object record entry width must be positive")
    per_record = (MAX_OBJECT_RECORD_LENGTH - 1) // entry_width
    if per_record <= 0:
        raise ValueError("Object record entry width exceeds record capacity")

    records = []
    for start in range(0, len(entries), per_record):
        chunk = entries[start:start + per_record]
        if any(len(entry) != entry_width for entry in chunk):
            raise ValueError(f"{record_type} record contains an invalid entry width")
        records.append(record_type + "".join(chunk))
    return records


def _parse_hex(field, description):
    try:
        return int(field, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal {description}: {field}") from exc


def _split_external_symbols(operand):
    if not operand:
        return []
    return [part.strip() for part in operand.split(',')]


def _user_csect_object_name(label, *, default=False):
    if label:
        try:
            return validate_object_name(label, "Control section name")
        except ValueError as exc:
            raise AssemblyError(str(exc), phase="object contract") from exc
    return SYNTHETIC_DEFAULT_CSECT if default else SYNTHETIC_UNNAMED_CSECT


def validate_source_object_contracts(source_path, parse_line):
    """Reject source-level object namespace ambiguity before Pass 1/2 emit records."""
    sections = []
    current = None
    first_statement = True

    def source_fail(line_number, message):
        raise AssemblyError(message, phase="object contract", line_number=line_number)

    def start_section(object_name, line_number):
        nonlocal current
        current = {
            'object_name': object_name,
            'line_number': line_number,
            'local_labels': {},
            'extdef': {},
            'extref': {},
        }
        sections.append(current)

    with open(source_path, 'r') as source:
        for line_number, line in enumerate(source, 1):
            label, opcode, operand, is_comment = parse_line(line)
            if is_comment:
                continue

            if first_statement and opcode == 'START':
                if label:
                    try:
                        object_name = validate_object_name(label, "Control section name")
                    except ValueError as exc:
                        source_fail(line_number, str(exc))
                else:
                    object_name = SYNTHETIC_DEFAULT_CSECT
                start_section(object_name, line_number)
                first_statement = False
                continue

            first_statement = False
            if current is None:
                start_section(SYNTHETIC_DEFAULT_CSECT, line_number)

            if opcode == 'CSECT':
                if label:
                    try:
                        object_name = validate_object_name(label, "Control section name")
                    except ValueError as exc:
                        source_fail(line_number, str(exc))
                else:
                    object_name = SYNTHETIC_UNNAMED_CSECT
                start_section(object_name, line_number)
                continue

            if label:
                current['local_labels'].setdefault(label, line_number)

            if opcode not in ('EXTDEF', 'EXTREF') or not operand:
                continue

            symbols = _split_external_symbols(operand)
            if any(not symbol for symbol in symbols):
                continue

            seen_on_line = set()
            for symbol in symbols:
                try:
                    validate_object_name(symbol, f"{opcode} symbol")
                except ValueError as exc:
                    source_fail(line_number, str(exc))

                if symbol in seen_on_line:
                    source_fail(line_number, f"Duplicate {opcode} symbol in directive: {symbol}")
                seen_on_line.add(symbol)

                own = current['extdef'] if opcode == 'EXTDEF' else current['extref']
                other = current['extref'] if opcode == 'EXTDEF' else current['extdef']
                if symbol in own:
                    source_fail(line_number, f"Duplicate {opcode} symbol in control section: {symbol}")
                if symbol in other:
                    source_fail(
                        line_number,
                        f"Symbol cannot be both EXTDEF and EXTREF in one control section: {symbol}",
                    )
                own[symbol] = line_number

    global_definitions = {}
    for section in sections:
        csect_name = section['object_name']
        line_number = section['line_number']
        if csect_name in global_definitions:
            previous_kind, previous_line = global_definitions[csect_name]
            source_fail(
                line_number,
                f"Duplicate object-program definition {csect_name}; already used by {previous_kind} at line {previous_line}",
            )
        global_definitions[csect_name] = ("control section", line_number)

        for symbol, extdef_line in section['extdef'].items():
            if symbol in global_definitions:
                previous_kind, previous_line = global_definitions[symbol]
                source_fail(
                    extdef_line,
                    f"Duplicate object-program definition {symbol}; already used by {previous_kind} at line {previous_line}",
                )
            global_definitions[symbol] = ("EXTDEF", extdef_line)

    for section in sections:
        csect_name = section['object_name']
        for symbol, ref_line in section['extref'].items():
            if symbol == csect_name:
                source_fail(
                    ref_line,
                    f"EXTREF cannot reference its own control section name: {symbol}",
                )
            if symbol in section['local_labels']:
                source_fail(
                    ref_line,
                    f"EXTREF symbol conflicts with a local symbol in {csect_name}: {symbol}",
                )


def _validate_d_record(record, defined_names):
    if len(record) > MAX_OBJECT_RECORD_LENGTH or len(record) <= 1:
        raise ValueError(f"Malformed D record: {record}")
    payload = record[1:]
    if len(payload) % 12:
        raise ValueError(f"Malformed D record: {record}")
    for index in range(0, len(payload), 12):
        name = parse_object_name_field(payload[index:index + 6], "D-record symbol")
        _parse_hex(payload[index + 6:index + 12], "D-record address")
        if name in defined_names:
            raise ValueError(f"Duplicate external definition in object program: {name}")
        defined_names.add(name)


def _validate_r_record(record, referenced_names):
    if len(record) > MAX_OBJECT_RECORD_LENGTH or len(record) <= 1:
        raise ValueError(f"Malformed R record: {record}")
    payload = record[1:]
    if len(payload) % 6:
        raise ValueError(f"Malformed R record: {record}")
    for index in range(0, len(payload), 6):
        name = parse_object_name_field(payload[index:index + 6], "R-record symbol")
        if name in referenced_names:
            raise ValueError(f"Duplicate external reference in control section: {name}")
        referenced_names.add(name)


def validate_object_records(records):
    """Validate fixed-field H/D/R/T/M/E object records and section framing."""
    saw_header = False
    saw_any_header = False
    defined_names = set()
    referenced_names = set()

    for record in records:
        if not record:
            continue
        record_type = record[0]

        if record_type == 'H':
            if saw_header:
                raise ValueError("H record encountered before previous control section ended")
            if len(record) != 19:
                raise ValueError(f"Malformed H record: {record}")
            csect_name = parse_object_name_field(record[1:7], "H-record control section")
            _parse_hex(record[7:13], "H-record start")
            _parse_hex(record[13:19], "H-record length")
            if csect_name in defined_names:
                raise ValueError(f"Duplicate external definition in object program: {csect_name}")
            defined_names.add(csect_name)
            referenced_names = set()
            saw_header = True
            saw_any_header = True
            continue

        if not saw_header:
            raise ValueError(f"{record_type} record encountered outside a control section: {record}")

        if record_type == 'D':
            _validate_d_record(record, defined_names)
        elif record_type == 'R':
            _validate_r_record(record, referenced_names)
        elif record_type == 'T':
            if len(record) < 9 or len(record) > 9 + MAX_TEXT_BYTES * 2:
                raise ValueError(f"Malformed T record: {record}")
            _parse_hex(record[1:7], "T-record address")
            length = _parse_hex(record[7:9], "T-record length")
            if length > MAX_TEXT_BYTES:
                raise ValueError(f"T record exceeds {MAX_TEXT_BYTES} bytes: {record}")
            code_hex = record[9:]
            if len(code_hex) != length * 2:
                raise ValueError(f"T record length mismatch: {record}")
            try:
                bytes.fromhex(code_hex)
            except ValueError as exc:
                raise ValueError(f"Invalid hexadecimal T-record data: {record}") from exc
        elif record_type == 'M':
            if len(record) != 16:
                raise ValueError(f"Malformed M record: {record}")
            _parse_hex(record[1:7], "M-record address")
            modification_length = _parse_hex(record[7:9], "M-record length")
            if modification_length not in (5, 6):
                raise ValueError(f"Unsupported modification length {modification_length}: {record}")
            if record[9] not in '+-':
                raise ValueError(f"Invalid modification sign: {record}")
            parse_object_name_field(record[10:16], "M-record symbol")
        elif record_type == 'E':
            if len(record) not in (1, 7):
                raise ValueError(f"Malformed E record: {record}")
            if len(record) == 7:
                _parse_hex(record[1:7], "E-record execution address")
            saw_header = False
            referenced_names = set()
        else:
            raise ValueError(f"Unknown object record type {record_type}: {record}")

    if saw_header:
        raise ValueError("Missing E record at end of object program")
    if not saw_any_header:
        raise ValueError("Object program does not contain an H record")


def canonicalize_object_file(filepath):
    """Split long D/R records, then validate the emitted object program contract."""
    with open(filepath, 'r') as object_file:
        records = [line.rstrip('\n') for line in object_file if line.strip()]

    canonical = []
    for record in records:
        if record.startswith('D'):
            payload = record[1:]
            if len(payload) % 12:
                raise AssemblyError(
                    f"Malformed generated D record: {record}",
                    phase="object contract",
                )
            entries = [payload[index:index + 12] for index in range(0, len(payload), 12)]
            canonical.extend(build_fixed_entry_records('D', entries, 12))
        elif record.startswith('R'):
            payload = record[1:]
            if len(payload) % 6:
                raise AssemblyError(
                    f"Malformed generated R record: {record}",
                    phase="object contract",
                )
            entries = [payload[index:index + 6] for index in range(0, len(payload), 6)]
            canonical.extend(build_fixed_entry_records('R', entries, 6))
        else:
            canonical.append(record)

    try:
        validate_object_records(canonical)
    except ValueError as exc:
        raise AssemblyError(str(exc), phase="object contract") from exc

    with open(filepath, 'w') as object_file:
        for record in canonical:
            object_file.write(record + '\n')
