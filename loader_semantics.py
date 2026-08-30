from address_space import validate_machine_range
from object_format import validate_object_records


def _parse_hex(field, description):
    try:
        return int(field, 16)
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal {description}: {field}") from exc


def _covered_by_text(intervals, start, length):
    return all(
        any(interval_start <= byte < interval_end for interval_start, interval_end in intervals)
        for byte in range(start, start + length)
    )


def analyze_object_records(records):
    """Validate loader-visible semantics and return structured control sections."""
    validate_object_records(records)

    sections = []
    current = None

    def finish_section():
        nonlocal current
        if current is None:
            return

        text_intervals = [
            (text['offset'], text['offset'] + text['length'])
            for text in current['texts']
        ]
        for modification in current['modifications']:
            if modification['symbol'] != current['name'] and modification['symbol'] not in current['references']:
                raise ValueError(
                    f"Modification symbol is not declared by R record in {current['name']}: "
                    f"{modification['symbol']}"
                )
            if not _covered_by_text(text_intervals, modification['offset'], 3):
                raise ValueError(
                    f"Modification field is not backed by loaded text in {current['name']}: "
                    f"{modification['record']}"
                )

        sections.append(current)
        current = None

    for record in records:
        if not record:
            continue
        record_type = record[0]

        if record_type == 'H':
            start = _parse_hex(record[7:13], "H-record start")
            length = _parse_hex(record[13:19], "H-record length")
            name = record[1:7].strip()
            try:
                validate_machine_range(start, length, f"Control section {name}")
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
            current = {
                'name': name,
                'start': start,
                'length': length,
                'definitions': [],
                'references': set(),
                'texts': [],
                'modifications': [],
                'execution_address': None,
            }
            continue

        if record_type == 'D':
            payload = record[1:]
            for index in range(0, len(payload), 12):
                name = payload[index:index + 6].strip()
                offset = _parse_hex(
                    payload[index + 6:index + 12],
                    "D-record address",
                )
                # A symbol may legally denote the one-past-end location (for
                # example BUFEND EQU *), but never a larger offset.
                if offset > current['length']:
                    raise ValueError(
                        f"D-record symbol lies outside control section {current['name']}: "
                        f"{name}={offset:06X}"
                    )
                current['definitions'].append((name, offset))
            continue

        if record_type == 'R':
            payload = record[1:]
            for index in range(0, len(payload), 6):
                current['references'].add(payload[index:index + 6].strip())
            continue

        if record_type == 'T':
            address = _parse_hex(record[1:7], "T-record address")
            length = _parse_hex(record[7:9], "T-record length")
            if length == 0:
                raise ValueError(f"Empty T record is not meaningful: {record}")
            offset = address - current['start']
            if offset < 0 or offset + length > current['length']:
                raise ValueError(
                    f"T record lies outside control section {current['name']}: {record}"
                )
            end = offset + length
            for existing in current['texts']:
                existing_start = existing['offset']
                existing_end = existing_start + existing['length']
                if max(offset, existing_start) < min(end, existing_end):
                    raise ValueError(
                        f"Overlapping T records in control section {current['name']}: "
                        f"{existing['record']} / {record}"
                    )
            current['texts'].append({
                'address': address,
                'offset': offset,
                'length': length,
                'data': bytes.fromhex(record[9:]),
                'record': record,
            })
            continue

        if record_type == 'M':
            address = _parse_hex(record[1:7], "M-record address")
            offset = address - current['start']
            half_bytes = _parse_hex(record[7:9], "M-record length")
            if offset < 0 or offset + 3 > current['length']:
                raise ValueError(
                    f"M record lies outside control section {current['name']}: {record}"
                )

            for existing in current['modifications']:
                same_field = (
                    offset == existing['offset']
                    and half_bytes == existing['half_bytes']
                )
                overlaps = max(offset, existing['offset']) < min(
                    offset + 3,
                    existing['offset'] + 3,
                )
                if overlaps and not same_field:
                    raise ValueError(
                        f"Overlapping modification fields in control section {current['name']}: "
                        f"{existing['record']} / {record}"
                    )

            current['modifications'].append({
                'address': address,
                'offset': offset,
                'half_bytes': half_bytes,
                'sign': record[9],
                'symbol': record[10:16].strip(),
                'record': record,
            })
            continue

        if record_type == 'E':
            if len(record) == 7:
                execution_address = _parse_hex(
                    record[1:7],
                    "E-record execution address",
                )
                if current['length'] == 0:
                    valid = execution_address == current['start']
                else:
                    valid = (
                        current['start']
                        <= execution_address
                        < current['start'] + current['length']
                    )
                if not valid:
                    raise ValueError(
                        f"Execution address lies outside control section {current['name']}: {record}"
                    )
                current['execution_address'] = execution_address
            finish_section()

    return sections
