from dataclasses import dataclass

from address_space import validate_machine_address, validate_machine_range
from loader_semantics import analyze_object_records
from relocation import (
    FORMAT4_RELOCATION_HALF_BYTES,
    decode_object_addend,
    encode_relocated_value,
)


class LoadPlanError(ValueError):
    """Raised when linked inputs cannot form one deterministic load plan."""


@dataclass(frozen=True)
class PlannedRelocation:
    offset: int
    address: int
    half_bytes: int
    addend: int
    delta: int
    relocated: int
    encoded: int
    symbols: tuple
    records: tuple


@dataclass(frozen=True)
class PlannedSection:
    file_path: str
    input_index: int
    section_index: int
    name: str
    source_start: int
    length: int
    load_address: int
    definitions: tuple
    references: tuple
    texts: tuple
    relocations: tuple
    unused_references: tuple
    source_execution_address: object
    loaded_execution_address: object


@dataclass(frozen=True)
class LoadPlan:
    progaddr: int
    sections: tuple
    estab: dict
    symbol_sources: dict
    execution_address: int
    execution_source: object
    total_length: int


def _read_sections(filepath):
    records = []
    try:
        with open(filepath, 'r') as object_file:
            for line in object_file:
                if line.strip():
                    records.append(line.rstrip('\n'))
    except OSError as exc:
        raise LoadPlanError(str(exc)) from exc

    try:
        return analyze_object_records(records)
    except ValueError as exc:
        raise LoadPlanError(f"Invalid object program {filepath}: {exc}") from exc


def _validate_progaddr(progaddr):
    try:
        validate_machine_address(progaddr, "PROGADDR")
    except ValueError as exc:
        raise LoadPlanError(str(exc)) from exc


def _validate_section_placement(load_address, length, name):
    try:
        validate_machine_range(
            load_address,
            length,
            f"Loaded control section {name}",
        )
    except ValueError as exc:
        raise LoadPlanError(str(exc)) from exc


def _definition_source(file_path, section_name, symbol=None):
    if symbol is None:
        return f"control section {section_name} in {file_path}"
    return f"EXTDEF {symbol} in control section {section_name} ({file_path})"


def _add_external_symbol(estab, sources, name, value, source):
    if name in estab:
        raise LoadPlanError(
            f"Duplicate external symbol {name}: first defined by {sources[name]}; "
            f"again by {source}"
        )
    estab[name] = value
    sources[name] = source


def _collect_inputs(obj_files, progaddr):
    _validate_progaddr(progaddr)
    parsed = []
    estab = {}
    sources = {}
    load_address = progaddr

    for input_index, filepath in enumerate(obj_files):
        file_path = str(filepath)
        sections = _read_sections(filepath)
        for section_index, section in enumerate(sections):
            _validate_section_placement(
                load_address,
                section['length'],
                section['name'],
            )

            _add_external_symbol(
                estab,
                sources,
                section['name'],
                load_address,
                _definition_source(file_path, section['name']),
            )
            for symbol, offset in section['definitions']:
                _add_external_symbol(
                    estab,
                    sources,
                    symbol,
                    load_address + offset,
                    _definition_source(file_path, section['name'], symbol),
                )

            parsed.append({
                'file_path': file_path,
                'input_index': input_index,
                'section_index': section_index,
                'section': section,
                'load_address': load_address,
            })
            load_address += section['length']

    return parsed, estab, sources


def build_estab(obj_files, progaddr):
    """Build placement + ESTAB without evaluating relocation arithmetic.

    This preserves the traditional loader Pass-1 boundary while sharing the
    exact same parsing, placement, and duplicate-definition rules as the full
    load-plan builder.
    """
    _, estab, _ = _collect_inputs(obj_files, progaddr)
    return estab


def _group_modifications(modifications):
    groups = {}
    order = []
    for modification in modifications:
        key = (modification['offset'], modification['half_bytes'])
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(modification)
    return [groups[key] for key in order]


def _loaded_bytes(section):
    result = {}
    for text in section['texts']:
        for index, byte in enumerate(text['data']):
            result[text['offset'] + index] = byte
    return result


def _raw_field_value(byte_map, offset):
    return (
        (byte_map[offset] << 16)
        | (byte_map[offset + 1] << 8)
        | byte_map[offset + 2]
    )


def _plan_relocations(item, estab):
    section = item['section']
    byte_map = _loaded_bytes(section)
    planned = []
    used_symbols = set()

    for group in _group_modifications(section['modifications']):
        first = group[0]
        raw_value = _raw_field_value(byte_map, first['offset'])
        try:
            addend = decode_object_addend(raw_value, first['half_bytes'])
        except ValueError as exc:
            raise LoadPlanError(str(exc)) from exc

        delta = 0
        symbols = []
        for modification in group:
            symbol = modification['symbol']
            used_symbols.add(symbol)
            symbols.append((modification['sign'], symbol))
            if symbol not in estab:
                raise LoadPlanError(
                    f"Undefined external symbol {symbol} referenced by "
                    f"{section['name']} in {item['file_path']} at "
                    f"{modification['address']:06X}"
                )
            symbol_value = estab[symbol]
            delta += symbol_value if modification['sign'] == '+' else -symbol_value

        relocated = addend + delta
        try:
            encoded = encode_relocated_value(relocated, first['half_bytes'])
        except ValueError as exc:
            raise LoadPlanError(
                f"{exc} in {section['name']} at {first['address']:06X} "
                f"(addend={addend}, delta={delta})"
            ) from exc

        if first['half_bytes'] == FORMAT4_RELOCATION_HALF_BYTES:
            encoded |= raw_value & 0xF00000

        planned.append(
            PlannedRelocation(
                offset=first['offset'],
                address=first['address'],
                half_bytes=first['half_bytes'],
                addend=addend,
                delta=delta,
                relocated=relocated,
                encoded=encoded,
                symbols=tuple(symbols),
                records=tuple(modification['record'] for modification in group),
            )
        )

    # R declarations that do not participate in any M expression are legal.
    # Retain them as deterministic plan metadata instead of treating them as an
    # error: producers may intentionally emit a superset of link references.
    unused = tuple(sorted(set(section['references']) - used_symbols))
    return tuple(planned), unused


def build_load_plan(obj_files, progaddr):
    """Resolve and validate every link-time decision before memory mutation."""
    parsed, estab, sources = _collect_inputs(obj_files, progaddr)

    explicit_entries = []
    planned_sections = []
    for item in parsed:
        section = item['section']
        relocations, unused_references = _plan_relocations(item, estab)

        source_exec = section['execution_address']
        loaded_exec = None
        if source_exec is not None:
            loaded_exec = item['load_address'] + (source_exec - section['start'])
            explicit_entries.append((loaded_exec, item, source_exec))

        planned_sections.append(
            PlannedSection(
                file_path=item['file_path'],
                input_index=item['input_index'],
                section_index=item['section_index'],
                name=section['name'],
                source_start=section['start'],
                length=section['length'],
                load_address=item['load_address'],
                definitions=tuple(section['definitions']),
                references=tuple(sorted(section['references'])),
                texts=tuple(section['texts']),
                relocations=relocations,
                unused_references=unused_references,
                source_execution_address=source_exec,
                loaded_execution_address=loaded_exec,
            )
        )

    if len(explicit_entries) > 1:
        _, first_item, first_source_exec = explicit_entries[0]
        _, second_item, second_source_exec = explicit_entries[1]
        raise LoadPlanError(
            "Multiple explicit execution addresses across object inputs: "
            f"{first_item['section']['name']} in {first_item['file_path']} "
            f"(E{first_source_exec:06X}) and "
            f"{second_item['section']['name']} in {second_item['file_path']} "
            f"(E{second_source_exec:06X})"
        )

    if explicit_entries:
        execution_address, entry_item, source_exec = explicit_entries[0]
        execution_source = (
            f"{entry_item['section']['name']} in {entry_item['file_path']} "
            f"(E{source_exec:06X})"
        )
    else:
        execution_address = progaddr
        execution_source = None

    total_length = sum(section.length for section in planned_sections)
    return LoadPlan(
        progaddr=progaddr,
        sections=tuple(planned_sections),
        estab=dict(estab),
        symbol_sources=dict(sources),
        execution_address=execution_address,
        execution_source=execution_source,
        total_length=total_length,
    )
