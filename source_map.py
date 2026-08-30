import hashlib
import json
import os
from pathlib import Path

from disassembler import decode_instruction, disassemble, render_disassembly
from pass1 import encode_byte_operand, instruction_size


SOURCE_MAP_SCHEMA = "sicxe-source-map-v1"
LINKED_DEBUG_SCHEMA = "sicxe-linked-debug-v1"


class SourceMapError(ValueError):
    pass


def default_source_map_path(obj_path):
    return str(Path(obj_path).with_suffix(".sourcemap.json"))


def default_debug_map_path(obj_files):
    if not obj_files:
        raise SourceMapError("At least one object file is required for a debug map")
    return str(Path(obj_files[0]).with_suffix(".debug.json"))


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _fingerprint(domain, value):
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(b"\0")
    digest.update(_canonical_json(value))
    return digest.hexdigest()


def _write_atomic_text(path, text):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return str(target)


def _source_statements(source_path, parse_line):
    statements = []
    with open(source_path, "r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            _, _, _, is_comment = parse_line(line)
            if not is_comment:
                statements.append({"line_number": line_number, "text": line.strip()})
    return statements


def _intermediate_records(int_path):
    records = []
    with open(int_path, "r", encoding="utf-8") as intermediate:
        for raw_line in intermediate:
            raw = raw_line.rstrip("\n")
            parts = raw.split("\t", 1)
            if len(parts) != 2:
                continue
            address_text = parts[0].strip()
            records.append({
                "address": int(address_text, 16) if address_text else None,
                "text": parts[1].strip(),
            })
    return records


def _is_synthetic_literal(text, parse_line):
    label, opcode, _, is_comment = parse_line(text)
    return not is_comment and opcode == "BYTE" and bool(label and label.startswith("="))


def _map_source_lines(source_path, int_path, parse_line):
    source = _source_statements(source_path, parse_line)
    records = _intermediate_records(int_path)
    source_index = 0
    last_matched = None

    for record in records:
        text = record["text"]
        line_number = None
        if source_index < len(source) and text == source[source_index]["text"]:
            line_number = source[source_index]["line_number"]
            last_matched = source[source_index]
            source_index += 1
        elif _is_synthetic_literal(text, parse_line):
            last_opcode = None
            if last_matched is not None:
                _, last_opcode, _, _ = parse_line(last_matched["text"])
            if last_opcode == "LTORG":
                line_number = last_matched["line_number"]
            elif source_index < len(source):
                _, next_opcode, _, _ = parse_line(source[source_index]["text"])
                if next_opcode in ("CSECT", "END"):
                    line_number = source[source_index]["line_number"]
        record["expanded_line"] = line_number
    return records


def _parse_reservation(opcode, operand):
    if operand is None:
        raise SourceMapError(f"{opcode} requires an operand")
    try:
        count = int(operand, 10)
    except ValueError as exc:
        raise SourceMapError(f"{opcode} requires a decimal integer: {operand}") from exc
    if count < 0:
        raise SourceMapError(f"{opcode} operand must be non-negative: {operand}")
    return count * 3 if opcode == "RESW" else count


def _classify_region(label, opcode, operand):
    if not opcode:
        return None, 0
    try:
        size = instruction_size(opcode)
    except ValueError as exc:
        raise SourceMapError(str(exc)) from exc
    if size is not None:
        return "instruction", size
    if opcode == "WORD":
        return "word", 3
    if opcode == "BYTE":
        try:
            size = len(encode_byte_operand(operand)) // 2
        except ValueError as exc:
            raise SourceMapError(str(exc)) from exc
        return ("literal" if label and label.startswith("=") else "byte"), size
    if opcode in ("RESB", "RESW"):
        return "reservation", _parse_reservation(opcode, operand)
    return None, 0


def _symbol_records(csect):
    records = []
    literal_addresses = {
        entry["address"]: spelling
        for spelling, entry in csect["literals"].items()
        if entry["address"] is not None
    }
    for name, address in csect["symtab"].items():
        if name in csect["symbol_blocks"]:
            kind = "label"
        elif name in csect["equ_defs"]:
            kind = "equ"
        else:
            kind = "symbol"
        records.append({
            "name": name,
            "source_address": address,
            "relocatable": name in csect["relocatable"],
            "kind": kind,
        })
    for address, spelling in literal_addresses.items():
        records.append({
            "name": spelling,
            "source_address": address,
            "relocatable": True,
            "kind": "literal",
        })
    return sorted(records, key=lambda item: (item["source_address"], item["name"]))


def build_source_map(expanded_path, int_path, obj_path, csects, parse_line):
    expanded_bytes = Path(expanded_path).read_bytes()
    object_bytes = Path(obj_path).read_bytes()
    mapped = _map_source_lines(expanded_path, int_path, parse_line)

    sections = []
    section_regions = {name: [] for name in csects}
    current_csect = None

    for record in mapped:
        label, opcode, operand, is_comment = parse_line(record["text"])
        if is_comment:
            continue
        if opcode == "START":
            current_csect = label or "DEFAULT"
            continue
        if current_csect is None:
            current_csect = "DEFAULT"
        if opcode == "CSECT":
            current_csect = label or "UNNAMED"
            continue
        if record["address"] is None:
            continue

        kind, length = _classify_region(label, opcode, operand)
        if kind is None or length <= 0:
            continue
        if current_csect not in csects:
            raise SourceMapError(f"Intermediate record refers to unknown control section {current_csect}")
        csect = csects[current_csect]
        source_address = record["address"]
        offset = source_address - csect["start"]
        if offset < 0 or offset + length > csect["length"]:
            raise SourceMapError(
                f"Source-map region outside {current_csect}: {source_address:06X}+{length}"
            )
        section_regions[current_csect].append({
            "source_address": source_address,
            "offset": offset,
            "length": length,
            "kind": kind,
            "expanded_line": record["expanded_line"],
            "text": record["text"],
        })

    for section_index, (name, csect) in enumerate(csects.items()):
        symbols = _symbol_records(csect)
        by_address = {}
        for symbol in symbols:
            if symbol["relocatable"]:
                by_address.setdefault(symbol["source_address"], []).append(symbol["name"])
        regions = []
        for region in section_regions[name]:
            item = dict(region)
            item["symbols"] = tuple(sorted(by_address.get(region["source_address"], ())))
            regions.append(item)
        sections.append({
            "section_index": section_index,
            "name": name,
            "source_start": csect["start"],
            "length": csect["length"],
            "symbols": symbols,
            "regions": regions,
        })

    payload = {
        "schema": SOURCE_MAP_SCHEMA,
        "object_sha256": hashlib.sha256(object_bytes).hexdigest(),
        "expanded_source_sha256": hashlib.sha256(expanded_bytes).hexdigest(),
        "sections": sections,
    }
    payload["source_map_fingerprint"] = _fingerprint(b"SICXE-SOURCE-MAP-v1", payload)
    return payload


def render_source_map(source_map):
    return json.dumps(source_map, indent=2, sort_keys=True) + "\n"


def write_source_map(expanded_path, int_path, obj_path, csects, parse_line, output_path=None):
    path = output_path or default_source_map_path(obj_path)
    source_map = build_source_map(expanded_path, int_path, obj_path, csects, parse_line)
    return _write_atomic_text(path, render_source_map(source_map))


def _validate_source_map_payload(payload, object_sha256=None):
    if not isinstance(payload, dict) or payload.get("schema") != SOURCE_MAP_SCHEMA:
        raise SourceMapError(f"Unsupported source-map schema: {payload.get('schema') if isinstance(payload, dict) else None!r}")
    required = ("object_sha256", "expanded_source_sha256", "sections", "source_map_fingerprint")
    missing = [key for key in required if key not in payload]
    if missing:
        raise SourceMapError("Source map missing required field(s): " + ", ".join(missing))
    fingerprint = payload["source_map_fingerprint"]
    unsigned = dict(payload)
    del unsigned["source_map_fingerprint"]
    expected = _fingerprint(b"SICXE-SOURCE-MAP-v1", unsigned)
    if fingerprint != expected:
        raise SourceMapError("Source-map fingerprint does not match canonical metadata")
    if object_sha256 is not None and payload["object_sha256"] != object_sha256:
        raise SourceMapError(
            "Source map does not match object bytes: "
            f"expected sha256={object_sha256}, source-map sha256={payload['object_sha256']}"
        )
    if not isinstance(payload["sections"], list):
        raise SourceMapError("Source-map sections must be a list")
    for expected_index, section in enumerate(payload["sections"]):
        for key in ("section_index", "name", "source_start", "length", "symbols", "regions"):
            if key not in section:
                raise SourceMapError(f"Source-map section missing {key}")
        if section["section_index"] != expected_index:
            raise SourceMapError("Source-map section indices must be contiguous and ordered")
        start = section["source_start"]
        length = section["length"]
        if start < 0 or length < 0:
            raise SourceMapError("Source-map section range must be non-negative")
        for region in section["regions"]:
            for key in ("source_address", "offset", "length", "kind", "expanded_line", "text", "symbols"):
                if key not in region:
                    raise SourceMapError(f"Source-map region missing {key}")
            if region["offset"] != region["source_address"] - start:
                raise SourceMapError("Source-map region offset/address mismatch")
            if region["length"] < 0 or region["offset"] < 0 or region["offset"] + region["length"] > length:
                raise SourceMapError("Source-map region lies outside its control section")
    return payload


def load_source_map(path, object_sha256=None):
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise SourceMapError(str(exc)) from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMapError(f"Invalid source-map JSON {path}: {exc}") from exc
    return _validate_source_map_payload(payload, object_sha256=object_sha256), raw


def _source_map_for_snapshot(snapshot):
    path = default_source_map_path(snapshot.file_path)
    if not Path(path).exists():
        return None, None, path
    payload, raw = load_source_map(path, object_sha256=snapshot.sha256)
    return payload, raw, path


def build_linked_debug_map(plan):
    sections = []
    inputs = []
    source_maps_by_input = {}

    for snapshot in plan.inputs:
        payload, raw, _ = _source_map_for_snapshot(snapshot)
        if payload is None:
            inputs.append({
                "input_index": snapshot.input_index,
                "object_sha256": snapshot.sha256,
                "source_map_present": False,
            })
            continue
        source_maps_by_input[snapshot.input_index] = payload
        inputs.append({
            "input_index": snapshot.input_index,
            "object_sha256": snapshot.sha256,
            "source_map_present": True,
            "source_map_sha256": hashlib.sha256(raw).hexdigest(),
            "source_map_fingerprint": payload["source_map_fingerprint"],
            "expanded_source_sha256": payload["expanded_source_sha256"],
        })

    for planned in plan.sections:
        source_map = source_maps_by_input.get(planned.input_index)
        if source_map is None:
            sections.append({
                "input_index": planned.input_index,
                "section_index": planned.section_index,
                "name": planned.name,
                "source_start": planned.source_start,
                "load_address": planned.load_address,
                "length": planned.length,
                "typed": False,
                "symbols": [],
                "regions": [],
            })
            continue
        if planned.section_index >= len(source_map["sections"]):
            raise SourceMapError(
                f"Source map has no section {planned.section_index} for input {planned.input_index}"
            )
        source_section = source_map["sections"][planned.section_index]
        identity = (source_section["name"], source_section["source_start"], source_section["length"])
        expected = (planned.name, planned.source_start, planned.length)
        if identity != expected:
            raise SourceMapError(
                f"Source-map section layout does not match object input {planned.input_index}: "
                f"expected {expected}, received {identity}"
            )

        symbols = []
        for symbol in source_section["symbols"]:
            item = dict(symbol)
            if symbol["relocatable"]:
                item["loaded_address"] = planned.load_address + (symbol["source_address"] - planned.source_start)
            else:
                item["loaded_address"] = symbol["source_address"]
            symbols.append(item)
        regions = []
        for region in source_section["regions"]:
            item = dict(region)
            item["loaded_address"] = planned.load_address + region["offset"]
            regions.append(item)
        sections.append({
            "input_index": planned.input_index,
            "section_index": planned.section_index,
            "name": planned.name,
            "source_start": planned.source_start,
            "load_address": planned.load_address,
            "length": planned.length,
            "typed": True,
            "symbols": symbols,
            "regions": regions,
        })

    payload = {
        "schema": LINKED_DEBUG_SCHEMA,
        "link_fingerprint": plan.link_fingerprint,
        "progaddr": plan.progaddr,
        "inputs": inputs,
        "sections": sections,
    }
    payload["debug_fingerprint"] = _fingerprint(b"SICXE-LINKED-DEBUG-v1", payload)
    return payload


def render_linked_debug_map(debug_map):
    return json.dumps(debug_map, indent=2, sort_keys=True) + "\n"


def write_linked_debug_map(plan, output_path=None):
    path = output_path or default_debug_map_path([snapshot.file_path for snapshot in plan.inputs])
    debug_map = build_linked_debug_map(plan)
    return _write_atomic_text(path, render_linked_debug_map(debug_map))


def _validate_linked_debug_payload(payload, link_fingerprint=None):
    if not isinstance(payload, dict) or payload.get("schema") != LINKED_DEBUG_SCHEMA:
        raise SourceMapError(f"Unsupported linked-debug schema: {payload.get('schema') if isinstance(payload, dict) else None!r}")
    required = ("link_fingerprint", "progaddr", "inputs", "sections", "debug_fingerprint")
    missing = [key for key in required if key not in payload]
    if missing:
        raise SourceMapError("Linked debug map missing required field(s): " + ", ".join(missing))
    unsigned = dict(payload)
    fingerprint = unsigned.pop("debug_fingerprint")
    expected = _fingerprint(b"SICXE-LINKED-DEBUG-v1", unsigned)
    if fingerprint != expected:
        raise SourceMapError("Linked debug fingerprint does not match canonical metadata")
    if link_fingerprint is not None and payload["link_fingerprint"] != link_fingerprint:
        raise SourceMapError("Linked debug map does not match manifest LINKID")
    return payload


def load_linked_debug_map(path, link_fingerprint=None):
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise SourceMapError(str(exc)) from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceMapError(f"Invalid linked-debug JSON {path}: {exc}") from exc
    return _validate_linked_debug_payload(payload, link_fingerprint=link_fingerprint), raw


def render_source_map_inspection(source_map):
    lines = [
        "SIC/XE SOURCE MAP",
        f"OBJECT_SHA {source_map['object_sha256']}",
        f"SOURCE_SHA {source_map['expanded_source_sha256']}",
        f"MAPID      {source_map['source_map_fingerprint']}",
    ]
    for section in source_map["sections"]:
        lines.append(
            f"SECTION {section['section_index']} {section['name']} "
            f"{section['source_start']:06X}-{section['source_start'] + section['length']:06X}"
        )
        for region in section["regions"]:
            line = "?" if region["expanded_line"] is None else str(region["expanded_line"])
            symbols = ",".join(region["symbols"]) or "-"
            lines.append(
                f"  {region['source_address']:06X} +{region['length']:04X} "
                f"{region['kind']:<11} line={line:<4} symbols={symbols}  {region['text']}"
            )
    return "\n".join(lines) + "\n"


def render_linked_debug_inspection(debug_map):
    lines = [
        "SIC/XE LINKED DEBUG MAP",
        f"LINKID   {debug_map['link_fingerprint']}",
        f"DEBUGID  {debug_map['debug_fingerprint']}",
        f"PROGADDR {debug_map['progaddr']:05X}",
    ]
    for section in debug_map["sections"]:
        lines.append(
            f"SECTION [{section['input_index']}:{section['section_index']}] {section['name']} "
            f"load={section['load_address']:05X}-{section['load_address'] + section['length']:05X} "
            f"typed={'yes' if section['typed'] else 'no'}"
        )
        for region in section["regions"]:
            line = "?" if region["expanded_line"] is None else str(region["expanded_line"])
            symbols = ",".join(region["symbols"]) or "-"
            lines.append(
                f"  {region['loaded_address']:05X} +{region['length']:04X} "
                f"{region['kind']:<11} line={line:<4} symbols={symbols}"
            )
    return "\n".join(lines) + "\n"


def _symbols_by_address(debug_map):
    result = {}
    for section in debug_map["sections"]:
        for symbol in section["symbols"]:
            if symbol["relocatable"]:
                result.setdefault(symbol["loaded_address"], []).append(symbol["name"])
    return {address: tuple(sorted(names)) for address, names in result.items()}


def _format_typed_instruction(raw, region, base_register, symbol_addresses):
    decoded = decode_instruction(raw, address=region["loaded_address"], base_register=base_register)
    labels = region.get("symbols") or ()
    prefix = ""
    if labels:
        prefix = " ".join(f"{label}:" for label in labels) + " "
    assembly = decoded.mnemonic + ((" " + decoded.operand) if decoded.operand else "")
    details = [f"type=instruction", f"line={region['expanded_line'] if region['expanded_line'] is not None else '?'}"]
    if decoded.flags:
        details.append(f"nixbpe={decoded.flags}")
    if decoded.target is not None:
        details.append(f"target={decoded.target:05X}")
        target_symbols = symbol_addresses.get(decoded.target, ())
        if target_symbols:
            details.append("target_symbol=" + ",".join(target_symbols))
    if decoded.size != region["length"]:
        details.append(f"debug-size={region['length']} decoded-size={decoded.size}")
    if decoded.warning:
        details.append(decoded.warning)
    return (
        f"{region['loaded_address']:05X}  {raw.hex().upper().ljust(8)}  "
        f"{prefix}{assembly} ; {'; '.join(details)}"
    )


def _clip_regions(section, start, end):
    return [
        region for region in section["regions"]
        if region["loaded_address"] < end
        and region["loaded_address"] + region["length"] > start
    ]


def render_typed_disassembly(image, image_start, debug_map, base_register=None, offset=0, length=None, max_instructions=None):
    raw_image = bytes(image)
    view_start = image_start + offset
    view_end = image_start + len(raw_image) if length is None else min(image_start + len(raw_image), view_start + length)
    if offset < 0 or offset > len(raw_image):
        raise SourceMapError(f"Debug disassembly offset {offset} exceeds image length {len(raw_image)}")
    symbol_addresses = _symbols_by_address(debug_map)
    lines = []
    decoded_count = 0

    for section in debug_map["sections"]:
        section_start = section["load_address"]
        section_end = section_start + section["length"]
        if section_end <= view_start or section_start >= view_end:
            continue
        if not section["typed"]:
            start = max(section_start, view_start)
            end = min(section_end, view_end)
            payload = raw_image[start - image_start:end - image_start]
            records = disassemble(
                payload,
                start_address=start,
                base_register=base_register,
                max_instructions=None if max_instructions is None else max(0, max_instructions - decoded_count),
            )
            if records:
                lines.append(f"; [{section['input_index']}:{section['section_index']}] {section['name']} untyped fallback")
                rendered = render_disassembly(records).rstrip("\n")
                if rendered:
                    lines.extend(rendered.splitlines())
                decoded_count += len(records)
            if max_instructions is not None and decoded_count >= max_instructions:
                break
            continue

        lines.append(f"; [{section['input_index']}:{section['section_index']}] {section['name']} typed source map")
        regions = sorted(
            _clip_regions(section, view_start, view_end),
            key=lambda item: (item["loaded_address"], item["kind"] == "reservation", item["expanded_line"] or 0),
        )
        for region in regions:
            if max_instructions is not None and decoded_count >= max_instructions:
                break
            address = region["loaded_address"]
            kind = region["kind"]
            line = region["expanded_line"] if region["expanded_line"] is not None else "?"
            labels = " ".join(f"{name}:" for name in region.get("symbols", ()))
            if kind == "reservation":
                lines.append(
                    f"{address:05X}  {'':8}  {labels + ' ' if labels else ''}.RESB {region['length']} "
                    f"; type=reservation; line={line}"
                )
                continue
            if address < image_start or address + region["length"] > image_start + len(raw_image):
                lines.append(
                    f"{address:05X}  {'':8}  <outside image> ; type={kind}; line={line}"
                )
                continue
            payload = raw_image[address - image_start:address - image_start + region["length"]]
            if kind == "instruction":
                lines.append(_format_typed_instruction(payload, region, base_register, symbol_addresses))
                decoded_count += 1
            elif kind == "word":
                value = int.from_bytes(payload, "big")
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{labels + ' ' if labels else ''}.WORD 0x{value:06X} ; type=word; line={line}"
                )
            elif kind in ("byte", "literal"):
                directive = ".LITERAL" if kind == "literal" else ".BYTE"
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{labels + ' ' if labels else ''}{directive} X'{payload.hex().upper()}' ; type={kind}; line={line}"
                )
        if max_instructions is not None and decoded_count >= max_instructions:
            break

    return "\n".join(lines) + ("\n" if lines else "")
