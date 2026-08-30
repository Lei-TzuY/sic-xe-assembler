from disassembler import decode_instruction, disassemble, render_disassembly
from source_map import SourceMapError


CONDITIONAL_BRANCHES = frozenset({"JEQ", "JGT", "JLT"})
UNCONDITIONAL_BRANCHES = frozenset({"J"})
CALL_INSTRUCTIONS = frozenset({"JSUB"})
RETURN_INSTRUCTIONS = frozenset({"RSUB"})


def _macro_stack_text(provenance):
    if not provenance:
        return None
    stack = provenance.get("macro_stack") or ()
    if not stack:
        return None
    return ">".join(
        f"{frame['name']}#{frame['expansion_id']}"
        for frame in stack
    )


def provenance_details(region):
    """Return stable human-readable source provenance fields for one region."""
    details = []
    expanded = region.get("expanded_line")
    details.append(f"expanded={expanded if expanded is not None else '?'}")
    provenance = region.get("provenance")
    if not provenance:
        return tuple(details)

    source_line = provenance.get("source_line")
    if source_line is not None:
        details.append(f"source={source_line}")
    definition_line = provenance.get("definition_line")
    if definition_line is not None:
        details.append(f"definition={definition_line}")
    macro_text = _macro_stack_text(provenance)
    if macro_text:
        details.append(f"macro={macro_text}")
    generated = provenance.get("generated")
    if generated:
        details.append(f"generated={generated}")
    return tuple(details)


def render_source_map_with_provenance(source_map):
    lines = [
        "SIC/XE SOURCE MAP",
        f"OBJECT_SHA {source_map['object_sha256']}",
        f"SOURCE_SHA {source_map['expanded_source_sha256']}",
    ]
    if source_map.get("original_source_sha256"):
        lines.append(f"ORIGIN_SHA {source_map['original_source_sha256']}")
    lines.append(f"MAPID      {source_map['source_map_fingerprint']}")

    for section in source_map["sections"]:
        lines.append(
            f"SECTION {section['section_index']} {section['name']} "
            f"{section['source_start']:06X}-{section['source_start'] + section['length']:06X}"
        )
        for region in section["regions"]:
            symbols = ",".join(region.get("symbols") or ()) or "-"
            provenance = "; ".join(provenance_details(region))
            lines.append(
                f"  {region['source_address']:06X} +{region['length']:04X} "
                f"{region['kind']:<11} symbols={symbols}  {region['text']} ; {provenance}"
            )
    return "\n".join(lines) + "\n"


def render_linked_debug_with_provenance(debug_map):
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
            symbols = ",".join(region.get("symbols") or ()) or "-"
            provenance = "; ".join(provenance_details(region))
            lines.append(
                f"  {region['loaded_address']:05X} +{region['length']:04X} "
                f"{region['kind']:<11} symbols={symbols} ; {provenance}"
            )
    return "\n".join(lines) + "\n"


def _symbols_by_address(debug_map):
    result = {}
    for section in debug_map["sections"]:
        for symbol in section.get("symbols", ()):
            if symbol.get("relocatable"):
                result.setdefault(symbol["loaded_address"], []).append(symbol["name"])
    return {
        address: tuple(sorted(names))
        for address, names in result.items()
    }


def _base_mnemonic(mnemonic):
    return mnemonic[1:] if mnemonic.startswith("+") else mnemonic


def _is_indirect(decoded):
    return bool(decoded.flags and decoded.flags.startswith("10"))


def _format_instruction(raw, region, decoded, symbol_addresses):
    labels = region.get("symbols") or ()
    prefix = " ".join(f"{label}:" for label in labels)
    if prefix:
        prefix += " "
    assembly = decoded.mnemonic
    if decoded.operand:
        assembly += " " + decoded.operand

    details = ["type=instruction"]
    details.extend(provenance_details(region))
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
        region
        for region in section.get("regions", ())
        if region["loaded_address"] < end
        and region["loaded_address"] + region["length"] > start
    ]


def _block_headers(cfg):
    if cfg is None:
        return {}
    headers = {}
    for block in cfg["blocks"]:
        successor_text = ",".join(
            edge.get("target_block") or (
                f"{edge['target']:05X}" if edge.get("target") is not None else edge["kind"]
            )
            for edge in block["successors"]
        ) or "-"
        headers[block["start"]] = (
            f"; BASIC BLOCK {block['id']} reachable={'yes' if block['reachable'] else 'no'} "
            f"successors={successor_text}"
        )
    return headers


def render_debug_disassembly(
    image,
    image_start,
    debug_map,
    base_register=None,
    offset=0,
    length=None,
    max_instructions=None,
    cfg=None,
):
    """Render typed disassembly with original-source provenance.

    Untyped CSECTs keep the historical deterministic linear-sweep fallback.
    Typed data/reservation regions are rendered as directives and never guessed
    as instructions.
    """
    raw_image = bytes(image)
    if offset < 0 or offset > len(raw_image):
        raise SourceMapError(
            f"Debug disassembly offset {offset} exceeds image length {len(raw_image)}"
        )
    view_start = image_start + offset
    view_end = (
        image_start + len(raw_image)
        if length is None
        else min(image_start + len(raw_image), view_start + length)
    )
    symbol_addresses = _symbols_by_address(debug_map)
    block_headers = _block_headers(cfg)
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
                max_instructions=(
                    None
                    if max_instructions is None
                    else max(0, max_instructions - decoded_count)
                ),
            )
            if records:
                lines.append(
                    f"; [{section['input_index']}:{section['section_index']}] "
                    f"{section['name']} untyped fallback"
                )
                rendered = render_disassembly(records).rstrip("\n")
                if rendered:
                    lines.extend(rendered.splitlines())
                decoded_count += len(records)
            if max_instructions is not None and decoded_count >= max_instructions:
                break
            continue

        lines.append(
            f"; [{section['input_index']}:{section['section_index']}] "
            f"{section['name']} typed source map"
        )
        regions = sorted(
            _clip_regions(section, view_start, view_end),
            key=lambda item: (
                item["loaded_address"],
                item["kind"] == "reservation",
                item.get("expanded_line") or 0,
            ),
        )

        for region in regions:
            if max_instructions is not None and decoded_count >= max_instructions:
                break
            address = region["loaded_address"]
            kind = region["kind"]
            labels = " ".join(f"{name}:" for name in region.get("symbols", ()))
            label_prefix = labels + " " if labels else ""
            details = "; ".join(provenance_details(region))

            if address in block_headers and kind == "instruction":
                lines.append(block_headers[address])

            if kind == "reservation":
                lines.append(
                    f"{address:05X}  {'':8}  {label_prefix}.RESB {region['length']} "
                    f"; type=reservation; {details}"
                )
                continue

            if (
                address < image_start
                or address + region["length"] > image_start + len(raw_image)
            ):
                lines.append(
                    f"{address:05X}  {'':8}  <outside image> "
                    f"; type={kind}; {details}"
                )
                continue

            payload = raw_image[
                address - image_start:address - image_start + region["length"]
            ]
            if kind == "instruction":
                decoded = decode_instruction(
                    payload,
                    address=address,
                    base_register=base_register,
                )
                lines.append(
                    _format_instruction(
                        payload,
                        region,
                        decoded,
                        symbol_addresses,
                    )
                )
                decoded_count += 1
            elif kind == "word":
                value = int.from_bytes(payload, "big")
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{label_prefix}.WORD 0x{value:06X} ; type=word; {details}"
                )
            elif kind == "literal":
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{label_prefix}.LITERAL X'{payload.hex().upper()}' "
                    f"; type=literal; {details}"
                )
            elif kind == "byte":
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{label_prefix}.BYTE X'{payload.hex().upper()}' "
                    f"; type=byte; {details}"
                )
            else:
                lines.append(
                    f"{address:05X}  {payload.hex().upper().ljust(8)}  "
                    f"{label_prefix}.BYTE X'{payload.hex().upper()}' "
                    f"; type={kind}; {details}"
                )

        if max_instructions is not None and decoded_count >= max_instructions:
            break

    return "\n".join(lines) + ("\n" if lines else "")


def _instruction_records(image, image_start, debug_map, base_register=None):
    raw_image = bytes(image)
    records = {}
    symbol_addresses = _symbols_by_address(debug_map)

    for section in debug_map["sections"]:
        if not section.get("typed"):
            continue
        for region in section.get("regions", ()):
            if region.get("kind") != "instruction":
                continue
            address = region["loaded_address"]
            length = region["length"]
            if address < image_start or address + length > image_start + len(raw_image):
                raise SourceMapError(
                    f"Instruction region {address:05X}+{length} lies outside linked image"
                )
            raw = raw_image[address - image_start:address - image_start + length]
            decoded = decode_instruction(
                raw,
                address=address,
                base_register=base_register,
            )
            records[address] = {
                "address": address,
                "size": length,
                "bytes_hex": raw.hex().upper(),
                "mnemonic": decoded.mnemonic,
                "operand": decoded.operand,
                "flags": decoded.flags,
                "target": decoded.target,
                "warning": decoded.warning,
                "symbols": tuple(region.get("symbols") or ()),
                "provenance": region.get("provenance"),
                "expanded_line": region.get("expanded_line"),
                "input_index": section["input_index"],
                "section_index": section["section_index"],
                "section": section["name"],
                "target_symbols": tuple(
                    symbol_addresses.get(decoded.target, ())
                    if decoded.target is not None
                    else ()
                ),
            }
    return records


def _flow_kind(record):
    mnemonic = _base_mnemonic(record["mnemonic"])
    if mnemonic in UNCONDITIONAL_BRANCHES:
        return "jump"
    if mnemonic in CONDITIONAL_BRANCHES:
        return "conditional"
    if mnemonic in CALL_INSTRUCTIONS:
        return "call"
    if mnemonic in RETURN_INSTRUCTIONS:
        return "return"
    return "fallthrough"


def _control_target(record):
    if _is_indirect(type("Decoded", (), {"flags": record.get("flags", "")})()):
        return None
    return record.get("target")


def _instruction_edges(record, instruction_addresses):
    flow = _flow_kind(record)
    next_address = record["address"] + record["size"]
    target = _control_target(record)
    edges = []

    def add(kind, address):
        edges.append({
            "kind": kind,
            "target": address,
            "resolved": address in instruction_addresses if address is not None else False,
            "target_block": None,
        })

    if flow == "jump":
        add("branch", target)
    elif flow == "conditional":
        add("branch", target)
        add("fallthrough", next_address)
    elif flow == "call":
        add("call", target)
        add("fallthrough", next_address)
    elif flow == "return":
        add("return", None)
    else:
        add("fallthrough", next_address)
    return edges


def build_control_flow_graph(
    image,
    image_start,
    debug_map,
    entry_address=None,
    base_register=None,
):
    """Build conservative basic blocks over typed instruction regions.

    The graph never invents code in data or reservation regions. Indirect
    branches and targets outside typed instruction regions remain unresolved.
    JSUB emits both a call edge and its return-site fallthrough edge.
    """
    instructions = _instruction_records(
        image,
        image_start,
        debug_map,
        base_register=base_register,
    )
    addresses = sorted(instructions)
    address_set = set(addresses)
    if entry_address is None:
        entry_address = debug_map.get("progaddr", image_start)

    for record in instructions.values():
        record["flow"] = _flow_kind(record)
        record["edges"] = _instruction_edges(record, address_set)

    leaders = set()
    if entry_address in address_set:
        leaders.add(entry_address)

    previous = None
    for address in addresses:
        record = instructions[address]
        if previous is None or previous["address"] + previous["size"] != address:
            leaders.add(address)
        if record["symbols"]:
            leaders.add(address)
        previous = record

    for record in instructions.values():
        if record["flow"] in {"jump", "conditional", "call", "return"}:
            next_address = record["address"] + record["size"]
            if next_address in address_set:
                leaders.add(next_address)
        for edge in record["edges"]:
            if edge["target"] in address_set:
                leaders.add(edge["target"])

    blocks = []
    current = []

    def finish():
        nonlocal current
        if not current:
            return
        first = current[0]
        last = current[-1]
        blocks.append({
            "id": f"B{len(blocks) + 1:04d}",
            "start": first["address"],
            "end_exclusive": last["address"] + last["size"],
            "instructions": tuple(item["address"] for item in current),
            "symbols": tuple(first["symbols"]),
            "reachable": False,
            "successors": [],
        })
        current = []

    for index, address in enumerate(addresses):
        record = instructions[address]
        if current and address in leaders:
            finish()
        current.append(record)

        next_address = addresses[index + 1] if index + 1 < len(addresses) else None
        terminates = record["flow"] in {"jump", "conditional", "call", "return"}
        contiguous = next_address == address + record["size"]
        if terminates or not contiguous:
            finish()
    finish()

    block_by_instruction = {}
    block_by_start = {}
    for block in blocks:
        block_by_start[block["start"]] = block
        for address in block["instructions"]:
            block_by_instruction[address] = block

    for block in blocks:
        last_address = block["instructions"][-1]
        successors = []
        for edge in instructions[last_address]["edges"]:
            item = dict(edge)
            target_block = (
                block_by_instruction.get(edge["target"])
                if edge["target"] is not None
                else None
            )
            item["target_block"] = target_block["id"] if target_block else None
            successors.append(item)
        block["successors"] = successors

    entry_block = block_by_instruction.get(entry_address)
    reachable = set()
    pending = [entry_block["id"]] if entry_block else []
    by_id = {block["id"]: block for block in blocks}
    while pending:
        block_id = pending.pop()
        if block_id in reachable:
            continue
        reachable.add(block_id)
        for edge in by_id[block_id]["successors"]:
            target_block = edge.get("target_block")
            if target_block and target_block not in reachable:
                pending.append(target_block)

    for block in blocks:
        block["reachable"] = block["id"] in reachable

    unresolved_edges = sum(
        1
        for block in blocks
        for edge in block["successors"]
        if edge["kind"] != "return" and not edge["resolved"]
    )
    edge_count = sum(len(block["successors"]) for block in blocks)

    return {
        "kind": "sicxe-control-flow-graph",
        "entry_address": entry_address,
        "entry_block": entry_block["id"] if entry_block else None,
        "instruction_count": len(instructions),
        "block_count": len(blocks),
        "reachable_block_count": len(reachable),
        "edge_count": edge_count,
        "unresolved_edge_count": unresolved_edges,
        "instructions": tuple(instructions[address] for address in addresses),
        "blocks": tuple(blocks),
    }


def _instruction_provenance_text(record):
    region = {
        "expanded_line": record.get("expanded_line"),
        "provenance": record.get("provenance"),
    }
    return "; ".join(provenance_details(region))


def render_control_flow_graph(cfg):
    lines = [
        "SIC/XE CONTROL FLOW GRAPH",
        f"ENTRY       {cfg['entry_address']:05X} "
        f"block={cfg['entry_block'] or '<untyped/unresolved>'}",
        f"INSTRUCTIONS {cfg['instruction_count']}",
        f"BLOCKS       {cfg['block_count']} reachable={cfg['reachable_block_count']}",
        f"EDGES        {cfg['edge_count']} unresolved={cfg['unresolved_edge_count']}",
        "",
    ]
    instruction_by_address = {
        item["address"]: item
        for item in cfg["instructions"]
    }

    for block in cfg["blocks"]:
        symbols = ",".join(block["symbols"]) or "-"
        lines.append(
            f"BLOCK {block['id']} {block['start']:05X}-{block['end_exclusive']:05X} "
            f"reachable={'yes' if block['reachable'] else 'no'} symbols={symbols}"
        )
        for address in block["instructions"]:
            record = instruction_by_address[address]
            assembly = record["mnemonic"]
            if record["operand"]:
                assembly += " " + record["operand"]
            provenance = _instruction_provenance_text(record)
            lines.append(
                f"  {address:05X}  {record['bytes_hex'].ljust(8)}  {assembly} "
                f"; flow={record['flow']}; {provenance}"
            )
        if not block["successors"]:
            lines.append("  -> <none>")
        for edge in block["successors"]:
            if edge["target"] is None:
                target = "<dynamic>" if edge["kind"] != "return" else "<return>"
            else:
                target = f"{edge['target']:05X}"
            if edge.get("target_block"):
                target += f" ({edge['target_block']})"
            state = "resolved" if edge["resolved"] else "unresolved"
            if edge["kind"] == "return":
                state = "dynamic"
            lines.append(f"  -> {edge['kind']:<11} {target} [{state}]")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
