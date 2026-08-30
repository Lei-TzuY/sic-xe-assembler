from disassembler import decode_instruction


CONDITIONAL_BRANCHES = {"JEQ", "JGT", "JLT"}
UNCONDITIONAL_BRANCHES = {"J"}
CALLS = {"JSUB"}
RETURNS = {"RSUB"}


class ControlFlowError(ValueError):
    pass


def _normalize_mnemonic(mnemonic):
    return mnemonic[1:] if mnemonic.startswith("+") else mnemonic


def _format_provenance(provenance):
    if not provenance:
        return "origin=?"
    source_line = provenance.get("source_line")
    invocation_line = provenance.get("invocation_line")
    stack = provenance.get("macro_stack") or ()
    if not stack:
        return f"origin=source:{source_line if source_line is not None else '?'}"
    frames = []
    for frame in stack:
        body = frame.get("body_line")
        frames.append(
            f"{frame.get('name')}#{frame.get('instance')}"
            f"(def={frame.get('definition_line')},"
            f"body={body if body is not None else '-'},"
            f"call={frame.get('invocation_line')})"
        )
    return (
        f"origin=source:{source_line if source_line is not None else '?'}; "
        f"invoke={invocation_line if invocation_line is not None else '?'}; "
        f"macro={' > '.join(frames)}"
    )


def _typed_instruction_nodes(image, image_start, debug_map, base_register=None):
    raw = bytes(image)
    nodes = []
    for section in debug_map.get("sections", ()):
        if not section.get("typed"):
            continue
        for region in section.get("regions", ()):
            if region.get("kind") != "instruction":
                continue
            address = region["loaded_address"]
            length = region["length"]
            offset = address - image_start
            if offset < 0 or offset + length > len(raw):
                raise ControlFlowError(
                    f"Instruction region {address:05X}+{length} lies outside linked image"
                )
            decoded = decode_instruction(
                raw[offset:offset + length],
                address=address,
                base_register=base_register,
            )
            nodes.append({
                "address": address,
                "end": address + length,
                "size": length,
                "decoded_size": decoded.size,
                "mnemonic": decoded.mnemonic,
                "base_mnemonic": _normalize_mnemonic(decoded.mnemonic),
                "operand": decoded.operand,
                "target": decoded.target,
                "flags": decoded.flags,
                "symbols": list(region.get("symbols") or ()),
                "expanded_line": region.get("expanded_line"),
                "provenance": region.get("provenance"),
                "input_index": section["input_index"],
                "section_index": section["section_index"],
                "section": section["name"],
            })
    nodes.sort(key=lambda item: (item["input_index"], item["section_index"], item["address"]))
    return nodes


def _static_control_target(node):
    target = node["target"]
    if target is None:
        return None, "unresolved-addressing"
    operand = node["operand"] or ""
    if operand.startswith("@"):
        return None, "indirect"
    if operand.endswith(",X"):
        return None, "indexed"
    return target, None


def _same_section(left, right):
    return (
        left["input_index"],
        left["section_index"],
    ) == (
        right["input_index"],
        right["section_index"],
    )


def _instruction_edges(nodes):
    by_address = {node["address"]: node for node in nodes}
    edges = []

    def add_edge(source, kind, target=None, reason=None):
        resolved = target in by_address if target is not None else False
        edges.append({
            "source": source["address"],
            "target": target,
            "kind": kind,
            "resolved": resolved,
            "reason": reason if reason is not None else (None if resolved else "outside-typed-code"),
        })

    for node in nodes:
        mnemonic = node["base_mnemonic"]
        candidate = by_address.get(node["end"])
        fallthrough = (
            node["end"]
            if candidate is not None and _same_section(node, candidate)
            else None
        )

        if mnemonic in UNCONDITIONAL_BRANCHES:
            target, reason = _static_control_target(node)
            add_edge(node, "jump", target, reason)
            continue
        if mnemonic in CONDITIONAL_BRANCHES:
            target, reason = _static_control_target(node)
            add_edge(node, "branch", target, reason)
            if fallthrough is not None:
                add_edge(node, "fallthrough", fallthrough)
            continue
        if mnemonic in CALLS:
            target, reason = _static_control_target(node)
            add_edge(node, "call", target, reason)
            if fallthrough is not None:
                add_edge(node, "fallthrough", fallthrough)
            continue
        if mnemonic in RETURNS:
            add_edge(node, "return", None, "dynamic-return")
            continue
        if fallthrough is not None:
            add_edge(node, "fallthrough", fallthrough)

    edges.sort(
        key=lambda item: (
            item["source"],
            item["kind"],
            -1 if item["target"] is None else item["target"],
        )
    )
    return edges


def _reachable_addresses(entry_address, nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    if entry_address not in by_address:
        return set()
    outgoing = {}
    for edge in edges:
        if edge["resolved"]:
            outgoing.setdefault(edge["source"], []).append(edge["target"])
    seen = set()
    pending = [entry_address]
    while pending:
        address = pending.pop()
        if address in seen:
            continue
        seen.add(address)
        pending.extend(
            target for target in outgoing.get(address, ())
            if target not in seen
        )
    return seen


def _build_blocks(entry_address, nodes, edges, reachable):
    by_address = {node["address"]: node for node in nodes}
    leaders = set()
    if entry_address in by_address:
        leaders.add(entry_address)

    transfer_sources = set()
    for edge in edges:
        source = by_address[edge["source"]]
        if edge["kind"] in ("jump", "branch", "call", "return"):
            transfer_sources.add(source["address"])
        if edge["resolved"] and edge["kind"] in ("jump", "branch", "call"):
            leaders.add(edge["target"])
        if edge["kind"] == "fallthrough" and source["base_mnemonic"] in (
            CONDITIONAL_BRANCHES | CALLS
        ):
            leaders.add(edge["target"])

    grouped = {}
    for node in nodes:
        grouped.setdefault((node["input_index"], node["section_index"]), []).append(node)

    raw_blocks = []
    for section_key in sorted(grouped):
        section_nodes = sorted(grouped[section_key], key=lambda item: item["address"])
        if section_nodes:
            leaders.add(section_nodes[0]["address"])
        current = []
        previous = None
        for node in section_nodes:
            start_new = (
                not current
                or node["address"] in leaders
                or previous is None
                or previous["end"] != node["address"]
                or previous["address"] in transfer_sources
            )
            if start_new and current:
                raw_blocks.append(current)
                current = []
            current.append(node)
            previous = node
        if current:
            raw_blocks.append(current)

    raw_blocks.sort(key=lambda block: (block[0]["input_index"], block[0]["section_index"], block[0]["address"]))
    blocks = []
    address_to_block = {}
    for index, block_nodes in enumerate(raw_blocks):
        block_id = f"B{index:03d}"
        for node in block_nodes:
            address_to_block[node["address"]] = block_id
        blocks.append({
            "id": block_id,
            "input_index": block_nodes[0]["input_index"],
            "section_index": block_nodes[0]["section_index"],
            "section": block_nodes[0]["section"],
            "start": block_nodes[0]["address"],
            "end": block_nodes[-1]["end"],
            "instruction_addresses": [node["address"] for node in block_nodes],
            "reachable": any(node["address"] in reachable for node in block_nodes),
        })

    for edge in edges:
        edge["source_block"] = address_to_block.get(edge["source"])
        edge["target_block"] = address_to_block.get(edge["target"])
    return blocks, address_to_block


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    """Build a deterministic CFG from typed instruction regions only."""
    nodes = _typed_instruction_nodes(
        image,
        image_start,
        debug_map,
        base_register=base_register,
    )
    edges = _instruction_edges(nodes)
    reachable = _reachable_addresses(entry_address, nodes, edges)
    blocks, address_to_block = _build_blocks(entry_address, nodes, edges, reachable)

    for node in nodes:
        node["reachable"] = node["address"] in reachable
        node["block"] = address_to_block.get(node["address"])

    return {
        "entry_address": entry_address,
        "entry_resolved": any(node["address"] == entry_address for node in nodes),
        "instructions": nodes,
        "blocks": blocks,
        "edges": edges,
        "reachable_instruction_count": len(reachable),
        "unreachable_instruction_count": len(nodes) - len(reachable),
    }


def render_control_flow_report(report):
    lines = [
        "SIC/XE CONTROL FLOW GRAPH",
        f"ENTRY       {report['entry_address']:05X} ({'typed' if report['entry_resolved'] else 'not in typed code'})",
        f"INSTRUCTIONS {len(report['instructions'])} reachable={report['reachable_instruction_count']} unreachable={report['unreachable_instruction_count']}",
        "",
        "BASIC BLOCKS",
    ]
    by_address = {item["address"]: item for item in report["instructions"]}
    for block in report["blocks"]:
        lines.append(
            f"  {block['id']} {block['start']:05X}-{block['end']:05X} "
            f"[{block['input_index']}:{block['section_index']}] {block['section']} "
            f"{'reachable' if block['reachable'] else 'UNREACHABLE'}"
        )
        for address in block["instruction_addresses"]:
            node = by_address[address]
            assembly = node["mnemonic"] + ((" " + node["operand"]) if node["operand"] else "")
            lines.append(
                f"    {address:05X}  {assembly} ; {_format_provenance(node.get('provenance'))}"
            )

    lines.extend(["", "EDGES"])
    for edge in report["edges"]:
        target = "?" if edge["target"] is None else f"{edge['target']:05X}"
        target_block = edge.get("target_block") or "-"
        status = "resolved" if edge["resolved"] else (edge.get("reason") or "unresolved")
        lines.append(
            f"  {edge.get('source_block') or '-'}:{edge['source']:05X} "
            f"--{edge['kind']}--> {target_block}:{target} [{status}]"
        )
    return "\n".join(lines) + "\n"


def render_control_flow_dot(report):
    lines = ["digraph sicxe_cfg {", "  rankdir=TB;"]
    for block in report["blocks"]:
        state = "reachable" if block["reachable"] else "unreachable"
        label = (
            f"{block['id']}\\n{block['section']} "
            f"{block['start']:05X}-{block['end']:05X}\\n{state}"
        )
        lines.append(f'  {block["id"]} [label="{label}"];')
    seen = set()
    for edge in report["edges"]:
        source = edge.get("source_block")
        target = edge.get("target_block")
        if source is None or target is None:
            continue
        key = (source, target, edge["kind"])
        if key in seen:
            continue
        seen.add(key)
        lines.append(f'  {source} -> {target} [label="{edge["kind"]}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def annotate_typed_disassembly(rendered, debug_map, control_flow=None):
    """Attach original-source/macro provenance and optional CFG state to typed output."""
    provenance_by_address = {}
    for section in debug_map.get("sections", ()):
        for region in section.get("regions", ()):
            provenance_by_address[region["loaded_address"]] = region.get("provenance")

    cfg_by_address = {}
    if control_flow is not None:
        cfg_by_address = {
            node["address"]: node
            for node in control_flow.get("instructions", ())
        }

    lines = []
    for line in rendered.splitlines():
        parts = line.split(None, 1)
        try:
            address = int(parts[0], 16) if len(parts) > 1 and len(parts[0]) == 5 else None
        except ValueError:
            address = None
        annotations = []
        if address is not None and address in provenance_by_address:
            annotations.append(_format_provenance(provenance_by_address[address]))
        node = cfg_by_address.get(address)
        if node is not None:
            annotations.append(
                f"cfg={'reachable' if node['reachable'] else 'UNREACHABLE'}; block={node['block']}"
            )
        if annotations:
            line += " ; " + "; ".join(annotations)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
