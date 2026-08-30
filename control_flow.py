from disassembler import decode_instruction
from static_analysis import (
    analyze_register_constants,
    known_registers,
    resolve_dynamic_base_targets,
)


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


def _typed_instruction_nodes(image, image_start, debug_map):
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
            payload = raw[offset:offset + length]
            decoded = decode_instruction(payload, address=address, base_register=None)
            nodes.append({
                "address": address,
                "end": address + length,
                "size": length,
                "decoded_size": decoded.size,
                "bytes": payload.hex().upper(),
                "mnemonic": decoded.mnemonic,
                "base_mnemonic": _normalize_mnemonic(decoded.mnemonic),
                "operand": decoded.operand,
                "target": decoded.target,
                "flags": decoded.flags,
                "warning": decoded.warning,
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
            "resolution": source.get("target_resolution"),
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


def _resolve_dataflow_targets(nodes, entry_address, initial_base):
    initial_registers = {} if initial_base is None else {"B": initial_base}
    edges = _instruction_edges(nodes)
    facts = {}
    max_iterations = max(2, len(nodes) + 2)
    for _ in range(max_iterations):
        facts = analyze_register_constants(
            nodes,
            edges,
            entry_address,
            initial_registers=initial_registers,
        )
        if not resolve_dynamic_base_targets(nodes, facts):
            break
        edges = _instruction_edges(nodes)
    else:
        raise ControlFlowError("Base-relative dataflow resolution did not converge")

    edges = _instruction_edges(nodes)
    facts = analyze_register_constants(
        nodes,
        edges,
        entry_address,
        initial_registers=initial_registers,
    )
    return edges, facts


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


def _is_block_graph_edge(edge, include_calls=True):
    source = edge.get("source_block")
    target = edge.get("target_block")
    if not edge.get("resolved") or source is None or target is None:
        return False
    if not include_calls and edge.get("kind") == "call":
        return False
    # Ordinary sequential fallthroughs inside one basic block are instruction
    # edges, not basic-block graph edges. Explicit branch/jump self-loops remain.
    if source == target and edge.get("kind") == "fallthrough":
        return False
    return True


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
            "predecessors": [],
            "successors": [],
        })

    for edge in edges:
        edge["source_block"] = address_to_block.get(edge["source"])
        edge["target_block"] = address_to_block.get(edge["target"])

    by_block = {block["id"]: block for block in blocks}
    for edge in edges:
        if not _is_block_graph_edge(edge):
            continue
        source_block = edge["source_block"]
        target_block = edge["target_block"]
        if target_block not in by_block[source_block]["successors"]:
            by_block[source_block]["successors"].append(target_block)
        if source_block not in by_block[target_block]["predecessors"]:
            by_block[target_block]["predecessors"].append(source_block)
    for block in blocks:
        block["predecessors"].sort()
        block["successors"].sort()
    return blocks, address_to_block


def _compute_dominators(entry_address, blocks, address_to_block, edges):
    entry_block = address_to_block.get(entry_address)
    reachable_blocks = {block["id"] for block in blocks if block["reachable"]}
    if entry_block is None or entry_block not in reachable_blocks:
        return {}, None

    predecessors = {block_id: set() for block_id in reachable_blocks}
    for edge in edges:
        if not _is_block_graph_edge(edge):
            continue
        source = edge["source_block"]
        target = edge["target_block"]
        if source in reachable_blocks and target in reachable_blocks:
            predecessors[target].add(source)

    dominators = {}
    for block_id in reachable_blocks:
        dominators[block_id] = {block_id} if block_id == entry_block else set(reachable_blocks)

    changed = True
    while changed:
        changed = False
        for block_id in sorted(reachable_blocks):
            if block_id == entry_block:
                continue
            preds = predecessors[block_id]
            if not preds:
                new_value = {block_id}
            else:
                intersection = set(reachable_blocks)
                for predecessor in preds:
                    intersection &= dominators[predecessor]
                new_value = {block_id} | intersection
            if new_value != dominators[block_id]:
                dominators[block_id] = new_value
                changed = True

    return {
        block_id: sorted(values)
        for block_id, values in sorted(dominators.items())
    }, entry_block


def _natural_loops(blocks, edges, dominators):
    predecessors = {block["id"]: set() for block in blocks}
    for edge in edges:
        if not _is_block_graph_edge(edge, include_calls=False):
            continue
        predecessors[edge["target_block"]].add(edge["source_block"])

    back_edges = []
    loops = []
    for edge in edges:
        if not _is_block_graph_edge(edge, include_calls=False):
            continue
        source = edge["source_block"]
        target = edge["target_block"]
        if source not in dominators or target not in dominators[source]:
            continue
        back_edges.append({
            "source_block": source,
            "target_block": target,
            "source": edge["source"],
            "target": edge["target"],
            "kind": edge["kind"],
        })
        members = {target, source}
        pending = [source]
        while pending:
            current = pending.pop()
            for predecessor in predecessors.get(current, ()):
                if predecessor not in members:
                    members.add(predecessor)
                    pending.append(predecessor)
        loops.append({
            "header": target,
            "latch": source,
            "blocks": sorted(members),
        })

    loops.sort(key=lambda item: (item["header"], item["latch"], item["blocks"]))
    back_edges.sort(key=lambda item: (item["target_block"], item["source_block"], item["kind"]))
    return back_edges, loops


def _weak_component_count(nodes, edges):
    nodes = set(nodes)
    if not nodes:
        return 0
    adjacency = {node: set() for node in nodes}
    for source, target in edges:
        if source in nodes and target in nodes:
            adjacency[source].add(target)
            adjacency[target].add(source)
    count = 0
    remaining = set(nodes)
    while remaining:
        count += 1
        pending = [remaining.pop()]
        while pending:
            current = pending.pop()
            for neighbor in adjacency[current]:
                if neighbor in remaining:
                    remaining.remove(neighbor)
                    pending.append(neighbor)
    return count


def _graph_metrics(blocks, edges, nodes, loops):
    reachable_blocks = {block["id"] for block in blocks if block["reachable"]}
    intraprocedural_edges = []
    for edge in edges:
        if not _is_block_graph_edge(edge, include_calls=False):
            continue
        source = edge["source_block"]
        target = edge["target_block"]
        if source in reachable_blocks and target in reachable_blocks:
            intraprocedural_edges.append((source, target, edge["kind"]))
    unique_edges = sorted(set(intraprocedural_edges))
    weak_edges = {(source, target) for source, target, _ in unique_edges}
    components = _weak_component_count(reachable_blocks, weak_edges)
    node_count = len(reachable_blocks)
    edge_count = len(unique_edges)
    complexity = edge_count - node_count + (2 * components) if node_count else 0
    decision_points = sum(
        1
        for node in nodes
        if node["reachable"] and node["base_mnemonic"] in CONDITIONAL_BRANCHES
    )
    return {
        "reachable_blocks": node_count,
        "resolved_intraprocedural_edges": edge_count,
        "weak_components": components,
        "cyclomatic_complexity": complexity,
        "decision_points": decision_points,
        "natural_loops": len(loops),
    }


def _call_graph(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    symbols_by_address = {
        node["address"]: tuple(node.get("symbols") or ())
        for node in nodes
        if node.get("symbols")
    }
    calls = []
    for edge in edges:
        if edge["kind"] != "call":
            continue
        source_node = by_address[edge["source"]]
        target_node = by_address.get(edge.get("target"))
        calls.append({
            "source": edge["source"],
            "source_block": edge.get("source_block"),
            "caller_section": source_node["section"],
            "target": edge.get("target"),
            "target_block": edge.get("target_block"),
            "callee_section": None if target_node is None else target_node["section"],
            "target_symbols": list(symbols_by_address.get(edge.get("target"), ())),
            "resolved": edge["resolved"],
            "reason": edge.get("reason"),
            "resolution": edge.get("resolution"),
        })
    return calls


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    """Build a conservative typed CFG with must-constant register dataflow."""
    nodes = _typed_instruction_nodes(image, image_start, debug_map)
    edges, register_facts = _resolve_dataflow_targets(nodes, entry_address, base_register)
    reachable = _reachable_addresses(entry_address, nodes, edges)

    for node in nodes:
        node["reachable"] = node["address"] in reachable
        facts = register_facts.get(node["address"], {"in": None, "out": None})
        node["registers_in"] = facts["in"]
        node["registers_out"] = facts["out"]

    blocks, address_to_block = _build_blocks(entry_address, nodes, edges, reachable)
    for node in nodes:
        node["block"] = address_to_block.get(node["address"])

    dominators, entry_block = _compute_dominators(entry_address, blocks, address_to_block, edges)
    for block in blocks:
        block["dominators"] = dominators.get(block["id"], [])

    back_edges, loops = _natural_loops(blocks, edges, dominators)
    calls = _call_graph(nodes, edges)
    metrics = _graph_metrics(blocks, edges, nodes, loops)

    return {
        "entry_address": entry_address,
        "entry_block": entry_block,
        "entry_resolved": any(node["address"] == entry_address for node in nodes),
        "instructions": nodes,
        "blocks": blocks,
        "edges": edges,
        "dominators": dominators,
        "back_edges": back_edges,
        "loops": loops,
        "calls": calls,
        "metrics": metrics,
        "reachable_instruction_count": len(reachable),
        "unreachable_instruction_count": len(nodes) - len(reachable),
    }


def _format_known_state(state):
    facts = known_registers(state)
    if not facts:
        return "-"
    return ",".join(f"{register}={value:06X}" for register, value in sorted(facts.items()))


def render_control_flow_report(report):
    metrics = report.get("metrics", {})
    lines = [
        "SIC/XE CONTROL FLOW GRAPH",
        f"ENTRY       {report['entry_address']:05X} ({'typed' if report['entry_resolved'] else 'not in typed code'})",
        f"INSTRUCTIONS {len(report['instructions'])} reachable={report['reachable_instruction_count']} unreachable={report['unreachable_instruction_count']}",
        (
            "METRICS     "
            f"blocks={metrics.get('reachable_blocks', 0)} "
            f"edges={metrics.get('resolved_intraprocedural_edges', 0)} "
            f"components={metrics.get('weak_components', 0)} "
            f"complexity={metrics.get('cyclomatic_complexity', 0)} "
            f"decisions={metrics.get('decision_points', 0)} "
            f"loops={metrics.get('natural_loops', 0)}"
        ),
        "",
        "BASIC BLOCKS",
    ]
    by_address = {item["address"]: item for item in report["instructions"]}
    for block in report["blocks"]:
        lines.append(
            f"  {block['id']} {block['start']:05X}-{block['end']:05X} "
            f"[{block['input_index']}:{block['section_index']}] {block['section']} "
            f"{'reachable' if block['reachable'] else 'UNREACHABLE'} "
            f"pred={','.join(block['predecessors']) or '-'} "
            f"succ={','.join(block['successors']) or '-'} "
            f"dom={','.join(block.get('dominators') or ()) or '-'}"
        )
        for address in block["instruction_addresses"]:
            node = by_address[address]
            assembly = node["mnemonic"] + ((" " + node["operand"]) if node["operand"] else "")
            resolution = (
                f"; target-resolution={node['target_resolution']} B={node['base_value']:06X}"
                if node.get("target_resolution")
                else ""
            )
            lines.append(
                f"    {address:05X}  {assembly} ; {_format_provenance(node.get('provenance'))}{resolution}"
            )

    lines.extend(["", "REGISTER FACTS"])
    any_register_facts = False
    for node in report["instructions"]:
        incoming = _format_known_state(node.get("registers_in"))
        outgoing = _format_known_state(node.get("registers_out"))
        if incoming == outgoing == "-":
            continue
        any_register_facts = True
        lines.append(f"  {node['address']:05X} in={incoming} out={outgoing}")
    if not any_register_facts:
        lines.append("  -")

    lines.extend(["", "EDGES"])
    for edge in report["edges"]:
        target = "?" if edge["target"] is None else f"{edge['target']:05X}"
        target_block = edge.get("target_block") or "-"
        status = "resolved" if edge["resolved"] else (edge.get("reason") or "unresolved")
        if edge.get("resolution"):
            status += "/" + edge["resolution"]
        lines.append(
            f"  {edge.get('source_block') or '-'}:{edge['source']:05X} "
            f"--{edge['kind']}--> {target_block}:{target} [{status}]"
        )

    lines.extend(["", "NATURAL LOOPS"])
    if report.get("loops"):
        for index, loop in enumerate(report["loops"]):
            lines.append(
                f"  L{index:03d} header={loop['header']} latch={loop['latch']} "
                f"blocks={','.join(loop['blocks'])}"
            )
    else:
        lines.append("  -")

    lines.extend(["", "CALL GRAPH"])
    if report.get("calls"):
        for call in report["calls"]:
            target = "?" if call["target"] is None else f"{call['target']:05X}"
            symbols = ",".join(call["target_symbols"]) or "-"
            status = "resolved" if call["resolved"] else (call.get("reason") or "unresolved")
            lines.append(
                f"  {call['source_block'] or '-'}:{call['source']:05X} "
                f"{call['caller_section']} -> {call['target_block'] or '-'}:{target} "
                f"{call['callee_section'] or '?'} symbols={symbols} [{status}]"
            )
    else:
        lines.append("  -")
    return "\n".join(lines) + "\n"


def render_control_flow_dot(report):
    lines = ["digraph sicxe_cfg {", "  rankdir=TB;"]
    loop_blocks = {block for loop in report.get("loops", ()) for block in loop["blocks"]}
    for block in report["blocks"]:
        state = "reachable" if block["reachable"] else "unreachable"
        loop = "\\nloop" if block["id"] in loop_blocks else ""
        label = (
            f"{block['id']}\\n{block['section']} "
            f"{block['start']:05X}-{block['end']:05X}\\n{state}{loop}"
        )
        lines.append(f'  {block["id"]} [label="{label}"];')
    seen = set()
    for edge in report["edges"]:
        source = edge.get("source_block")
        target = edge.get("target_block")
        if source is None or target is None:
            continue
        if source == target and edge.get("kind") == "fallthrough":
            continue
        key = (source, target, edge["kind"])
        if key in seen:
            continue
        seen.add(key)
        label = edge["kind"]
        if edge.get("resolution"):
            label += "/" + edge["resolution"]
        lines.append(f'  {source} -> {target} [label="{label}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def annotate_typed_disassembly(rendered, debug_map, control_flow=None):
    """Attach original-source/macro provenance, dataflow, and optional CFG state."""
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
            known_in = known_registers(node.get("registers_in"))
            if known_in:
                annotations.append(
                    "regs_in=" + ",".join(
                        f"{register}={value:06X}"
                        for register, value in sorted(known_in.items())
                    )
                )
            if node.get("target_resolution"):
                annotations.append(
                    f"target_resolution={node['target_resolution']}; B={node['base_value']:06X}"
                )
        if annotations:
            line += " ; " + "; ".join(annotations)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
