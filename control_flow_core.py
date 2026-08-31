from disassembler import decode_instruction
from range_analysis import analyze_value_ranges, known_ranges, possible_conditions
from range_targets import resolve_singleton_base_targets
from static_analysis import (
    analyze_register_constants,
    known_condition,
    known_registers,
    resolve_dynamic_base_targets,
    summarize_subroutines,
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


def _edge_analysis_signature(edges):
    return tuple(
        (
            edge["source"],
            edge.get("target"),
            edge["kind"],
            bool(edge.get("resolved")),
            edge.get("reason"),
            edge.get("resolution"),
        )
        for edge in edges
    )


def _condition_fixed_point(nodes, edges, entry_address, initial_registers):
    max_iterations = max(2, len(edges) + 2)
    facts = {}
    range_facts = {}
    for _ in range(max_iterations):
        before = _edge_analysis_signature(edges)
        facts = analyze_register_constants(
            nodes,
            edges,
            entry_address,
            initial_registers=initial_registers,
        )
        range_facts = analyze_value_ranges(
            nodes,
            edges,
            entry_address,
            initial_registers=initial_registers,
        )
        after = _edge_analysis_signature(edges)
        if after == before:
            return facts, range_facts
    raise ControlFlowError("Condition/range analysis did not converge")


def _add_interprocedural_return_edges(nodes, edges, summaries):
    by_address = {node["address"]: node for node in nodes}
    fallthrough_by_source = {
        edge["source"]: edge["target"]
        for edge in edges
        if edge.get("kind") == "fallthrough" and edge.get("resolved")
    }
    additions = []
    seen = set()
    for call in edges:
        if (
            call.get("kind") != "call"
            or not call.get("resolved")
            or call.get("target") not in by_address
        ):
            continue
        continuation = fallthrough_by_source.get(call["source"])
        summary = summaries.get(call["target"])
        if (
            continuation is None
            or summary is None
            or not summary.get("may_return")
            or not summary.get("link_register_preserved")
        ):
            continue
        call["return_continuation"] = continuation
        call["return_sites"] = list(summary.get("return_sites") or ())
        for return_site in summary.get("return_sites") or ():
            key = (return_site, continuation, call["source"])
            if key in seen:
                continue
            seen.add(key)
            additions.append({
                "source": return_site,
                "target": continuation,
                "kind": "return",
                "resolved": True,
                "reason": None,
                "resolution": "link-register-summary",
                "synthetic_return": True,
                "call_source": call["source"],
                "callee_entry": call["target"],
            })
    edges.extend(additions)
    edges.sort(
        key=lambda item: (
            item["source"],
            item["kind"],
            -1 if item.get("target") is None else item["target"],
            -1 if item.get("call_source") is None else item["call_source"],
        )
    )
    return edges


def _resolve_dataflow_targets(nodes, entry_address, initial_base):
    initial_registers = {} if initial_base is None else {"B": initial_base}
    max_iterations = max(2, len(nodes) + 2)
    facts = {}
    range_facts = {}
    edges = []
    for _ in range(max_iterations):
        edges = _instruction_edges(nodes)
        facts, range_facts = _condition_fixed_point(
            nodes,
            edges,
            entry_address,
            initial_registers,
        )
        if resolve_dynamic_base_targets(nodes, facts):
            continue
        if resolve_singleton_base_targets(nodes, range_facts):
            continue
        summaries = summarize_subroutines(nodes, edges)
        edges = _add_interprocedural_return_edges(nodes, edges, summaries)
        return edges, facts, range_facts, summaries
    raise ControlFlowError("Base-relative dataflow resolution did not converge")


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


def _is_block_graph_edge(edge, include_calls=True, include_returns=True):
    source = edge.get("source_block")
    target = edge.get("target_block")
    if not edge.get("resolved") or source is None or target is None:
        return False
    if not include_calls and edge.get("kind") == "call":
        return False
    if not include_returns and edge.get("synthetic_return"):
        return False
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
        if edge["resolved"] and edge["kind"] in ("jump", "branch", "call", "return"):
            if edge.get("target") in by_address:
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
        edge["target_block"] = address_to_block.get(edge.get("target"))

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
        if not _is_block_graph_edge(edge, include_calls=False, include_returns=False):
            continue
        predecessors[edge["target_block"]].add(edge["source_block"])

    back_edges = []
    loops = []
    for edge in edges:
        if not _is_block_graph_edge(edge, include_calls=False, include_returns=False):
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
        if not _is_block_graph_edge(edge, include_calls=False, include_returns=False):
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
    returns_by_call = {}
    for edge in edges:
        if edge.get("synthetic_return"):
            returns_by_call.setdefault(edge.get("call_source"), []).append(edge)
    fallthrough_by_source = {
        edge["source"]: edge.get("target")
        for edge in edges
        if edge.get("kind") == "fallthrough" and edge.get("resolved")
    }
    calls = []
    for edge in edges:
        if edge["kind"] != "call":
            continue
        source_node = by_address[edge["source"]]
        target_node = by_address.get(edge.get("target"))
        summary = source_node.get("call_summary")
        return_edges = sorted(
            returns_by_call.get(edge["source"], ()),
            key=lambda item: (item["source"], item["target"]),
        )
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
            "continuation": fallthrough_by_source.get(edge["source"]),
            "return_sites": [item["source"] for item in return_edges],
            "returns_resolved": bool(return_edges),
            "summary": summary,
        })
    return calls


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    """Build a typed CFG with exact constants, ranges, and interprocedural edges."""
    nodes = _typed_instruction_nodes(image, image_start, debug_map)
    edges, register_facts, range_facts, summaries = _resolve_dataflow_targets(
        nodes,
        entry_address,
        base_register,
    )
    reachable = _reachable_addresses(entry_address, nodes, edges)

    for node in nodes:
        node["reachable"] = node["address"] in reachable
        facts = register_facts.get(node["address"], {"in": None, "out": None})
        ranges = range_facts.get(node["address"], {"in": None, "out": None})
        node["registers_in"] = facts["in"]
        node["registers_out"] = facts["out"]
        node["ranges_in"] = ranges["in"]
        node["ranges_out"] = ranges["out"]

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
        "subroutines": [summaries[address] for address in sorted(summaries)],
        "metrics": metrics,
        "reachable_instruction_count": len(reachable),
        "unreachable_instruction_count": len(nodes) - len(reachable),
    }


def _format_known_state(state):
    facts = known_registers(state)
    cc = known_condition(state)
    parts = [f"{register}={value:06X}" for register, value in sorted(facts.items())]
    if cc is not None:
        parts.append(f"CC={cc}")
    return ",".join(parts) if parts else "-"


def _format_range_state(state):
    ranges = known_ranges(state)
    parts = []
    for register, bounds in sorted(ranges.items()):
        low, high = bounds
        parts.append(f"{register}=[{low},{high}]" if low != high else f"{register}={low}")
    conditions = possible_conditions(state)
    if conditions is not None:
        parts.append("CC={" + ",".join(conditions) + "}")
    return ",".join(parts) if parts else "-"


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

    lines.extend(["", "ABSTRACT VALUE FACTS"])
    any_facts = False
    for node in report["instructions"]:
        exact_in = _format_known_state(node.get("registers_in"))
        range_in = _format_range_state(node.get("ranges_in"))
        if exact_in == range_in == "-":
            continue
        any_facts = True
        lines.append(f"  {node['address']:05X} exact={exact_in} range={range_in}")
    if not any_facts:
        lines.append("  -")

    lines.extend(["", "EDGES"])
    for edge in report["edges"]:
        target = "?" if edge.get("target") is None else f"{edge['target']:05X}"
        target_block = edge.get("target_block") or "-"
        status = "resolved" if edge["resolved"] else (edge.get("reason") or "unresolved")
        if edge.get("resolution"):
            status += "/" + edge["resolution"]
        if edge.get("condition_values"):
            status += "/CC={" + ",".join(edge["condition_values"]) + "}"
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
            continuation = "?" if call.get("continuation") is None else f"{call['continuation']:05X}"
            return_sites = ",".join(f"{value:05X}" for value in call.get("return_sites") or ()) or "-"
            lines.append(
                f"  {call['source_block'] or '-'}:{call['source']:05X} "
                f"{call['caller_section']} -> {call['target_block'] or '-'}:{target} "
                f"{call['callee_section'] or '?'} symbols={symbols} [{status}] "
                f"continuation={continuation} returns={return_sites}"
            )
    else:
        lines.append("  -")

    lines.extend(["", "SUBROUTINE SUMMARIES"])
    if report.get("subroutines"):
        for summary in report["subroutines"]:
            lines.append(
                f"  {summary['entry']:05X} symbols={','.join(summary['symbols']) or '-'} "
                f"preserved={','.join(summary['preserved']) or '-'} "
                f"clobber={','.join(summary['may_clobber']) or '-'} "
                f"nested={','.join(f'{value:05X}' for value in summary.get('nested_callees') or ()) or '-'} "
                f"returns={','.join(f'{value:05X}' for value in summary['return_sites']) or '-'} "
                f"link={'preserved' if summary.get('link_register_preserved') else 'unknown'}"
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
        if source is None or target is None or not edge.get("resolved"):
            continue
        if source == target and edge.get("kind") == "fallthrough":
            continue
        key = (source, target, edge["kind"], edge.get("resolution"))
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
    """Attach original-source/macro provenance, abstract facts, and CFG state."""
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
            ranges_in = known_ranges(node.get("ranges_in"))
            nonconstant_ranges = {
                register: bounds
                for register, bounds in ranges_in.items()
                if bounds[0] != bounds[1] and register not in known_in
            }
            if nonconstant_ranges:
                annotations.append(
                    "ranges_in=" + ",".join(
                        f"{register}=[{bounds[0]},{bounds[1]}]"
                        for register, bounds in sorted(nonconstant_ranges.items())
                    )
                )
            cc = known_condition(node.get("registers_in"))
            if cc is not None:
                annotations.append(f"CC={cc}")
            elif possible_conditions(node.get("ranges_in")) is not None:
                annotations.append(
                    "CC_possible={" + ",".join(possible_conditions(node.get("ranges_in"))) + "}"
                )
            if node.get("target_resolution"):
                annotations.append(
                    f"target_resolution={node['target_resolution']}; B={node['base_value']:06X}"
                )
        if annotations:
            line += " ; " + "; ".join(annotations)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
