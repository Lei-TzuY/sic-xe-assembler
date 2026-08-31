from static_analysis import TRACKED_REGISTERS


CONDITIONAL_BRANCHES = {"JEQ", "JGT", "JLT"}


def _intraprocedural_successors(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    successors = {address: set() for address in by_address}
    for edge in edges:
        if (
            not edge.get("resolved")
            or edge.get("target") not in by_address
            or edge.get("kind") == "call"
            or edge.get("synthetic_return")
        ):
            continue
        successors[edge["source"]].add(edge["target"])
    return successors


def _closure(entry, successors):
    seen = set()
    pending = [entry]
    while pending:
        address = pending.pop()
        if address in seen or address not in successors:
            continue
        seen.add(address)
        pending.extend(target for target in successors[address] if target not in seen)
    return seen


def _weak_components(blocks, edges):
    blocks = set(blocks)
    if not blocks:
        return 0
    adjacency = {block: set() for block in blocks}
    for source, target in edges:
        if source in blocks and target in blocks:
            adjacency[source].add(target)
            adjacency[target].add(source)
    remaining = set(blocks)
    count = 0
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


def _function_metrics(instruction_addresses, block_ids, nodes_by_address, edges):
    block_ids = set(block_ids)
    graph_edges = set()
    for edge in edges:
        if (
            not edge.get("resolved")
            or edge.get("kind") == "call"
            or edge.get("synthetic_return")
        ):
            continue
        source = edge.get("source_block")
        target = edge.get("target_block")
        if source not in block_ids or target not in block_ids:
            continue
        if source == target and edge.get("kind") == "fallthrough":
            continue
        graph_edges.add((source, target, edge.get("kind")))
    weak_edges = {(source, target) for source, target, _ in graph_edges}
    components = _weak_components(block_ids, weak_edges)
    node_count = len(block_ids)
    edge_count = len(graph_edges)
    complexity = edge_count - node_count + (2 * components) if node_count else 0
    decisions = sum(
        1
        for address in instruction_addresses
        if nodes_by_address[address]["base_mnemonic"] in CONDITIONAL_BRANCHES
    )
    return {
        "blocks": node_count,
        "resolved_intraprocedural_edges": edge_count,
        "weak_components": components,
        "cyclomatic_complexity": complexity,
        "decision_points": decisions,
    }


def analyze_functions(nodes, edges, blocks, entry_address, summaries, liveness):
    """Discover call-target functions and summarize their intraprocedural bodies.

    Function entries are the manifest execution entry plus every resolved call
    target. Bodies are conservative non-call CFG closures. Shared tails are
    intentionally allowed: an instruction may belong to multiple function
    objects rather than being forced into an unsound unique partition.
    """
    by_address = {node["address"]: node for node in nodes}
    summaries = summaries or {}
    resolved_targets = {
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call"
        and edge.get("resolved")
        and edge.get("target") in by_address
    }
    entries = []
    if entry_address in by_address:
        entries.append(entry_address)
    entries.extend(sorted(resolved_targets - set(entries)))
    successors = _intraprocedural_successors(nodes, edges)

    functions = []
    ownership = {address: [] for address in by_address}
    entry_to_id = {}
    for index, entry in enumerate(entries):
        function_id = f"F{index:03d}"
        entry_to_id[entry] = function_id
        addresses = sorted(_closure(entry, successors))
        for address in addresses:
            ownership[address].append(function_id)
        entry_node = by_address[entry]
        symbols = list(entry_node.get("symbols") or ())
        if not symbols and entry == entry_address:
            symbols = [entry_node.get("section") or "ENTRY"]
        block_ids = sorted({
            by_address[address].get("block")
            for address in addresses
            if by_address[address].get("block") is not None
        })
        return_sites = [
            address for address in addresses
            if by_address[address]["base_mnemonic"] == "RSUB"
        ]
        call_sites = [
            address for address in addresses
            if by_address[address]["base_mnemonic"] == "JSUB"
        ]
        clobbered = set()
        dead_write_sites = []
        for address in addresses:
            facts = liveness.get(address, {})
            clobbered.update(
                register
                for register in facts.get("defs") or ()
                if register in TRACKED_REGISTERS
            )
            if facts.get("dead_writes"):
                dead_write_sites.append({
                    "address": address,
                    "registers": list(facts["dead_writes"]),
                })
        summary = summaries.get(entry)
        if summary is not None:
            clobbered |= set(summary.get("may_clobber") or ())
        metrics = _function_metrics(addresses, block_ids, by_address, edges)
        functions.append({
            "id": function_id,
            "entry": entry,
            "entry_block": entry_node.get("block"),
            "section": entry_node.get("section"),
            "symbols": symbols,
            "is_program_entry": entry == entry_address,
            "reachable_from_program_entry": bool(entry_node.get("reachable")),
            "instruction_addresses": addresses,
            "blocks": block_ids,
            "return_sites": return_sites,
            "call_sites": call_sites,
            "callers": [],
            "callees": [],
            "preserved": sorted(set(TRACKED_REGISTERS) - clobbered),
            "may_clobber": sorted(clobbered),
            "live_in": list(liveness.get(entry, {}).get("live_in") or ()),
            "dead_write_sites": dead_write_sites,
            "metrics": metrics,
        })

    by_id = {function["id"]: function for function in functions}
    for edge in edges:
        if edge.get("kind") != "call":
            continue
        caller_ids = ownership.get(edge.get("source"), ())
        callee_id = entry_to_id.get(edge.get("target")) if edge.get("resolved") else None
        if callee_id is None:
            continue
        for caller_id in caller_ids:
            if callee_id not in by_id[caller_id]["callees"]:
                by_id[caller_id]["callees"].append(callee_id)
            if caller_id not in by_id[callee_id]["callers"]:
                by_id[callee_id]["callers"].append(caller_id)

    for function in functions:
        function["callers"].sort()
        function["callees"].sort()
    for address in ownership:
        ownership[address].sort()
    return functions, ownership, entry_to_id
