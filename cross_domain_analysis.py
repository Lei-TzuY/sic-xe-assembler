import control_flow_core as core
import range_analysis as ranges
import static_analysis as exact
from memory_interprocedural import analyze_memory_dataflow
from range_targets import resolve_singleton_base_targets


LOAD_REGISTERS = {
    "LDA": "A",
    "LDB": "B",
    "LDL": "L",
    "LDS": "S",
    "LDT": "T",
    "LDX": "X",
}
ACCUMULATOR_OPS = {"ADD", "SUB", "MUL", "DIV", "AND", "OR"}


class CrossDomainAnalysisError(ValueError):
    pass


def _memory_fact(memory, address):
    return (memory.get("instruction_facts") or {}).get(address, {})


def _memory_constant(memory, address):
    return _memory_fact(memory, address).get("memory_constant")


def _apply_word_operation(left, right, mnemonic):
    if left is None or right is None:
        return None
    if mnemonic == "ADD":
        value = left + right
    elif mnemonic == "SUB":
        value = left - right
    elif mnemonic == "MUL":
        value = left * right
    elif mnemonic == "DIV":
        if right == 0:
            return None
        value = int(left / right)
    elif mnemonic == "AND":
        value = left & right
    else:
        value = left | right
    return value & exact.REGISTER_MASK


def transfer_exact_with_memory(node, incoming, memory):
    """Apply historical exact transfer, then refine direct memory operations."""
    state = exact.transfer_register_state(node, incoming)
    value = _memory_constant(memory, node["address"])
    if value is None:
        node.pop("memory_feedback", None)
        return state

    mnemonic = node["base_mnemonic"]
    if mnemonic in LOAD_REGISTERS:
        state[LOAD_REGISTERS[mnemonic]] = value & exact.REGISTER_MASK
        node["memory_feedback"] = "load"
    elif mnemonic == "LDCH":
        accumulator = incoming.get("A")
        state["A"] = None if accumulator is None else ((accumulator & 0xFFFF00) | (value & 0xFF))
        node["memory_feedback"] = "load-byte"
    elif mnemonic in ACCUMULATOR_OPS:
        state["A"] = _apply_word_operation(incoming.get("A"), value, mnemonic)
        node["memory_feedback"] = "arithmetic"
    elif mnemonic == "COMP":
        accumulator = incoming.get("A")
        state["CC"] = exact._compare24(accumulator, value) if accumulator is not None else None
        node["memory_feedback"] = "compare"
    elif mnemonic == "TIX":
        incremented = None if incoming.get("X") is None else (incoming["X"] + 1) & exact.REGISTER_MASK
        state["X"] = incremented
        state["CC"] = exact._compare24(incremented, value) if incremented is not None else None
        node["memory_feedback"] = "tix"
    else:
        node.pop("memory_feedback", None)
    return state


def transfer_range_with_memory(node, incoming, memory):
    """Apply historical interval transfer, refined by singleton memory values."""
    state = ranges.transfer_range_state(node, incoming)
    value = _memory_constant(memory, node["address"])
    if value is None:
        return state
    singleton = ranges._singleton(value)
    mnemonic = node["base_mnemonic"]

    if mnemonic in LOAD_REGISTERS:
        state[LOAD_REGISTERS[mnemonic]] = singleton
    elif mnemonic in ACCUMULATOR_OPS:
        left = incoming.get("A")
        operation = {
            "ADD": ranges._interval_add,
            "SUB": ranges._interval_sub,
            "MUL": ranges._interval_mul,
            "DIV": ranges._interval_div,
        }.get(mnemonic)
        if operation is not None:
            state["A"] = operation(left, singleton)
        elif mnemonic == "AND":
            if singleton[0] == singleton[1]:
                state["A"] = ranges._interval_bitwise_and(left, value)
        else:
            if singleton[0] == singleton[1]:
                state["A"] = ranges._interval_bitwise_or(left, value)
    elif mnemonic == "COMP":
        state["CC"] = ranges._possible_compare(incoming.get("A"), singleton)
    elif mnemonic == "TIX":
        state["X"] = ranges._increment_interval(incoming.get("X"))
        state["CC"] = ranges._possible_compare(state.get("X"), singleton)
    return state


def _analyze_exact(nodes, edges, entry_address, memory, initial_registers):
    by_address = {node["address"]: node for node in nodes}
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}

    summaries = exact.summarize_subroutines(nodes, edges)
    entry_state = exact.unknown_state()
    for register, value in (initial_registers or {}).items():
        if register in exact.TRACKED_REGISTERS:
            entry_state[register] = None if value is None else value & exact.REGISTER_MASK
    incoming[entry_address] = entry_state

    outgoing_edges = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("target") in by_address
            and not edge.get("synthetic_return")
        ):
            outgoing_edges.setdefault(edge["source"], []).append(edge)

    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = transfer_exact_with_memory(node, state_in, memory)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not exact._conditional_edge_feasible(node, edge, state_out):
                continue
            target = edge["target"]
            candidate = exact._edge_state(node, edge, state_out, summaries)
            merged = exact._join_states(incoming[target], candidate)
            if not exact._state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        source = by_address.get(edge.get("source"))
        state_out = outgoing.get(edge.get("source"))
        if source is None or source["base_mnemonic"] not in exact.CONDITIONAL_MNEMONICS:
            continue
        cc = None if state_out is None else state_out.get("CC")
        if cc not in exact.CONDITION_VALUES or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        edge["condition_code"] = cc
        edge["condition_required"] = exact.CONDITIONAL_MNEMONICS[source["base_mnemonic"]]
        feasible = exact._conditional_edge_feasible(source, edge, state_out)
        edge["feasible"] = feasible
        if not feasible:
            edge["resolved"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "abstract-condition"

    return {
        address: {
            "in": None if incoming[address] is None else exact._copy_state(incoming[address]),
            "out": None if outgoing[address] is None else exact._copy_state(outgoing[address]),
        }
        for address in by_address
    }


def _analyze_ranges(nodes, edges, entry_address, memory, initial_registers):
    by_address = {node["address"]: node for node in nodes}
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}

    summaries = exact.summarize_subroutines(nodes, edges)
    entry_state = ranges.unknown_range_state()
    for register, value in (initial_registers or {}).items():
        if register in exact.TRACKED_REGISTERS:
            entry_state[register] = None if value is None else ranges._singleton(value)
    incoming[entry_address] = entry_state

    outgoing_edges = {}
    for edge in edges:
        if edge.get("resolved") and edge.get("target") in by_address and not edge.get("synthetic_return"):
            outgoing_edges.setdefault(edge["source"], []).append(edge)

    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = transfer_range_with_memory(node, state_in, memory)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not ranges._conditional_edge_feasible(node, edge, state_out):
                continue
            target = edge["target"]
            candidate = ranges._edge_state(node, edge, state_out, summaries)
            merged = ranges._join_states(incoming[target], candidate)
            if not ranges._state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        source = by_address.get(edge.get("source"))
        state_out = outgoing.get(edge.get("source"))
        if source is None or source["base_mnemonic"] not in exact.CONDITIONAL_MNEMONICS:
            continue
        possible = None if state_out is None else state_out.get("CC")
        if possible is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        edge["condition_values"] = list(possible)
        edge["condition_required"] = exact.CONDITIONAL_MNEMONICS[source["base_mnemonic"]]
        feasible = ranges._conditional_edge_feasible(source, edge, state_out)
        edge["feasible"] = feasible
        if not feasible and edge.get("resolved"):
            edge["resolved"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "abstract-range-condition"

    return {
        address: {
            "in": None if incoming[address] is None else ranges._copy_state(incoming[address]),
            "out": None if outgoing[address] is None else ranges._copy_state(outgoing[address]),
        }
        for address in by_address
    }


def _memory_signature(memory):
    facts = memory.get("instruction_facts") or {}
    return tuple(
        (
            address,
            facts[address].get("memory_constant"),
            facts[address].get("stored_constant"),
            tuple(facts[address].get("memory_sources") or ()),
        )
        for address in sorted(facts)
    )


def _state_signature(facts):
    result = []
    for address in sorted(facts):
        item = facts[address]
        for direction in ("in", "out"):
            state = item.get(direction)
            if state is None:
                result.append((address, direction, None))
            else:
                result.append((address, direction, tuple((key, state.get(key)) for key in sorted(state))))
    return tuple(result)


def _target_signature(nodes):
    return tuple(
        (
            node["address"],
            node.get("target"),
            node.get("operand"),
            node.get("target_resolution"),
            node.get("base_value"),
        )
        for node in nodes
    )


def _rebuild_report(report, nodes, edges, exact_facts, range_facts):
    entry_address = report.get("entry_address")
    reachable = core._reachable_addresses(entry_address, nodes, edges)
    for node in nodes:
        node["reachable"] = node["address"] in reachable
        exact_item = exact_facts.get(node["address"], {"in": None, "out": None})
        range_item = range_facts.get(node["address"], {"in": None, "out": None})
        node["registers_in"] = exact_item.get("in")
        node["registers_out"] = exact_item.get("out")
        node["ranges_in"] = range_item.get("in")
        node["ranges_out"] = range_item.get("out")

    blocks, address_to_block = core._build_blocks(entry_address, nodes, edges, reachable)
    for node in nodes:
        node["block"] = address_to_block.get(node["address"])
    dominators, entry_block = core._compute_dominators(entry_address, blocks, address_to_block, edges)
    for block in blocks:
        block["dominators"] = dominators.get(block["id"], [])
    back_edges, loops = core._natural_loops(blocks, edges, dominators)
    calls = core._call_graph(nodes, edges)
    metrics = core._graph_metrics(blocks, edges, nodes, loops)
    summaries = exact.summarize_subroutines(nodes, edges)

    report.update({
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
    })
    return report


def refine_cross_domain(report, base_register=None):
    """Reach a register/range/memory/control-flow fixed point.

    The executable/debug artifacts are not modified. This refinement repeatedly
    rebuilds instruction edges, computes selective interprocedural memory facts,
    feeds proven memory constants into exact/range transfer functions, re-runs
    condition pruning, and lets recovered B values resolve base-relative targets.
    """
    nodes = report.get("instructions", [])
    entry_address = report.get("entry_address")
    if not nodes:
        report["cross_domain_iterations"] = 0
        report["memory_feedback_instruction_count"] = 0
        return report

    initial_registers = {} if base_register is None else {"B": base_register}
    previous_signature = None
    final_edges = []
    final_exact = {}
    final_ranges = {}
    final_memory = {}
    max_iterations = max(8, len(nodes) * 3 + 8)

    for iteration in range(1, max_iterations + 1):
        edges = core._instruction_edges(nodes)
        memory = analyze_memory_dataflow(nodes, edges, entry_address)
        exact_facts = _analyze_exact(nodes, edges, entry_address, memory, initial_registers)
        range_facts = _analyze_ranges(nodes, edges, entry_address, memory, initial_registers)

        for node in nodes:
            node["registers_in"] = exact_facts.get(node["address"], {}).get("in")
            node["registers_out"] = exact_facts.get(node["address"], {}).get("out")
            node["ranges_in"] = range_facts.get(node["address"], {}).get("in")
            node["ranges_out"] = range_facts.get(node["address"], {}).get("out")

        target_changed = exact.resolve_dynamic_base_targets(nodes, exact_facts)
        if not target_changed:
            target_changed = resolve_singleton_base_targets(nodes, range_facts)
        if target_changed:
            previous_signature = None
            continue

        summaries = exact.summarize_subroutines(nodes, edges)
        edges = core._add_interprocedural_return_edges(nodes, edges, summaries)
        memory_after = analyze_memory_dataflow(nodes, edges, entry_address)
        signature = (
            _target_signature(nodes),
            core._edge_analysis_signature(edges),
            _memory_signature(memory_after),
            _state_signature(exact_facts),
            _state_signature(range_facts),
        )

        final_edges = edges
        final_exact = exact_facts
        final_ranges = range_facts
        final_memory = memory_after
        if signature == previous_signature:
            report = _rebuild_report(report, nodes, final_edges, final_exact, final_ranges)
            report["cross_domain_iterations"] = iteration
            report["memory_feedback_instruction_count"] = sum(
                1 for node in nodes if node.get("memory_feedback")
            )
            report["cross_domain_memory_preview"] = final_memory
            return report
        previous_signature = signature

    raise CrossDomainAnalysisError("Cross-domain register/memory/CFG analysis did not converge")
