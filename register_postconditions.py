import control_flow_core as _core
from disassembler import decode_instruction
from memory_feedback import (
    _memory_aware_exact_transfer,
    _memory_aware_range_transfer,
)
from range_analysis import (
    _copy_state as _copy_range_state,
    _join_states as _join_range_states,
    _state_equal as _range_state_equal,
    transfer_range_state,
    unknown_range_state,
)
from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    _copy_state as _copy_exact_state,
    _join_states as _join_exact_states,
    _state_equal as _exact_state_equal,
    summarize_subroutines,
    transfer_register_state,
    unknown_state,
)


REGISTER_POSTCONDITION_BASE_RESOLUTIONS = {
    "register-postcondition-base",
    "register-postcondition-range-base",
}


class RegisterPostconditionError(ValueError):
    pass


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - 0x1000000


def _merged_summaries(nodes, edges, hints=None):
    structural = summarize_subroutines(nodes, edges)
    hints = hints or {}
    result = {}
    for entry, summary in structural.items():
        merged = dict(summary)
        hint = hints.get(entry) or {}
        merged["return_constants"] = dict(hint.get("return_constants") or {})
        merged["return_ranges"] = {
            register: list(interval)
            for register, interval in (hint.get("return_ranges") or {}).items()
        }
        merged["return_conditions"] = list(hint.get("return_conditions") or ())
        merged["return_value_registers"] = sorted(
            set(merged["return_constants"]) | set(merged["return_ranges"])
        )
        result[entry] = merged
    return result


def _apply_exact_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_state()
    result = _copy_exact_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None

    # Return values are consumed only when the structural analysis also proves
    # that the callee preserves the link register. A represented RSUB alone is
    # not enough evidence that execution actually returns to this continuation.
    if summary.get("link_register_preserved"):
        for register, value in (summary.get("return_constants") or {}).items():
            if register in TRACKED_REGISTERS:
                result[register] = value & REGISTER_MASK
        conditions = tuple(summary.get("return_conditions") or ())
        if len(conditions) == 1:
            result["CC"] = conditions[0]
    return result


def _apply_range_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_range_state()
    result = _copy_range_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None

    if summary.get("link_register_preserved"):
        constants = summary.get("return_constants") or {}
        ranges = summary.get("return_ranges") or {}
        for register in TRACKED_REGISTERS:
            interval = ranges.get(register)
            if interval is not None:
                result[register] = tuple(interval)
            elif register in constants:
                signed = _signed24(constants[register])
                result[register] = (signed, signed)
        conditions = tuple(summary.get("return_conditions") or ())
        if conditions:
            result["CC"] = tuple(
                condition for condition in CONDITION_VALUES if condition in conditions
            )
    return result


def _resolved_outgoing(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)
    return by_address, outgoing


def _exact_edge_feasible(node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    cc = None if state is None else state.get("CC")
    if cc not in CONDITION_VALUES:
        return True
    return (cc == required) if edge["kind"] == "branch" else (cc != required)


def _range_edge_feasible(node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    possible = None if state is None else state.get("CC")
    if possible is None:
        return True
    if edge["kind"] == "branch":
        return required in possible
    return any(value != required for value in possible)


def _base_relative(node):
    flags = node.get("flags") or ""
    return len(flags) == 6 and flags[3] == "1" and flags[4] == "0" and flags[5] == "0"


def _node_with_exact_base(node, state):
    if not _base_relative(node):
        return node
    base = None if state is None else state.get("B")
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=base,
    )
    local = dict(node)
    local["operand"] = decoded.operand
    local["target"] = decoded.target
    local["warning"] = decoded.warning
    return local


def _node_with_range_base(node, state):
    if not _base_relative(node):
        return node
    interval = None if state is None else state.get("B")
    base = None
    if interval is not None and interval[0] == interval[1]:
        base = interval[0] & REGISTER_MASK
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=base,
    )
    local = dict(node)
    local["operand"] = decoded.operand
    local["target"] = decoded.target
    local["warning"] = decoded.warning
    return local


def _analyze_local_exact(nodes, edges, entry, summaries):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry not in by_address:
        return incoming, outgoing
    incoming[entry] = unknown_state()
    pending = [entry]
    queued = {entry}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        transfer_node = _node_with_exact_base(node, state_in)
        state_out = transfer_register_state(transfer_node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _exact_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_exact_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_exact_summary(
                    state_out,
                    summaries.get(node.get("target")),
                )
            target = edge["target"]
            merged = _join_exact_states(incoming[target], candidate)
            if not _exact_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return incoming, outgoing


def _analyze_local_ranges(nodes, edges, entry, summaries):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry not in by_address:
        return incoming, outgoing
    incoming[entry] = unknown_range_state()
    pending = [entry]
    queued = {entry}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        transfer_node = _node_with_range_base(node, state_in)
        state_out = transfer_range_state(transfer_node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _range_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_range_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_range_summary(
                    state_out,
                    summaries.get(node.get("target")),
                )
            target = edge["target"]
            merged = _join_range_states(incoming[target], candidate)
            if not _range_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return incoming, outgoing


def _derive_entry_summary(structural, exact_out, range_out):
    summary = dict(structural)
    returns = list(structural.get("return_sites") or ())
    constants = {}
    ranges = {}
    conditions = []

    # Every represented return must have a state. If one is unreachable to the
    # conservative local analysis, do not silently drop it and overstate a
    # contract from the remaining exits.
    if returns and all(exact_out.get(site) is not None for site in returns):
        for register in TRACKED_REGISTERS:
            values = [exact_out[site].get(register) for site in returns]
            if values[0] is not None and all(value == values[0] for value in values):
                constants[register] = values[0] & REGISTER_MASK
        cc_values = [exact_out[site].get("CC") for site in returns]
        if cc_values[0] in CONDITION_VALUES and all(value == cc_values[0] for value in cc_values):
            conditions = [cc_values[0]]

    if returns and all(range_out.get(site) is not None for site in returns):
        for register in TRACKED_REGISTERS:
            intervals = [range_out[site].get(register) for site in returns]
            if all(interval is not None for interval in intervals):
                ranges[register] = [
                    min(interval[0] for interval in intervals),
                    max(interval[1] for interval in intervals),
                ]
        if not conditions:
            cc_sets = [range_out[site].get("CC") for site in returns]
            if all(values is not None for values in cc_sets):
                union = set()
                for values in cc_sets:
                    union.update(values)
                conditions = [
                    condition for condition in CONDITION_VALUES if condition in union
                ]

    summary["return_constants"] = constants
    summary["return_ranges"] = ranges
    summary["return_conditions"] = conditions
    summary["return_value_registers"] = sorted(set(constants) | set(ranges))
    return summary


def _summary_signature(summaries):
    return tuple(
        (
            entry,
            tuple(sorted(summary.get("return_constants", {}).items())),
            tuple(
                sorted(
                    (register, tuple(interval))
                    for register, interval in summary.get("return_ranges", {}).items()
                )
            ),
            tuple(summary.get("return_conditions") or ()),
        )
        for entry, summary in sorted(summaries.items())
    )


def infer_register_return_postconditions(nodes, edges):
    """Infer caller-independent register/CC facts at every represented return."""
    structural = summarize_subroutines(nodes, edges)
    hints = {}
    previous = None
    max_iterations = max(4, len(structural) * 2 + 4)
    for iteration in range(1, max_iterations + 1):
        summaries = _merged_summaries(nodes, edges, hints)
        derived = {}
        for entry, shape in structural.items():
            exact_in, exact_out = _analyze_local_exact(nodes, edges, entry, summaries)
            range_in, range_out = _analyze_local_ranges(nodes, edges, entry, summaries)
            derived[entry] = _derive_entry_summary(shape, exact_out, range_out)
        signature = _summary_signature(derived)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": derived,
                "summaries": [derived[key] for key in sorted(derived)],
            }
        previous = signature
        hints = derived
    raise RegisterPostconditionError("Register return-postcondition analysis did not converge")


def _global_exact(nodes, edges, entry_address, summaries, initial_registers):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}
    entry_state = unknown_state()
    for register, value in (initial_registers or {}).items():
        if register in TRACKED_REGISTERS:
            entry_state[register] = None if value is None else value & REGISTER_MASK
    incoming[entry_address] = entry_state
    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = _memory_aware_exact_transfer(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _exact_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_exact_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_exact_summary(
                    state_out,
                    summaries.get(node.get("target")),
                )
            target = edge["target"]
            merged = _join_exact_states(incoming[target], candidate)
            if not _exact_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        if not edge.get("resolved"):
            continue
        source = by_address.get(edge.get("source"))
        if source is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        state = outgoing.get(source["address"])
        if source["base_mnemonic"] in CONDITIONAL_MNEMONICS and not _exact_edge_feasible(source, edge, state):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "register-postcondition-condition"
    return {
        address: {
            "in": None if incoming[address] is None else _copy_exact_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_exact_state(outgoing[address]),
        }
        for address in by_address
    }


def _global_ranges(nodes, edges, entry_address, summaries, initial_registers):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}
    entry_state = unknown_range_state()
    for register, value in (initial_registers or {}).items():
        if register in TRACKED_REGISTERS:
            signed = _signed24(value)
            entry_state[register] = (signed, signed)
    incoming[entry_address] = entry_state
    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = _memory_aware_range_transfer(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _range_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_range_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_range_summary(
                    state_out,
                    summaries.get(node.get("target")),
                )
            target = edge["target"]
            merged = _join_range_states(incoming[target], candidate)
            if not _range_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        if not edge.get("resolved"):
            continue
        source = by_address.get(edge.get("source"))
        if source is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        state = outgoing.get(source["address"])
        if source["base_mnemonic"] in CONDITIONAL_MNEMONICS and not _range_edge_feasible(source, edge, state):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "register-postcondition-range-condition"
    return {
        address: {
            "in": None if incoming[address] is None else _copy_range_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_range_state(outgoing[address]),
        }
        for address in by_address
    }


def _clear_postcondition_base(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution") in REGISTER_POSTCONDITION_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _resolve_postcondition_base_targets(nodes, exact, ranges):
    changed = False
    for node in nodes:
        if not _base_relative(node):
            continue
        resolution = node.get("target_resolution")
        if resolution is not None and resolution not in REGISTER_POSTCONDITION_BASE_RESOLUTIONS:
            continue
        exact_state = (exact.get(node["address"]) or {}).get("in")
        range_state = (ranges.get(node["address"]) or {}).get("in")
        base = None if exact_state is None else exact_state.get("B")
        new_resolution = None
        if base is not None:
            new_resolution = "register-postcondition-base"
        elif range_state is not None:
            interval = range_state.get("B")
            if interval is not None and interval[0] == interval[1]:
                base = interval[0] & REGISTER_MASK
                new_resolution = "register-postcondition-range-base"
        if base is None:
            if resolution in REGISTER_POSTCONDITION_BASE_RESOLUTIONS:
                changed = _clear_postcondition_base(node) or changed
            continue
        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base,
        )
        if decoded.target is None:
            if resolution in REGISTER_POSTCONDITION_BASE_RESOLUTIONS:
                changed = _clear_postcondition_base(node) or changed
            continue
        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base
            or node.get("target_resolution") != new_resolution
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            node["base_value"] = base
            node["target_resolution"] = new_resolution
            changed = True
    return changed


def _rebuild_edges(nodes):
    edges = _core._instruction_edges(nodes)
    summaries = summarize_subroutines(nodes, edges)
    _core._add_interprocedural_return_edges(nodes, edges, summaries)
    return edges


def _refinement_signature(nodes, edges, summaries):
    return (
        _summary_signature(summaries),
        tuple(
            (
                node["address"],
                repr(node.get("registers_in")),
                repr(node.get("registers_out")),
                repr(node.get("ranges_in")),
                repr(node.get("ranges_out")),
                node.get("target"),
                node.get("target_resolution"),
            )
            for node in nodes
        ),
        tuple(
            (
                edge.get("source"),
                edge.get("target"),
                edge.get("kind"),
                bool(edge.get("resolved")),
                edge.get("resolution"),
                edge.get("reason"),
            )
            for edge in edges
        ),
    )


def refine_register_postconditions(nodes, edges, entry_address, base_register=None):
    """Infer callee return facts and feed them back through caller dataflow/CFG."""
    initial = {} if base_register is None else {"B": base_register}
    previous = None
    max_iterations = max(5, len(nodes) + 5)
    inferred = None
    for iteration in range(1, max_iterations + 1):
        inferred = infer_register_return_postconditions(nodes, edges)
        summaries = inferred["summary_map"]
        exact = _global_exact(nodes, edges, entry_address, summaries, initial)
        ranges = _global_ranges(nodes, edges, entry_address, summaries, initial)
        for node in nodes:
            node["registers_in"] = exact[node["address"]]["in"]
            node["registers_out"] = exact[node["address"]]["out"]
            node["ranges_in"] = ranges[node["address"]]["in"]
            node["ranges_out"] = ranges[node["address"]]["out"]
            if node["base_mnemonic"] == "JSUB":
                summary = summaries.get(node.get("target"))
                node["register_return_summary"] = summary
                if summary is not None:
                    node["call_summary"] = summary

        if _resolve_postcondition_base_targets(nodes, exact, ranges):
            edges[:] = _rebuild_edges(nodes)
            previous = None
            continue

        signature = _refinement_signature(nodes, edges, summaries)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": summaries,
                "summaries": [summaries[key] for key in sorted(summaries)],
                "base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution") == "register-postcondition-base"
                ),
                "range_base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution") == "register-postcondition-range-base"
                ),
            }
        previous = signature
    raise RegisterPostconditionError("Register postcondition/CFG refinement did not converge")
