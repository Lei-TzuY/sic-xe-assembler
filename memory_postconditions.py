import control_flow_core as _core
from disassembler import decode_instruction
from memory_analysis import LOAD_DESTINATION_REGISTERS, STORE_SOURCE_REGISTERS, WORD_BYTES, _cell_id, _ranges_overlap
from memory_feedback import (
    _tracked_cells,
    analyze_memory_aware_constants,
    analyze_memory_aware_ranges,
    summarize_memory_effects,
)
from static_analysis import REGISTER_MASK, summarize_subroutines


INITIALIZED_REGION_KINDS = {"word", "byte", "literal"}
MEMORY_BASE_RESOLUTIONS = {"memory-feedback-base", "memory-feedback-range-base"}
CORE_BASE_RESOLUTIONS = {"dataflow-base", "range-singleton-base"}


class MemoryPostconditionError(ValueError):
    pass


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - 0x1000000


def _unknown_value():
    return {"constant": None, "range": None, "origin": None}


def _copy_value(value):
    if value is None:
        return _unknown_value()
    interval = value.get("range")
    return {
        "constant": value.get("constant"),
        "range": None if interval is None else tuple(interval),
        "origin": value.get("origin"),
    }


def _value_equal(left, right):
    return (
        left.get("constant") == right.get("constant")
        and left.get("range") == right.get("range")
        and left.get("origin") == right.get("origin")
    )


def _join_value(left, right):
    left = _copy_value(left)
    right = _copy_value(right)
    left_constant = left.get("constant")
    right_constant = right.get("constant")
    constant = left_constant if left_constant is not None and left_constant == right_constant else None
    left_range = left.get("range")
    right_range = right.get("range")
    interval = None
    if left_range is not None and right_range is not None:
        interval = (
            min(left_range[0], right_range[0]),
            max(left_range[1], right_range[1]),
        )
    if constant is not None and interval is None:
        signed = _signed24(constant)
        interval = (signed, signed)
    origin = left.get("origin") if left.get("origin") == right.get("origin") else "merged"
    return {"constant": constant, "range": interval, "origin": origin}


def _empty_state(cells):
    return {cell: _unknown_value() for cell in cells}


def _copy_state(state, cells):
    return {cell: _copy_value(state.get(cell)) for cell in cells}


def _state_equal(left, right, cells):
    return all(
        _value_equal(
            left.get(cell, _unknown_value()),
            right.get(cell, _unknown_value()),
        )
        for cell in cells
    )


def _join_state(left, right, cells):
    if left is None:
        return _copy_state(right, cells)
    return {cell: _join_value(left.get(cell), right.get(cell)) for cell in cells}


def _covering_initialized_region(debug_map, cell):
    start, width = cell
    matches = []
    for section in debug_map.get("sections", ()):
        if not section.get("typed"):
            continue
        for region in section.get("regions", ()):
            if region.get("kind") not in INITIALIZED_REGION_KINDS:
                continue
            region_start = region.get("loaded_address")
            region_length = region.get("length")
            if not isinstance(region_start, int) or not isinstance(region_length, int):
                continue
            if region_start <= start and start + width <= region_start + region_length:
                matches.append((section, region))
    if len(matches) != 1:
        return None
    return matches[0]


def seed_initialized_memory(image, image_start, debug_map, cells):
    """Seed tracked cells from typed initialized regions in the linked image.

    The linked image is authoritative because relocation has already been applied.
    A cell is seeded only when one typed WORD/BYTE/literal region wholly covers
    the access. Reservations are ignored even when ORG intentionally overlays
    them with initialized bytes.
    """
    raw = bytes(image)
    seeds = {}
    for cell in cells:
        match = _covering_initialized_region(debug_map, cell)
        if match is None:
            continue
        section, region = match
        start, width = cell
        offset = start - image_start
        if offset < 0 or offset + width > len(raw):
            continue
        payload = raw[offset:offset + width]
        constant = int.from_bytes(payload, "big")
        interval = None
        if width == WORD_BYTES:
            signed = _signed24(constant)
            interval = (signed, signed)
        seeds[cell] = {
            "constant": constant,
            "range": interval,
            "origin": "linked-image-initializer",
            "cell": _cell_id(cell),
            "region_kind": region.get("kind"),
            "region_address": region.get("loaded_address"),
            "symbols": list(region.get("symbols") or ()),
            "section": section.get("name"),
            "bytes": payload.hex().upper(),
        }
    return seeds


def _predecessors(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    predecessors = {address: set() for address in by_address}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            predecessors[edge["target"]].add(edge["source"])
    return predecessors


def _function_entries(nodes, edges, entry_address):
    by_address = {node["address"]: node for node in nodes}
    entries = {entry_address} if entry_address in by_address else set()
    entries.update(
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call"
        and edge.get("resolved")
        and edge.get("target") in by_address
    )
    return sorted(entries)


def _register_store_value(node, cell):
    register = STORE_SOURCE_REGISTERS.get(node["base_mnemonic"])
    if register is None:
        return _unknown_value()
    exact_state = node.get("registers_in") or {}
    range_state = node.get("ranges_in") or {}
    constant = exact_state.get(register)
    interval = range_state.get(register)
    if node["base_mnemonic"] == "STCH":
        constant = None if constant is None else constant & 0xFF
        interval = None
    elif cell[1] != WORD_BYTES:
        interval = None
    return {
        "constant": None if constant is None else constant & REGISTER_MASK,
        "range": None if interval is None else tuple(interval),
        "origin": f"store@{node['address']:05X}",
    }


def _summary_by_entry(structural, hints):
    result = {}
    for entry, summary in structural.items():
        merged = dict(summary)
        hint = (hints or {}).get(entry) or {}
        merged["return_constants"] = dict(hint.get("return_constants") or {})
        merged["return_ranges"] = dict(hint.get("return_ranges") or {})
        result[entry] = merged
    return result


def _apply_call_value_effect(outgoing, summary, cells, cells_by_id):
    result = _copy_state(outgoing, cells)
    if summary is None or summary.get("unknown_write"):
        return _empty_state(cells)
    may_write = set(summary.get("may_write_cells") or ())
    return_constants = summary.get("return_constants") or {}
    return_ranges = summary.get("return_ranges") or {}
    for cell_id in may_write:
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        constant = return_constants.get(cell_id)
        raw_range = return_ranges.get(cell_id)
        if constant is None and raw_range is None:
            result[cell] = _unknown_value()
            continue
        interval = None if raw_range is None else tuple(raw_range)
        if constant is not None and interval is None and cell[1] == WORD_BYTES:
            signed = _signed24(constant)
            interval = (signed, signed)
        result[cell] = {
            "constant": constant,
            "range": interval,
            "origin": f"callee-return@{summary['entry']:05X}",
        }
    return result


def _transfer_value(node, incoming, cells, operation, summaries, cells_by_id):
    outgoing = _copy_state(incoming, cells)
    if node["base_mnemonic"] == "JSUB":
        return _apply_call_value_effect(
            outgoing,
            summaries.get(node.get("target")),
            cells,
            cells_by_id,
        )
    if operation.get("unknown_write") or operation.get("barrier"):
        outgoing = _empty_state(cells)
    write = operation.get("write")
    if write is not None:
        value = _register_store_value(node, write)
        for cell in cells:
            if not _ranges_overlap(cell, write):
                continue
            outgoing[cell] = value if cell == write else _unknown_value()
    return outgoing


def analyze_memory_values(nodes, edges, entry_address, seeds, summary_hints=None):
    """Compute must memory constants/ranges independently of reaching-store IDs."""
    by_address = {node["address"]: node for node in nodes}
    cells, operations = _tracked_cells(nodes)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    structural = summarize_memory_effects(nodes, edges, cells, operations)
    summaries = _summary_by_entry(structural, summary_hints)
    predecessors = _predecessors(nodes, edges)
    entries = _function_entries(nodes, edges, entry_address)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}

    for function_entry in entries:
        state = _empty_state(cells)
        if function_entry == entry_address:
            for cell, value in seeds.items():
                if cell in state:
                    state[cell] = _copy_value(value)
        incoming[function_entry] = _join_state(incoming[function_entry], state, cells)

    ordered = sorted(by_address)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            candidate = incoming[address]
            for predecessor in predecessors[address]:
                predecessor_state = outgoing.get(predecessor)
                if predecessor_state is not None:
                    candidate = _join_state(candidate, predecessor_state, cells)
            if candidate is None:
                continue
            state_out = _transfer_value(
                by_address[address],
                candidate,
                cells,
                operations[address],
                summaries,
                cells_by_id,
            )
            if incoming[address] is None or not _state_equal(incoming[address], candidate, cells):
                incoming[address] = candidate
                changed = True
            if outgoing[address] is None or not _state_equal(outgoing[address], state_out, cells):
                outgoing[address] = state_out
                changed = True

    instruction_facts = {}
    for address in ordered:
        operation = operations[address]
        read = operation.get("read")
        value = None
        if read is not None and incoming[address] is not None:
            value = incoming[address].get(read)
        instruction_facts[address] = {
            "memory_read": None if read is None else _cell_id(read),
            "constant": None if value is None else value.get("constant"),
            "range": None if value is None or value.get("range") is None else list(value["range"]),
            "origin": None if value is None else value.get("origin"),
        }

    return {
        "cells": cells,
        "operations": operations,
        "incoming": incoming,
        "outgoing": outgoing,
        "instruction_facts": instruction_facts,
        "structural_summaries": structural,
    }


def derive_return_postconditions(value_analysis):
    cells = value_analysis["cells"]
    outgoing = value_analysis["outgoing"]
    result = {}
    for entry, summary in value_analysis["structural_summaries"].items():
        returns = list(summary.get("return_sites") or ())
        constants = {}
        ranges = {}
        if returns:
            for cell in cells:
                values = [
                    (outgoing.get(site) or {}).get(cell)
                    for site in returns
                ]
                if any(value is None for value in values):
                    continue
                exact_values = [value.get("constant") for value in values]
                if (
                    exact_values
                    and exact_values[0] is not None
                    and all(value == exact_values[0] for value in exact_values)
                ):
                    constants[_cell_id(cell)] = exact_values[0]
                intervals = [value.get("range") for value in values]
                if intervals and all(interval is not None for interval in intervals):
                    ranges[_cell_id(cell)] = [
                        min(interval[0] for interval in intervals),
                        max(interval[1] for interval in intervals),
                    ]
        enriched = dict(summary)
        enriched["return_constants"] = constants
        enriched["return_ranges"] = ranges
        enriched["return_value_cells"] = sorted(set(constants) | set(ranges))
        result[entry] = enriched
    return result


def _attach_value_facts(nodes, value_analysis):
    """Publish must-value facts and explicitly revoke facts that widened away."""
    for node in nodes:
        facts = value_analysis["instruction_facts"].get(node["address"], {})
        if facts.get("memory_read") is None:
            node.pop("memory_value_resolution", None)
            continue

        constant = facts.get("constant")
        raw_range = facts.get("range")
        node["memory_constant"] = constant
        node["memory_range"] = None if raw_range is None else list(raw_range)
        node["memory_value_resolution"] = facts.get("origin") or "abstract-memory-value"

        destination = LOAD_DESTINATION_REGISTERS.get(node["base_mnemonic"])
        if destination is None:
            node["loaded_register_constant"] = None
            node["loaded_register_range"] = None
            continue
        node["loaded_register_constant"] = (
            None
            if constant is None
            else {"register": destination, "value": constant & REGISTER_MASK}
        )
        node["loaded_register_range"] = (
            None
            if raw_range is None
            else {"register": destination, "range": list(raw_range)}
        )


def _clear_memory_base_resolution(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution") in MEMORY_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _resolve_memory_base_targets(nodes, exact_facts, range_facts):
    changed = False
    for node in nodes:
        flags = node.get("flags") or ""
        if len(flags) != 6 or flags[3] != "1" or flags[4] != "0" or flags[5] != "0":
            continue
        if node.get("target_resolution") in CORE_BASE_RESOLUTIONS:
            continue
        exact_in = (exact_facts.get(node["address"]) or {}).get("in")
        range_in = (range_facts.get(node["address"]) or {}).get("in")
        base_value = None if exact_in is None else exact_in.get("B")
        resolution = None
        if base_value is not None:
            resolution = "memory-feedback-base"
        elif range_in is not None:
            interval = range_in.get("B")
            if interval is not None and interval[0] == interval[1]:
                base_value = interval[0] & REGISTER_MASK
                resolution = "memory-feedback-range-base"
        if base_value is None:
            if node.get("target_resolution") in MEMORY_BASE_RESOLUTIONS:
                changed = _clear_memory_base_resolution(node) or changed
            continue
        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base_value,
        )
        if decoded.target is None:
            if node.get("target_resolution") in MEMORY_BASE_RESOLUTIONS:
                changed = _clear_memory_base_resolution(node) or changed
            continue
        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base_value
            or node.get("target_resolution") != resolution
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            node["base_value"] = base_value
            node["target_resolution"] = resolution
            changed = True
    return changed


def _rebuild_edges(nodes):
    edges = _core._instruction_edges(nodes)
    summaries = summarize_subroutines(nodes, edges)
    _core._add_interprocedural_return_edges(nodes, edges, summaries)
    return edges


def _signature(nodes, edges, summaries, value_analysis):
    return (
        tuple(
            (
                node["address"],
                repr(node.get("registers_in")),
                repr(node.get("registers_out")),
                repr(node.get("ranges_in")),
                repr(node.get("ranges_out")),
                node.get("memory_constant"),
                repr(node.get("memory_range")),
                node.get("memory_value_resolution"),
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
        tuple(
            (
                entry,
                tuple(sorted(summary.get("return_constants", {}).items())),
                tuple(
                    sorted(
                        (key, tuple(value))
                        for key, value in summary.get("return_ranges", {}).items()
                    )
                ),
            )
            for entry, summary in sorted(summaries.items())
        ),
        tuple(
            (
                address,
                fact.get("constant"),
                repr(fact.get("range")),
                fact.get("origin"),
            )
            for address, fact in sorted(value_analysis["instruction_facts"].items())
        ),
    )


def refine_initialized_memory_postconditions(
    nodes,
    edges,
    entry_address,
    image,
    image_start,
    debug_map,
    base_register=None,
):
    """Close initialized-memory, callee-return, register/range and CFG feedback."""
    initial_registers = {} if base_register is None else {"B": base_register}
    summary_hints = {}
    previous = None
    max_iterations = max(5, len(nodes) + 5)

    for iteration in range(1, max_iterations + 1):
        cells, _ = _tracked_cells(nodes)
        seeds = seed_initialized_memory(image, image_start, debug_map, cells)
        value_analysis = analyze_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            summary_hints=summary_hints,
        )
        summaries = derive_return_postconditions(value_analysis)
        _attach_value_facts(nodes, value_analysis)

        exact = analyze_memory_aware_constants(
            nodes,
            edges,
            entry_address,
            initial_registers=initial_registers,
        )
        ranges = analyze_memory_aware_ranges(
            nodes,
            edges,
            entry_address,
            initial_registers=initial_registers,
        )
        for node in nodes:
            node["registers_in"] = exact[node["address"]]["in"]
            node["registers_out"] = exact[node["address"]]["out"]
            node["ranges_in"] = ranges[node["address"]]["in"]
            node["ranges_out"] = ranges[node["address"]]["out"]

        if _resolve_memory_base_targets(nodes, exact, ranges):
            edges[:] = _rebuild_edges(nodes)
            summary_hints = summaries
            previous = None
            continue

        signature = _signature(nodes, edges, summaries, value_analysis)
        if signature == previous:
            exact_resolutions = sum(
                1
                for node in nodes
                if node.get("target_resolution") == "memory-feedback-base"
            )
            range_resolutions = sum(
                1
                for node in nodes
                if node.get("target_resolution") == "memory-feedback-range-base"
            )
            return {
                "iterations": iteration,
                "converged": True,
                "seeds": [seeds[cell] for cell in sorted(seeds)],
                "summaries": [summaries[key] for key in sorted(summaries)],
                "summary_map": summaries,
                "value_analysis": value_analysis,
                "memory_base_resolutions": exact_resolutions,
                "memory_range_base_resolutions": range_resolutions,
            }
        previous = signature
        summary_hints = summaries

    raise MemoryPostconditionError(
        "Initialized-memory/postcondition analysis did not converge"
    )


def attach_final_value_facts(nodes, refinement):
    value_analysis = refinement.get("value_analysis")
    if value_analysis is not None:
        _attach_value_facts(nodes, value_analysis)
