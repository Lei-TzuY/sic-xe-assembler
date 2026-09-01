from disassembler import decode_instruction
from memory_analysis import STORE_SOURCE_REGISTERS, WORD_BYTES, _cell_id, _ranges_overlap
from memory_feedback import _tracked_cells, summarize_memory_effects
from memory_postconditions import (
    _attach_value_facts,
    _copy_state as _copy_value_state,
    _empty_state as _empty_value_state,
    _join_state as _join_value_state,
    _register_store_value,
    _state_equal as _value_state_equal,
    _unknown_value,
    seed_initialized_memory,
)
from sparse_linear_transfers import (
    SPARSE_LINEAR_BASE_RESOLUTIONS,
    _add_expr,
    _apply_symbolic_summary,
    _base_relative,
    _const,
    _copy_exact_state,
    _copy_range_state,
    _copy_symbolic,
    _deserialize,
    _evaluate_exact,
    _evaluate_range,
    _exact_edge_feasible,
    _global_exact,
    _global_ranges,
    _input_registers,
    _join_symbolic,
    _range_edge_feasible,
    _rebuild_edges,
    _serialize,
    _signed24,
    _substitute,
    _symbolic_entry_state,
    _symbolic_equal,
    _symbolic_transfer,
)
from static_analysis import CONDITION_VALUES, CONDITIONAL_MNEMONICS, REGISTER_MASK, TRACKED_REGISTERS


SYMBOLIC_MEMORY_BASE_RESOLUTIONS = {
    "symbolic-memory-base",
    "symbolic-memory-range-base",
}
SYMBOLIC_MEMORY_CONDITION_RESOLUTIONS = {
    "symbolic-memory-condition",
    "symbolic-memory-range-condition",
}


class SymbolicMemoryTransferError(ValueError):
    pass


def _empty_symbolic_memory(cells):
    return {cell: None for cell in cells}


def _copy_symbolic_memory(state, cells):
    return {cell: state.get(cell) for cell in cells}


def _join_symbolic_memory(left, right, cells):
    if left is None:
        return _copy_symbolic_memory(right, cells)
    return {
        cell: left.get(cell)
        if left.get(cell) is not None and left.get(cell) == right.get(cell)
        else None
        for cell in cells
    }


def _symbolic_memory_equal(left, right, cells):
    if left is None or right is None:
        return left is right
    return all(left.get(cell) == right.get(cell) for cell in cells)


def _intraprocedural_outgoing(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)
    return by_address, outgoing


def _merge_summary_layers(memory_structural, register_summaries, memory_summaries, hints):
    result = {}
    for entry, structural in memory_structural.items():
        merged = dict(structural)
        register = (register_summaries or {}).get(entry) or {}
        memory = (memory_summaries or {}).get(entry) or {}
        hint = (hints or {}).get(entry) or {}
        for key in (
            "may_return",
            "link_register_preserved",
            "preserved",
            "may_clobber",
            "return_sites",
        ):
            if key in register:
                merged[key] = register[key]
        merged["return_constants"] = dict(memory.get("return_constants") or {})
        merged["return_ranges"] = {
            key: list(value)
            for key, value in (memory.get("return_ranges") or {}).items()
        }
        merged["return_linear_transfers"] = dict(
            register.get("return_linear_transfers") or {}
        )
        merged["return_memory_linear_transfers"] = dict(
            hint.get("return_memory_linear_transfers") or {}
        )
        result[entry] = merged
    return result


def _apply_symbolic_memory_summary(memory_state, register_inputs, summary, cells, cells_by_id):
    result = _copy_symbolic_memory(memory_state, cells)
    if summary is None or not summary.get("may_return"):
        return _empty_symbolic_memory(cells)

    if summary.get("unknown_write"):
        result = _empty_symbolic_memory(cells)
    else:
        for cell_id in summary.get("may_write_cells") or ():
            cell = cells_by_id.get(cell_id)
            if cell is not None:
                result[cell] = None

    # Existing caller-independent constant postconditions remain useful when
    # composing a larger symbolic function summary.
    for cell_id, value in (summary.get("return_constants") or {}).items():
        cell = cells_by_id.get(cell_id)
        if cell is not None:
            result[cell] = _const(value)

    if not summary.get("link_register_preserved"):
        return result

    for cell_id, spec in (summary.get("return_memory_linear_transfers") or {}).items():
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        result[cell] = _substitute(_deserialize(spec), register_inputs)
    return result


def _symbolic_memory_instruction_transfer(node, incoming_registers, incoming_memory, cells, operation):
    outgoing = _copy_symbolic_memory(incoming_memory, cells)
    if node["base_mnemonic"] == "JSUB":
        return outgoing

    if operation.get("unknown_write") or operation.get("barrier"):
        outgoing = _empty_symbolic_memory(cells)

    write = operation.get("write")
    if write is None:
        return outgoing

    source_register = STORE_SOURCE_REGISTERS.get(node["base_mnemonic"])
    source_expression = (
        None if source_register is None else incoming_registers.get(source_register)
    )
    for cell in cells:
        if not _ranges_overlap(cell, write):
            continue
        outgoing[cell] = None
        if cell != write or source_expression is None:
            continue
        if cell[1] == WORD_BYTES:
            outgoing[cell] = source_expression
        elif node["base_mnemonic"] == "STCH" and not source_expression[0]:
            outgoing[cell] = _const(source_expression[1] & 0xFF)
    return outgoing


def _analyze_function_symbolic_memory(nodes, edges, entry, summaries, cells, operations):
    by_address, outgoing_edges = _intraprocedural_outgoing(nodes, edges)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    register_in = {address: None for address in by_address}
    register_out = {address: None for address in by_address}
    memory_in = {address: None for address in by_address}
    memory_out = {address: None for address in by_address}
    if entry not in by_address:
        return register_out, memory_out

    register_in[entry] = _symbolic_entry_state()
    memory_in[entry] = _empty_symbolic_memory(cells)
    pending = [entry]
    queued = {entry}

    while pending:
        address = pending.pop(0)
        queued.discard(address)
        registers = register_in[address]
        memory = memory_in[address]
        if registers is None or memory is None:
            continue
        node = by_address[address]
        registers_after = _symbolic_transfer(node, registers)
        memory_after = _symbolic_memory_instruction_transfer(
            node,
            registers,
            memory,
            cells,
            operations[address],
        )
        register_out[address] = registers_after
        memory_out[address] = memory_after

        for edge in outgoing_edges.get(address, ()):
            candidate_registers = _copy_symbolic(registers_after)
            candidate_memory = _copy_symbolic_memory(memory_after, cells)
            if node["base_mnemonic"] == "JSUB" and edge.get("kind") == "fallthrough":
                summary = summaries.get(node.get("target"))
                candidate_memory = _apply_symbolic_memory_summary(
                    candidate_memory,
                    candidate_registers,
                    summary,
                    cells,
                    cells_by_id,
                )
                candidate_registers = _apply_symbolic_summary(
                    candidate_registers,
                    summary,
                )

            target = edge["target"]
            merged_registers = _join_symbolic(
                register_in[target],
                candidate_registers,
            )
            merged_memory = _join_symbolic_memory(
                memory_in[target],
                candidate_memory,
                cells,
            )
            changed = (
                not _symbolic_equal(register_in[target], merged_registers)
                or not _symbolic_memory_equal(memory_in[target], merged_memory, cells)
            )
            if changed:
                register_in[target] = merged_registers
                memory_in[target] = merged_memory
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return register_out, memory_out


def _derive_memory_symbolic_summary(shape, memory_out, cells):
    summary = dict(shape)
    returns = list(summary.get("return_sites") or ())
    transfers = {}
    if returns and all(memory_out.get(site) is not None for site in returns):
        for cell in cells:
            expressions = [memory_out[site].get(cell) for site in returns]
            if expressions[0] is None or any(expr != expressions[0] for expr in expressions):
                continue
            expression = expressions[0]
            if not expression[0]:
                continue
            transfers[_cell_id(cell)] = _serialize(expression)

    summary["return_memory_linear_transfers"] = transfers
    summary["memory_linear_input_registers"] = sorted({
        register
        for spec in transfers.values()
        for register in _input_registers(spec)
    })
    summary["symbolic_memory_return_cells"] = sorted(transfers)
    summary["multivariate_memory_return_cells"] = sorted(
        cell_id
        for cell_id, spec in transfers.items()
        if spec.get("kind") == "linear"
    )
    return summary


def _memory_transfer_signature(summaries):
    return tuple(
        (
            entry,
            tuple(
                (
                    cell_id,
                    spec.get("kind"),
                    tuple(sorted((spec.get("coefficients") or {}).items())),
                    spec.get("source"),
                    spec.get("scale"),
                    spec.get("offset"),
                )
                for cell_id, spec in sorted(
                    summary.get("return_memory_linear_transfers", {}).items()
                )
            ),
        )
        for entry, summary in sorted(summaries.items())
    )


def infer_symbolic_memory_return_transfers(
    nodes,
    edges,
    register_summaries=None,
    memory_summaries=None,
):
    """Infer caller-independent register-linear formulas for returned memory cells."""
    cells, operations = _tracked_cells(nodes)
    structural = summarize_memory_effects(nodes, edges, cells, operations)
    hints = {}
    previous = None
    max_iterations = max(4, len(structural) * 2 + 4)

    for iteration in range(1, max_iterations + 1):
        available = _merge_summary_layers(
            structural,
            register_summaries,
            memory_summaries,
            hints,
        )
        derived = {}
        for entry, shape in available.items():
            _, memory_out = _analyze_function_symbolic_memory(
                nodes,
                edges,
                entry,
                available,
                cells,
                operations,
            )
            symbolic = _derive_memory_symbolic_summary(shape, memory_out, cells)
            derived[entry] = symbolic
        signature = _memory_transfer_signature(derived)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "cells": cells,
                "summary_map": derived,
                "summaries": [derived[key] for key in sorted(derived)],
            }
        previous = signature
        hints = derived

    raise SymbolicMemoryTransferError(
        "Symbolic memory return-transfer inference did not converge"
    )


def _instantiate_calls(nodes, summaries, exact_out, range_out):
    result = {}
    for node in nodes:
        if node["base_mnemonic"] != "JSUB":
            continue
        summary = summaries.get(node.get("target"))
        if summary is None or not summary.get("link_register_preserved"):
            node.pop("symbolic_memory_instantiation", None)
            continue
        exact_inputs = exact_out.get(node["address"])
        range_inputs = range_out.get(node["address"])
        exact = {}
        ranges = {}
        for cell_id, spec in (
            summary.get("return_memory_linear_transfers") or {}
        ).items():
            value = None if exact_inputs is None else _evaluate_exact(spec, exact_inputs)
            interval = None if range_inputs is None else _evaluate_range(spec, range_inputs)
            if value is not None:
                exact[cell_id] = value
            if interval is not None:
                ranges[cell_id] = list(interval)
        item = {
            "callee_entry": node.get("target"),
            "exact": exact,
            "ranges": ranges,
            "transfers": dict(summary.get("return_memory_linear_transfers") or {}),
        }
        node["symbolic_memory_instantiation"] = item
        result[node["address"]] = item
    return result


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


def _apply_concrete_call_memory(outgoing, summary, instantiation, cells, cells_by_id):
    result = _copy_value_state(outgoing, cells)
    if summary is None or not summary.get("may_return"):
        return _empty_value_state(cells)

    if summary.get("unknown_write"):
        result = _empty_value_state(cells)
    else:
        for cell_id in summary.get("may_write_cells") or ():
            cell = cells_by_id.get(cell_id)
            if cell is not None:
                result[cell] = _unknown_value()

    for cell_id in set(summary.get("may_write_cells") or ()) | set(
        (summary.get("return_constants") or {}).keys()
    ) | set((summary.get("return_ranges") or {}).keys()):
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        constant = (summary.get("return_constants") or {}).get(cell_id)
        raw_range = (summary.get("return_ranges") or {}).get(cell_id)
        if constant is None and raw_range is None:
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

    if not summary.get("link_register_preserved") or instantiation is None:
        return result

    exact = instantiation.get("exact") or {}
    ranges = instantiation.get("ranges") or {}
    for cell_id in set(exact) | set(ranges):
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        constant = exact.get(cell_id)
        raw_range = ranges.get(cell_id)
        interval = None if raw_range is None else tuple(raw_range)
        if constant is not None and interval is None and cell[1] == WORD_BYTES:
            signed = _signed24(constant)
            interval = (signed, signed)
        result[cell] = {
            "constant": constant,
            "range": interval,
            "origin": f"symbolic-callee-return@{summary['entry']:05X}",
        }
    return result


def _transfer_concrete_memory(
    node,
    incoming,
    cells,
    operation,
    summaries,
    instantiations,
    cells_by_id,
):
    outgoing = _copy_value_state(incoming, cells)
    if node["base_mnemonic"] == "JSUB":
        return _apply_concrete_call_memory(
            outgoing,
            summaries.get(node.get("target")),
            instantiations.get(node["address"]),
            cells,
            cells_by_id,
        )

    if operation.get("unknown_write") or operation.get("barrier"):
        outgoing = _empty_value_state(cells)

    write = operation.get("write")
    if write is not None:
        value = _register_store_value(node, write)
        for cell in cells:
            if not _ranges_overlap(cell, write):
                continue
            outgoing[cell] = value if cell == write else _unknown_value()
    return outgoing


def analyze_callsite_memory_values(
    nodes,
    edges,
    entry_address,
    seeds,
    summaries,
    instantiations,
):
    """Compute concrete must memory values with call-site-specific postconditions."""
    by_address = {node["address"]: node for node in nodes}
    cells, operations = _tracked_cells(nodes)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    predecessors = _predecessors(nodes, edges)
    entries = _function_entries(nodes, edges, entry_address)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}

    for function_entry in entries:
        state = _empty_value_state(cells)
        if function_entry == entry_address:
            for cell, value in seeds.items():
                if cell in state:
                    state[cell] = dict(value)
        incoming[function_entry] = _join_value_state(
            incoming[function_entry],
            state,
            cells,
        )

    changed = True
    ordered = sorted(by_address)
    while changed:
        changed = False
        for address in ordered:
            candidate = incoming[address]
            for predecessor in predecessors[address]:
                predecessor_state = outgoing.get(predecessor)
                if predecessor_state is not None:
                    candidate = _join_value_state(candidate, predecessor_state, cells)
            if candidate is None:
                continue
            state_out = _transfer_concrete_memory(
                by_address[address],
                candidate,
                cells,
                operations[address],
                summaries,
                instantiations,
                cells_by_id,
            )
            if incoming[address] is None or not _value_state_equal(
                incoming[address], candidate, cells
            ):
                incoming[address] = candidate
                changed = True
            if outgoing[address] is None or not _value_state_equal(
                outgoing[address], state_out, cells
            ):
                outgoing[address] = state_out
                changed = True

    instruction_facts = {}
    for address in ordered:
        read = operations[address].get("read")
        value = None
        if read is not None and incoming[address] is not None:
            value = incoming[address].get(read)
        instruction_facts[address] = {
            "memory_read": None if read is None else _cell_id(read),
            "constant": None if value is None else value.get("constant"),
            "range": (
                None
                if value is None or value.get("range") is None
                else list(value["range"])
            ),
            "origin": None if value is None else value.get("origin"),
        }

    return {
        "cells": cells,
        "operations": operations,
        "incoming": incoming,
        "outgoing": outgoing,
        "instruction_facts": instruction_facts,
    }


def _clear_symbolic_memory_base(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution") in SYMBOLIC_MEMORY_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _resolve_symbolic_memory_base_targets(nodes, exact_in, range_in):
    changed = False
    for node in nodes:
        if not _base_relative(node):
            continue
        resolution = node.get("target_resolution")
        if resolution is not None and resolution not in (
            SYMBOLIC_MEMORY_BASE_RESOLUTIONS | SPARSE_LINEAR_BASE_RESOLUTIONS
        ):
            continue
        exact_state = exact_in.get(node["address"])
        range_state = range_in.get(node["address"])
        base = None if exact_state is None else exact_state.get("B")
        new_resolution = None
        if base is not None:
            new_resolution = "symbolic-memory-base"
        elif range_state is not None:
            interval = range_state.get("B")
            if interval is not None and interval[0] == interval[1]:
                base = interval[0] & REGISTER_MASK
                new_resolution = "symbolic-memory-range-base"
        if base is None:
            if resolution in SYMBOLIC_MEMORY_BASE_RESOLUTIONS:
                changed = _clear_symbolic_memory_base(node) or changed
            continue
        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base,
        )
        if decoded.target is None:
            if resolution in SYMBOLIC_MEMORY_BASE_RESOLUTIONS:
                changed = _clear_symbolic_memory_base(node) or changed
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


def _mark_symbolic_memory_impossible_edges(nodes, edges, exact_out, range_out):
    by_address = {node["address"]: node for node in nodes}
    for edge in edges:
        if not edge.get("resolved") or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        node = by_address.get(edge.get("source"))
        if node is None or node["base_mnemonic"] not in CONDITIONAL_MNEMONICS:
            continue
        exact_state = exact_out.get(node["address"])
        if exact_state is not None and exact_state.get("CC") in CONDITION_VALUES:
            if not _exact_edge_feasible(node, edge, exact_state):
                edge["resolved"] = False
                edge["feasible"] = False
                edge["reason"] = "condition-false"
                edge["resolution"] = "symbolic-memory-condition"
                continue
        range_state = range_out.get(node["address"])
        if range_state is not None and range_state.get("CC") is not None:
            if not _range_edge_feasible(node, edge, range_state):
                edge["resolved"] = False
                edge["feasible"] = False
                edge["reason"] = "condition-false"
                edge["resolution"] = "symbolic-memory-range-condition"


def _refinement_signature(nodes, edges, summaries, instantiations, value_analysis):
    return (
        _memory_transfer_signature(summaries),
        tuple(
            (
                address,
                tuple(sorted((item.get("exact") or {}).items())),
                tuple(
                    sorted(
                        (key, tuple(value))
                        for key, value in (item.get("ranges") or {}).items()
                    )
                ),
            )
            for address, item in sorted(instantiations.items())
        ),
        tuple(
            (
                node["address"],
                repr(node.get("registers_in")),
                repr(node.get("ranges_in")),
                node.get("memory_constant"),
                repr(node.get("memory_range")),
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
                address,
                fact.get("constant"),
                repr(fact.get("range")),
                fact.get("origin"),
            )
            for address, fact in sorted(value_analysis["instruction_facts"].items())
        ),
    )


def refine_symbolic_memory_transfers(
    nodes,
    edges,
    entry_address,
    image,
    image_start,
    debug_map,
    register_summaries=None,
    memory_summaries=None,
    base_register=None,
):
    """Instantiate symbolic memory postconditions and close memory/register/CFG feedback."""
    initial_registers = {} if base_register is None else {"B": base_register}
    previous = None
    max_iterations = max(5, len(nodes) + 5)
    exact_in = {node["address"]: node.get("registers_in") for node in nodes}
    exact_out = {node["address"]: node.get("registers_out") for node in nodes}
    range_in = {node["address"]: node.get("ranges_in") for node in nodes}
    range_out = {node["address"]: node.get("ranges_out") for node in nodes}

    for iteration in range(1, max_iterations + 1):
        inferred = infer_symbolic_memory_return_transfers(
            nodes,
            edges,
            register_summaries=register_summaries,
            memory_summaries=memory_summaries,
        )
        summaries = inferred["summary_map"]
        instantiations = _instantiate_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
        )
        cells, _ = _tracked_cells(nodes)
        seeds = seed_initialized_memory(image, image_start, debug_map, cells)
        value_analysis = analyze_callsite_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            summaries,
            instantiations,
        )
        _attach_value_facts(nodes, value_analysis)

        exact_in, exact_out = _global_exact(
            nodes,
            edges,
            entry_address,
            register_summaries or {},
            initial_registers,
        )
        range_in, range_out = _global_ranges(
            nodes,
            edges,
            entry_address,
            register_summaries or {},
            initial_registers,
        )
        for node in nodes:
            node["registers_in"] = (
                None
                if exact_in[node["address"]] is None
                else _copy_exact_state(exact_in[node["address"]])
            )
            node["registers_out"] = (
                None
                if exact_out[node["address"]] is None
                else _copy_exact_state(exact_out[node["address"]])
            )
            node["ranges_in"] = (
                None
                if range_in[node["address"]] is None
                else _copy_range_state(range_in[node["address"]])
            )
            node["ranges_out"] = (
                None
                if range_out[node["address"]] is None
                else _copy_range_state(range_out[node["address"]])
            )
            if node["base_mnemonic"] == "JSUB":
                node["symbolic_memory_transfer_summary"] = summaries.get(
                    node.get("target")
                )

        if _resolve_symbolic_memory_base_targets(nodes, exact_in, range_in):
            edges[:] = _rebuild_edges(nodes)
            previous = None
            continue

        _mark_symbolic_memory_impossible_edges(
            nodes,
            edges,
            exact_out,
            range_out,
        )
        final_instantiations = _instantiate_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
        )
        signature = _refinement_signature(
            nodes,
            edges,
            summaries,
            final_instantiations,
            value_analysis,
        )
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summaries": [summaries[key] for key in sorted(summaries)],
                "summary_map": summaries,
                "instantiations": final_instantiations,
                "value_analysis": value_analysis,
                "seeds": [seeds[cell] for cell in sorted(seeds)],
                "base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution") == "symbolic-memory-base"
                ),
                "range_base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution") == "symbolic-memory-range-base"
                ),
                "multivariate_transfers": sum(
                    len(summary.get("multivariate_memory_return_cells") or ())
                    for summary in summaries.values()
                ),
            }
        previous = signature

    raise SymbolicMemoryTransferError(
        "Symbolic memory transfer/CFG refinement did not converge"
    )
