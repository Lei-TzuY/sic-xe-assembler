import guarded_transfer_refinement as _base
import symbolic_memory_inputs as _inputs
from static_analysis import CONDITION_VALUES, TRACKED_REGISTERS, summarize_subroutines


CONDITION_WRITERS_UNKNOWN = {"TD", "COMPF", "TIX", "TIXR", "LPS", "SVC"}


def _condition_signature(values):
    if values is None:
        return None
    return tuple(value for value in CONDITION_VALUES if value in values)


def _case_signature(case):
    return (
        _base._case_signature(case),
        _condition_signature(case.get("condition_values")),
    )


def _summary_signature(summaries):
    return tuple(
        (
            entry,
            bool(summary.get("guarded_supported")),
            summary.get("guarded_reason"),
            tuple(summary.get("register_contract_registers") or ()),
            tuple(summary.get("memory_contract_cells") or ()),
            tuple(_case_signature(case) for case in summary.get("guarded_cases", ())),
        )
        for entry, summary in sorted(summaries.items())
    )


def _condition_after_instruction(node, comparison, conditions, registers, memory, operation):
    mnemonic = node["base_mnemonic"]
    if mnemonic in ("COMP", "COMPR"):
        comparison = _base._legacy._comparison_expression(
            node,
            registers,
            memory,
            operation,
        )
        return (
            comparison,
            tuple(CONDITION_VALUES) if comparison is not None else None,
        )
    if mnemonic in CONDITION_WRITERS_UNKNOWN:
        return None, None
    return comparison, conditions


def _condition_after_summary(summary):
    if summary is None or not summary.get("link_register_preserved"):
        return None
    values = tuple(summary.get("return_conditions") or ())
    if not values:
        return None
    return _condition_signature(values)


def _compose_guarded_callee(
    node,
    registers,
    memory,
    guards,
    nested_trace,
    summary,
    cells,
    cells_by_id,
):
    if (
        summary is None
        or not summary.get("guarded_supported")
        or not summary.get("link_register_preserved")
        or not summary.get("guarded_cases")
    ):
        return None

    expansions = []
    for case in summary.get("guarded_cases") or ():
        composed_guards = list(_base._legacy._copy_guards(guards))
        for guard in case.get("guards", ()):
            substituted = _base._substitute_guard(
                guard,
                registers,
                memory,
                cells,
            )
            if substituted is None:
                return None
            composed_guards.append(substituted)

        result_registers, result_memory = _base._apply_guarded_case(
            registers,
            memory,
            summary,
            case,
            cells,
            cells_by_id,
        )
        trace = list(nested_trace)
        trace.append(
            {
                "call_source": node["address"],
                "callee_entry": node.get("target"),
                "case_id": case.get("id"),
            }
        )
        expansions.append(
            (
                result_registers,
                result_memory,
                tuple(composed_guards),
                tuple(trace),
                _condition_signature(case.get("condition_values")),
            )
        )
    return expansions


def _unsupported(reason, contract_registers, contract_cells, composed_calls, explored=0):
    return {
        "supported": False,
        "reason": reason,
        "cases": [],
        "register_contract_registers": list(contract_registers),
        "memory_contract_cells": list(contract_cells),
        "nested_composed_calls": len(composed_calls),
        "explored_states": explored,
    }


def _analyze_guarded_function(nodes, structural_edges, summary, summaries):
    cells, operations = _base._legacy._tracked_cells(nodes)
    cells_by_id = {
        _base._cell_id(cell): cell
        for cell in cells
    }
    contract_registers = _base._register_contract_registers(summary)
    contract_cells = _base._memory_contract_cells(summary, cells)
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in structural_edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)

    entry = summary.get("entry")
    return_sites = set(summary.get("return_sites") or ())
    if entry not in by_address or not return_sites:
        return _unsupported(
            "no-return-shape",
            contract_registers,
            contract_cells,
            set(),
        )

    queue = [
        {
            "address": entry,
            "registers": _base._legacy._entry_registers(),
            "memory": _base._legacy._entry_memory(cells),
            "comparison": None,
            "conditions": None,
            "guards": (),
            "nested_trace": (),
            "visited": frozenset(),
        }
    ]
    raw_cases = []
    explored = 0
    composed_calls = set()

    while queue:
        if explored >= _base._legacy.MAX_PATH_STATES:
            return _unsupported(
                "path-budget",
                contract_registers,
                contract_cells,
                composed_calls,
                explored,
            )

        state = queue.pop(0)
        explored += 1
        address = state["address"]
        if address in state["visited"]:
            return _unsupported(
                "loop-or-revisit",
                contract_registers,
                contract_cells,
                composed_calls,
                explored,
            )

        node = by_address[address]
        registers = state["registers"]
        memory = state["memory"]
        operation = operations[address]
        comparison, conditions = _condition_after_instruction(
            node,
            state["comparison"],
            state["conditions"],
            registers,
            memory,
            operation,
        )

        registers_after = _base._legacy._hybrid_register_transfer(
            node,
            registers,
            memory,
            operation,
        )
        memory_after = _base._legacy._hybrid_memory_transfer(
            node,
            registers,
            memory,
            cells,
            operation,
        )

        if address in return_sites:
            register_outputs, memory_outputs = _base._path_outputs(
                registers_after,
                memory_after,
                contract_registers,
                contract_cells,
                cells_by_id,
            )
            raw_cases.append(
                {
                    "return_site": address,
                    "guards": [dict(item) for item in state["guards"]],
                    "register_outputs": register_outputs,
                    "memory_outputs": memory_outputs,
                    "condition_values": (
                        None
                        if conditions is None
                        else list(_condition_signature(conditions))
                    ),
                    "nested_cases": [
                        dict(item) for item in state["nested_trace"]
                    ],
                }
            )
            if len(raw_cases) > _base._legacy.MAX_GUARDED_CASES:
                return _unsupported(
                    "case-budget",
                    contract_registers,
                    contract_cells,
                    composed_calls,
                    explored,
                )
            continue

        edges = outgoing.get(address, ())
        conditional = node["base_mnemonic"] in _base._legacy.CONDITIONAL_MNEMONICS
        if conditional and comparison is None and conditions is None:
            return _unsupported(
                "unguarded-condition",
                contract_registers,
                contract_cells,
                composed_calls,
                explored,
            )

        for edge in edges:
            candidate_registers = _base._legacy._copy_symbolic_registers(
                registers_after
            )
            candidate_memory = _base._legacy._copy_symbolic_memory(
                memory_after,
                cells,
            )
            candidate_comparison = comparison
            candidate_conditions = conditions
            candidate_guards = list(
                _base._legacy._copy_guards(state["guards"])
            )
            candidate_trace = tuple(state["nested_trace"])

            if conditional:
                allowed = _base._legacy._edge_allowed_conditions(
                    node["base_mnemonic"],
                    edge.get("kind"),
                )
                if not allowed:
                    continue
                if candidate_conditions is not None:
                    narrowed = tuple(
                        value
                        for value in CONDITION_VALUES
                        if value in candidate_conditions and value in allowed
                    )
                    if not narrowed:
                        continue
                    candidate_conditions = narrowed
                if candidate_comparison is not None:
                    guard = _base._legacy._serialize_guard(
                        candidate_comparison,
                        allowed,
                    )
                    if guard is None:
                        return _unsupported(
                            "unguarded-edge",
                            contract_registers,
                            contract_cells,
                            composed_calls,
                            explored,
                        )
                    candidate_guards.append(guard)

            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                callee = summaries.get(node.get("target"))
                expansions = _compose_guarded_callee(
                    node,
                    candidate_registers,
                    candidate_memory,
                    candidate_guards,
                    candidate_trace,
                    callee,
                    cells,
                    cells_by_id,
                )
                if expansions is not None:
                    composed_calls.add(address)
                    for (
                        nested_registers,
                        nested_memory,
                        nested_guards,
                        nested_case_trace,
                        nested_conditions,
                    ) in expansions:
                        queue.append(
                            {
                                "address": edge["target"],
                                "registers": nested_registers,
                                "memory": nested_memory,
                                "comparison": None,
                                "conditions": nested_conditions,
                                "guards": nested_guards,
                                "nested_trace": nested_case_trace,
                                "visited": state["visited"] | {address},
                            }
                        )
                    continue

                candidate_registers, candidate_memory = (
                    _base._legacy._apply_hybrid_summary(
                        candidate_registers,
                        candidate_memory,
                        callee,
                        cells,
                        cells_by_id,
                    )
                )
                candidate_comparison = None
                candidate_conditions = _condition_after_summary(callee)

            queue.append(
                {
                    "address": edge["target"],
                    "registers": candidate_registers,
                    "memory": candidate_memory,
                    "comparison": candidate_comparison,
                    "conditions": candidate_conditions,
                    "guards": tuple(candidate_guards),
                    "nested_trace": candidate_trace,
                    "visited": state["visited"] | {address},
                }
            )

    deduped = []
    seen = set()
    for case in raw_cases:
        signature = _case_signature(case)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(case)

    if len(deduped) <= 1:
        return _unsupported(
            "not-piecewise",
            contract_registers,
            contract_cells,
            composed_calls,
            explored,
        )

    for index, case in enumerate(deduped):
        case["id"] = f"C{index}"
    return {
        "supported": True,
        "reason": None,
        "cases": deduped,
        "register_contract_registers": list(contract_registers),
        "memory_contract_cells": list(contract_cells),
        "nested_composed_calls": len(composed_calls),
        "explored_states": explored,
    }


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    """Infer guarded register/memory/CC contracts from pristine CFG shape."""
    structural_edges = _base._legacy._rebuild_edges(nodes)
    structural = summarize_subroutines(nodes, structural_edges)
    entries = sorted(set(structural) | set(base_summaries or {}))

    base_available = {}
    for entry in entries:
        merged = dict((base_summaries or {}).get(entry) or {})
        shape = structural.get(entry)
        if shape is not None:
            merged.update(shape)
        merged.setdefault("guarded_supported", False)
        merged.setdefault("guarded_reason", "not-analyzed")
        merged.setdefault("guarded_cases", [])
        merged.setdefault("guarded_case_count", 0)
        merged.setdefault("guarded_explored_states", 0)
        merged.setdefault("guarded_nested_composed_calls", 0)
        base_available[entry] = merged

    available = {entry: dict(item) for entry, item in base_available.items()}
    previous = None
    max_iterations = max(3, len(entries) + 3)

    for iteration in range(1, max_iterations + 1):
        result = {}
        for entry in entries:
            item = dict(base_available[entry])
            analyzed = _analyze_guarded_function(
                nodes,
                structural_edges,
                item,
                available,
            )
            item["register_contract_registers"] = analyzed[
                "register_contract_registers"
            ]
            item["memory_contract_cells"] = analyzed["memory_contract_cells"]
            item["guarded_supported"] = analyzed["supported"]
            item["guarded_reason"] = analyzed["reason"]
            item["guarded_cases"] = analyzed["cases"]
            item["guarded_case_count"] = len(analyzed["cases"])
            item["guarded_explored_states"] = analyzed.get(
                "explored_states", 0
            )
            item["guarded_nested_composed_calls"] = analyzed.get(
                "nested_composed_calls", 0
            )
            result[entry] = item

        signature = _summary_signature(result)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": result,
                "summaries": [result[key] for key in sorted(result)],
            }
        previous = signature
        available = result

    raise _base.GuardedRefinementError(
        "Guarded condition summary composition did not converge"
    )


def _condition_instantiation(feasible):
    if not feasible:
        return {
            "condition_known": False,
            "exact_condition": None,
            "range_conditions": None,
            "condition_mode": "unknown",
        }
    raw = [case.get("condition_values") for case in feasible]
    if any(values is None for values in raw):
        return {
            "condition_known": False,
            "exact_condition": None,
            "range_conditions": None,
            "condition_mode": "unknown",
        }

    possible = {
        value
        for values in raw
        for value in values
        if value in CONDITION_VALUES
    }
    ordered = [value for value in CONDITION_VALUES if value in possible]
    return {
        "condition_known": True,
        "exact_condition": ordered[0] if len(ordered) == 1 else None,
        "range_conditions": ordered,
        "condition_mode": "exact" if len(ordered) == 1 else "set",
    }


def instantiate_guarded_calls(
    nodes,
    summaries,
    exact_out,
    range_out,
    memory_in,
):
    result = _base.instantiate_guarded_calls(
        nodes,
        summaries,
        exact_out,
        range_out,
        memory_in,
    )
    by_address = {node["address"]: node for node in nodes}

    for address, item in result.items():
        node = by_address[address]
        summary = (summaries or {}).get(node.get("target")) or {}
        feasible_ids = set(item.get("feasible_cases") or ())
        feasible = [
            case
            for case in summary.get("guarded_cases", ())
            if case.get("id") in feasible_ids
        ]
        condition = _condition_instantiation(feasible)
        item.update(condition)
        node["guarded_transfer_instantiation"] = item
    return result


def _merge_instantiations(base, guarded):
    merged = _base._legacy._merge_instantiations(base, guarded)
    for address, item in merged.items():
        guard_item = (guarded or {}).get(address)
        if guard_item is None:
            continue
        for field in (
            "condition_known",
            "exact_condition",
            "range_conditions",
            "condition_mode",
        ):
            if field in guard_item:
                item[field] = guard_item[field]
    return merged


def _global_exact(
    nodes,
    edges,
    entry_address,
    base_register_summaries,
    instantiations,
    initial,
):
    by_address, outgoing_edges = _inputs._resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return incoming, outgoing

    entry_state = _inputs.unknown_state()
    for register, value in initial.items():
        if register in _inputs.TRACKED_REGISTERS:
            entry_state[register] = (
                None if value is None else value & _inputs.REGISTER_MASK
            )
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
        state_out = _inputs._memory_aware_exact_transfer(node, state_in)
        outgoing[address] = state_out

        for edge in outgoing_edges.get(address, ()):
            if not _inputs._exact_edge_feasible(node, edge, state_out):
                continue
            candidate = _inputs._copy_exact_state(state_out)
            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate = _inputs._apply_exact_call(
                    state_out,
                    base_register_summaries.get(node.get("target")),
                )
                instantiation = instantiations.get(node["address"])
                if instantiation is not None:
                    for register, value in (
                        instantiation.get("exact_registers") or {}
                    ).items():
                        if register in _inputs.TRACKED_REGISTERS:
                            candidate[register] = (
                                value & _inputs.REGISTER_MASK
                            )
                    if "condition_known" in instantiation:
                        candidate["CC"] = (
                            instantiation.get("exact_condition")
                            if instantiation.get("condition_known")
                            else None
                        )

            target = edge["target"]
            merged = _inputs._join_exact_states(incoming[target], candidate)
            if not _inputs._exact_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    return incoming, outgoing


def _global_ranges(
    nodes,
    edges,
    entry_address,
    base_register_summaries,
    instantiations,
    initial,
):
    by_address, outgoing_edges = _inputs._resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return incoming, outgoing

    entry_state = _inputs.unknown_range_state()
    for register, value in initial.items():
        if register in _inputs.TRACKED_REGISTERS:
            signed = _inputs._signed24(value)
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
        state_out = _inputs._memory_aware_range_transfer(node, state_in)
        outgoing[address] = state_out

        for edge in outgoing_edges.get(address, ()):
            if not _inputs._range_edge_feasible(node, edge, state_out):
                continue
            candidate = _inputs._copy_range_state(state_out)
            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate = _inputs._apply_range_call(
                    state_out,
                    base_register_summaries.get(node.get("target")),
                )
                instantiation = instantiations.get(node["address"])
                if instantiation is not None:
                    for register, interval in (
                        instantiation.get("range_registers") or {}
                    ).items():
                        if register in _inputs.TRACKED_REGISTERS:
                            candidate[register] = tuple(interval)
                    if "condition_known" in instantiation:
                        candidate["CC"] = (
                            tuple(instantiation.get("range_conditions") or ())
                            if instantiation.get("condition_known")
                            else None
                        )

            target = edge["target"]
            merged = _inputs._join_range_states(incoming[target], candidate)
            if not _inputs._range_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    return incoming, outgoing


def _signature(nodes, edges, summaries, instantiations, value_analysis):
    return (
        _base._legacy._signature(
            nodes,
            edges,
            summaries,
            instantiations,
            value_analysis,
        ),
        tuple(
            (
                entry,
                tuple(
                    (
                        case.get("id"),
                        _condition_signature(case.get("condition_values")),
                    )
                    for case in summary.get("guarded_cases", ())
                ),
            )
            for entry, summary in sorted(summaries.items())
        ),
        tuple(
            (
                address,
                item.get("condition_known"),
                item.get("exact_condition"),
                tuple(item.get("range_conditions") or ()),
            )
            for address, item in sorted(instantiations.items())
        ),
    )


def _condition_metrics(summaries):
    cases = [
        case
        for summary in (summaries or {}).values()
        for case in summary.get("guarded_cases", ())
    ]
    return {
        "condition_exact_outputs": sum(
            1
            for case in cases
            if case.get("condition_values") is not None
            and len(case.get("condition_values") or ()) == 1
        ),
        "condition_set_outputs": sum(
            1
            for case in cases
            if case.get("condition_values") is not None
            and len(case.get("condition_values") or ()) > 1
        ),
        "condition_unknown_outputs": sum(
            1 for case in cases if case.get("condition_values") is None
        ),
    }


def refine_guarded_transfers(
    nodes,
    edges,
    entry_address,
    image,
    image_start,
    debug_map,
    base_summaries,
    base_instantiations,
    base_memory_summaries,
    base_memory_instantiations,
    base_register=None,
):
    """Refine guarded register/memory/CC contracts into caller CFG facts."""
    inferred = infer_guarded_transfer_summaries(
        nodes,
        edges,
        base_summaries or {},
    )
    summaries = inferred["summary_map"]
    cells, _ = _base._legacy._tracked_cells(nodes)
    seeds = _base._legacy.seed_initialized_memory(
        image,
        image_start,
        debug_map,
        cells,
    )
    initial = {} if base_register is None else {"B": base_register}

    exact_in = {
        node["address"]: node.get("registers_in")
        for node in nodes
    }
    exact_out = {
        node["address"]: node.get("registers_out")
        for node in nodes
    }
    range_in = {
        node["address"]: node.get("ranges_in")
        for node in nodes
    }
    range_out = {
        node["address"]: node.get("ranges_out")
        for node in nodes
    }

    value_analysis = _base._legacy.analyze_symbolic_input_memory_values(
        nodes,
        edges,
        entry_address,
        seeds,
        base_memory_summaries or {},
        base_memory_instantiations or {},
        base_summaries or {},
        base_instantiations or {},
    )

    previous = None
    max_iterations = max(5, len(nodes) + 5)
    for iteration in range(1, max_iterations + 1):
        guarded = instantiate_guarded_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
            value_analysis["incoming"],
        )
        combined = _merge_instantiations(
            base_instantiations,
            guarded,
        )
        value_analysis = _base._legacy.analyze_symbolic_input_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            base_memory_summaries or {},
            base_memory_instantiations or {},
            base_summaries or {},
            combined,
        )
        _base._legacy._attach_value_facts(nodes, value_analysis)

        exact_in, exact_out = _global_exact(
            nodes,
            edges,
            entry_address,
            base_summaries or {},
            combined,
            initial,
        )
        range_in, range_out = _global_ranges(
            nodes,
            edges,
            entry_address,
            base_summaries or {},
            combined,
            initial,
        )

        for node in nodes:
            address = node["address"]
            node["registers_in"] = (
                None
                if exact_in[address] is None
                else _base._legacy._copy_exact_state(exact_in[address])
            )
            node["registers_out"] = (
                None
                if exact_out[address] is None
                else _base._legacy._copy_exact_state(exact_out[address])
            )
            node["ranges_in"] = (
                None
                if range_in[address] is None
                else dict(range_in[address])
            )
            node["ranges_out"] = (
                None
                if range_out[address] is None
                else dict(range_out[address])
            )

        if _base._legacy._resolve_base_targets(
            nodes,
            exact_in,
            range_in,
        ):
            edges[:] = _base._legacy._rebuild_edges(nodes)
            previous = None
            continue

        _base._legacy._mark_impossible_edges(
            nodes,
            edges,
            exact_out,
            range_out,
        )
        final_guarded = instantiate_guarded_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
            value_analysis["incoming"],
        )
        signature = _signature(
            nodes,
            edges,
            summaries,
            final_guarded,
            value_analysis,
        )
        if signature == previous:
            metrics = _base._summary_metrics(summaries)
            condition_metrics = _condition_metrics(summaries)
            return {
                "iterations": iteration,
                "converged": True,
                "summary_inference_iterations": inferred.get(
                    "iterations", 0
                ),
                "summary_map": summaries,
                "summaries": [
                    summaries[key] for key in sorted(summaries)
                ],
                "instantiations": final_guarded,
                "value_analysis": value_analysis,
                "base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution")
                    == "guarded-transfer-base"
                ),
                "range_base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution")
                    == "guarded-transfer-range-base"
                ),
                "guarded_functions": sum(
                    1
                    for summary in summaries.values()
                    if summary.get("guarded_supported")
                ),
                "guarded_cases": sum(
                    len(summary.get("guarded_cases") or ())
                    for summary in summaries.values()
                ),
                **metrics,
                **condition_metrics,
            }
        previous = signature

    raise _base.GuardedRefinementError(
        "Guarded condition transfer/CFG refinement did not converge"
    )
