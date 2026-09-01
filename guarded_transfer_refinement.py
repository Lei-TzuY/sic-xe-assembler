import guarded_transfers as _legacy
from memory_analysis import _cell_id
from static_analysis import TRACKED_REGISTERS, summarize_subroutines
from symbolic_memory_inputs import _deserialize, _substitute


class GuardedRefinementError(ValueError):
    pass


def _memory_contract_cells(summary, cells):
    known = {_cell_id(cell) for cell in cells}
    if (summary or {}).get("unknown_write"):
        return tuple(sorted(known))
    return tuple(
        sorted(
            cell_id
            for cell_id in ((summary or {}).get("may_write_cells") or ())
            if cell_id in known
        )
    )


def _memory_output_spec(expression, cell_id):
    if expression is None:
        return {"kind": "unknown"}
    if _legacy._identity_memory(expression, cell_id):
        return {"kind": "identity"}
    return _legacy._serialize(expression)


def _path_outputs(registers, memory, contract_cells, cells_by_id):
    register_outputs = {}
    memory_outputs = {}
    for register in TRACKED_REGISTERS:
        expression = registers.get(register)
        if expression is None or expression == _legacy._source_register(register):
            continue
        register_outputs[register] = _legacy._serialize(expression)

    for cell_id in contract_cells:
        cell = cells_by_id.get(cell_id)
        expression = None if cell is None else memory.get(cell)
        memory_outputs[cell_id] = _memory_output_spec(expression, cell_id)
    return register_outputs, memory_outputs


def _spec_signature(spec):
    if not spec:
        return ("missing",)
    kind = spec.get("kind")
    if kind in ("identity", "unknown"):
        return (kind,)
    return (
        kind,
        tuple(sorted((spec.get("register_coefficients") or {}).items())),
        tuple(sorted((spec.get("memory_coefficients") or {}).items())),
        spec.get("offset"),
    )


def _case_signature(case):
    return (
        tuple(
            (
                _spec_signature(guard.get("left")),
                _spec_signature(guard.get("right")),
                tuple(guard.get("allowed") or ()),
            )
            for guard in case.get("guards", ())
        ),
        tuple(
            (register, _spec_signature(spec))
            for register, spec in sorted(
                (case.get("register_outputs") or {}).items()
            )
        ),
        tuple(
            (cell_id, _spec_signature(spec))
            for cell_id, spec in sorted(
                (case.get("memory_outputs") or {}).items()
            )
        ),
    )


def _summary_signature(summaries):
    return tuple(
        (
            entry,
            bool(summary.get("guarded_supported")),
            summary.get("guarded_reason"),
            tuple(summary.get("memory_contract_cells") or ()),
            tuple(
                _case_signature(case)
                for case in summary.get("guarded_cases", ())
            ),
        )
        for entry, summary in sorted(summaries.items())
    )


def _substitute_guard(guard, registers, memory, cells):
    memory_by_id = {
        _cell_id(cell): memory.get(cell)
        for cell in cells
    }
    left = _substitute(
        _deserialize(guard.get("left")),
        registers,
        memory_by_id,
    )
    right = _substitute(
        _deserialize(guard.get("right")),
        registers,
        memory_by_id,
    )
    if left is None or right is None:
        return None
    return {
        "left": _legacy._serialize(left),
        "right": _legacy._serialize(right),
        "allowed": list(guard.get("allowed") or ()),
    }


def _apply_guarded_case(
    registers,
    memory,
    summary,
    case,
    cells,
    cells_by_id,
):
    input_registers = _legacy._copy_symbolic_registers(registers)
    input_memory = _legacy._copy_symbolic_memory(memory, cells)
    memory_inputs_by_id = {
        _cell_id(cell): expression
        for cell, expression in input_memory.items()
    }

    result_registers = _legacy._copy_symbolic_registers(registers)
    preserved = set((summary or {}).get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result_registers[register] = None

    result_memory = _legacy._copy_symbolic_memory(memory, cells)
    if (summary or {}).get("unknown_write"):
        result_memory = {cell: None for cell in cells}
    else:
        for cell_id in (summary or {}).get("may_write_cells") or ():
            cell = cells_by_id.get(cell_id)
            if cell is not None:
                result_memory[cell] = None

    for register, spec in (case.get("register_outputs") or {}).items():
        if register not in TRACKED_REGISTERS:
            continue
        result_registers[register] = _substitute(
            _deserialize(spec),
            input_registers,
            memory_inputs_by_id,
        )

    for cell_id in (summary or {}).get("memory_contract_cells") or ():
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        spec = (case.get("memory_outputs") or {}).get(cell_id)
        kind = None if spec is None else spec.get("kind")
        if kind == "identity":
            result_memory[cell] = input_memory.get(cell)
        elif kind == "unknown" or spec is None:
            result_memory[cell] = None
        else:
            result_memory[cell] = _substitute(
                _deserialize(spec),
                input_registers,
                memory_inputs_by_id,
            )
    return result_registers, result_memory


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
        composed_guards = list(_legacy._copy_guards(guards))
        for guard in case.get("guards", ()):
            substituted = _substitute_guard(
                guard,
                registers,
                memory,
                cells,
            )
            if substituted is None:
                return None
            composed_guards.append(substituted)

        result_registers, result_memory = _apply_guarded_case(
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
            )
        )
    return expansions


def _analyze_guarded_function(
    nodes,
    structural_edges,
    summary,
    summaries,
):
    cells, operations = _legacy._tracked_cells(nodes)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    contract_cells = _memory_contract_cells(summary, cells)
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
        return {
            "supported": False,
            "reason": "no-return-shape",
            "cases": [],
            "memory_contract_cells": list(contract_cells),
            "nested_composed_calls": 0,
        }

    queue = [
        {
            "address": entry,
            "registers": _legacy._entry_registers(),
            "memory": _legacy._entry_memory(cells),
            "comparison": None,
            "guards": (),
            "nested_trace": (),
            "visited": frozenset(),
        }
    ]
    raw_cases = []
    explored = 0
    composed_calls = set()

    while queue:
        if explored >= _legacy.MAX_PATH_STATES:
            return {
                "supported": False,
                "reason": "path-budget",
                "cases": [],
                "memory_contract_cells": list(contract_cells),
                "nested_composed_calls": len(composed_calls),
            }
        state = queue.pop(0)
        explored += 1
        address = state["address"]
        if address in state["visited"]:
            return {
                "supported": False,
                "reason": "loop-or-revisit",
                "cases": [],
                "memory_contract_cells": list(contract_cells),
                "nested_composed_calls": len(composed_calls),
            }

        node = by_address[address]
        registers = state["registers"]
        memory = state["memory"]
        operation = operations[address]
        comparison = state["comparison"]

        if node["base_mnemonic"] in ("COMP", "COMPR"):
            comparison = _legacy._comparison_expression(
                node,
                registers,
                memory,
                operation,
            )
        elif node["base_mnemonic"] in ("TIX", "TIXR"):
            comparison = None

        registers_after = _legacy._hybrid_register_transfer(
            node,
            registers,
            memory,
            operation,
        )
        memory_after = _legacy._hybrid_memory_transfer(
            node,
            registers,
            memory,
            cells,
            operation,
        )

        if address in return_sites:
            register_outputs, memory_outputs = _path_outputs(
                registers_after,
                memory_after,
                contract_cells,
                cells_by_id,
            )
            raw_cases.append(
                {
                    "return_site": address,
                    "guards": [
                        dict(item) for item in state["guards"]
                    ],
                    "register_outputs": register_outputs,
                    "memory_outputs": memory_outputs,
                    "nested_cases": [
                        dict(item) for item in state["nested_trace"]
                    ],
                }
            )
            if len(raw_cases) > _legacy.MAX_GUARDED_CASES:
                return {
                    "supported": False,
                    "reason": "case-budget",
                    "cases": [],
                    "memory_contract_cells": list(contract_cells),
                    "nested_composed_calls": len(composed_calls),
                }
            continue

        edges = outgoing.get(address, ())
        conditional = node["base_mnemonic"] in _legacy.CONDITIONAL_MNEMONICS
        if conditional and comparison is None:
            return {
                "supported": False,
                "reason": "unguarded-condition",
                "cases": [],
                "memory_contract_cells": list(contract_cells),
                "nested_composed_calls": len(composed_calls),
            }

        for edge in edges:
            candidate_registers = _legacy._copy_symbolic_registers(
                registers_after
            )
            candidate_memory = _legacy._copy_symbolic_memory(
                memory_after,
                cells,
            )
            candidate_comparison = comparison
            candidate_guards = list(
                _legacy._copy_guards(state["guards"])
            )
            candidate_trace = tuple(state["nested_trace"])

            if conditional:
                allowed = _legacy._edge_allowed_conditions(
                    node["base_mnemonic"],
                    edge.get("kind"),
                )
                guard = _legacy._serialize_guard(comparison, allowed)
                if guard is None:
                    return {
                        "supported": False,
                        "reason": "unguarded-edge",
                        "cases": [],
                        "memory_contract_cells": list(contract_cells),
                        "nested_composed_calls": len(composed_calls),
                    }
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
                    ) in expansions:
                        queue.append(
                            {
                                "address": edge["target"],
                                "registers": nested_registers,
                                "memory": nested_memory,
                                "comparison": None,
                                "guards": nested_guards,
                                "nested_trace": nested_case_trace,
                                "visited": state["visited"] | {address},
                            }
                        )
                    continue

                candidate_registers, candidate_memory = (
                    _legacy._apply_hybrid_summary(
                        candidate_registers,
                        candidate_memory,
                        callee,
                        cells,
                        cells_by_id,
                    )
                )
                candidate_comparison = None

            queue.append(
                {
                    "address": edge["target"],
                    "registers": candidate_registers,
                    "memory": candidate_memory,
                    "comparison": candidate_comparison,
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
        return {
            "supported": False,
            "reason": "not-piecewise",
            "cases": [],
            "memory_contract_cells": list(contract_cells),
            "nested_composed_calls": len(composed_calls),
            "explored_states": explored,
        }

    for index, case in enumerate(deduped):
        case["id"] = f"C{index}"
    return {
        "supported": True,
        "reason": None,
        "cases": deduped,
        "memory_contract_cells": list(contract_cells),
        "nested_composed_calls": len(composed_calls),
        "explored_states": explored,
    }


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    """Infer compositional guarded cases from pristine structural CFG shape."""
    structural_edges = _legacy._rebuild_edges(nodes)
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

    available = {
        entry: dict(item)
        for entry, item in base_available.items()
    }
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
            item["memory_contract_cells"] = analyzed[
                "memory_contract_cells"
            ]
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
                "summaries": [
                    result[key] for key in sorted(result)
                ],
            }
        previous = signature
        available = result

    raise GuardedRefinementError(
        "Guarded summary composition did not converge"
    )


def _memory_spec_value(
    spec,
    cell_id,
    register_exact,
    register_ranges,
    memory_exact,
    memory_ranges,
):
    if not spec:
        return None, None
    kind = spec.get("kind")
    if kind == "identity":
        exact = (memory_exact or {}).get(cell_id)
        interval = (memory_ranges or {}).get(cell_id)
    elif kind == "unknown":
        return None, None
    else:
        exact = _legacy._evaluate_exact(
            spec,
            register_exact or {},
            memory_exact or {},
        )
        interval = _legacy._evaluate_range(
            spec,
            register_ranges or {},
            memory_ranges or {},
        )

    if interval is None and exact is not None:
        interval = _legacy._signed_singleton(exact)
    return exact, interval


def _join_memory_case_output(
    cases,
    cell_id,
    register_exact,
    register_ranges,
    memory_exact,
    memory_ranges,
):
    exact_values = []
    intervals = []
    complete_ranges = True

    for case in cases:
        spec = (case.get("memory_outputs") or {}).get(cell_id)
        exact, interval = _memory_spec_value(
            spec,
            cell_id,
            register_exact,
            register_ranges,
            memory_exact,
            memory_ranges,
        )
        exact_values.append(exact)
        if interval is None:
            complete_ranges = False
        else:
            intervals.append(interval)

    exact = (
        exact_values[0]
        if exact_values
        and exact_values[0] is not None
        and all(value == exact_values[0] for value in exact_values)
        else None
    )
    interval = (
        (
            min(item[0] for item in intervals),
            max(item[1] for item in intervals),
        )
        if complete_ranges and intervals
        else None
    )
    return exact, interval


def instantiate_guarded_calls(
    nodes,
    summaries,
    exact_out,
    range_out,
    memory_in,
):
    result = {}
    for node in nodes:
        if node["base_mnemonic"] != "JSUB":
            continue

        summary = (summaries or {}).get(node.get("target"))
        if (
            summary is None
            or not summary.get("guarded_supported")
            or not summary.get("link_register_preserved")
        ):
            node.pop("guarded_transfer_instantiation", None)
            continue

        register_exact = exact_out.get(node["address"])
        register_ranges = range_out.get(node["address"])
        memory_exact, memory_ranges = _legacy._memory_value_inputs(
            memory_in.get(node["address"])
        )
        cases = list(summary.get("guarded_cases") or ())
        feasible = [
            case
            for case in cases
            if _legacy._case_feasible(
                case,
                register_exact,
                register_ranges,
                memory_exact,
                memory_ranges,
            )
        ]

        exact_registers = {}
        range_registers = {}
        exact_memory = {}
        range_memory = {}

        register_keys = sorted(
            {
                register
                for case in feasible
                for register in (
                    case.get("register_outputs") or {}
                )
            }
        )
        for register in register_keys:
            exact, interval = _legacy._join_case_output(
                feasible,
                register,
                "register_outputs",
                register_exact,
                register_ranges,
                memory_exact,
                memory_ranges,
            )
            if exact is not None:
                exact_registers[register] = (
                    exact & _legacy.REGISTER_MASK
                )
            if interval is not None:
                range_registers[register] = list(interval)

        memory_modes = {}
        for cell_id in summary.get("memory_contract_cells") or ():
            exact, interval = _join_memory_case_output(
                feasible,
                cell_id,
                register_exact,
                register_ranges,
                memory_exact,
                memory_ranges,
            )
            if exact is not None:
                exact_memory[cell_id] = exact & _legacy.REGISTER_MASK
            if interval is not None:
                range_memory[cell_id] = list(interval)

            modes = {
                ((case.get("memory_outputs") or {}).get(cell_id) or {}).get(
                    "kind", "unknown"
                )
                for case in feasible
            }
            if len(modes) == 1:
                memory_modes[cell_id] = next(iter(modes))
            elif modes:
                memory_modes[cell_id] = "joined"

        item = {
            "callee_entry": node.get("target"),
            "feasible_cases": [
                case["id"] for case in feasible
            ],
            "ruled_out_cases": [
                case["id"] for case in cases if case not in feasible
            ],
            "exact_registers": exact_registers,
            "range_registers": range_registers,
            "exact_memory": exact_memory,
            "range_memory": range_memory,
            "memory_modes": memory_modes,
        }
        node["guarded_transfer_instantiation"] = item
        result[node["address"]] = item
    return result


def _summary_metrics(summaries):
    values = list((summaries or {}).values())
    cases = [
        case
        for summary in values
        for case in summary.get("guarded_cases", ())
    ]
    memory_specs = [
        spec
        for case in cases
        for spec in (case.get("memory_outputs") or {}).values()
    ]
    return {
        "nested_composed_calls": sum(
            summary.get("guarded_nested_composed_calls", 0)
            for summary in values
        ),
        "memory_identity_outputs": sum(
            1 for spec in memory_specs
            if spec.get("kind") == "identity"
        ),
        "memory_unknown_outputs": sum(
            1 for spec in memory_specs
            if spec.get("kind") == "unknown"
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
    """Instantiate compositional guarded summaries and feed them into CFG facts."""
    inferred = infer_guarded_transfer_summaries(
        nodes,
        edges,
        base_summaries or {},
    )
    summaries = inferred["summary_map"]
    cells, _ = _legacy._tracked_cells(nodes)
    seeds = _legacy.seed_initialized_memory(
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

    value_analysis = _legacy.analyze_symbolic_input_memory_values(
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
        combined = _legacy._merge_instantiations(
            base_instantiations,
            guarded,
        )
        value_analysis = _legacy.analyze_symbolic_input_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            base_memory_summaries or {},
            base_memory_instantiations or {},
            base_summaries or {},
            combined,
        )
        _legacy._attach_value_facts(nodes, value_analysis)

        exact_in, exact_out = _legacy._global_exact(
            nodes,
            edges,
            entry_address,
            base_summaries or {},
            combined,
            initial,
        )
        range_in, range_out = _legacy._global_ranges(
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
                else _legacy._copy_exact_state(exact_in[address])
            )
            node["registers_out"] = (
                None
                if exact_out[address] is None
                else _legacy._copy_exact_state(exact_out[address])
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

        if _legacy._resolve_base_targets(nodes, exact_in, range_in):
            edges[:] = _legacy._rebuild_edges(nodes)
            previous = None
            continue

        _legacy._mark_impossible_edges(
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
        signature = _legacy._signature(
            nodes,
            edges,
            summaries,
            final_guarded,
            value_analysis,
        )
        if signature == previous:
            metrics = _summary_metrics(summaries)
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
            }
        previous = signature

    raise GuardedRefinementError(
        "Guarded transfer/CFG refinement did not converge"
    )
