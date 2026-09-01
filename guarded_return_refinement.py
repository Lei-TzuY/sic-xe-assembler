import control_flow_core as _core
import guarded_condition_refinement as _condition
from static_analysis import CONDITION_VALUES, summarize_subroutines


_legacy = _condition._base._legacy
_transfer = _condition._base


RETURNABILITY_UNKNOWN = "unknown"
RETURNABILITY_RETURNS = "returns"
RETURNABILITY_NO_RETURN = "no-return"
RETURNABILITY_MIXED = "mixed"


def _case_signature(case):
    return (
        tuple(
            (
                repr(guard.get("left")),
                repr(guard.get("right")),
                tuple(guard.get("allowed") or ()),
            )
            for guard in case.get("guards", ())
        ),
        case.get("returns"),
        case.get("terminal_kind"),
        tuple(case.get("terminal_nodes") or ()),
        tuple(
            (
                item.get("call_source"),
                item.get("callee_entry"),
                item.get("case_id"),
            )
            for item in case.get("nested_cases", ())
        ),
    )


def _summary_signature(summaries):
    return tuple(
        (
            entry,
            bool(summary.get("guarded_returnability_supported")),
            summary.get("guarded_returnability_reason"),
            tuple(
                _case_signature(case)
                for case in summary.get("returnability_cases", ())
            ),
        )
        for entry, summary in sorted(summaries.items())
    )


def _tarjan_scc(addresses, adjacency):
    index = 0
    stack = []
    on_stack = set()
    indexes = {}
    lowlinks = {}
    result = []

    def visit(address):
        nonlocal index
        indexes[address] = index
        lowlinks[address] = index
        index += 1
        stack.append(address)
        on_stack.add(address)

        for target in adjacency.get(address, ()):
            if target not in indexes:
                visit(target)
                lowlinks[address] = min(lowlinks[address], lowlinks[target])
            elif target in on_stack:
                lowlinks[address] = min(lowlinks[address], indexes[target])

        if lowlinks[address] == indexes[address]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == address:
                    break
            result.append(tuple(sorted(component)))

    for address in sorted(addresses):
        if address not in indexes:
            visit(address)
    return result


def _closed_nonreturn_cycles(summary, structural_edges, by_address):
    addresses = set(summary.get("instruction_addresses") or ())
    returns = set(summary.get("return_sites") or ())
    all_edges = {}
    adjacency = {}
    for edge in structural_edges:
        source = edge.get("source")
        if source not in addresses or edge.get("synthetic_return"):
            continue
        all_edges.setdefault(source, []).append(edge)
        if (
            edge.get("resolved")
            and edge.get("kind") != "call"
            and edge.get("target") in addresses
        ):
            adjacency.setdefault(source, []).append(edge["target"])

    cycles = {}
    for component in _tarjan_scc(addresses, adjacency):
        members = set(component)
        cyclic = len(component) > 1 or any(
            target == component[0]
            for target in adjacency.get(component[0], ())
        )
        if not cyclic or members & returns:
            continue
        if any(
            by_address.get(address, {}).get("base_mnemonic") == "JSUB"
            for address in members
        ):
            continue

        closed = True
        for address in members:
            edges = all_edges.get(address, ())
            if not edges:
                closed = False
                break
            for edge in edges:
                if edge.get("kind") == "call" or not edge.get("resolved"):
                    closed = False
                    break
                if edge.get("target") not in members:
                    closed = False
                    break
            if not closed:
                break
        if not closed:
            continue
        for address in members:
            cycles[address] = component
    return cycles


def _copy_guards(guards):
    return tuple(dict(guard) for guard in guards)


def _terminal_case(state, returns, terminal_kind, terminal_nodes=(), terminal_address=None):
    return {
        "guards": [dict(item) for item in state.get("guards", ())],
        "returns": returns,
        "terminal_kind": terminal_kind,
        "terminal_address": terminal_address,
        "terminal_nodes": list(terminal_nodes),
        "nested_cases": [dict(item) for item in state.get("nested_trace", ())],
    }


def _substitute_nested_guards(case, registers, memory, cells):
    result = []
    for guard in case.get("guards", ()):
        substituted = _transfer._substitute_guard(
            guard,
            registers,
            memory,
            cells,
        )
        if substituted is None:
            return None
        result.append(substituted)
    return result


def _analyze_returnability_function(nodes, structural_edges, summary, summaries):
    by_address = {node["address"]: node for node in nodes}
    cells, operations = _legacy._tracked_cells(nodes)
    addresses = set(summary.get("instruction_addresses") or ())
    entry = summary.get("entry")
    return_sites = set(summary.get("return_sites") or ())
    if entry not in by_address or entry not in addresses:
        return {
            "supported": False,
            "reason": "no-function-shape",
            "cases": [],
            "explored_states": 0,
            "nested_composed_calls": 0,
        }

    closed_cycles = _closed_nonreturn_cycles(summary, structural_edges, by_address)
    all_edges = {}
    for edge in structural_edges:
        source = edge.get("source")
        if source in addresses and not edge.get("synthetic_return"):
            all_edges.setdefault(source, []).append(edge)

    queue = [
        {
            "address": entry,
            "registers": _legacy._entry_registers(),
            "memory": _legacy._entry_memory(cells),
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
        if explored >= _legacy.MAX_PATH_STATES:
            return {
                "supported": False,
                "reason": "path-budget",
                "cases": [],
                "explored_states": explored,
                "nested_composed_calls": len(composed_calls),
            }
        state = queue.pop(0)
        explored += 1
        address = state["address"]

        cycle = closed_cycles.get(address)
        if cycle is not None:
            raw_cases.append(
                _terminal_case(
                    state,
                    False,
                    "closed-cycle",
                    terminal_nodes=cycle,
                    terminal_address=address,
                )
            )
            if len(raw_cases) > _legacy.MAX_GUARDED_CASES:
                return {
                    "supported": False,
                    "reason": "case-budget",
                    "cases": [],
                    "explored_states": explored,
                    "nested_composed_calls": len(composed_calls),
                }
            continue

        if address in state["visited"]:
            return {
                "supported": False,
                "reason": "loop-or-revisit",
                "cases": [],
                "explored_states": explored,
                "nested_composed_calls": len(composed_calls),
            }

        node = by_address[address]
        registers = state["registers"]
        memory = state["memory"]
        operation = operations[address]
        comparison, conditions = _condition._condition_after_instruction(
            node,
            state["comparison"],
            state["conditions"],
            registers,
            memory,
            operation,
        )
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
            raw_cases.append(
                _terminal_case(
                    state,
                    True if summary.get("link_register_preserved") else None,
                    "return" if summary.get("link_register_preserved") else "unproven-return",
                    terminal_address=address,
                )
            )
            if len(raw_cases) > _legacy.MAX_GUARDED_CASES:
                return {
                    "supported": False,
                    "reason": "case-budget",
                    "cases": [],
                    "explored_states": explored,
                    "nested_composed_calls": len(composed_calls),
                }
            continue

        edges = all_edges.get(address, ())
        if not edges:
            raw_cases.append(
                _terminal_case(
                    state,
                    None,
                    "unknown-terminal",
                    terminal_address=address,
                )
            )
            continue

        conditional = node["base_mnemonic"] in _legacy.CONDITIONAL_MNEMONICS
        handled_any = False
        for edge in edges:
            if edge.get("kind") == "call":
                continue
            handled_any = True
            candidate_registers = _legacy._copy_symbolic_registers(registers_after)
            candidate_memory = _legacy._copy_symbolic_memory(memory_after, cells)
            candidate_comparison = comparison
            candidate_conditions = conditions
            candidate_guards = list(_copy_guards(state["guards"]))
            candidate_trace = tuple(state["nested_trace"])

            if conditional and edge.get("kind") in ("branch", "fallthrough"):
                allowed = _legacy._edge_allowed_conditions(
                    node["base_mnemonic"], edge.get("kind")
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
                    guard = _legacy._serialize_guard(candidate_comparison, allowed)
                    if guard is not None:
                        candidate_guards.append(guard)

            if not edge.get("resolved") or edge.get("target") not in addresses:
                raw_cases.append(
                    {
                        "guards": [dict(item) for item in candidate_guards],
                        "returns": None,
                        "terminal_kind": "unresolved-control",
                        "terminal_address": address,
                        "terminal_nodes": [],
                        "nested_cases": [dict(item) for item in candidate_trace],
                    }
                )
                continue

            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                callee = summaries.get(node.get("target"))
                return_cases = [] if callee is None else list(
                    callee.get("returnability_cases") or ()
                )
                if not callee or not callee.get("guarded_returnability_supported") or not return_cases:
                    raw_cases.append(
                        {
                            "guards": [dict(item) for item in candidate_guards],
                            "returns": None,
                            "terminal_kind": "nested-returnability-unknown",
                            "terminal_address": address,
                            "terminal_nodes": [],
                            "nested_cases": [dict(item) for item in candidate_trace],
                        }
                    )
                    continue

                composed_calls.add(address)
                for nested in return_cases:
                    nested_guards = _substitute_nested_guards(
                        nested,
                        candidate_registers,
                        candidate_memory,
                        cells,
                    )
                    if nested_guards is None:
                        raw_cases.append(
                            {
                                "guards": [dict(item) for item in candidate_guards],
                                "returns": None,
                                "terminal_kind": "nested-guard-unknown",
                                "terminal_address": address,
                                "terminal_nodes": [],
                                "nested_cases": [dict(item) for item in candidate_trace],
                            }
                        )
                        continue
                    combined_guards = candidate_guards + nested_guards
                    trace = list(candidate_trace)
                    trace.append(
                        {
                            "call_source": address,
                            "callee_entry": node.get("target"),
                            "case_id": nested.get("id"),
                        }
                    )
                    if nested.get("returns") is False:
                        raw_cases.append(
                            {
                                "guards": [dict(item) for item in combined_guards],
                                "returns": False,
                                "terminal_kind": "nested-no-return",
                                "terminal_address": address,
                                "terminal_nodes": list(nested.get("terminal_nodes") or ()),
                                "nested_cases": [dict(item) for item in trace],
                            }
                        )
                        continue
                    if nested.get("returns") is not True:
                        raw_cases.append(
                            {
                                "guards": [dict(item) for item in combined_guards],
                                "returns": None,
                                "terminal_kind": "nested-return-unknown",
                                "terminal_address": address,
                                "terminal_nodes": [],
                                "nested_cases": [dict(item) for item in trace],
                            }
                        )
                        continue

                    nested_registers, nested_memory = _legacy._apply_hybrid_summary(
                        candidate_registers,
                        candidate_memory,
                        callee,
                        cells,
                        {_transfer._cell_id(cell): cell for cell in cells},
                    )
                    queue.append(
                        {
                            "address": edge["target"],
                            "registers": nested_registers,
                            "memory": nested_memory,
                            "comparison": None,
                            "conditions": _condition._condition_after_summary(callee),
                            "guards": tuple(combined_guards),
                            "nested_trace": tuple(trace),
                            "visited": state["visited"] | {address},
                        }
                    )
                continue

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

        if node["base_mnemonic"] == "JSUB":
            call_edges = [edge for edge in edges if edge.get("kind") == "call"]
            if not call_edges or any(not edge.get("resolved") for edge in call_edges):
                raw_cases.append(
                    _terminal_case(
                        state,
                        None,
                        "unresolved-call",
                        terminal_address=address,
                    )
                )
        elif not handled_any:
            raw_cases.append(
                _terminal_case(
                    state,
                    None,
                    "unknown-terminal",
                    terminal_address=address,
                )
            )

        if len(raw_cases) > _legacy.MAX_GUARDED_CASES:
            return {
                "supported": False,
                "reason": "case-budget",
                "cases": [],
                "explored_states": explored,
                "nested_composed_calls": len(composed_calls),
            }

    deduped = []
    seen = set()
    for case in raw_cases:
        signature = _case_signature(case)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(case)

    if not deduped:
        return {
            "supported": False,
            "reason": "no-terminal-cases",
            "cases": [],
            "explored_states": explored,
            "nested_composed_calls": len(composed_calls),
        }

    for index, case in enumerate(deduped):
        case["id"] = f"R{index}"
    return {
        "supported": True,
        "reason": None,
        "cases": deduped,
        "explored_states": explored,
        "nested_composed_calls": len(composed_calls),
    }


def infer_guarded_returnability(nodes, edges, base_summaries=None):
    structural_edges = _legacy._rebuild_edges(nodes)
    structural = summarize_subroutines(nodes, structural_edges)
    entries = sorted(set(structural) | set(base_summaries or {}))

    base_available = {}
    for entry in entries:
        merged = dict((base_summaries or {}).get(entry) or {})
        shape = structural.get(entry)
        if shape is not None:
            merged.update(shape)
        base_available[entry] = merged

    available = {entry: dict(item) for entry, item in base_available.items()}
    previous = None
    max_iterations = max(3, len(entries) + 3)
    for iteration in range(1, max_iterations + 1):
        result = {}
        for entry in entries:
            item = dict(base_available[entry])
            analyzed = _analyze_returnability_function(
                nodes,
                structural_edges,
                item,
                available,
            )
            cases = analyzed["cases"]
            item["guarded_returnability_supported"] = analyzed["supported"]
            item["guarded_returnability_reason"] = analyzed["reason"]
            item["returnability_cases"] = cases
            item["returnability_case_count"] = len(cases)
            item["returnability_explored_states"] = analyzed.get("explored_states", 0)
            item["returnability_nested_composed_calls"] = analyzed.get(
                "nested_composed_calls", 0
            )
            item["guarded_may_return"] = any(
                case.get("returns") is not False for case in cases
            )
            item["guarded_must_return"] = bool(cases) and all(
                case.get("returns") is True for case in cases
            )
            item["guarded_may_not_return"] = any(
                case.get("returns") is not True for case in cases
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

    raise _condition._base.GuardedRefinementError(
        "Guarded returnability summary composition did not converge"
    )


def _returnability_actionable(summary):
    return bool(
        summary.get("guarded_returnability_supported")
        and any(
            case.get("returns") is False
            for case in summary.get("returnability_cases", ())
        )
    )


def _merge_summary_fields(base_item, return_item):
    merged = dict(base_item or {})
    for key in (
        "guarded_returnability_supported",
        "guarded_returnability_reason",
        "returnability_cases",
        "returnability_case_count",
        "returnability_explored_states",
        "returnability_nested_composed_calls",
        "guarded_may_return",
        "guarded_must_return",
        "guarded_may_not_return",
    ):
        if key in return_item:
            merged[key] = return_item[key]
    return merged


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    base = _condition.infer_guarded_transfer_summaries(nodes, edges, base_summaries)
    returned = infer_guarded_returnability(nodes, edges, base_summaries)
    return_by_entry = returned["summary_map"]
    summaries = []
    summary_map = {}
    for item in base.get("summaries", ()):
        entry = item["entry"]
        merged = _merge_summary_fields(item, return_by_entry.get(entry, {}))
        merged["guarded_value_supported"] = bool(item.get("guarded_supported"))
        if _returnability_actionable(merged):
            merged["guarded_supported"] = True
        summaries.append(merged)
        summary_map[entry] = merged
    for entry in sorted(set(return_by_entry) - set(summary_map)):
        merged = _merge_summary_fields({"entry": entry, "guarded_supported": False}, return_by_entry[entry])
        merged["guarded_value_supported"] = False
        if _returnability_actionable(merged):
            merged["guarded_supported"] = True
        summaries.append(merged)
        summary_map[entry] = merged
    summaries.sort(key=lambda item: item["entry"])
    return {
        "iterations": max(base.get("iterations", 0), returned.get("iterations", 0)),
        "converged": bool(base.get("converged")) and bool(returned.get("converged")),
        "summary_map": summary_map,
        "summaries": summaries,
    }


def _instantiate_returnability(nodes, summaries, memory_in):
    result = {}
    for node in nodes:
        if node["base_mnemonic"] != "JSUB":
            continue
        summary = (summaries or {}).get(node.get("target")) or {}
        if not summary.get("guarded_returnability_supported"):
            continue
        cases = list(summary.get("returnability_cases") or ())
        if not cases:
            continue
        register_exact = node.get("registers_out")
        register_ranges = node.get("ranges_out")
        memory_exact, memory_ranges = _legacy._memory_value_inputs(
            (memory_in or {}).get(node["address"])
        )
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
        states = {case.get("returns") for case in feasible}
        if feasible and states == {False}:
            mode = RETURNABILITY_NO_RETURN
        elif feasible and states == {True}:
            mode = RETURNABILITY_RETURNS
        elif feasible and None not in states and states == {True, False}:
            mode = RETURNABILITY_MIXED
        else:
            mode = RETURNABILITY_UNKNOWN
        item = {
            "returnability_known": mode in (RETURNABILITY_RETURNS, RETURNABILITY_NO_RETURN),
            "return_mode": mode,
            "must_return": mode == RETURNABILITY_RETURNS,
            "may_return": mode != RETURNABILITY_NO_RETURN,
            "must_not_return": mode == RETURNABILITY_NO_RETURN,
            "return_feasible_cases": [case["id"] for case in feasible],
            "return_ruled_out_cases": [
                case["id"] for case in cases if case not in feasible
            ],
        }
        result[node["address"]] = item
        existing = node.get("guarded_transfer_instantiation")
        if existing is not None:
            existing.update(item)
    return result


def _prune_no_return_calls(edges, instantiations):
    no_return_sources = {
        address
        for address, item in instantiations.items()
        if item.get("return_mode") == RETURNABILITY_NO_RETURN
    }
    if not no_return_sources:
        return 0, 0

    pruned_fallthrough = 0
    removed_returns = 0
    kept = []
    for edge in edges:
        call_source = edge.get("call_source")
        if edge.get("synthetic_return") and call_source in no_return_sources:
            removed_returns += 1
            continue
        if (
            edge.get("source") in no_return_sources
            and edge.get("kind") == "fallthrough"
        ):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "guarded-no-return"
            edge["resolution"] = "guarded-returnability"
            pruned_fallthrough += 1
        kept.append(edge)
    edges[:] = kept
    return pruned_fallthrough, removed_returns


def _clear_newly_unreachable(nodes, edges, entry_address):
    reachable = _core._reachable_addresses(entry_address, nodes, edges)
    for node in nodes:
        if node["address"] in reachable:
            continue
        node["registers_in"] = None
        node["registers_out"] = None
        node["ranges_in"] = None
        node["ranges_out"] = None
    return reachable


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
    base_result = _condition.refine_guarded_transfers(
        nodes,
        edges,
        entry_address,
        image,
        image_start,
        debug_map,
        base_summaries=base_summaries,
        base_instantiations=base_instantiations,
        base_memory_summaries=base_memory_summaries,
        base_memory_instantiations=base_memory_instantiations,
        base_register=base_register,
    )

    returned = infer_guarded_returnability(nodes, edges, base_summaries)
    return_by_entry = returned["summary_map"]
    merged_summary_map = {}
    for entry in sorted(set(base_result.get("summary_map", {})) | set(return_by_entry)):
        base_item = (base_result.get("summary_map") or {}).get(entry, {"entry": entry})
        merged = _merge_summary_fields(base_item, return_by_entry.get(entry, {}))
        merged["guarded_value_supported"] = bool(base_item.get("guarded_supported"))
        merged_summary_map[entry] = merged

    value_analysis = base_result.get("value_analysis") or {}
    return_instantiations = _instantiate_returnability(
        nodes,
        merged_summary_map,
        value_analysis.get("incoming") or {},
    )
    merged_instantiations = dict(base_result.get("instantiations") or {})
    by_address = {node["address"]: node for node in nodes}
    for address, item in return_instantiations.items():
        merged_instantiations.setdefault(address, {}).update(item)
        if address in by_address:
            by_address[address]["guarded_transfer_instantiation"] = merged_instantiations[address]

    pruned_fallthrough, removed_returns = _prune_no_return_calls(
        edges,
        return_instantiations,
    )
    if pruned_fallthrough or removed_returns:
        _clear_newly_unreachable(nodes, edges, entry_address)

    result = dict(base_result)
    result["summary_map"] = merged_summary_map
    result["summaries"] = [
        merged_summary_map[key] for key in sorted(merged_summary_map)
    ]
    result["instantiations"] = merged_instantiations
    result["returnability_summary_iterations"] = returned.get("iterations", 0)
    result["returnability_functions"] = sum(
        1
        for item in merged_summary_map.values()
        if item.get("guarded_returnability_supported")
    )
    result["returnability_cases"] = sum(
        len(item.get("returnability_cases") or ())
        for item in merged_summary_map.values()
    )
    result["no_return_calls"] = sum(
        1
        for item in return_instantiations.values()
        if item.get("return_mode") == RETURNABILITY_NO_RETURN
    )
    result["mixed_return_calls"] = sum(
        1
        for item in return_instantiations.values()
        if item.get("return_mode") == RETURNABILITY_MIXED
    )
    result["returnability_pruned_fallthroughs"] = pruned_fallthrough
    result["returnability_removed_synthetic_returns"] = removed_returns
    return result
