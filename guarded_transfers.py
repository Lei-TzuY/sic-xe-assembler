from disassembler import decode_instruction
from memory_analysis import _cell_id
from memory_postconditions import _attach_value_facts, seed_initialized_memory
from range_analysis import _possible_compare
from sparse_linear_transfers import (
    _base_relative,
    _exact_edge_feasible,
    _range_edge_feasible,
    _rebuild_edges,
    _signed24,
)
from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    _compare24,
    _copy_state as _copy_exact_state,
)
from symbolic_memory_inputs import (
    _apply_hybrid_summary,
    _const,
    _copy_symbolic_memory,
    _copy_symbolic_registers,
    _entry_memory,
    _entry_registers,
    _evaluate_exact,
    _evaluate_range,
    _global_exact,
    _global_ranges,
    _has_memory_input,
    _hybrid_memory_transfer,
    _hybrid_register_transfer,
    _identity_memory,
    _memory_value_inputs,
    _read_expression,
    _register_operands,
    _serialize,
    _source_memory,
    _source_register,
    _tracked_cells,
    analyze_symbolic_input_memory_values,
)


MAX_GUARDED_CASES = 8
MAX_PATH_STATES = 128
GUARDED_BASE_RESOLUTIONS = {
    "guarded-transfer-base",
    "guarded-transfer-range-base",
}
GUARDED_CONDITION_RESOLUTIONS = {
    "guarded-transfer-condition",
    "guarded-transfer-range-condition",
}


class GuardedTransferError(ValueError):
    pass


def _copy_guards(guards):
    return tuple(dict(item) for item in guards)


def _comparison_expression(node, registers, memory, operation):
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    fields = _register_operands(operand)
    if mnemonic == "COMP":
        left = registers.get("A")
        target = node.get("target")
        if (
            operand.startswith("#")
            and not operand.endswith(",X")
            and target is not None
        ):
            right = _const(target)
        else:
            right = _read_expression(operation, memory)
        return None if left is None or right is None else (left, right)
    if mnemonic == "COMPR" and len(fields) == 2:
        left = registers.get(fields[0])
        right = registers.get(fields[1])
        return None if left is None or right is None else (left, right)
    return None


def _edge_allowed_conditions(mnemonic, edge_kind):
    required = {
        "JEQ": "EQ",
        "JLT": "LT",
        "JGT": "GT",
    }.get(mnemonic)
    if required is None:
        return None
    if edge_kind == "branch":
        return (required,)
    if edge_kind == "fallthrough":
        return tuple(
            value for value in CONDITION_VALUES
            if value != required
        )
    return None


def _serialize_guard(comparison, allowed):
    if comparison is None or not allowed:
        return None
    left, right = comparison
    return {
        "left": _serialize(left),
        "right": _serialize(right),
        "allowed": list(allowed),
    }


def _path_outputs(registers, memory, cells):
    register_outputs = {}
    memory_outputs = {}
    for register in TRACKED_REGISTERS:
        expression = registers.get(register)
        if expression is None or expression == _source_register(register):
            continue
        register_outputs[register] = _serialize(expression)
    for cell in cells:
        expression = memory.get(cell)
        cell_id = _cell_id(cell)
        if (
            expression is None
            or _identity_memory(expression, cell_id)
        ):
            continue
        memory_outputs[cell_id] = _serialize(expression)
    return register_outputs, memory_outputs


def _case_signature(case):
    def spec_signature(spec):
        return (
            tuple(sorted((spec.get("register_coefficients") or {}).items())),
            tuple(sorted((spec.get("memory_coefficients") or {}).items())),
            spec.get("offset"),
        )

    return (
        tuple(
            (
                spec_signature(guard["left"]),
                spec_signature(guard["right"]),
                tuple(guard["allowed"]),
            )
            for guard in case.get("guards", ())
        ),
        tuple(
            (register, spec_signature(spec))
            for register, spec in sorted(
                (case.get("register_outputs") or {}).items()
            )
        ),
        tuple(
            (cell_id, spec_signature(spec))
            for cell_id, spec in sorted(
                (case.get("memory_outputs") or {}).items()
            )
        ),
    )


def _analyze_guarded_function(nodes, structural_edges, summary, summaries):
    cells, operations = _tracked_cells(nodes)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
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
        }

    queue = [
        {
            "address": entry,
            "registers": _entry_registers(),
            "memory": _entry_memory(cells),
            "comparison": None,
            "guards": (),
            "visited": frozenset(),
        }
    ]
    raw_cases = []
    explored = 0

    while queue:
        if explored >= MAX_PATH_STATES:
            return {
                "supported": False,
                "reason": "path-budget",
                "cases": [],
            }
        state = queue.pop(0)
        explored += 1
        address = state["address"]
        if address in state["visited"]:
            return {
                "supported": False,
                "reason": "loop-or-revisit",
                "cases": [],
            }

        node = by_address[address]
        registers = state["registers"]
        memory = state["memory"]
        operation = operations[address]
        comparison = state["comparison"]

        if node["base_mnemonic"] in ("COMP", "COMPR"):
            comparison = _comparison_expression(
                node,
                registers,
                memory,
                operation,
            )
        elif node["base_mnemonic"] in ("TIX", "TIXR"):
            comparison = None

        registers_after = _hybrid_register_transfer(
            node,
            registers,
            memory,
            operation,
        )
        memory_after = _hybrid_memory_transfer(
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
                cells,
            )
            raw_cases.append(
                {
                    "return_site": address,
                    "guards": [dict(item) for item in state["guards"]],
                    "register_outputs": register_outputs,
                    "memory_outputs": memory_outputs,
                }
            )
            if len(raw_cases) > MAX_GUARDED_CASES:
                return {
                    "supported": False,
                    "reason": "case-budget",
                    "cases": [],
                }
            continue

        edges = outgoing.get(address, ())
        conditional = node["base_mnemonic"] in CONDITIONAL_MNEMONICS
        if conditional and comparison is None:
            return {
                "supported": False,
                "reason": "unguarded-condition",
                "cases": [],
            }

        for edge in edges:
            candidate_registers = _copy_symbolic_registers(registers_after)
            candidate_memory = _copy_symbolic_memory(memory_after, cells)
            candidate_comparison = comparison
            candidate_guards = list(_copy_guards(state["guards"]))

            if conditional:
                allowed = _edge_allowed_conditions(
                    node["base_mnemonic"],
                    edge.get("kind"),
                )
                guard = _serialize_guard(comparison, allowed)
                if guard is None:
                    return {
                        "supported": False,
                        "reason": "unguarded-edge",
                        "cases": [],
                    }
                candidate_guards.append(guard)

            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate_registers, candidate_memory = _apply_hybrid_summary(
                    candidate_registers,
                    candidate_memory,
                    summaries.get(node.get("target")),
                    cells,
                    cells_by_id,
                )
                candidate_comparison = None

            queue.append(
                {
                    "address": edge["target"],
                    "registers": candidate_registers,
                    "memory": candidate_memory,
                    "comparison": candidate_comparison,
                    "guards": tuple(candidate_guards),
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
        }

    for index, case in enumerate(deduped):
        case["id"] = f"C{index}"
    return {
        "supported": True,
        "reason": None,
        "cases": deduped,
        "explored_states": explored,
    }


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    structural_edges = _rebuild_edges(nodes)
    result = {}
    for entry, base in sorted((base_summaries or {}).items()):
        item = dict(base)
        analyzed = _analyze_guarded_function(
            nodes,
            structural_edges,
            item,
            base_summaries or {},
        )
        item["guarded_supported"] = analyzed["supported"]
        item["guarded_reason"] = analyzed["reason"]
        item["guarded_cases"] = analyzed["cases"]
        item["guarded_case_count"] = len(analyzed["cases"])
        item["guarded_explored_states"] = analyzed.get("explored_states", 0)
        result[entry] = item
    return {
        "summary_map": result,
        "summaries": [result[key] for key in sorted(result)],
    }


def _guard_feasible(guard, register_exact, register_ranges, memory_exact, memory_ranges):
    allowed = set(guard.get("allowed") or ())
    if not allowed:
        return False

    left_exact = _evaluate_exact(
        guard.get("left"),
        register_exact or {},
        memory_exact or {},
    )
    right_exact = _evaluate_exact(
        guard.get("right"),
        register_exact or {},
        memory_exact or {},
    )
    if left_exact is not None and right_exact is not None:
        return _compare24(left_exact, right_exact) in allowed

    left_range = _evaluate_range(
        guard.get("left"),
        register_ranges or {},
        memory_ranges or {},
    )
    right_range = _evaluate_range(
        guard.get("right"),
        register_ranges or {},
        memory_ranges or {},
    )
    possible = _possible_compare(left_range, right_range)
    if possible is None:
        return True
    return bool(allowed & set(possible))


def _case_feasible(case, register_exact, register_ranges, memory_exact, memory_ranges):
    return all(
        _guard_feasible(
            guard,
            register_exact,
            register_ranges,
            memory_exact,
            memory_ranges,
        )
        for guard in case.get("guards", ())
    )


def _signed_singleton(value):
    signed = _signed24(value)
    return (signed, signed)


def _join_case_output(
    cases,
    key,
    output_field,
    register_exact,
    register_ranges,
    memory_exact,
    memory_ranges,
):
    exact_values = []
    intervals = []
    for case in cases:
        spec = (case.get(output_field) or {}).get(key)
        if spec is None:
            return None, None
        exact = _evaluate_exact(
            spec,
            register_exact or {},
            memory_exact or {},
        )
        interval = _evaluate_range(
            spec,
            register_ranges or {},
            memory_ranges or {},
        )
        exact_values.append(exact)
        if interval is None and exact is not None:
            interval = _signed_singleton(exact)
        if interval is None:
            return (
                exact_values[0]
                if exact_values
                and exact_values[0] is not None
                and all(value == exact_values[0] for value in exact_values)
                else None,
                None,
            )
        intervals.append(interval)

    exact = (
        exact_values[0]
        if exact_values
        and exact_values[0] is not None
        and all(value == exact_values[0] for value in exact_values)
        else None
    )
    interval = (
        (min(item[0] for item in intervals), max(item[1] for item in intervals))
        if intervals
        else None
    )
    return exact, interval


def instantiate_guarded_calls(nodes, summaries, exact_out, range_out, memory_in):
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
        memory_exact, memory_ranges = _memory_value_inputs(
            memory_in.get(node["address"])
        )
        cases = list(summary.get("guarded_cases") or ())
        feasible = [
            case for case in cases
            if _case_feasible(
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

        register_keys = sorted({
            register
            for case in feasible
            for register in (case.get("register_outputs") or {})
        })
        memory_keys = sorted({
            cell_id
            for case in feasible
            for cell_id in (case.get("memory_outputs") or {})
        })

        for register in register_keys:
            exact, interval = _join_case_output(
                feasible,
                register,
                "register_outputs",
                register_exact,
                register_ranges,
                memory_exact,
                memory_ranges,
            )
            if exact is not None:
                exact_registers[register] = exact & REGISTER_MASK
            if interval is not None:
                range_registers[register] = list(interval)

        for cell_id in memory_keys:
            exact, interval = _join_case_output(
                feasible,
                cell_id,
                "memory_outputs",
                register_exact,
                register_ranges,
                memory_exact,
                memory_ranges,
            )
            if exact is not None:
                exact_memory[cell_id] = exact & REGISTER_MASK
            if interval is not None:
                range_memory[cell_id] = list(interval)

        item = {
            "callee_entry": node.get("target"),
            "feasible_cases": [case["id"] for case in feasible],
            "ruled_out_cases": [
                case["id"] for case in cases if case not in feasible
            ],
            "exact_registers": exact_registers,
            "range_registers": range_registers,
            "exact_memory": exact_memory,
            "range_memory": range_memory,
        }
        node["guarded_transfer_instantiation"] = item
        result[node["address"]] = item
    return result


def _merge_instantiation(base, guarded):
    if base is None and guarded is None:
        return None
    result = {
        "exact_registers": {},
        "range_registers": {},
        "exact_memory": {},
        "range_memory": {},
    }
    for source in (base or {}, guarded or {}):
        for field in result:
            result[field].update(source.get(field) or {})
    if base:
        for key, value in base.items():
            if key not in result:
                result[key] = value
    if guarded:
        result["guarded_feasible_cases"] = list(
            guarded.get("feasible_cases") or ()
        )
    return result


def _merge_instantiations(base, guarded):
    addresses = set(base or {}) | set(guarded or {})
    return {
        address: _merge_instantiation(
            (base or {}).get(address),
            (guarded or {}).get(address),
        )
        for address in addresses
    }


def _clear_base(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution") in GUARDED_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _resolve_base_targets(nodes, exact_in, range_in):
    changed = False
    for node in nodes:
        if not _base_relative(node):
            continue
        resolution = node.get("target_resolution")
        if resolution is not None and resolution not in GUARDED_BASE_RESOLUTIONS:
            continue
        exact_state = exact_in.get(node["address"])
        range_state = range_in.get(node["address"])
        base = None if exact_state is None else exact_state.get("B")
        new_resolution = None
        if base is not None:
            new_resolution = "guarded-transfer-base"
        elif range_state is not None:
            interval = range_state.get("B")
            if interval is not None and interval[0] == interval[1]:
                base = interval[0] & REGISTER_MASK
                new_resolution = "guarded-transfer-range-base"
        if base is None:
            if resolution in GUARDED_BASE_RESOLUTIONS:
                changed = _clear_base(node) or changed
            continue
        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base,
        )
        if decoded.target is None:
            if resolution in GUARDED_BASE_RESOLUTIONS:
                changed = _clear_base(node) or changed
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


def _mark_impossible_edges(nodes, edges, exact_out, range_out):
    by_address = {node["address"]: node for node in nodes}
    for edge in edges:
        if (
            not edge.get("resolved")
            or edge.get("kind") not in ("branch", "fallthrough")
        ):
            continue
        node = by_address.get(edge.get("source"))
        if node is None or node["base_mnemonic"] not in CONDITIONAL_MNEMONICS:
            continue
        exact_state = exact_out.get(node["address"])
        if (
            exact_state is not None
            and exact_state.get("CC") in CONDITION_VALUES
            and not _exact_edge_feasible(node, edge, exact_state)
        ):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "guarded-transfer-condition"
            continue
        range_state = range_out.get(node["address"])
        if (
            range_state is not None
            and range_state.get("CC") is not None
            and not _range_edge_feasible(node, edge, range_state)
        ):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "guarded-transfer-range-condition"


def _signature(nodes, edges, summaries, instantiations, value_analysis):
    return (
        tuple(
            (
                entry,
                tuple(
                    (
                        case.get("id"),
                        tuple(
                            (
                                repr(guard.get("left")),
                                repr(guard.get("right")),
                                tuple(guard.get("allowed") or ()),
                            )
                            for guard in case.get("guards", ())
                        ),
                        repr(case.get("register_outputs")),
                        repr(case.get("memory_outputs")),
                    )
                    for case in summary.get("guarded_cases", ())
                ),
            )
            for entry, summary in sorted(summaries.items())
        ),
        tuple(
            (
                address,
                tuple(item.get("feasible_cases") or ()),
                repr(item.get("exact_registers")),
                repr(item.get("range_registers")),
                repr(item.get("exact_memory")),
                repr(item.get("range_memory")),
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
            for address, fact in sorted(
                value_analysis["instruction_facts"].items()
            )
        ),
    )


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
    """Instantiate bounded guarded summaries and feed selected cases into CFG facts."""
    inferred = infer_guarded_transfer_summaries(
        nodes,
        edges,
        base_summaries or {},
    )
    summaries = inferred["summary_map"]
    cells, _ = _tracked_cells(nodes)
    seeds = seed_initialized_memory(
        image,
        image_start,
        debug_map,
        cells,
    )
    initial = {} if base_register is None else {"B": base_register}

    exact_in = {node["address"]: node.get("registers_in") for node in nodes}
    exact_out = {node["address"]: node.get("registers_out") for node in nodes}
    range_in = {node["address"]: node.get("ranges_in") for node in nodes}
    range_out = {node["address"]: node.get("ranges_out") for node in nodes}
    value_analysis = analyze_symbolic_input_memory_values(
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
        combined = _merge_instantiations(base_instantiations, guarded)
        value_analysis = analyze_symbolic_input_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            base_memory_summaries or {},
            base_memory_instantiations or {},
            base_summaries or {},
            combined,
        )
        _attach_value_facts(nodes, value_analysis)

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
                None if exact_in[address] is None
                else _copy_exact_state(exact_in[address])
            )
            node["registers_out"] = (
                None if exact_out[address] is None
                else _copy_exact_state(exact_out[address])
            )
            node["ranges_in"] = (
                None if range_in[address] is None
                else dict(range_in[address])
            )
            node["ranges_out"] = (
                None if range_out[address] is None
                else dict(range_out[address])
            )

        if _resolve_base_targets(nodes, exact_in, range_in):
            edges[:] = _rebuild_edges(nodes)
            previous = None
            continue

        _mark_impossible_edges(nodes, edges, exact_out, range_out)
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
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": summaries,
                "summaries": [summaries[key] for key in sorted(summaries)],
                "instantiations": final_guarded,
                "value_analysis": value_analysis,
                "base_resolutions": sum(
                    1 for node in nodes
                    if node.get("target_resolution") == "guarded-transfer-base"
                ),
                "range_base_resolutions": sum(
                    1 for node in nodes
                    if node.get("target_resolution") == "guarded-transfer-range-base"
                ),
                "guarded_functions": sum(
                    1 for summary in summaries.values()
                    if summary.get("guarded_supported")
                ),
                "guarded_cases": sum(
                    len(summary.get("guarded_cases") or ())
                    for summary in summaries.values()
                ),
            }
        previous = signature

    raise GuardedTransferError("Guarded transfer/CFG refinement did not converge")
