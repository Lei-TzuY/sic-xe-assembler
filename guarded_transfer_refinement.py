import guarded_transfers as _legacy
from static_analysis import summarize_subroutines


class GuardedRefinementError(ValueError):
    pass


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    """Infer guarded cases from pristine structural CFG shape.

    Earlier analysis layers may have pruned caller-specific callee paths.  A
    reusable guarded summary must never inherit those path-existence choices,
    so return sites and control-flow proof fields are rebuilt from structural
    instruction edges.  Older summaries remain value-transfer hints only.
    """
    structural_edges = _legacy._rebuild_edges(nodes)
    structural = summarize_subroutines(nodes, structural_edges)
    entries = sorted(set(structural) | set(base_summaries or {}))

    available = {}
    for entry in entries:
        merged = dict((base_summaries or {}).get(entry) or {})
        shape = structural.get(entry)
        if shape is not None:
            # Structural facts are authoritative.  In particular return_sites,
            # may_return and link_register_preserved must not come from a
            # caller-specialized predecessor analysis.
            merged.update(shape)
        available[entry] = merged

    result = {}
    for entry in entries:
        item = dict(available[entry])
        analyzed = _legacy._analyze_guarded_function(
            nodes,
            structural_edges,
            item,
            available,
        )
        item["guarded_supported"] = analyzed["supported"]
        item["guarded_reason"] = analyzed["reason"]
        item["guarded_cases"] = analyzed["cases"]
        item["guarded_case_count"] = len(analyzed["cases"])
        item["guarded_explored_states"] = analyzed.get(
            "explored_states", 0
        )
        result[entry] = item

    return {
        "summary_map": result,
        "summaries": [result[key] for key in sorted(result)],
    }


def _total_memory_outputs(summary):
    """Return cells explicitly represented on every guarded return case.

    The v1 case schema intentionally omits both identity outputs and unknown
    outputs.  Until those two states have distinct serialization, a missing
    memory output is ambiguous.  Requiring a cell on every case keeps caller
    must-memory updates sound and preserves the legacy partial-write contract.
    """
    cases = list((summary or {}).get("guarded_cases") or ())
    if not cases:
        return set()
    total = set((cases[0].get("memory_outputs") or {}).keys())
    for case in cases[1:]:
        total &= set((case.get("memory_outputs") or {}).keys())
    return total


def instantiate_guarded_calls(
    nodes,
    summaries,
    exact_out,
    range_out,
    memory_in,
):
    result = _legacy.instantiate_guarded_calls(
        nodes,
        summaries,
        exact_out,
        range_out,
        memory_in,
    )

    # Register outputs are path-local expressions and are safe to consume from
    # the feasible cases.  Memory writes need a stronger rule because an
    # omitted cell currently conflates identity with unknown.  Filter concrete
    # memory postconditions to cells represented on every guarded case.
    for address, item in result.items():
        summary = (summaries or {}).get(item.get("callee_entry"))
        total_cells = _total_memory_outputs(summary)
        item["exact_memory"] = {
            cell_id: value
            for cell_id, value in (item.get("exact_memory") or {}).items()
            if cell_id in total_cells
        }
        item["range_memory"] = {
            cell_id: value
            for cell_id, value in (item.get("range_memory") or {}).items()
            if cell_id in total_cells
        }
    return result


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
    """Instantiate hardened guarded summaries and feed them into CFG facts."""
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
        node["address"]: node.get("registers_in") for node in nodes
    }
    exact_out = {
        node["address"]: node.get("registers_out") for node in nodes
    }
    range_in = {
        node["address"]: node.get("ranges_in") for node in nodes
    }
    range_out = {
        node["address"]: node.get("ranges_out") for node in nodes
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
                None if range_in[address] is None else dict(range_in[address])
            )
            node["ranges_out"] = (
                None if range_out[address] is None else dict(range_out[address])
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
            return {
                "iterations": iteration,
                "converged": True,
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
            }
        previous = signature

    raise GuardedRefinementError(
        "Guarded transfer/CFG refinement did not converge"
    )
