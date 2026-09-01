import guarded_transfers as _legacy
from guarded_case_feasibility import conjunctive_case_feasible

_legacy._case_feasible = conjunctive_case_feasible

import guarded_return_refinement as _base
from memory_feedback import summarize_memory_effects


_RETURN_FIELDS = (
    "returnability_known",
    "return_mode",
    "must_return",
    "may_return",
    "must_not_return",
    "return_feasible_cases",
    "return_ruled_out_cases",
)


def _structural_base_summaries(nodes, base_summaries):
    """Replace caller-specialized memory shape with pristine CFG effects."""
    structural_edges = _legacy._rebuild_edges(nodes)
    cells, operations = _legacy._tracked_cells(nodes)
    memory_effects = summarize_memory_effects(
        nodes,
        structural_edges,
        cells,
        operations,
    )
    entries = set(base_summaries or {}) | set(memory_effects)
    result = {}
    for entry in entries:
        merged = dict((base_summaries or {}).get(entry) or {})
        effect = memory_effects.get(entry)
        if effect is not None:
            for key in (
                "may_read_cells",
                "may_write_cells",
                "unknown_read",
                "unknown_write",
                "preserved_cells",
            ):
                merged[key] = effect[key]
        result[entry] = merged
    return result


def _respect_link_gate(nodes, result):
    """Keep the historical L gate except for a positive no-return proof.

    Register/memory/CC postconditions require a proven return to the caller.
    Returnability can add one useful exception: a proven no-return case remains
    actionable even when L preservation is not proven because no continuation
    state is consumed. Unknown/mixed/returning metadata must not create a new
    guarded call-site instantiation behind the established L gate.
    """
    summaries = result.get("summary_map") or {}
    instantiations = result.get("instantiations") or {}
    by_address = {node["address"]: node for node in nodes}
    for address in list(instantiations):
        node = by_address.get(address)
        if node is None or node.get("base_mnemonic") != "JSUB":
            continue
        summary = summaries.get(node.get("target")) or {}
        if summary.get("link_register_preserved"):
            continue
        item = instantiations[address]
        if item.get("return_mode") == "no-return":
            continue
        for field in _RETURN_FIELDS:
            item.pop(field, None)
        if not item:
            instantiations.pop(address, None)
            node.pop("guarded_transfer_instantiation", None)
    return result


def infer_guarded_transfer_summaries(nodes, edges, base_summaries):
    return _base.infer_guarded_transfer_summaries(
        nodes,
        edges,
        _structural_base_summaries(nodes, base_summaries),
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
    result = _base.refine_guarded_transfers(
        nodes,
        edges,
        entry_address,
        image,
        image_start,
        debug_map,
        base_summaries=_structural_base_summaries(
            nodes,
            base_summaries,
        ),
        base_instantiations=base_instantiations,
        base_memory_summaries=base_memory_summaries,
        base_memory_instantiations=base_memory_instantiations,
        base_register=base_register,
    )
    return _respect_link_gate(nodes, result)
