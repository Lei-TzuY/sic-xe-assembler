import guarded_transfers as _legacy
from guarded_case_feasibility import conjunctive_case_feasible

_legacy._case_feasible = conjunctive_case_feasible

import guarded_condition_refinement as _base
from memory_feedback import summarize_memory_effects


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
    return _base.refine_guarded_transfers(
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
