import control_flow_enrichment_base as _base
from control_flow_enrichment_base import *
from control_flow_enrichment_base import analyze_control_flow as _analyze_control_flow_base
from control_flow_enrichment_base import annotate_typed_disassembly as _annotate_typed_disassembly_base
from control_flow_enrichment_base import render_control_flow_report as _render_control_flow_report_base
from callsite_transfers import refine_callsite_transfers
from function_analysis import analyze_functions
from liveness_analysis import analyze_liveness
from memory_analysis import enrich_function_memory_contracts
from memory_feedback import analyze_effect_aware_memory
from reaching_definitions import analyze_reaching_definitions, enrich_function_contracts


def _summary_by_entry(items):
    return {
        item["entry"]: item
        for item in (items or ())
        if item.get("entry") is not None
    }


def _refresh_after_callsite_transfer(report, refinement):
    """Recompute CFG-dependent compiler analyses after symbolic call refinement."""
    nodes = report.get("instructions", [])
    old_metrics = dict(report.get("metrics") or {})

    _base._rebuild_structure(report)
    graph_metrics = dict(report.get("metrics") or {})
    old_metrics.update(graph_metrics)
    report["metrics"] = old_metrics

    edges = report.get("edges", [])
    blocks = report.get("blocks", [])
    summaries = _base._summary_map(report)

    liveness = analyze_liveness(nodes, edges, summaries=summaries)
    for node in nodes:
        facts = liveness.get(node["address"], {})
        node["uses"] = list(facts.get("uses") or ())
        node["defs"] = list(facts.get("defs") or ())
        node["live_in"] = list(facts.get("live_in") or ())
        node["live_out"] = list(facts.get("live_out") or ())
        node["dead_writes"] = list(facts.get("dead_writes") or ())
        node["dead_condition_write"] = bool(facts.get("dead_condition_write"))
        node["memory_read"] = bool(facts.get("memory_read"))
        node["memory_write"] = bool(facts.get("memory_write"))
        node["side_effects"] = bool(facts.get("side_effects"))
        node["opaque_liveness"] = bool(facts.get("opaque"))

    reaching = analyze_reaching_definitions(
        nodes,
        edges,
        report.get("entry_address"),
        summaries=summaries,
        liveness=liveness,
    )
    for node in nodes:
        facts = reaching.get("instruction_facts", {}).get(node["address"], {})
        node["reaching_in"] = dict(facts.get("reaching_in") or {})
        node["reaching_out"] = dict(facts.get("reaching_out") or {})
        node["use_definitions"] = dict(facts.get("use_definitions") or {})
        node["definition_ids"] = dict(facts.get("definition_ids") or {})
        node["unresolved_uses"] = list(facts.get("unresolved_uses") or ())

    # Recompute may-reaching memory provenance for the refined graph, but do not
    # overwrite the richer must-value annotations already attached by the base
    # memory/postcondition layers.
    memory = analyze_effect_aware_memory(
        nodes,
        edges,
        report.get("entry_address"),
    )

    functions, ownership, entry_to_id = analyze_functions(
        nodes,
        edges,
        blocks,
        report.get("entry_address"),
        summaries,
        liveness,
    )
    enrich_function_contracts(functions, reaching)
    enrich_function_memory_contracts(functions, memory)

    memory_summary_by_entry = _summary_by_entry(report.get("memory_effect_summaries"))
    register_summary_by_entry = _summary_by_entry(report.get("register_return_summaries"))
    transfer_summary_by_entry = dict(refinement.get("summary_map") or {})
    instantiations = dict(refinement.get("instantiations") or {})

    for function in functions:
        entry = function["entry"]
        function["memory_effect_summary"] = memory_summary_by_entry.get(entry)
        function["register_return_summary"] = register_summary_by_entry.get(entry)
        function["register_transfer_summary"] = transfer_summary_by_entry.get(entry)

    for node in nodes:
        node["functions"] = list(ownership.get(node["address"], ()))
    for block in blocks:
        owners = set()
        for address in block.get("instruction_addresses", ()):
            owners.update(ownership.get(address, ()))
        block["functions"] = sorted(owners)

    for call in report.get("calls", ()):
        source = call.get("source")
        target = call.get("target")
        call["caller_functions"] = list(ownership.get(source, ()))
        call["callee_function"] = entry_to_id.get(target) if call.get("resolved") else None
        call["memory_effect_summary"] = memory_summary_by_entry.get(target)
        call["register_return_summary"] = register_summary_by_entry.get(target)
        call["register_transfer_summary"] = transfer_summary_by_entry.get(target)
        call["transfer_instantiation"] = instantiations.get(source)

    dead_writes = [
        {"address": node["address"], "registers": list(node["dead_writes"])}
        for node in nodes
        if node.get("dead_writes")
    ]
    report["functions"] = functions
    report["dead_writes"] = dead_writes
    report["definitions"] = list(reaching.get("definitions") or ())
    report["def_use_chains"] = list(reaching.get("chains") or ())
    report["unresolved_uses"] = list(reaching.get("unresolved_uses") or ())
    report["dead_definitions"] = list(reaching.get("dead_definitions") or ())
    report["memory_cells"] = list(memory.get("cells") or ())
    report["memory_definitions"] = list(memory.get("definitions") or ())
    report["memory_def_use_chains"] = list(memory.get("chains") or ())
    report["unresolved_memory_reads"] = list(memory.get("unresolved_reads") or ())
    report["overwritten_stores"] = list(memory.get("overwritten_stores") or ())
    report["same_value_store_candidates"] = list(memory.get("same_value_store_candidates") or ())
    report["register_transfer_summaries"] = list(refinement.get("summaries") or ())
    report["callsite_transfer_instantiations"] = [
        {"call_address": address, **item}
        for address, item in sorted(instantiations.items())
    ]
    report["callsite_transfers"] = {
        "iterations": refinement.get("iterations"),
        "converged": bool(refinement.get("converged")),
        "base_resolutions": refinement.get("base_resolutions", 0),
        "range_base_resolutions": refinement.get("range_base_resolutions", 0),
    }

    metrics = report.setdefault("metrics", {})
    metrics["functions"] = len(functions)
    metrics["dead_register_writes"] = sum(len(item["registers"]) for item in dead_writes)
    metrics["instructions_with_dead_writes"] = len(dead_writes)
    metrics["reaching_definitions"] = len(report["definitions"])
    metrics["def_use_links"] = sum(
        len(chain.get("use_sites") or ()) for chain in report["def_use_chains"]
    )
    metrics["unresolved_uses"] = len(report["unresolved_uses"])
    metrics["memory_cells"] = len(report["memory_cells"])
    metrics["memory_definitions"] = len(report["memory_definitions"])
    metrics["memory_def_use_links"] = sum(
        len(chain.get("use_sites") or ()) for chain in report["memory_def_use_chains"]
    )
    metrics["overwritten_stores"] = len(report["overwritten_stores"])
    metrics["same_value_store_candidates"] = len(report["same_value_store_candidates"])
    metrics["callsite_transfer_iterations"] = refinement.get("iterations", 0)
    metrics["symbolic_return_transfers"] = sum(
        len(summary.get("return_transfers") or {})
        for summary in report["register_transfer_summaries"]
    )
    metrics["callsite_transfer_instantiations"] = len(instantiations)
    metrics["callsite_transfer_base_resolutions"] = refinement.get("base_resolutions", 0)
    metrics["callsite_transfer_range_base_resolutions"] = refinement.get("range_base_resolutions", 0)
    metrics["callsite_transfer_pruned_edges"] = sum(
        1
        for edge in edges
        if edge.get("resolution") in (
            "call-transfer-condition",
            "call-transfer-range-condition",
        )
        and not edge.get("resolved")
    )
    return report


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    report = _analyze_control_flow_base(
        image,
        image_start,
        debug_map,
        entry_address,
        base_register=base_register,
    )
    refinement = refine_callsite_transfers(
        report.get("instructions", []),
        report.get("edges", []),
        report.get("entry_address"),
        register_summaries=_summary_by_entry(report.get("register_return_summaries")),
        base_register=base_register,
    )
    return _refresh_after_callsite_transfer(report, refinement)


def _format_transfer(spec):
    if not spec:
        return "?"
    if spec.get("kind") == "constant":
        return f"{spec.get('value', 0):06X}"
    source = spec.get("source", "?")
    scale = spec.get("scale", 1)
    offset = spec.get("offset", 0)
    if scale == 1:
        prefix = source
    elif scale == -1:
        prefix = f"-{source}"
    else:
        prefix = f"{scale}*{source}"
    if offset > 0:
        return f"{prefix}+{offset}"
    if offset < 0:
        return f"{prefix}{offset}"
    return prefix


def render_control_flow_report(report):
    base = _render_control_flow_report_base(report).rstrip("\n")
    status = report.get("callsite_transfers") or {}
    lines = [
        base,
        "",
        (
            "CALL-SITE SYMBOLIC TRANSFERS "
            f"iterations={status.get('iterations', 0)} "
            f"converged={str(bool(status.get('converged'))).lower()} "
            f"base-resolved={status.get('base_resolutions', 0)} "
            f"range-base-resolved={status.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('callsite_transfer_pruned_edges', 0)}"
        ),
    ]
    any_summary = False
    for summary in report.get("register_transfer_summaries", ()):
        transfers = summary.get("return_transfers") or {}
        if not transfers:
            continue
        any_summary = True
        rendered = ",".join(
            f"{register}={_format_transfer(spec)}"
            for register, spec in sorted(transfers.items())
        )
        lines.append(
            f"  {summary['entry']:05X} transfer={rendered} "
            f"inputs={','.join(summary.get('transfer_input_registers') or ()) or '-'} "
            f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
        )
    if not any_summary:
        lines.append("  -")

    if report.get("callsite_transfer_instantiations"):
        lines.append("  call-site instantiations:")
        for item in report["callsite_transfer_instantiations"]:
            exact = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted((item.get("exact") or {}).items())
            ) or "-"
            ranges = ",".join(
                f"{register}={_base._format_optional_range(interval)}"
                for register, interval in sorted((item.get("ranges") or {}).items())
            ) or "-"
            lines.append(
                f"    {item['call_address']:05X} -> {item.get('callee_entry', 0):05X} "
                f"exact={exact} range={ranges}"
            )
    return "\n".join(lines) + "\n"


def annotate_typed_disassembly(rendered, debug_map, control_flow=None):
    annotated = _annotate_typed_disassembly_base(
        rendered,
        debug_map,
        control_flow=control_flow,
    )
    if control_flow is None:
        return annotated
    by_address = {
        node["address"]: node
        for node in control_flow.get("instructions", ())
    }
    lines = []
    for line in annotated.splitlines():
        parts = line.split(None, 1)
        try:
            address = int(parts[0], 16) if len(parts) > 1 and len(parts[0]) == 5 else None
        except ValueError:
            address = None
        node = by_address.get(address)
        instantiation = None if node is None else node.get("call_transfer_instantiation")
        if instantiation:
            exact = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted((instantiation.get("exact") or {}).items())
            )
            ranges = ",".join(
                f"{register}={_base._format_optional_range(interval)}"
                for register, interval in sorted((instantiation.get("ranges") or {}).items())
            )
            additions = []
            if exact:
                additions.append("call_xfer=" + exact)
            if ranges:
                additions.append("call_xfer_range=" + ranges)
            if additions:
                line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
