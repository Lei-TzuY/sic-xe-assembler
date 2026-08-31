import control_flow_core as _core
from control_flow_core import *
from control_flow_core import analyze_control_flow as _analyze_control_flow_core
from control_flow_core import annotate_typed_disassembly as _annotate_typed_disassembly_core
from control_flow_core import render_control_flow_report as _render_control_flow_report_core
from function_analysis import analyze_functions
from liveness_analysis import analyze_liveness
from memory_analysis import enrich_function_memory_contracts
from memory_feedback import (
    _attach_memory_facts,
    analyze_effect_aware_memory,
    refine_memory_feedback,
)
from memory_postconditions import (
    attach_final_value_facts,
    refine_initialized_memory_postconditions,
)
from reaching_definitions import analyze_reaching_definitions, enrich_function_contracts
from register_postconditions import refine_register_postconditions
from static_analysis import summarize_subroutines


def _summary_map(report):
    return {
        summary["entry"]: summary
        for summary in report.get("subroutines", ())
        if summary.get("entry") is not None
    }


def _rebuild_structure(report):
    """Recompute structural CFG products after feedback prunes control edges."""
    nodes = report.get("instructions", [])
    edges = report.get("edges", [])
    entry = report.get("entry_address")
    reachable = _core._reachable_addresses(entry, nodes, edges)
    for node in nodes:
        node["reachable"] = node["address"] in reachable

    blocks, address_to_block = _core._build_blocks(entry, nodes, edges, reachable)
    for node in nodes:
        node["block"] = address_to_block.get(node["address"])

    dominators, entry_block = _core._compute_dominators(
        entry, blocks, address_to_block, edges
    )
    for block in blocks:
        block["dominators"] = dominators.get(block["id"], [])
    back_edges, loops = _core._natural_loops(blocks, edges, dominators)
    summaries = summarize_subroutines(nodes, edges)
    calls = _core._call_graph(nodes, edges)
    metrics = _core._graph_metrics(blocks, edges, nodes, loops)

    report["blocks"] = blocks
    report["entry_block"] = entry_block
    report["entry_resolved"] = any(node["address"] == entry for node in nodes)
    report["dominators"] = dominators
    report["back_edges"] = back_edges
    report["loops"] = loops
    report["calls"] = calls
    report["subroutines"] = [summaries[address] for address in sorted(summaries)]
    report["metrics"] = metrics
    report["reachable_instruction_count"] = len(reachable)
    report["unreachable_instruction_count"] = len(nodes) - len(reachable)
    return report


def _enrich_control_flow(
    report,
    image,
    image_start,
    debug_map,
    base_register=None,
):
    nodes = report.get("instructions", [])
    edges = report.get("edges", [])

    # Preserve the historical register/range <-> reaching-store refinement.
    feedback_memory = refine_memory_feedback(
        nodes,
        edges,
        report.get("entry_address"),
        base_register=base_register,
    )

    # Then add a must-value memory domain. It seeds typed initialized bytes from
    # the relocated linked image, composes callee return memory postconditions,
    # and can resolve b-relative targets when B is proven through memory.
    value_refinement = refine_initialized_memory_postconditions(
        nodes,
        edges,
        report.get("entry_address"),
        image,
        image_start,
        debug_map,
        base_register=base_register,
    )

    # Finally infer caller-independent register return contracts from unknown
    # function-entry state and feed them back through the richer memory-aware
    # caller analysis. This can prove post-call comparisons/branches and B-based
    # targets without making callee summaries depend on one caller's memory.
    register_refinement = refine_register_postconditions(
        nodes,
        edges,
        report.get("entry_address"),
        base_register=base_register,
    )

    _rebuild_structure(report)
    edges = report.get("edges", [])
    blocks = report.get("blocks", [])
    summaries = _summary_map(report)

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

    # Keep may-reaching store provenance independent from must-value facts.
    memory = analyze_effect_aware_memory(
        nodes,
        edges,
        report.get("entry_address"),
    )
    _attach_memory_facts(nodes, memory)
    attach_final_value_facts(nodes, value_refinement)

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

    value_summary_by_entry = dict(value_refinement.get("summary_map") or {})
    register_summary_by_entry = dict(register_refinement.get("summary_map") or {})
    for function in functions:
        function["memory_effect_summary"] = value_summary_by_entry.get(function["entry"])
        function["register_return_summary"] = register_summary_by_entry.get(function["entry"])
    for node in nodes:
        node["functions"] = list(ownership.get(node["address"], ()))
    for block in blocks:
        owners = set()
        for address in block.get("instruction_addresses", ()):
            owners.update(ownership.get(address, ()))
        block["functions"] = sorted(owners)

    for call in report.get("calls", ()):
        call["caller_functions"] = list(ownership.get(call.get("source"), ()))
        call["callee_function"] = (
            entry_to_id.get(call.get("target"))
            if call.get("resolved")
            else None
        )
        call["memory_effect_summary"] = value_summary_by_entry.get(call.get("target"))
        call["register_return_summary"] = register_summary_by_entry.get(call.get("target"))

    dead_writes = [
        {
            "address": node["address"],
            "registers": list(node["dead_writes"]),
        }
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
    report["memory_effect_summaries"] = list(value_refinement.get("summaries") or ())
    report["initialized_memory"] = list(value_refinement.get("seeds") or ())
    report["register_return_summaries"] = list(register_refinement.get("summaries") or ())
    report["memory_feedback"] = {
        "iterations": feedback_memory.get("feedback_iterations"),
        "converged": bool(feedback_memory.get("feedback_converged")),
        "value_iterations": value_refinement.get("iterations"),
        "value_converged": bool(value_refinement.get("converged")),
        "initialized_cells": len(report["initialized_memory"]),
        "memory_base_resolutions": value_refinement.get("memory_base_resolutions", 0),
        "memory_range_base_resolutions": value_refinement.get("memory_range_base_resolutions", 0),
    }
    report["register_postconditions"] = {
        "iterations": register_refinement.get("iterations"),
        "converged": bool(register_refinement.get("converged")),
        "base_resolutions": register_refinement.get("base_resolutions", 0),
        "range_base_resolutions": register_refinement.get("range_base_resolutions", 0),
    }

    metrics = report.setdefault("metrics", {})
    metrics["functions"] = len(functions)
    metrics["dead_register_writes"] = sum(
        len(item["registers"])
        for item in dead_writes
    )
    metrics["instructions_with_dead_writes"] = len(dead_writes)
    metrics["reaching_definitions"] = len(report["definitions"])
    metrics["def_use_links"] = sum(
        len(chain.get("use_sites") or ())
        for chain in report["def_use_chains"]
    )
    metrics["unresolved_uses"] = len(report["unresolved_uses"])
    metrics["memory_cells"] = len(report["memory_cells"])
    metrics["memory_definitions"] = len(report["memory_definitions"])
    metrics["memory_def_use_links"] = sum(
        len(chain.get("use_sites") or ())
        for chain in report["memory_def_use_chains"]
    )
    metrics["overwritten_stores"] = len(report["overwritten_stores"])
    metrics["same_value_store_candidates"] = len(report["same_value_store_candidates"])
    metrics["memory_effect_summaries"] = len(report["memory_effect_summaries"])
    metrics["memory_feedback_iterations"] = feedback_memory.get("feedback_iterations", 0)
    metrics["memory_value_iterations"] = value_refinement.get("iterations", 0)
    metrics["initialized_memory_cells"] = len(report["initialized_memory"])
    metrics["memory_base_resolutions"] = value_refinement.get("memory_base_resolutions", 0)
    metrics["memory_range_base_resolutions"] = value_refinement.get("memory_range_base_resolutions", 0)
    metrics["return_memory_postconditions"] = sum(
        len(summary.get("return_value_cells") or ())
        for summary in report["memory_effect_summaries"]
    )
    metrics["register_postcondition_iterations"] = register_refinement.get("iterations", 0)
    metrics["return_register_postconditions"] = sum(
        len(summary.get("return_value_registers") or ())
        for summary in report["register_return_summaries"]
    )
    metrics["register_postcondition_base_resolutions"] = register_refinement.get("base_resolutions", 0)
    metrics["register_postcondition_range_base_resolutions"] = register_refinement.get("range_base_resolutions", 0)
    metrics["memory_feedback_pruned_edges"] = sum(
        1
        for edge in edges
        if edge.get("resolution") in (
            "memory-feedback-condition",
            "memory-feedback-range-condition",
        )
        and not edge.get("resolved")
    )
    metrics["register_postcondition_pruned_edges"] = sum(
        1
        for edge in edges
        if edge.get("resolution") in (
            "register-postcondition-condition",
            "register-postcondition-range-condition",
        )
        and not edge.get("resolved")
    )
    return report


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    """Build the historical CFG and enrich it with compiler-style analyses."""
    report = _analyze_control_flow_core(
        image,
        image_start,
        debug_map,
        entry_address,
        base_register=base_register,
    )
    return _enrich_control_flow(
        report,
        image,
        image_start,
        debug_map,
        base_register=base_register,
    )


def _format_values(values):
    return ",".join(values) if values else "-"


def _format_optional_constant(value):
    return "?" if value is None else f"{value:06X}"


def _format_optional_range(value):
    if value is None:
        return "?"
    low, high = value
    return str(low) if low == high else f"[{low},{high}]"


def _format_summary_constants(summary):
    values = summary.get("return_constants") or {}
    return ",".join(f"{name}={value:06X}" for name, value in sorted(values.items())) or "-"


def _format_summary_ranges(summary):
    values = summary.get("return_ranges") or {}
    return ",".join(
        f"{name}={_format_optional_range(interval)}"
        for name, interval in sorted(values.items())
    ) or "-"


def render_control_flow_report(report):
    base = _render_control_flow_report_core(report).rstrip("\n")
    feedback = report.get("memory_feedback") or {}
    register_feedback = report.get("register_postconditions") or {}
    lines = [
        base,
        "",
        (
            "MEMORY FEEDBACK "
            f"iterations={feedback.get('iterations', 0)} "
            f"converged={str(bool(feedback.get('converged'))).lower()} "
            f"values={feedback.get('value_iterations', 0)} "
            f"values-converged={str(bool(feedback.get('value_converged'))).lower()} "
            f"initialized={feedback.get('initialized_cells', 0)} "
            f"base-resolved={feedback.get('memory_base_resolutions', 0)} "
            f"range-base-resolved={feedback.get('memory_range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('memory_feedback_pruned_edges', 0)}"
        ),
        (
            "REGISTER POSTCONDITIONS "
            f"iterations={register_feedback.get('iterations', 0)} "
            f"converged={str(bool(register_feedback.get('converged'))).lower()} "
            f"base-resolved={register_feedback.get('base_resolutions', 0)} "
            f"range-base-resolved={register_feedback.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('register_postcondition_pruned_edges', 0)}"
        ),
        "",
        "LIVENESS",
    ]
    any_liveness = False
    for node in report.get("instructions", ()):
        uses = node.get("uses") or ()
        defs = node.get("defs") or ()
        live_in = node.get("live_in") or ()
        live_out = node.get("live_out") or ()
        dead = node.get("dead_writes") or ()
        if not uses and not defs and not dead:
            continue
        any_liveness = True
        lines.append(
            f"  {node['address']:05X} "
            f"use={_format_values(uses)} "
            f"def={_format_values(defs)} "
            f"in={_format_values(live_in)} "
            f"out={_format_values(live_out)} "
            f"dead={_format_values(dead)}"
        )
    if not any_liveness:
        lines.append("  -")

    lines.extend(["", "REACHING DEFINITIONS"])
    any_chains = False
    for node in report.get("instructions", ()):
        use_defs = node.get("use_definitions") or {}
        definition_ids = node.get("definition_ids") or {}
        if not use_defs and not definition_ids:
            continue
        any_chains = True
        uses = ";".join(
            f"{value}<-{','.join(definitions) or '?'}"
            for value, definitions in sorted(use_defs.items())
        ) or "-"
        defs = ",".join(
            f"{value}={definition_id}"
            for value, definition_id in sorted(definition_ids.items())
        ) or "-"
        lines.append(f"  {node['address']:05X} uses={uses} defs={defs}")
    if not any_chains:
        lines.append("  -")

    lines.extend(["", "MEMORY DATAFLOW"])
    if report.get("initialized_memory"):
        lines.append("  initialized cells:")
        for item in report["initialized_memory"]:
            parts = [
                f"    {item['cell']}",
                f"kind={item['region_kind']}",
                f"bytes={item['bytes']}",
            ]
            if item.get("constant") is not None:
                parts.append(f"value={_format_optional_constant(item['constant'])}")
            lines.append(" ".join(parts))

    any_memory = False
    for node in report.get("instructions", ()):
        read_cell = node.get("memory_cell_read")
        write_cell = node.get("memory_cell_write")
        if not read_cell and not write_cell and not node.get("memory_barrier") and not node.get("unknown_memory_write"):
            continue
        any_memory = True
        parts = []
        if read_cell:
            parts.append(
                f"read={read_cell}<-{','.join(node.get('memory_sources') or ()) or '?'}"
            )
            if node.get("memory_constant") is not None:
                parts.append(f"value={_format_optional_constant(node['memory_constant'])}")
            if node.get("memory_range") is not None:
                parts.append(f"range={_format_optional_range(node['memory_range'])}")
            if node.get("memory_value_resolution"):
                parts.append(f"via={node['memory_value_resolution']}")
        if write_cell:
            parts.append(
                f"write={write_cell}={node.get('store_definition_id') or '?'}"
            )
            if node.get("stored_constant") is not None:
                parts.append(f"stored={_format_optional_constant(node['stored_constant'])}")
            if node.get("stored_range") is not None:
                parts.append(f"stored-range={_format_optional_range(node['stored_range'])}")
        if node.get("memory_barrier"):
            parts.append("barrier")
        if node.get("unknown_memory_read"):
            parts.append("unknown-read")
        if node.get("unknown_memory_write"):
            parts.append("unknown-write")
        lines.append(f"  {node['address']:05X} " + " ".join(parts))
    if not any_memory:
        lines.append("  -")

    if report.get("memory_effect_summaries"):
        lines.append("  callee memory summaries:")
        for summary in report["memory_effect_summaries"]:
            lines.append(
                f"    {summary['entry']:05X} "
                f"read={','.join(summary.get('may_read_cells') or ()) or '-'} "
                f"write={','.join(summary.get('may_write_cells') or ()) or '-'} "
                f"return={_format_summary_constants(summary)} "
                f"return-range={_format_summary_ranges(summary)} "
                f"unknown-read={str(bool(summary.get('unknown_read'))).lower()} "
                f"unknown-write={str(bool(summary.get('unknown_write'))).lower()}"
            )
    if report.get("overwritten_stores"):
        lines.append("  overwritten-store candidates:")
        for item in report["overwritten_stores"]:
            lines.append(
                f"    {item['address']:05X} {item['cell']} {item['definition_id']}"
            )
    if report.get("same_value_store_candidates"):
        lines.append("  same-value-store candidates:")
        for item in report["same_value_store_candidates"]:
            lines.append(
                f"    {item['address']:05X} {item['cell']} value={item['constant']:06X}"
            )

    lines.extend(["", "REGISTER RETURN POSTCONDITIONS"])
    if report.get("register_return_summaries"):
        for summary in report["register_return_summaries"]:
            lines.append(
                f"  {summary['entry']:05X} "
                f"return={_format_summary_constants(summary)} "
                f"return-range={_format_summary_ranges(summary)} "
                f"cc={','.join(summary.get('return_conditions') or ()) or '-'} "
                f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
            )
    else:
        lines.append("  -")

    lines.extend(["", "FUNCTIONS"])
    if report.get("functions"):
        for function in report["functions"]:
            metrics = function.get("metrics", {})
            register_summary = function.get("register_return_summary") or {}
            lines.append(
                f"  {function['id']} entry={function['entry']:05X} "
                f"symbols={','.join(function.get('symbols') or ()) or '-'} "
                f"blocks={','.join(function.get('blocks') or ()) or '-'} "
                f"callers={','.join(function.get('callers') or ()) or '-'} "
                f"callees={','.join(function.get('callees') or ()) or '-'} "
                f"required={','.join(function.get('required_inputs') or ()) or '-'} "
                f"outputs={','.join(function.get('produced_outputs') or ()) or '-'} "
                f"passthrough={','.join(function.get('passthrough_inputs') or ()) or '-'} "
                f"overwritten={','.join(function.get('overwritten_inputs') or ()) or '-'} "
                f"mem-in={','.join(function.get('memory_inputs') or ()) or '-'} "
                f"mem-out={','.join(function.get('memory_outputs') or ()) or '-'} "
                f"mem-write={','.join(function.get('memory_writes') or ()) or '-'} "
                f"ret={_format_summary_constants(register_summary)} "
                f"ret-range={_format_summary_ranges(register_summary)} "
                f"preserved={','.join(function.get('preserved') or ()) or '-'} "
                f"clobber={','.join(function.get('may_clobber') or ()) or '-'} "
                f"complexity={metrics.get('cyclomatic_complexity', 0)}"
            )
    else:
        lines.append("  -")
    return "\n".join(lines) + "\n"


def annotate_typed_disassembly(rendered, debug_map, control_flow=None):
    annotated = _annotate_typed_disassembly_core(
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
        additions = []
        if node is not None:
            if node.get("live_in"):
                additions.append("live_in=" + ",".join(node["live_in"]))
            if node.get("dead_writes"):
                additions.append("dead_writes=" + ",".join(node["dead_writes"]))
            if node.get("use_definitions"):
                additions.append(
                    "use_defs=" + ";".join(
                        f"{value}<-{','.join(definitions) or '?'}"
                        for value, definitions in sorted(node["use_definitions"].items())
                    )
                )
            if node.get("memory_cell_read"):
                additions.append(
                    "mem_src=" + ",".join(node.get("memory_sources") or ())
                )
                if node.get("memory_constant") is not None:
                    additions.append(f"mem_const={node['memory_constant']:06X}")
                elif node.get("memory_range") is not None:
                    additions.append("mem_range=" + _format_optional_range(node["memory_range"]))
                if node.get("memory_value_resolution"):
                    additions.append("mem_via=" + node["memory_value_resolution"])
            if node.get("store_definition_id"):
                additions.append("mem_def=" + node["store_definition_id"])
            if node.get("register_return_summary"):
                summary = node["register_return_summary"]
                additions.append("ret=" + _format_summary_constants(summary))
                if summary.get("return_ranges"):
                    additions.append("ret_range=" + _format_summary_ranges(summary))
            if node.get("functions"):
                additions.append("functions=" + ",".join(node["functions"]))
        if additions:
            line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")