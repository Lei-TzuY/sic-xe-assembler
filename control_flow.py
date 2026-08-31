from control_flow_core import *
from control_flow_core import analyze_control_flow as _analyze_control_flow_core
from control_flow_core import annotate_typed_disassembly as _annotate_typed_disassembly_core
from control_flow_core import render_control_flow_report as _render_control_flow_report_core
from function_analysis import analyze_functions
from liveness_analysis import analyze_liveness
from memory_analysis import analyze_memory_dataflow, enrich_function_memory_contracts
from reaching_definitions import analyze_reaching_definitions, enrich_function_contracts


def _summary_map(report):
    return {
        summary["entry"]: summary
        for summary in report.get("subroutines", ())
        if summary.get("entry") is not None
    }


def _enrich_control_flow(report):
    nodes = report.get("instructions", [])
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

    memory = analyze_memory_dataflow(
        nodes,
        edges,
        report.get("entry_address"),
    )
    for node in nodes:
        facts = memory.get("instruction_facts", {}).get(node["address"], {})
        node["memory_cell_read"] = facts.get("memory_read")
        node["memory_cell_write"] = facts.get("memory_write")
        node["memory_sources"] = list(facts.get("memory_sources") or ())
        node["load_from_stores"] = list(facts.get("load_from_stores") or ())
        node["memory_constant"] = facts.get("memory_constant")
        node["loaded_register_constant"] = facts.get("loaded_register_constant")
        node["store_definition_id"] = facts.get("store_definition_id")
        node["stored_constant"] = facts.get("stored_constant")
        node["unknown_memory_read"] = bool(facts.get("unknown_memory_read"))
        node["unknown_memory_write"] = bool(facts.get("unknown_memory_write"))
        node["memory_barrier"] = bool(facts.get("memory_barrier"))
        node["reaching_memory_in"] = dict(facts.get("reaching_memory_in") or {})
        node["reaching_memory_out"] = dict(facts.get("reaching_memory_out") or {})

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
    return _enrich_control_flow(report)


def _format_values(values):
    return ",".join(values) if values else "-"


def _format_optional_constant(value):
    return "?" if value is None else f"{value:06X}"


def render_control_flow_report(report):
    base = _render_control_flow_report_core(report).rstrip("\n")
    lines = [base, "", "LIVENESS"]
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
        if write_cell:
            parts.append(
                f"write={write_cell}={node.get('store_definition_id') or '?'}"
            )
            if node.get("stored_constant") is not None:
                parts.append(f"stored={_format_optional_constant(node['stored_constant'])}")
        if node.get("memory_barrier"):
            parts.append("barrier")
        if node.get("unknown_memory_read"):
            parts.append("unknown-read")
        if node.get("unknown_memory_write"):
            parts.append("unknown-write")
        lines.append(f"  {node['address']:05X} " + " ".join(parts))
    if not any_memory:
        lines.append("  -")

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

    lines.extend(["", "FUNCTIONS"])
    if report.get("functions"):
        for function in report["functions"]:
            metrics = function.get("metrics", {})
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
            if node.get("store_definition_id"):
                additions.append("mem_def=" + node["store_definition_id"])
            if node.get("functions"):
                additions.append("functions=" + ",".join(node["functions"]))
        if additions:
            line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
