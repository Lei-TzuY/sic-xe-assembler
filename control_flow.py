from control_flow_core import *
from control_flow_core import analyze_control_flow as _analyze_control_flow_core
from control_flow_core import annotate_typed_disassembly as _annotate_typed_disassembly_core
from control_flow_core import render_control_flow_report as _render_control_flow_report_core
from function_analysis import analyze_functions
from liveness_analysis import analyze_liveness
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

    functions, ownership, entry_to_id = analyze_functions(
        nodes,
        edges,
        blocks,
        report.get("entry_address"),
        summaries,
        liveness,
    )
    enrich_function_contracts(functions, reaching)
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
            if node.get("functions"):
                additions.append("functions=" + ",".join(node["functions"]))
        if additions:
            line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
