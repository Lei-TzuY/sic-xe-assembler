from control_flow_core import *
from control_flow_core import analyze_control_flow as _analyze_control_flow_core
from control_flow_core import annotate_typed_disassembly as _annotate_typed_disassembly_core
from control_flow_core import render_control_flow_report as _render_control_flow_report_core
from function_analysis import analyze_functions
from liveness_analysis import analyze_liveness


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

    functions, ownership, entry_to_id = analyze_functions(
        nodes,
        edges,
        blocks,
        report.get("entry_address"),
        summaries,
        liveness,
    )
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
    metrics = report.setdefault("metrics", {})
    metrics["functions"] = len(functions)
    metrics["dead_register_writes"] = sum(
        len(item["registers"])
        for item in dead_writes
    )
    metrics["instructions_with_dead_writes"] = len(dead_writes)
    return report


def analyze_control_flow(image, image_start, debug_map, entry_address, base_register=None):
    """Build the historical CFG and enrich it with liveness/function analysis."""
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
            if node.get("functions"):
                additions.append("functions=" + ",".join(node["functions"]))
        if additions:
            line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
