import control_flow_symbolic_inputs_base as _base
from control_flow_symbolic_inputs_base import *
from control_flow_symbolic_inputs_base import analyze_control_flow as _analyze_control_flow_base
from control_flow_symbolic_inputs_base import annotate_typed_disassembly as _annotate_typed_disassembly_base
from control_flow_symbolic_inputs_base import render_control_flow_report as _render_control_flow_report_base
from guarded_transfer_refinement import (
    infer_guarded_transfer_summaries,
    refine_guarded_transfers,
)


def _summary_by_entry(items):
    return {
        item["entry"]: item
        for item in (items or ())
        if item.get("entry") is not None
    }


def _instantiation_by_call(items):
    return {
        item["call_address"]: {
            key: value
            for key, value in item.items()
            if key != "call_address"
        }
        for item in (items or ())
        if item.get("call_address") is not None
    }


def _snapshot_symbolic_input_refinement(report):
    summaries = list(report.get("symbolic_memory_input_summaries") or ())
    instantiations = list(report.get("symbolic_memory_input_instantiations") or ())
    status = dict(report.get("symbolic_memory_inputs") or {})
    return {
        "iterations": status.get("iterations", 0),
        "converged": bool(status.get("converged")),
        "summary_map": _summary_by_entry(summaries),
        "summaries": summaries,
        "instantiations": _instantiation_by_call(instantiations),
        "base_resolutions": status.get("base_resolutions", 0),
        "range_base_resolutions": status.get("range_base_resolutions", 0),
        "return_register_transfers": status.get("return_register_transfers", 0),
        "return_memory_transfers": status.get("return_memory_transfers", 0),
    }


def _guard_base_summaries(report):
    symbolic = _summary_by_entry(report.get("symbolic_memory_input_summaries"))
    sparse = _summary_by_entry(report.get("sparse_linear_transfer_summaries"))
    result = {}
    for entry, item in symbolic.items():
        merged = dict(item)
        register = sparse.get(entry) or {}
        merged["return_constants"] = dict(register.get("return_constants") or {})
        merged["return_ranges"] = {
            key: list(value)
            for key, value in (register.get("return_ranges") or {}).items()
        }
        merged["return_conditions"] = list(register.get("return_conditions") or ())
        merged["return_linear_transfers"] = dict(
            register.get("return_linear_transfers") or {}
        )
        result[entry] = merged
    return result


def _restore_prior_ownership(report, ownership, refinement):
    _base._restore_prior_ownership(report, ownership, refinement)
    refinement["base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution") == "guarded-transfer-base"
    )
    refinement["range_base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution") == "guarded-transfer-range-base"
    )


def _attach_guarded_layer(report, refinement):
    summaries = list(refinement.get("summaries") or ())
    summary_by_entry = dict(refinement.get("summary_map") or {})
    instantiations = dict(refinement.get("instantiations") or {})
    report["guarded_transfer_summaries"] = summaries
    report["guarded_transfer_instantiations"] = [
        {"call_address": address, **item}
        for address, item in sorted(instantiations.items())
    ]
    report["guarded_transfers"] = {
        "iterations": refinement.get("iterations", 0),
        "converged": bool(refinement.get("converged")),
        "guarded_functions": refinement.get("guarded_functions", 0),
        "guarded_cases": refinement.get("guarded_cases", 0),
        "base_resolutions": refinement.get("base_resolutions", 0),
        "range_base_resolutions": refinement.get("range_base_resolutions", 0),
    }

    for node in report.get("instructions", ()):
        if node["base_mnemonic"] != "JSUB":
            continue
        source = node["address"]
        target = node.get("target")
        node["guarded_transfer_summary"] = summary_by_entry.get(target)
        item = instantiations.get(source)
        if item is None:
            node.pop("guarded_transfer_instantiation", None)
        else:
            node["guarded_transfer_instantiation"] = item

    for function in report.get("functions", ()):
        function["guarded_transfer_summary"] = summary_by_entry.get(
            function["entry"]
        )

    for call in report.get("calls", ()):
        source = call.get("source")
        target = call.get("target")
        call["guarded_transfer_summary"] = summary_by_entry.get(target)
        call["guarded_transfer_instantiation"] = instantiations.get(source)

    metrics = report.setdefault("metrics", {})
    metrics["guarded_transfer_iterations"] = refinement.get("iterations", 0)
    metrics["guarded_transfer_functions"] = refinement.get("guarded_functions", 0)
    metrics["guarded_transfer_cases"] = refinement.get("guarded_cases", 0)
    metrics["guarded_transfer_instantiations"] = len(instantiations)
    metrics["guarded_transfer_selected_single_case"] = sum(
        1
        for item in instantiations.values()
        if len(item.get("feasible_cases") or ()) == 1
    )
    metrics["guarded_transfer_exact_registers"] = sum(
        len(item.get("exact_registers") or {})
        for item in instantiations.values()
    )
    metrics["guarded_transfer_range_registers"] = sum(
        len(item.get("range_registers") or {})
        for item in instantiations.values()
    )
    metrics["guarded_transfer_exact_cells"] = sum(
        len(item.get("exact_memory") or {})
        for item in instantiations.values()
    )
    metrics["guarded_transfer_range_cells"] = sum(
        len(item.get("range_memory") or {})
        for item in instantiations.values()
    )
    metrics["guarded_transfer_base_resolutions"] = refinement.get(
        "base_resolutions", 0
    )
    metrics["guarded_transfer_range_base_resolutions"] = refinement.get(
        "range_base_resolutions", 0
    )
    metrics["guarded_transfer_pruned_edges"] = sum(
        1
        for edge in report.get("edges", ())
        if edge.get("resolution")
        in ("guarded-transfer-condition", "guarded-transfer-range-condition")
        and not edge.get("resolved")
    )
    return report


def _refresh_after_guarded(
    report,
    refinement,
    input_snapshot,
    symbolic_snapshot,
    sparse_snapshot,
    legacy_snapshot,
):
    report = _base._refresh_after_symbolic_memory_inputs(
        report,
        input_snapshot,
        symbolic_snapshot,
        sparse_snapshot,
        legacy_snapshot,
    )
    return _attach_guarded_layer(report, refinement)


def _inference_only_refinement(inferred):
    summaries = list(inferred.get("summaries") or ())
    summary_map = dict(inferred.get("summary_map") or {})
    return {
        "iterations": 0,
        "converged": True,
        "summary_map": summary_map,
        "summaries": summaries,
        "instantiations": {},
        "base_resolutions": 0,
        "range_base_resolutions": 0,
        "guarded_functions": 0,
        "guarded_cases": 0,
    }


def analyze_control_flow(
    image,
    image_start,
    debug_map,
    entry_address,
    base_register=None,
):
    report = _analyze_control_flow_base(
        image,
        image_start,
        debug_map,
        entry_address,
        base_register=base_register,
    )
    guard_summaries = _guard_base_summaries(report)

    # Most programs have only must-style return behavior. Infer bounded guarded
    # shapes first, and avoid a second whole-program exact/range/memory fixed
    # point entirely when no function actually has a usable piecewise summary.
    inferred = infer_guarded_transfer_summaries(
        report.get("instructions", []),
        report.get("edges", []),
        guard_summaries,
    )
    if not any(
        item.get("guarded_supported")
        for item in inferred.get("summaries", ())
    ):
        return _attach_guarded_layer(
            report,
            _inference_only_refinement(inferred),
        )

    legacy_snapshot = _base._base._snapshot_legacy_callsite(report)
    sparse_snapshot = _base._base._snapshot_sparse(report)
    symbolic_snapshot = _base._snapshot_symbolic_memory(report)
    input_snapshot = _snapshot_symbolic_input_refinement(report)
    ownership = _base._snapshot_prior_ownership(report)

    refinement = refine_guarded_transfers(
        report.get("instructions", []),
        report.get("edges", []),
        report.get("entry_address"),
        image,
        image_start,
        debug_map,
        base_summaries=guard_summaries,
        base_instantiations=_instantiation_by_call(
            report.get("symbolic_memory_input_instantiations")
        ),
        base_memory_summaries=_summary_by_entry(
            report.get("symbolic_memory_transfer_summaries")
        ),
        base_memory_instantiations=_instantiation_by_call(
            report.get("symbolic_memory_instantiations")
        ),
        base_register=base_register,
    )
    _restore_prior_ownership(report, ownership, refinement)
    return _refresh_after_guarded(
        report,
        refinement,
        input_snapshot,
        symbolic_snapshot,
        sparse_snapshot,
        legacy_snapshot,
    )


def _format_guard(guard):
    left = _base._format_input_transfer(guard.get("left"))
    right = _base._format_input_transfer(guard.get("right"))
    allowed = "/".join(guard.get("allowed") or ()) or "?"
    return f"{left} ? {right} in {{{allowed}}}"


def _format_outputs(outputs, prefix=""):
    return ",".join(
        f"{prefix}{name}={_base._format_input_transfer(spec)}"
        for name, spec in sorted((outputs or {}).items())
    ) or "-"


def render_control_flow_report(report):
    base = _render_control_flow_report_base(report).rstrip("\n")
    status = report.get("guarded_transfers") or {}
    lines = [
        base,
        "",
        (
            "GUARDED CALL TRANSFERS "
            f"iterations={status.get('iterations', 0)} "
            f"converged={str(bool(status.get('converged'))).lower()} "
            f"functions={status.get('guarded_functions', 0)} "
            f"cases={status.get('guarded_cases', 0)} "
            f"base-resolved={status.get('base_resolutions', 0)} "
            f"range-base-resolved={status.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('guarded_transfer_pruned_edges', 0)}"
        ),
    ]

    any_summary = False
    for summary in report.get("guarded_transfer_summaries", ()):
        cases = summary.get("guarded_cases") or ()
        if not cases:
            continue
        any_summary = True
        lines.append(
            f"  {summary['entry']:05X} cases={len(cases)} "
            f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
        )
        for case in cases:
            guards = " && ".join(
                _format_guard(guard)
                for guard in case.get("guards", ())
            ) or "true"
            registers = _format_outputs(case.get("register_outputs"))
            memory = _format_outputs(case.get("memory_outputs"), "MEM[")
            if memory != "-":
                memory = memory.replace("=", "]=", 1)
            lines.append(
                f"    {case['id']} if {guards} -> regs={registers} mem={memory}"
            )
    if not any_summary:
        lines.append("  -")

    if report.get("guarded_transfer_instantiations"):
        lines.append("  call-site cases:")
        for item in report["guarded_transfer_instantiations"]:
            feasible = ",".join(item.get("feasible_cases") or ()) or "-"
            ruled = ",".join(item.get("ruled_out_cases") or ()) or "-"
            exact_regs = ",".join(
                f"{name}={value:06X}"
                for name, value in sorted((item.get("exact_registers") or {}).items())
            ) or "-"
            exact_mem = ",".join(
                f"{name}={value:06X}"
                for name, value in sorted((item.get("exact_memory") or {}).items())
            ) or "-"
            lines.append(
                f"    {item['call_address']:05X} -> {item.get('callee_entry', 0):05X} "
                f"feasible={feasible} ruled-out={ruled} "
                f"regs={exact_regs} mem={exact_mem}"
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
            address = (
                int(parts[0], 16)
                if len(parts) > 1 and len(parts[0]) == 5
                else None
            )
        except ValueError:
            address = None
        node = by_address.get(address)
        item = None if node is None else node.get("guarded_transfer_instantiation")
        if item:
            feasible = ",".join(item.get("feasible_cases") or ())
            additions = []
            if feasible:
                additions.append("guard_cases=" + feasible)
            exact = ",".join(
                f"{name}={value:06X}"
                for name, value in sorted((item.get("exact_registers") or {}).items())
            )
            if exact:
                additions.append("guard_xfer=" + exact)
            if additions:
                line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")