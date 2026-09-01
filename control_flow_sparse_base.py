import control_flow_callsite_base as _base
from control_flow_callsite_base import *
from control_flow_callsite_base import analyze_control_flow as _analyze_control_flow_base
from control_flow_callsite_base import annotate_typed_disassembly as _annotate_typed_disassembly_base
from control_flow_callsite_base import render_control_flow_report as _render_control_flow_report_base
from sparse_linear_transfers import refine_sparse_linear_transfers


_LEGACY_METRICS = (
    "callsite_transfer_iterations",
    "symbolic_return_transfers",
    "callsite_transfer_instantiations",
    "callsite_transfer_base_resolutions",
    "callsite_transfer_range_base_resolutions",
    "callsite_transfer_pruned_edges",
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


def _refresh_after_sparse_linear(report, refinement, legacy):
    """Reuse the proven call-site refresh path, then restore its legacy schema."""
    # The previous wrapper already knows how to recompute structure, liveness,
    # reaching definitions, memory provenance, functions, and ownership after a
    # CFG refinement. Reuse that path with the new summary layer rather than
    # duplicating the compiler-analysis refresh logic.
    report = _base._refresh_after_callsite_transfer(report, refinement)

    sparse_summary_by_entry = dict(refinement.get("summary_map") or {})
    sparse_instantiations = dict(refinement.get("instantiations") or {})
    legacy_summary_by_entry = _summary_by_entry(legacy["summaries"])
    legacy_instantiations = _instantiation_by_call(legacy["instantiations"])

    # Preserve the established single-source public fields unchanged.
    report["register_transfer_summaries"] = legacy["summaries"]
    report["callsite_transfer_instantiations"] = legacy["instantiations"]
    report["callsite_transfers"] = legacy["status"]

    # Expose the multivariate layer independently.
    report["sparse_linear_transfer_summaries"] = list(
        refinement.get("summaries") or ()
    )
    report["sparse_linear_instantiations"] = [
        {"call_address": address, **item}
        for address, item in sorted(sparse_instantiations.items())
    ]
    report["sparse_linear_transfers"] = {
        "iterations": refinement.get("iterations"),
        "converged": bool(refinement.get("converged")),
        "base_resolutions": refinement.get("base_resolutions", 0),
        "range_base_resolutions": refinement.get("range_base_resolutions", 0),
        "multivariate_transfers": refinement.get("multivariate_transfers", 0),
    }

    for node in report.get("instructions", ()):
        if node["base_mnemonic"] != "JSUB":
            continue
        target = node.get("target")
        source = node["address"]
        node["register_transfer_summary"] = legacy_summary_by_entry.get(target)
        legacy_instantiation = legacy_instantiations.get(source)
        if legacy_instantiation is None:
            node.pop("call_transfer_instantiation", None)
        else:
            node["call_transfer_instantiation"] = legacy_instantiation
        node["sparse_linear_transfer_summary"] = sparse_summary_by_entry.get(target)
        sparse_instantiation = sparse_instantiations.get(source)
        if sparse_instantiation is None:
            node.pop("sparse_linear_instantiation", None)
        else:
            node["sparse_linear_instantiation"] = sparse_instantiation

    for function in report.get("functions", ()):
        entry = function["entry"]
        function["register_transfer_summary"] = legacy_summary_by_entry.get(entry)
        function["sparse_linear_transfer_summary"] = sparse_summary_by_entry.get(entry)

    for call in report.get("calls", ()):
        source = call.get("source")
        target = call.get("target")
        call["register_transfer_summary"] = legacy_summary_by_entry.get(target)
        call["transfer_instantiation"] = legacy_instantiations.get(source)
        call["sparse_linear_transfer_summary"] = sparse_summary_by_entry.get(target)
        call["sparse_linear_instantiation"] = sparse_instantiations.get(source)

    metrics = report.setdefault("metrics", {})
    for key, value in legacy["metrics"].items():
        metrics[key] = value
    metrics["sparse_linear_iterations"] = refinement.get("iterations", 0)
    metrics["sparse_linear_return_transfers"] = sum(
        len(summary.get("return_linear_transfers") or {})
        for summary in report["sparse_linear_transfer_summaries"]
    )
    metrics["sparse_linear_multivariate_transfers"] = refinement.get(
        "multivariate_transfers", 0
    )
    metrics["sparse_linear_instantiations"] = len(sparse_instantiations)
    metrics["sparse_linear_base_resolutions"] = refinement.get(
        "base_resolutions", 0
    )
    metrics["sparse_linear_range_base_resolutions"] = refinement.get(
        "range_base_resolutions", 0
    )
    metrics["sparse_linear_pruned_edges"] = sum(
        1
        for edge in report.get("edges", ())
        if edge.get("resolution") in (
            "sparse-linear-condition",
            "sparse-linear-range-condition",
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
    legacy = {
        "summaries": list(report.get("register_transfer_summaries") or ()),
        "instantiations": list(report.get("callsite_transfer_instantiations") or ()),
        "status": dict(report.get("callsite_transfers") or {}),
        "metrics": {
            key: report.get("metrics", {}).get(key, 0)
            for key in _LEGACY_METRICS
        },
    }
    refinement = refine_sparse_linear_transfers(
        report.get("instructions", []),
        report.get("edges", []),
        report.get("entry_address"),
        register_summaries=_summary_by_entry(
            report.get("register_return_summaries")
        ),
        base_register=base_register,
    )
    return _refresh_after_sparse_linear(report, refinement, legacy)


def _format_sparse_term(register, coefficient, first):
    sign = "-" if coefficient < 0 else ("" if first else "+")
    magnitude = abs(coefficient)
    body = register if magnitude == 1 else f"{magnitude}*{register}"
    return sign + body


def _format_sparse_transfer(spec):
    if not spec:
        return "?"
    if spec.get("kind") != "linear":
        return _base._format_transfer(spec)
    coefficients = spec.get("coefficients") or {}
    parts = []
    for register, coefficient in sorted(coefficients.items()):
        if not coefficient:
            continue
        parts.append(_format_sparse_term(register, coefficient, not parts))
    offset = spec.get("offset", 0)
    if offset > 0:
        parts.append(("+" if parts else "") + str(offset))
    elif offset < 0:
        parts.append(str(offset))
    return "".join(parts) or "0"


def render_control_flow_report(report):
    base = _render_control_flow_report_base(report).rstrip("\n")
    status = report.get("sparse_linear_transfers") or {}
    lines = [
        base,
        "",
        (
            "SPARSE LINEAR CALL TRANSFERS "
            f"iterations={status.get('iterations', 0)} "
            f"converged={str(bool(status.get('converged'))).lower()} "
            f"multivariate={status.get('multivariate_transfers', 0)} "
            f"base-resolved={status.get('base_resolutions', 0)} "
            f"range-base-resolved={status.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('sparse_linear_pruned_edges', 0)}"
        ),
    ]
    any_summary = False
    for summary in report.get("sparse_linear_transfer_summaries", ()):
        transfers = summary.get("return_linear_transfers") or {}
        if not transfers:
            continue
        any_summary = True
        rendered = ",".join(
            f"{register}={_format_sparse_transfer(spec)}"
            for register, spec in sorted(transfers.items())
        )
        lines.append(
            f"  {summary['entry']:05X} transfer={rendered} "
            f"inputs={','.join(summary.get('linear_input_registers') or ()) or '-'} "
            f"multi={','.join(summary.get('multivariate_return_registers') or ()) or '-'} "
            f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
        )
    if not any_summary:
        lines.append("  -")

    if report.get("sparse_linear_instantiations"):
        lines.append("  call-site instantiations:")
        for item in report["sparse_linear_instantiations"]:
            exact = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted((item.get("exact") or {}).items())
            ) or "-"
            ranges = ",".join(
                f"{register}={_base._base._format_optional_range(interval)}"
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
            address = (
                int(parts[0], 16)
                if len(parts) > 1 and len(parts[0]) == 5
                else None
            )
        except ValueError:
            address = None
        node = by_address.get(address)
        instantiation = (
            None if node is None else node.get("sparse_linear_instantiation")
        )
        if instantiation:
            exact = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted(
                    (instantiation.get("exact") or {}).items()
                )
            )
            ranges = ",".join(
                f"{register}={_base._base._format_optional_range(interval)}"
                for register, interval in sorted(
                    (instantiation.get("ranges") or {}).items()
                )
            )
            additions = []
            if exact:
                additions.append("linear_xfer=" + exact)
            if ranges:
                additions.append("linear_xfer_range=" + ranges)
            if additions:
                line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
