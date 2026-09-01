import control_flow_sparse_base as _base
from control_flow_sparse_base import *
from control_flow_sparse_base import analyze_control_flow as _analyze_control_flow_base
from control_flow_sparse_base import annotate_typed_disassembly as _annotate_typed_disassembly_base
from control_flow_sparse_base import render_control_flow_report as _render_control_flow_report_base
from symbolic_memory_transfers import refine_symbolic_memory_transfers


_SPARSE_BASE_RESOLUTIONS = {
    "sparse-linear-base",
    "sparse-linear-range-base",
}


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


def _snapshot_legacy_callsite(report):
    return {
        "summaries": list(report.get("register_transfer_summaries") or ()),
        "instantiations": list(report.get("callsite_transfer_instantiations") or ()),
        "status": dict(report.get("callsite_transfers") or {}),
        "metrics": {
            key: report.get("metrics", {}).get(key, 0)
            for key in _base._LEGACY_METRICS
        },
    }


def _snapshot_sparse(report):
    summaries = list(report.get("sparse_linear_transfer_summaries") or ())
    instantiations = list(report.get("sparse_linear_instantiations") or ())
    status = dict(report.get("sparse_linear_transfers") or {})
    return {
        "iterations": status.get("iterations", 0),
        "converged": bool(status.get("converged")),
        "summary_map": _summary_by_entry(summaries),
        "summaries": summaries,
        "instantiations": _instantiation_by_call(instantiations),
        "base_resolutions": status.get("base_resolutions", 0),
        "range_base_resolutions": status.get("range_base_resolutions", 0),
        "multivariate_transfers": status.get("multivariate_transfers", 0),
    }


def _snapshot_sparse_base_ownership(report):
    """Freeze target facts already owned by the proven sparse-register layer."""
    result = {}
    for node in report.get("instructions", ()):
        if node.get("target_resolution") not in _SPARSE_BASE_RESOLUTIONS:
            continue
        result[node["address"]] = {
            "operand": node.get("operand"),
            "target": node.get("target"),
            "warning": node.get("warning"),
            "base_value": node.get("base_value"),
            "target_resolution": node.get("target_resolution"),
        }
    return result


def _restore_sparse_base_ownership(report, ownership, refinement):
    """A later evidence layer may refine new targets, but must not relabel old ones."""
    by_address = {
        node["address"]: node
        for node in report.get("instructions", ())
    }
    for address, saved in ownership.items():
        node = by_address.get(address)
        if node is None:
            continue
        node["operand"] = saved["operand"]
        node["target"] = saved["target"]
        node["warning"] = saved["warning"]
        node["target_resolution"] = saved["target_resolution"]
        if saved["base_value"] is None:
            node.pop("base_value", None)
        else:
            node["base_value"] = saved["base_value"]

    # Counters describe final ownership, not transient relabeling during the
    # new fixed point.
    refinement["base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution") == "symbolic-memory-base"
    )
    refinement["range_base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution") == "symbolic-memory-range-base"
    )


def _refresh_after_symbolic_memory(report, refinement, sparse_snapshot, legacy_snapshot):
    """Rebuild CFG-dependent products while preserving every established layer."""
    report = _base._refresh_after_sparse_linear(
        report,
        sparse_snapshot,
        legacy_snapshot,
    )

    summaries = list(refinement.get("summaries") or ())
    summary_by_entry = dict(refinement.get("summary_map") or {})
    instantiations = dict(refinement.get("instantiations") or {})
    report["symbolic_memory_transfer_summaries"] = summaries
    report["symbolic_memory_instantiations"] = [
        {"call_address": address, **item}
        for address, item in sorted(instantiations.items())
    ]
    report["symbolic_memory_transfers"] = {
        "iterations": refinement.get("iterations", 0),
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
        node["symbolic_memory_transfer_summary"] = summary_by_entry.get(target)
        instantiation = instantiations.get(source)
        if instantiation is None:
            node.pop("symbolic_memory_instantiation", None)
        else:
            node["symbolic_memory_instantiation"] = instantiation

    for function in report.get("functions", ()):
        function["symbolic_memory_transfer_summary"] = summary_by_entry.get(
            function["entry"]
        )

    for call in report.get("calls", ()):
        source = call.get("source")
        target = call.get("target")
        call["symbolic_memory_transfer_summary"] = summary_by_entry.get(target)
        call["symbolic_memory_instantiation"] = instantiations.get(source)

    metrics = report.setdefault("metrics", {})
    metrics["symbolic_memory_iterations"] = refinement.get("iterations", 0)
    metrics["symbolic_memory_return_transfers"] = sum(
        len(summary.get("return_memory_linear_transfers") or {})
        for summary in summaries
    )
    metrics["symbolic_memory_multivariate_transfers"] = refinement.get(
        "multivariate_transfers", 0
    )
    metrics["symbolic_memory_instantiations"] = len(instantiations)
    metrics["symbolic_memory_instantiated_exact_cells"] = sum(
        len(item.get("exact") or {}) for item in instantiations.values()
    )
    metrics["symbolic_memory_instantiated_range_cells"] = sum(
        len(item.get("ranges") or {}) for item in instantiations.values()
    )
    metrics["symbolic_memory_base_resolutions"] = refinement.get(
        "base_resolutions", 0
    )
    metrics["symbolic_memory_range_base_resolutions"] = refinement.get(
        "range_base_resolutions", 0
    )
    metrics["symbolic_memory_pruned_edges"] = sum(
        1
        for edge in report.get("edges", ())
        if edge.get("resolution") in (
            "symbolic-memory-condition",
            "symbolic-memory-range-condition",
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
    legacy_snapshot = _snapshot_legacy_callsite(report)
    sparse_snapshot = _snapshot_sparse(report)
    sparse_base_ownership = _snapshot_sparse_base_ownership(report)
    refinement = refine_symbolic_memory_transfers(
        report.get("instructions", []),
        report.get("edges", []),
        report.get("entry_address"),
        image,
        image_start,
        debug_map,
        register_summaries=_summary_by_entry(
            report.get("sparse_linear_transfer_summaries")
        ),
        memory_summaries=_summary_by_entry(report.get("memory_effect_summaries")),
        base_register=base_register,
    )
    _restore_sparse_base_ownership(report, sparse_base_ownership, refinement)
    return _refresh_after_symbolic_memory(
        report,
        refinement,
        sparse_snapshot,
        legacy_snapshot,
    )


def _format_memory_transfer(spec):
    return _base._format_sparse_transfer(spec)


def render_control_flow_report(report):
    base = _render_control_flow_report_base(report).rstrip("\n")
    status = report.get("symbolic_memory_transfers") or {}
    lines = [
        base,
        "",
        (
            "SYMBOLIC MEMORY CALL TRANSFERS "
            f"iterations={status.get('iterations', 0)} "
            f"converged={str(bool(status.get('converged'))).lower()} "
            f"multivariate={status.get('multivariate_transfers', 0)} "
            f"base-resolved={status.get('base_resolutions', 0)} "
            f"range-base-resolved={status.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('symbolic_memory_pruned_edges', 0)}"
        ),
    ]

    any_summary = False
    for summary in report.get("symbolic_memory_transfer_summaries", ()):
        transfers = summary.get("return_memory_linear_transfers") or {}
        if not transfers:
            continue
        any_summary = True
        rendered = ",".join(
            f"{cell_id}={_format_memory_transfer(spec)}"
            for cell_id, spec in sorted(transfers.items())
        )
        lines.append(
            f"  {summary['entry']:05X} memory={rendered} "
            f"inputs={','.join(summary.get('memory_linear_input_registers') or ()) or '-'} "
            f"multi={','.join(summary.get('multivariate_memory_return_cells') or ()) or '-'} "
            f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
        )
    if not any_summary:
        lines.append("  -")

    if report.get("symbolic_memory_instantiations"):
        lines.append("  call-site instantiations:")
        for item in report["symbolic_memory_instantiations"]:
            exact = ",".join(
                f"{cell_id}={value:06X}"
                for cell_id, value in sorted((item.get("exact") or {}).items())
            ) or "-"
            ranges = ",".join(
                f"{cell_id}={_base._base._base._format_optional_range(interval)}"
                for cell_id, interval in sorted((item.get("ranges") or {}).items())
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
            None if node is None else node.get("symbolic_memory_instantiation")
        )
        if instantiation:
            exact = ",".join(
                f"{cell_id}={value:06X}"
                for cell_id, value in sorted((instantiation.get("exact") or {}).items())
            )
            ranges = ",".join(
                f"{cell_id}={_base._base._base._format_optional_range(interval)}"
                for cell_id, interval in sorted((instantiation.get("ranges") or {}).items())
            )
            additions = []
            if exact:
                additions.append("mem_xfer=" + exact)
            if ranges:
                additions.append("mem_xfer_range=" + ranges)
            if additions:
                line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
