import control_flow_symbolic_memory_base as _base
from control_flow_symbolic_memory_base import *
from control_flow_symbolic_memory_base import analyze_control_flow as _analyze_control_flow_base
from control_flow_symbolic_memory_base import annotate_typed_disassembly as _annotate_typed_disassembly_base
from control_flow_symbolic_memory_base import render_control_flow_report as _render_control_flow_report_base
from symbolic_memory_inputs import refine_symbolic_memory_inputs


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


def _snapshot_symbolic_memory(report):
    summaries = list(
        report.get("symbolic_memory_transfer_summaries") or ()
    )
    instantiations = list(
        report.get("symbolic_memory_instantiations") or ()
    )
    status = dict(report.get("symbolic_memory_transfers") or {})
    return {
        "iterations": status.get("iterations", 0),
        "converged": bool(status.get("converged")),
        "summary_map": _summary_by_entry(summaries),
        "summaries": summaries,
        "instantiations": _instantiation_by_call(instantiations),
        "base_resolutions": status.get("base_resolutions", 0),
        "range_base_resolutions": status.get(
            "range_base_resolutions",
            0,
        ),
        "multivariate_transfers": status.get(
            "multivariate_transfers",
            0,
        ),
    }


def _snapshot_prior_ownership(report):
    targets = {}
    for node in report.get("instructions", ()):
        if node.get("target_resolution") is None:
            continue
        targets[node["address"]] = {
            "operand": node.get("operand"),
            "target": node.get("target"),
            "warning": node.get("warning"),
            "base_value": node.get("base_value"),
            "target_resolution": node.get("target_resolution"),
        }

    edges = {}
    for edge in report.get("edges", ()):
        if edge.get("resolution") is None:
            continue
        key = (
            edge.get("source"),
            edge.get("target"),
            edge.get("kind"),
        )
        edges[key] = {
            "resolved": bool(edge.get("resolved")),
            "feasible": edge.get("feasible"),
            "reason": edge.get("reason"),
            "resolution": edge.get("resolution"),
        }
    return {"targets": targets, "edges": edges}


def _restore_prior_ownership(report, ownership, refinement):
    by_address = {
        node["address"]: node
        for node in report.get("instructions", ())
    }
    for address, saved in ownership["targets"].items():
        node = by_address.get(address)
        if node is None:
            continue
        node["operand"] = saved["operand"]
        node["target"] = saved["target"]
        node["warning"] = saved["warning"]
        node["target_resolution"] = saved[
            "target_resolution"
        ]
        if saved["base_value"] is None:
            node.pop("base_value", None)
        else:
            node["base_value"] = saved["base_value"]

    by_edge = {
        (
            edge.get("source"),
            edge.get("target"),
            edge.get("kind"),
        ): edge
        for edge in report.get("edges", ())
    }
    for key, saved in ownership["edges"].items():
        edge = by_edge.get(key)
        if edge is None:
            continue
        edge["resolved"] = saved["resolved"]
        if saved["feasible"] is None:
            edge.pop("feasible", None)
        else:
            edge["feasible"] = saved["feasible"]
        if saved["reason"] is None:
            edge.pop("reason", None)
        else:
            edge["reason"] = saved["reason"]
        edge["resolution"] = saved["resolution"]

    refinement["base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution")
        == "symbolic-memory-input-base"
    )
    refinement["range_base_resolutions"] = sum(
        1
        for node in report.get("instructions", ())
        if node.get("target_resolution")
        == "symbolic-memory-input-range-base"
    )


def _refresh_after_symbolic_memory_inputs(
    report,
    refinement,
    symbolic_snapshot,
    sparse_snapshot,
    legacy_snapshot,
):
    report = _base._refresh_after_symbolic_memory(
        report,
        symbolic_snapshot,
        sparse_snapshot,
        legacy_snapshot,
    )

    summaries = list(refinement.get("summaries") or ())
    summary_by_entry = dict(
        refinement.get("summary_map") or {}
    )
    instantiations = dict(
        refinement.get("instantiations") or {}
    )

    report["symbolic_memory_input_summaries"] = summaries
    report["symbolic_memory_input_instantiations"] = [
        {"call_address": address, **item}
        for address, item in sorted(instantiations.items())
    ]
    report["symbolic_memory_inputs"] = {
        "iterations": refinement.get("iterations", 0),
        "converged": bool(refinement.get("converged")),
        "base_resolutions": refinement.get(
            "base_resolutions",
            0,
        ),
        "range_base_resolutions": refinement.get(
            "range_base_resolutions",
            0,
        ),
        "return_register_transfers": refinement.get(
            "return_register_transfers",
            0,
        ),
        "return_memory_transfers": refinement.get(
            "return_memory_transfers",
            0,
        ),
    }

    for node in report.get("instructions", ()):
        if node["base_mnemonic"] != "JSUB":
            continue
        target = node.get("target")
        source = node["address"]
        node["symbolic_memory_input_summary"] = (
            summary_by_entry.get(target)
        )
        item = instantiations.get(source)
        if item is None:
            node.pop(
                "symbolic_memory_input_instantiation",
                None,
            )
        else:
            node[
                "symbolic_memory_input_instantiation"
            ] = item

    for function in report.get("functions", ()):
        function["symbolic_memory_input_summary"] = (
            summary_by_entry.get(function["entry"])
        )

    for call in report.get("calls", ()):
        source = call.get("source")
        target = call.get("target")
        call["symbolic_memory_input_summary"] = (
            summary_by_entry.get(target)
        )
        call["symbolic_memory_input_instantiation"] = (
            instantiations.get(source)
        )

    metrics = report.setdefault("metrics", {})
    metrics["symbolic_memory_input_iterations"] = (
        refinement.get("iterations", 0)
    )
    metrics["symbolic_memory_input_return_registers"] = (
        refinement.get("return_register_transfers", 0)
    )
    metrics["symbolic_memory_input_return_cells"] = (
        refinement.get("return_memory_transfers", 0)
    )
    metrics["symbolic_memory_input_instantiations"] = len(
        instantiations
    )
    metrics["symbolic_memory_input_exact_registers"] = sum(
        len(item.get("exact_registers") or {})
        for item in instantiations.values()
    )
    metrics["symbolic_memory_input_range_registers"] = sum(
        len(item.get("range_registers") or {})
        for item in instantiations.values()
    )
    metrics["symbolic_memory_input_exact_cells"] = sum(
        len(item.get("exact_memory") or {})
        for item in instantiations.values()
    )
    metrics["symbolic_memory_input_range_cells"] = sum(
        len(item.get("range_memory") or {})
        for item in instantiations.values()
    )
    metrics["symbolic_memory_input_base_resolutions"] = (
        refinement.get("base_resolutions", 0)
    )
    metrics[
        "symbolic_memory_input_range_base_resolutions"
    ] = refinement.get("range_base_resolutions", 0)
    metrics["symbolic_memory_input_pruned_edges"] = sum(
        1
        for edge in report.get("edges", ())
        if edge.get("resolution")
        in (
            "symbolic-memory-input-condition",
            "symbolic-memory-input-range-condition",
        )
        and not edge.get("resolved")
    )
    return report


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
    legacy_snapshot = _base._snapshot_legacy_callsite(
        report
    )
    sparse_snapshot = _base._snapshot_sparse(report)
    symbolic_snapshot = _snapshot_symbolic_memory(report)
    ownership = _snapshot_prior_ownership(report)

    refinement = refine_symbolic_memory_inputs(
        report.get("instructions", []),
        report.get("edges", []),
        report.get("entry_address"),
        image,
        image_start,
        debug_map,
        register_summaries=_summary_by_entry(
            report.get(
                "sparse_linear_transfer_summaries"
            )
        ),
        memory_summaries=_summary_by_entry(
            report.get(
                "symbolic_memory_transfer_summaries"
            )
        ),
        memory_instantiations=_instantiation_by_call(
            report.get("symbolic_memory_instantiations")
        ),
        base_register=base_register,
    )
    _restore_prior_ownership(
        report,
        ownership,
        refinement,
    )
    return _refresh_after_symbolic_memory_inputs(
        report,
        refinement,
        symbolic_snapshot,
        sparse_snapshot,
        legacy_snapshot,
    )


def _format_term(body, coefficient, first):
    sign = (
        "-"
        if coefficient < 0
        else ("" if first else "+")
    )
    magnitude = abs(coefficient)
    if magnitude != 1:
        body = f"{magnitude}*{body}"
    return sign + body


def _format_input_transfer(spec):
    if not spec:
        return "?"
    parts = []
    for register, coefficient in sorted(
        (spec.get("register_coefficients") or {}).items()
    ):
        if coefficient:
            parts.append(
                _format_term(
                    register,
                    coefficient,
                    not parts,
                )
            )
    for cell_id, coefficient in sorted(
        (spec.get("memory_coefficients") or {}).items()
    ):
        if coefficient:
            parts.append(
                _format_term(
                    f"MEM[{cell_id}]",
                    coefficient,
                    not parts,
                )
            )
    offset = spec.get("offset", 0)
    if offset > 0:
        parts.append(("+" if parts else "") + str(offset))
    elif offset < 0:
        parts.append(str(offset))
    return "".join(parts) or "0"


def render_control_flow_report(report):
    base = _render_control_flow_report_base(
        report
    ).rstrip("\n")
    status = report.get("symbolic_memory_inputs") or {}
    lines = [
        base,
        "",
        (
            "SYMBOLIC MEMORY INPUT TRANSFERS "
            f"iterations={status.get('iterations', 0)} "
            f"converged={str(bool(status.get('converged'))).lower()} "
            f"register-returns={status.get('return_register_transfers', 0)} "
            f"memory-returns={status.get('return_memory_transfers', 0)} "
            f"base-resolved={status.get('base_resolutions', 0)} "
            f"range-base-resolved={status.get('range_base_resolutions', 0)} "
            f"pruned={report.get('metrics', {}).get('symbolic_memory_input_pruned_edges', 0)}"
        ),
    ]

    any_summary = False
    for summary in report.get(
        "symbolic_memory_input_summaries",
        (),
    ):
        register_transfers = summary.get(
            "return_register_memory_transfers"
        ) or {}
        memory_transfers = summary.get(
            "return_memory_input_transfers"
        ) or {}
        if not register_transfers and not memory_transfers:
            continue
        any_summary = True
        registers = ",".join(
            f"{register}={_format_input_transfer(spec)}"
            for register, spec in sorted(
                register_transfers.items()
            )
        ) or "-"
        memory = ",".join(
            f"{cell_id}={_format_input_transfer(spec)}"
            for cell_id, spec in sorted(
                memory_transfers.items()
            )
        ) or "-"
        lines.append(
            f"  {summary['entry']:05X} "
            f"register={registers} memory={memory} "
            f"memory-inputs={','.join(summary.get('memory_input_cells') or ()) or '-'} "
            f"register-inputs={','.join(summary.get('memory_input_registers') or ()) or '-'} "
            f"link-preserved={str(bool(summary.get('link_register_preserved'))).lower()}"
        )
    if not any_summary:
        lines.append("  -")

    if report.get("symbolic_memory_input_instantiations"):
        lines.append("  call-site instantiations:")
        for item in report[
            "symbolic_memory_input_instantiations"
        ]:
            exact_registers = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted(
                    (item.get("exact_registers") or {}).items()
                )
            ) or "-"
            range_registers = ",".join(
                f"{register}={_base._base._base._base._format_optional_range(interval)}"
                for register, interval in sorted(
                    (item.get("range_registers") or {}).items()
                )
            ) or "-"
            exact_memory = ",".join(
                f"{cell_id}={value:06X}"
                for cell_id, value in sorted(
                    (item.get("exact_memory") or {}).items()
                )
            ) or "-"
            range_memory = ",".join(
                f"{cell_id}={_base._base._base._base._format_optional_range(interval)}"
                for cell_id, interval in sorted(
                    (item.get("range_memory") or {}).items()
                )
            ) or "-"
            lines.append(
                f"    {item['call_address']:05X} -> {item.get('callee_entry', 0):05X} "
                f"reg={exact_registers} reg-range={range_registers} "
                f"mem={exact_memory} mem-range={range_memory}"
            )
    return "\n".join(lines) + "\n"


def annotate_typed_disassembly(
    rendered,
    debug_map,
    control_flow=None,
):
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
                if len(parts) > 1
                and len(parts[0]) == 5
                else None
            )
        except ValueError:
            address = None

        node = by_address.get(address)
        item = (
            None
            if node is None
            else node.get(
                "symbolic_memory_input_instantiation"
            )
        )
        if item:
            additions = []
            exact_registers = ",".join(
                f"{register}={value:06X}"
                for register, value in sorted(
                    (item.get("exact_registers") or {}).items()
                )
            )
            exact_memory = ",".join(
                f"{cell_id}={value:06X}"
                for cell_id, value in sorted(
                    (item.get("exact_memory") or {}).items()
                )
            )
            if exact_registers:
                additions.append(
                    "mem_in_reg=" + exact_registers
                )
            if exact_memory:
                additions.append(
                    "mem_in_mem=" + exact_memory
                )
            if additions:
                line += " ; " + "; ".join(additions)
        lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")
