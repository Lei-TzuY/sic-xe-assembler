import control_flow_core as _core
from disassembler import decode_instruction
from memory_feedback import _memory_aware_exact_transfer, _memory_aware_range_transfer
from range_analysis import (
    SIGNED_MAX,
    SIGNED_MIN,
    _copy_state as _copy_range_state,
    _join_states as _join_range_states,
    _state_equal as _range_state_equal,
    unknown_range_state,
)
from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    _copy_state as _copy_exact_state,
    _join_states as _join_exact_states,
    _state_equal as _exact_state_equal,
    summarize_subroutines,
    unknown_state,
)


MODULUS = 1 << 24
CALL_TRANSFER_BASE_RESOLUTIONS = {
    "call-transfer-base",
    "call-transfer-range-base",
}


class CallsiteTransferError(ValueError):
    pass


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - MODULUS


def _const(value):
    return (None, 0, value & REGISTER_MASK)


def _source(register):
    return (register, 1, 0)


def _is_const(expr):
    return expr is not None and expr[0] is None


def _normalize(source, scale, offset):
    if source is None or scale == 0:
        return _const(offset)
    return (source, int(scale), int(offset) % MODULUS)


def _add_expr(left, right):
    if left is None or right is None:
        return None
    ls, lk, lo = left
    rs, rk, ro = right
    if ls is None:
        return _normalize(rs, rk, ro + lo)
    if rs is None:
        return _normalize(ls, lk, lo + ro)
    if ls != rs:
        return None
    return _normalize(ls, lk + rk, lo + ro)


def _sub_expr(left, right):
    if left is None or right is None:
        return None
    rs, rk, ro = right
    return _add_expr(left, _normalize(rs, -rk, -ro))


def _mul_expr(left, right):
    if left is None or right is None:
        return None
    if _is_const(left):
        constant = left[2]
        source, scale, offset = right
    elif _is_const(right):
        constant = right[2]
        source, scale, offset = left
    else:
        return None
    signed_constant = _signed24(constant)
    return _normalize(source, scale * signed_constant, offset * signed_constant)


def _div_expr(left, right):
    if left is None or right is None or not _is_const(right):
        return None
    divisor = _signed24(right[2])
    if divisor == 1:
        return left
    if divisor == -1:
        source, scale, offset = left
        return _normalize(source, -scale, -offset)
    if _is_const(left) and divisor != 0:
        return _const(int(_signed24(left[2]) / divisor))
    return None


def _serialize(expr):
    if expr is None:
        return None
    source, scale, offset = expr
    if source is None:
        return {"kind": "constant", "value": offset & REGISTER_MASK}
    return {
        "kind": "affine",
        "source": source,
        "scale": scale,
        "offset": _signed24(offset),
        "modulus": MODULUS,
    }


def _deserialize(spec):
    if not spec:
        return None
    if spec.get("kind") == "constant":
        return _const(spec["value"])
    if spec.get("kind") == "affine" and spec.get("source") in TRACKED_REGISTERS:
        return _normalize(spec["source"], spec.get("scale", 1), spec.get("offset", 0))
    return None


def _symbolic_entry_state():
    return {register: _source(register) for register in TRACKED_REGISTERS}


def _copy_symbolic(state):
    return {register: state.get(register) for register in TRACKED_REGISTERS}


def _join_symbolic(left, right):
    if left is None:
        return _copy_symbolic(right)
    return {
        register: left.get(register)
        if left.get(register) is not None and left.get(register) == right.get(register)
        else None
        for register in TRACKED_REGISTERS
    }


def _symbolic_equal(left, right):
    if left is None or right is None:
        return left is right
    return all(left.get(register) == right.get(register) for register in TRACKED_REGISTERS)


def _register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


def _symbolic_transfer(node, incoming):
    state = _copy_symbolic(incoming)
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    target = node.get("target")
    fields = _register_operands(operand)

    loads = {
        "LDA": "A", "LDB": "B", "LDL": "L",
        "LDS": "S", "LDT": "T", "LDX": "X",
    }
    if mnemonic in loads:
        destination = loads[mnemonic]
        if operand.startswith("#") and not operand.endswith(",X") and target is not None:
            state[destination] = _const(target)
        else:
            state[destination] = None
        return state
    if mnemonic == "LDCH":
        state["A"] = None
        return state
    if mnemonic == "CLEAR" and len(fields) == 1 and fields[0] in TRACKED_REGISTERS:
        state[fields[0]] = _const(0)
        return state
    if mnemonic == "RMO" and len(fields) == 2 and fields[1] in TRACKED_REGISTERS:
        state[fields[1]] = state.get(fields[0])
        return state
    if mnemonic in ("ADDR", "SUBR", "MULR", "DIVR") and len(fields) == 2 and fields[1] in TRACKED_REGISTERS:
        source = state.get(fields[0])
        destination = state.get(fields[1])
        operation = {
            "ADDR": _add_expr,
            "SUBR": _sub_expr,
            "MULR": _mul_expr,
            "DIVR": _div_expr,
        }[mnemonic]
        state[fields[1]] = operation(destination, source)
        return state
    if mnemonic in ("SHIFTL", "SHIFTR") and fields and fields[0] in TRACKED_REGISTERS:
        expression = state.get(fields[0])
        if _is_const(expression):
            count_text = fields[1] if len(fields) > 1 else None
            try:
                count = int(count_text) if count_text is not None else None
            except ValueError:
                count = None
            if count is not None:
                value = expression[2]
                if mnemonic == "SHIFTL":
                    value = (value << count) & REGISTER_MASK
                else:
                    value = (value & REGISTER_MASK) >> count
                state[fields[0]] = _const(value)
                return state
        state[fields[0]] = None
        return state
    if mnemonic in ("TIX", "TIXR"):
        state["X"] = _add_expr(state.get("X"), _const(1))
        return state
    if mnemonic == "JSUB":
        state["L"] = _const(node["end"])
        return state
    if mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        current = state.get("A")
        if not operand.startswith("#") or operand.endswith(",X") or target is None:
            state["A"] = None
            return state
        immediate = _const(target)
        if mnemonic == "ADD":
            state["A"] = _add_expr(current, immediate)
        elif mnemonic == "SUB":
            state["A"] = _sub_expr(current, immediate)
        elif mnemonic == "MUL":
            state["A"] = _mul_expr(current, immediate)
        elif mnemonic == "DIV":
            state["A"] = _div_expr(current, immediate)
        elif mnemonic == "AND":
            if target & REGISTER_MASK == 0:
                state["A"] = _const(0)
            elif target & REGISTER_MASK == REGISTER_MASK:
                state["A"] = current
            elif _is_const(current):
                state["A"] = _const(current[2] & target)
            else:
                state["A"] = None
        else:
            if target & REGISTER_MASK == 0:
                state["A"] = current
            elif _is_const(current):
                state["A"] = _const(current[2] | target)
            else:
                state["A"] = None
        return state
    if mnemonic in ("RD", "FIX"):
        state["A"] = None
        return state
    if mnemonic in ("LPS", "SVC"):
        return {register: None for register in TRACKED_REGISTERS}
    return state


def _intraprocedural_outgoing(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)
    return by_address, outgoing


def _apply_symbolic_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return {register: None for register in TRACKED_REGISTERS}
    result = _copy_symbolic(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    if not summary.get("link_register_preserved"):
        return result

    inputs = _copy_symbolic(outgoing)
    for register, value in (summary.get("return_constants") or {}).items():
        if register in TRACKED_REGISTERS:
            result[register] = _const(value)
    for register, spec in (summary.get("return_transfers") or {}).items():
        expression = _deserialize(spec)
        if expression is None or register not in TRACKED_REGISTERS:
            continue
        source, scale, offset = expression
        if source is None:
            result[register] = expression
            continue
        source_expr = inputs.get(source)
        if source_expr is None:
            result[register] = None
            continue
        ss, sk, so = source_expr
        result[register] = _normalize(ss, sk * scale, so * scale + offset)
    return result


def _analyze_function_symbolically(nodes, edges, entry, summaries):
    by_address, outgoing_edges = _intraprocedural_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry not in by_address:
        return incoming, outgoing
    incoming[entry] = _symbolic_entry_state()
    pending = [entry]
    queued = {entry}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = _symbolic_transfer(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            candidate = _copy_symbolic(state_out)
            if node["base_mnemonic"] == "JSUB" and edge.get("kind") == "fallthrough":
                candidate = _apply_symbolic_summary(
                    state_out,
                    summaries.get(node.get("target")),
                )
            target = edge["target"]
            merged = _join_symbolic(incoming[target], candidate)
            if not _symbolic_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return incoming, outgoing


def _derive_symbolic_summary(structural, outgoing):
    summary = dict(structural)
    returns = list(summary.get("return_sites") or ())
    transfers = {}
    if returns and all(outgoing.get(site) is not None for site in returns):
        for register in TRACKED_REGISTERS:
            expressions = [outgoing[site].get(register) for site in returns]
            if expressions[0] is None or any(expr != expressions[0] for expr in expressions):
                continue
            expression = expressions[0]
            source, scale, offset = expression
            if source is None:
                continue
            if source == register and scale == 1 and offset % MODULUS == 0:
                continue
            transfers[register] = _serialize(expression)
    summary["return_transfers"] = transfers
    summary["transfer_input_registers"] = sorted({
        spec["source"]
        for spec in transfers.values()
        if spec.get("kind") == "affine"
    })
    summary["symbolic_return_registers"] = sorted(transfers)
    return summary


def _merge_summary_layers(structural, register_summaries, transfer_hints):
    result = {}
    for entry, base in structural.items():
        merged = dict(base)
        register = (register_summaries or {}).get(entry) or {}
        merged["return_constants"] = dict(register.get("return_constants") or {})
        merged["return_ranges"] = {
            key: list(value)
            for key, value in (register.get("return_ranges") or {}).items()
        }
        merged["return_conditions"] = list(register.get("return_conditions") or ())
        transfer = (transfer_hints or {}).get(entry) or {}
        merged["return_transfers"] = dict(transfer.get("return_transfers") or {})
        result[entry] = merged
    return result


def _transfer_signature(summaries):
    return tuple(
        (
            entry,
            tuple(
                (register, tuple(sorted(spec.items())))
                for register, spec in sorted(summary.get("return_transfers", {}).items())
            ),
        )
        for entry, summary in sorted(summaries.items())
    )


def infer_symbolic_return_transfers(nodes, edges, register_summaries=None):
    """Infer caller-independent single-source affine register return formulas."""
    structural = summarize_subroutines(nodes, edges)
    hints = {}
    previous = None
    max_iterations = max(4, len(structural) * 2 + 4)
    for iteration in range(1, max_iterations + 1):
        available = _merge_summary_layers(structural, register_summaries, hints)
        derived = {}
        for entry, shape in structural.items():
            _, outgoing = _analyze_function_symbolically(nodes, edges, entry, available)
            symbolic = _derive_symbolic_summary(shape, outgoing)
            register = (register_summaries or {}).get(entry) or {}
            symbolic["return_constants"] = dict(register.get("return_constants") or {})
            symbolic["return_ranges"] = {
                key: list(value)
                for key, value in (register.get("return_ranges") or {}).items()
            }
            symbolic["return_conditions"] = list(register.get("return_conditions") or ())
            derived[entry] = symbolic
        signature = _transfer_signature(derived)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": derived,
                "summaries": [derived[key] for key in sorted(derived)],
            }
        previous = signature
        hints = derived
    raise CallsiteTransferError("Symbolic return-transfer inference did not converge")


def _evaluate_exact(spec, inputs):
    expression = _deserialize(spec)
    if expression is None:
        return None
    source, scale, offset = expression
    if source is None:
        return offset & REGISTER_MASK
    value = inputs.get(source)
    if value is None:
        return None
    return (scale * value + offset) & REGISTER_MASK


def _evaluate_range(spec, inputs):
    expression = _deserialize(spec)
    if expression is None:
        return None
    source, scale, offset = expression
    if source is None:
        value = _signed24(offset)
        return (value, value)
    interval = inputs.get(source)
    if interval is None:
        return None
    candidates = (scale * interval[0] + _signed24(offset), scale * interval[1] + _signed24(offset))
    low, high = min(candidates), max(candidates)
    if low < SIGNED_MIN or high > SIGNED_MAX:
        return None
    return (low, high)


def _apply_exact_call(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_state()
    result = _copy_exact_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None
    if not summary.get("link_register_preserved"):
        return result
    inputs = _copy_exact_state(outgoing)
    for register, value in (summary.get("return_constants") or {}).items():
        if register in TRACKED_REGISTERS:
            result[register] = value & REGISTER_MASK
    for register, spec in (summary.get("return_transfers") or {}).items():
        if register in TRACKED_REGISTERS:
            result[register] = _evaluate_exact(spec, inputs)
    conditions = tuple(summary.get("return_conditions") or ())
    if len(conditions) == 1:
        result["CC"] = conditions[0]
    return result


def _apply_range_call(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_range_state()
    result = _copy_range_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None
    if not summary.get("link_register_preserved"):
        return result
    inputs = _copy_range_state(outgoing)
    constants = summary.get("return_constants") or {}
    ranges = summary.get("return_ranges") or {}
    for register in TRACKED_REGISTERS:
        if register in constants:
            value = _signed24(constants[register])
            result[register] = (value, value)
        elif register in ranges:
            result[register] = tuple(ranges[register])
    for register, spec in (summary.get("return_transfers") or {}).items():
        if register in TRACKED_REGISTERS:
            result[register] = _evaluate_range(spec, inputs)
    conditions = tuple(summary.get("return_conditions") or ())
    if conditions:
        result["CC"] = tuple(
            value for value in CONDITION_VALUES if value in conditions
        )
    return result


def _resolved_outgoing(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)
    return by_address, outgoing


def _exact_edge_feasible(node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    cc = None if state is None else state.get("CC")
    if cc not in CONDITION_VALUES:
        return True
    return (cc == required) if edge["kind"] == "branch" else (cc != required)


def _range_edge_feasible(node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    possible = None if state is None else state.get("CC")
    if possible is None:
        return True
    if edge["kind"] == "branch":
        return required in possible
    return any(value != required for value in possible)


def _global_exact(nodes, edges, entry_address, summaries, initial):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return incoming, outgoing
    entry_state = unknown_state()
    for register, value in initial.items():
        if register in TRACKED_REGISTERS:
            entry_state[register] = None if value is None else value & REGISTER_MASK
    incoming[entry_address] = entry_state
    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = _memory_aware_exact_transfer(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _exact_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_exact_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge.get("kind") == "fallthrough":
                candidate = _apply_exact_call(state_out, summaries.get(node.get("target")))
            target = edge["target"]
            merged = _join_exact_states(incoming[target], candidate)
            if not _exact_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return incoming, outgoing


def _global_ranges(nodes, edges, entry_address, summaries, initial):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return incoming, outgoing
    entry_state = unknown_range_state()
    for register, value in initial.items():
        if register in TRACKED_REGISTERS:
            signed = _signed24(value)
            entry_state[register] = (signed, signed)
    incoming[entry_address] = entry_state
    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = _memory_aware_range_transfer(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _range_edge_feasible(node, edge, state_out):
                continue
            candidate = _copy_range_state(state_out)
            if node["base_mnemonic"] == "JSUB" and edge.get("kind") == "fallthrough":
                candidate = _apply_range_call(state_out, summaries.get(node.get("target")))
            target = edge["target"]
            merged = _join_range_states(incoming[target], candidate)
            if not _range_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)
    return incoming, outgoing


def _clear_owned_base(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution") in CALL_TRANSFER_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _base_relative(node):
    flags = node.get("flags") or ""
    return len(flags) == 6 and flags[3] == "1" and flags[4] == "0" and flags[5] == "0"


def _resolve_base_targets(nodes, exact_in, range_in):
    changed = False
    for node in nodes:
        if not _base_relative(node):
            continue
        resolution = node.get("target_resolution")
        if resolution is not None and resolution not in CALL_TRANSFER_BASE_RESOLUTIONS:
            continue
        exact_state = exact_in.get(node["address"])
        range_state = range_in.get(node["address"])
        base = None if exact_state is None else exact_state.get("B")
        new_resolution = None
        if base is not None:
            new_resolution = "call-transfer-base"
        elif range_state is not None:
            interval = range_state.get("B")
            if interval is not None and interval[0] == interval[1]:
                base = interval[0] & REGISTER_MASK
                new_resolution = "call-transfer-range-base"
        if base is None:
            if resolution in CALL_TRANSFER_BASE_RESOLUTIONS:
                changed = _clear_owned_base(node) or changed
            continue
        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base,
        )
        if decoded.target is None:
            if resolution in CALL_TRANSFER_BASE_RESOLUTIONS:
                changed = _clear_owned_base(node) or changed
            continue
        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base
            or node.get("target_resolution") != new_resolution
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            node["base_value"] = base
            node["target_resolution"] = new_resolution
            changed = True
    return changed


def _rebuild_edges(nodes):
    edges = _core._instruction_edges(nodes)
    structural = summarize_subroutines(nodes, edges)
    _core._add_interprocedural_return_edges(nodes, edges, structural)
    return edges


def _mark_impossible_edges(nodes, edges, exact_out, range_out):
    by_address = {node["address"]: node for node in nodes}
    for edge in edges:
        if not edge.get("resolved") or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        node = by_address.get(edge.get("source"))
        if node is None or node["base_mnemonic"] not in CONDITIONAL_MNEMONICS:
            continue
        exact_state = exact_out.get(node["address"])
        if exact_state is not None and exact_state.get("CC") in CONDITION_VALUES:
            if not _exact_edge_feasible(node, edge, exact_state):
                edge["resolved"] = False
                edge["feasible"] = False
                edge["reason"] = "condition-false"
                edge["resolution"] = "call-transfer-condition"
                continue
        range_state = range_out.get(node["address"])
        if range_state is not None and range_state.get("CC") is not None:
            if not _range_edge_feasible(node, edge, range_state):
                edge["resolved"] = False
                edge["feasible"] = False
                edge["reason"] = "condition-false"
                edge["resolution"] = "call-transfer-range-condition"


def _instantiations(nodes, summaries, exact_out, range_out):
    result = {}
    for node in nodes:
        if node["base_mnemonic"] != "JSUB":
            continue
        summary = summaries.get(node.get("target"))
        if summary is None or not summary.get("link_register_preserved"):
            node.pop("call_transfer_instantiation", None)
            continue
        exact_inputs = exact_out.get(node["address"])
        range_inputs = range_out.get(node["address"])
        exact = {}
        ranges = {}
        for register, spec in (summary.get("return_transfers") or {}).items():
            value = None if exact_inputs is None else _evaluate_exact(spec, exact_inputs)
            interval = None if range_inputs is None else _evaluate_range(spec, range_inputs)
            if value is not None:
                exact[register] = value
            if interval is not None:
                ranges[register] = list(interval)
        item = {
            "callee_entry": node.get("target"),
            "exact": exact,
            "ranges": ranges,
            "transfers": dict(summary.get("return_transfers") or {}),
        }
        node["call_transfer_instantiation"] = item
        result[node["address"]] = item
    return result


def _signature(nodes, edges, summaries, exact_in, range_in):
    return (
        _transfer_signature(summaries),
        tuple(
            (
                node["address"],
                repr(exact_in.get(node["address"])),
                repr(range_in.get(node["address"])),
                node.get("target"),
                node.get("target_resolution"),
            )
            for node in nodes
        ),
        tuple(
            (
                edge.get("source"), edge.get("target"), edge.get("kind"),
                bool(edge.get("resolved")), edge.get("resolution"), edge.get("reason"),
            )
            for edge in edges
        ),
    )


def refine_callsite_transfers(
    nodes,
    edges,
    entry_address,
    register_summaries=None,
    base_register=None,
):
    """Instantiate symbolic callee transfer formulas at each concrete call site."""
    initial = {} if base_register is None else {"B": base_register}
    previous = None
    max_iterations = max(5, len(nodes) + 5)
    inferred = None
    for iteration in range(1, max_iterations + 1):
        inferred = infer_symbolic_return_transfers(
            nodes,
            edges,
            register_summaries=register_summaries,
        )
        summaries = inferred["summary_map"]
        exact_in, exact_out = _global_exact(nodes, edges, entry_address, summaries, initial)
        range_in, range_out = _global_ranges(nodes, edges, entry_address, summaries, initial)

        for node in nodes:
            node["registers_in"] = None if exact_in[node["address"]] is None else _copy_exact_state(exact_in[node["address"]])
            node["registers_out"] = None if exact_out[node["address"]] is None else _copy_exact_state(exact_out[node["address"]])
            node["ranges_in"] = None if range_in[node["address"]] is None else _copy_range_state(range_in[node["address"]])
            node["ranges_out"] = None if range_out[node["address"]] is None else _copy_range_state(range_out[node["address"]])
            if node["base_mnemonic"] == "JSUB":
                node["register_transfer_summary"] = summaries.get(node.get("target"))

        if _resolve_base_targets(nodes, exact_in, range_in):
            edges[:] = _rebuild_edges(nodes)
            previous = None
            continue

        _mark_impossible_edges(nodes, edges, exact_out, range_out)
        instantiations = _instantiations(nodes, summaries, exact_out, range_out)
        signature = _signature(nodes, edges, summaries, exact_in, range_in)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summary_map": summaries,
                "summaries": [summaries[key] for key in sorted(summaries)],
                "instantiations": instantiations,
                "base_resolutions": sum(
                    1 for node in nodes
                    if node.get("target_resolution") == "call-transfer-base"
                ),
                "range_base_resolutions": sum(
                    1 for node in nodes
                    if node.get("target_resolution") == "call-transfer-range-base"
                ),
            }
        previous = signature
    raise CallsiteTransferError("Call-site symbolic transfer/CFG refinement did not converge")
