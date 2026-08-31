from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    summarize_subroutines,
)


SIGNED_MIN = -(1 << 23)
SIGNED_MAX = (1 << 23) - 1
RANGE_STATE_KEYS = TRACKED_REGISTERS + ("CC",)


class RangeAnalysisError(ValueError):
    pass


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - 0x1000000


def _raw24(value):
    return value & REGISTER_MASK


def unknown_range_state():
    return {key: None for key in RANGE_STATE_KEYS}


def _copy_state(state):
    result = {}
    for key in RANGE_STATE_KEYS:
        value = state.get(key)
        if key == "CC" and value is not None:
            result[key] = tuple(value)
        elif value is not None:
            result[key] = tuple(value)
        else:
            result[key] = None
    return result


def _state_equal(left, right):
    if left is None or right is None:
        return left is right
    return all(left.get(key) == right.get(key) for key in RANGE_STATE_KEYS)


def _join_ranges(left, right):
    if left is None or right is None:
        return None
    return (min(left[0], right[0]), max(left[1], right[1]))


def _join_conditions(left, right):
    if left is None or right is None:
        return None
    return tuple(value for value in CONDITION_VALUES if value in set(left) | set(right))


def _join_states(left, right):
    if left is None:
        return _copy_state(right)
    result = {}
    for register in TRACKED_REGISTERS:
        result[register] = _join_ranges(left.get(register), right.get(register))
    result["CC"] = _join_conditions(left.get("CC"), right.get("CC"))
    return result


def _parse_register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


def _bounded_interval(low, high):
    if low > high:
        low, high = high, low
    if low < SIGNED_MIN or high > SIGNED_MAX:
        return None
    return (low, high)


def _singleton(raw_value):
    value = _signed24(raw_value)
    return (value, value)


def _interval_add(left, right):
    if left is None or right is None:
        return None
    return _bounded_interval(left[0] + right[0], left[1] + right[1])


def _interval_sub(left, right):
    if left is None or right is None:
        return None
    return _bounded_interval(left[0] - right[1], left[1] - right[0])


def _interval_mul(left, right):
    if left is None or right is None:
        return None
    candidates = (
        left[0] * right[0],
        left[0] * right[1],
        left[1] * right[0],
        left[1] * right[1],
    )
    return _bounded_interval(min(candidates), max(candidates))


def _trunc_div(value, divisor):
    return int(value / divisor)


def _interval_div(left, right):
    if left is None or right is None or right[0] <= 0 <= right[1]:
        return None
    candidates = (
        _trunc_div(left[0], right[0]),
        _trunc_div(left[0], right[1]),
        _trunc_div(left[1], right[0]),
        _trunc_div(left[1], right[1]),
    )
    return _bounded_interval(min(candidates), max(candidates))


def _interval_bitwise_and(left, immediate):
    mask = immediate & REGISTER_MASK
    if mask <= SIGNED_MAX:
        # Even a completely unknown 24-bit input becomes non-negative and no
        # larger than the non-sign-bit mask after AND.
        return (0, mask)
    if left is not None and left[0] == left[1]:
        return _singleton(_raw24(left[0]) & mask)
    return None


def _interval_bitwise_or(left, immediate):
    if left is not None and left[0] == left[1]:
        return _singleton(_raw24(left[0]) | (immediate & REGISTER_MASK))
    return None


def _possible_compare(left, right):
    if left is None or right is None:
        return None
    possible = []
    if left[0] < right[1]:
        possible.append("LT")
    if max(left[0], right[0]) <= min(left[1], right[1]):
        possible.append("EQ")
    if left[1] > right[0]:
        possible.append("GT")
    return tuple(value for value in CONDITION_VALUES if value in possible)


def _increment_interval(interval):
    if interval is None or interval[1] >= SIGNED_MAX:
        return None
    return (interval[0] + 1, interval[1] + 1)


def transfer_range_state(node, incoming):
    """Apply a conservative signed-24-bit interval transfer function."""
    state = _copy_state(incoming)
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    target = node.get("target")
    fields = _parse_register_operands(operand)

    load_registers = {
        "LDA": "A",
        "LDB": "B",
        "LDL": "L",
        "LDS": "S",
        "LDT": "T",
        "LDX": "X",
    }
    if mnemonic in load_registers:
        destination = load_registers[mnemonic]
        if operand.startswith("#") and not operand.endswith(",X") and target is not None:
            state[destination] = _singleton(target)
        else:
            state[destination] = None
        return state

    if mnemonic == "LDCH":
        state["A"] = None
        return state

    if mnemonic == "CLEAR" and len(fields) == 1 and fields[0] in TRACKED_REGISTERS:
        state[fields[0]] = (0, 0)
        return state

    if mnemonic == "RMO" and len(fields) == 2 and fields[1] in TRACKED_REGISTERS:
        state[fields[1]] = state.get(fields[0])
        return state

    if mnemonic in ("ADDR", "SUBR", "MULR", "DIVR") and len(fields) == 2 and fields[1] in TRACKED_REGISTERS:
        source = state.get(fields[0])
        destination = state.get(fields[1])
        operation = {
            "ADDR": _interval_add,
            "SUBR": _interval_sub,
            "MULR": _interval_mul,
            "DIVR": _interval_div,
        }[mnemonic]
        state[fields[1]] = operation(destination, source)
        return state

    if mnemonic in ("SHIFTL", "SHIFTR") and fields and fields[0] in TRACKED_REGISTERS:
        state[fields[0]] = None
        return state

    if mnemonic == "COMP":
        if operand.startswith("#") and not operand.endswith(",X") and target is not None:
            state["CC"] = _possible_compare(state.get("A"), _singleton(target))
        else:
            state["CC"] = None
        return state

    if mnemonic == "COMPR" and len(fields) == 2:
        state["CC"] = _possible_compare(state.get(fields[0]), state.get(fields[1]))
        return state

    if mnemonic == "TIX":
        state["X"] = _increment_interval(state.get("X"))
        if operand.startswith("#") and not operand.endswith(",X") and target is not None:
            state["CC"] = _possible_compare(state.get("X"), _singleton(target))
        else:
            state["CC"] = None
        return state

    if mnemonic == "TIXR":
        state["X"] = _increment_interval(state.get("X"))
        compare_register = fields[0] if len(fields) == 1 else None
        state["CC"] = _possible_compare(
            state.get("X"),
            state.get(compare_register) if compare_register is not None else None,
        )
        return state

    if mnemonic == "JSUB":
        state["L"] = _singleton(node["end"])
        return state

    if mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        if not operand.startswith("#") or operand.endswith(",X") or target is None:
            state["A"] = None
            return state
        immediate = _singleton(target)
        if mnemonic == "ADD":
            state["A"] = _interval_add(state.get("A"), immediate)
        elif mnemonic == "SUB":
            state["A"] = _interval_sub(state.get("A"), immediate)
        elif mnemonic == "MUL":
            state["A"] = _interval_mul(state.get("A"), immediate)
        elif mnemonic == "DIV":
            state["A"] = _interval_div(state.get("A"), immediate)
        elif mnemonic == "AND":
            state["A"] = _interval_bitwise_and(state.get("A"), target)
        else:
            state["A"] = _interval_bitwise_or(state.get("A"), target)
        return state

    if mnemonic in ("RD", "FIX"):
        state["A"] = None
        return state
    if mnemonic in ("TD", "COMPF"):
        state["CC"] = None
        return state
    if mnemonic in ("LPS", "SVC"):
        return unknown_range_state()
    return state


def _apply_subroutine_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_range_state()
    preserved = set(summary.get("preserved") or ())
    result = _copy_state(outgoing)
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None
    return result


def _edge_state(source_node, edge, outgoing, summaries):
    if source_node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
        return _apply_subroutine_summary(outgoing, summaries.get(source_node.get("target")))
    return _copy_state(outgoing)


def _conditional_edge_feasible(source_node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(source_node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    possible = None if state is None else state.get("CC")
    if possible is None:
        return True
    if edge["kind"] == "branch":
        return required in possible
    return any(value != required for value in possible)


def analyze_value_ranges(nodes, edges, entry_address, initial_registers=None):
    """Compute path-joined signed intervals and prune range-impossible branches."""
    by_address = {node["address"]: node for node in nodes}
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}

    summaries = summarize_subroutines(nodes, edges)
    entry_state = unknown_range_state()
    for register, value in (initial_registers or {}).items():
        if register in TRACKED_REGISTERS:
            entry_state[register] = None if value is None else _singleton(value)
    incoming[entry_address] = entry_state

    outgoing_edges = {}
    for edge in edges:
        if edge.get("resolved") and edge.get("target") in by_address:
            # Synthetic interprocedural return edges are structural. Caller
            # continuation state is already propagated through the summarized
            # JSUB fallthrough and must not be contaminated by context-free
            # callee state.
            if edge.get("synthetic_return"):
                continue
            outgoing_edges.setdefault(edge["source"], []).append(edge)

    pending = [entry_address]
    queued = {entry_address}
    while pending:
        address = pending.pop(0)
        queued.discard(address)
        state_in = incoming[address]
        if state_in is None:
            continue
        node = by_address[address]
        state_out = transfer_range_state(node, state_in)
        outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _conditional_edge_feasible(node, edge, state_out):
                continue
            target = edge["target"]
            candidate = _edge_state(node, edge, state_out, summaries)
            merged = _join_states(incoming[target], candidate)
            if not _state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        source = by_address.get(edge.get("source"))
        state_out = outgoing.get(edge.get("source"))
        if source is None or source["base_mnemonic"] not in CONDITIONAL_MNEMONICS:
            continue
        possible = None if state_out is None else state_out.get("CC")
        if possible is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        edge["condition_values"] = list(possible)
        edge["condition_required"] = CONDITIONAL_MNEMONICS[source["base_mnemonic"]]
        feasible = _conditional_edge_feasible(source, edge, state_out)
        edge["feasible"] = feasible
        if not feasible and edge.get("resolved"):
            edge["resolved"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "abstract-range-condition"

    return {
        address: {
            "in": None if incoming[address] is None else _copy_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_state(outgoing[address]),
        }
        for address in by_address
    }


def known_ranges(state):
    if state is None:
        return {}
    return {
        register: state.get(register)
        for register in TRACKED_REGISTERS
        if state.get(register) is not None
    }


def possible_conditions(state):
    if state is None or state.get("CC") is None:
        return None
    return tuple(state["CC"])
