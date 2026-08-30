from disassembler import decode_instruction


TRACKED_REGISTERS = ("A", "X", "L", "B", "S", "T")
STATE_KEYS = TRACKED_REGISTERS + ("CC",)
REGISTER_MASK = 0xFFFFFF
CONDITION_VALUES = ("LT", "EQ", "GT")
CONDITIONAL_MNEMONICS = {"JEQ": "EQ", "JLT": "LT", "JGT": "GT"}


class StaticAnalysisError(ValueError):
    pass


def unknown_state():
    return {key: None for key in STATE_KEYS}


def _copy_state(state):
    return {key: state.get(key) for key in STATE_KEYS}


def _join_states(left, right):
    if left is None:
        return _copy_state(right)
    result = {}
    for key in STATE_KEYS:
        lhs = left.get(key)
        rhs = right.get(key)
        result[key] = lhs if lhs is not None and lhs == rhs else None
    return result


def _state_equal(left, right):
    if left is None or right is None:
        return left is right
    return all(left.get(key) == right.get(key) for key in STATE_KEYS)


def _parse_register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - 0x1000000


def _compare24(left, right):
    lhs = _signed24(left)
    rhs = _signed24(right)
    if lhs < rhs:
        return "LT"
    if lhs > rhs:
        return "GT"
    return "EQ"


def _binary_register_operation(state, source, destination, operator):
    src = state.get(source)
    dst = state.get(destination)
    if src is None or dst is None:
        state[destination] = None
        return
    if operator == "add":
        value = dst + src
    elif operator == "sub":
        value = dst - src
    elif operator == "mul":
        value = dst * src
    elif operator == "div":
        if src == 0:
            state[destination] = None
            return
        value = int(dst / src)
    else:
        state[destination] = None
        return
    state[destination] = value & REGISTER_MASK


def transfer_register_state(node, incoming):
    """Apply a conservative SIC/XE transfer function to one typed instruction.

    The abstract state proves constants for A/X/L/B/S/T plus the condition code
    (LT/EQ/GT). Unsupported or memory-dependent writes become unknown rather
    than being guessed.
    """
    state = _copy_state(incoming)
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    target = node.get("target")

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
            state[destination] = target & REGISTER_MASK
        else:
            state[destination] = None
        return state

    if mnemonic == "LDCH":
        state["A"] = None
        return state

    fields = _parse_register_operands(operand)
    if mnemonic == "CLEAR" and len(fields) == 1 and fields[0] in state:
        state[fields[0]] = 0
        return state
    if mnemonic == "RMO" and len(fields) == 2 and fields[1] in state:
        state[fields[1]] = state.get(fields[0])
        return state
    if mnemonic in ("ADDR", "SUBR", "MULR", "DIVR") and len(fields) == 2 and fields[1] in state:
        operation = {
            "ADDR": "add",
            "SUBR": "sub",
            "MULR": "mul",
            "DIVR": "div",
        }[mnemonic]
        _binary_register_operation(state, fields[0], fields[1], operation)
        return state
    if mnemonic in ("SHIFTL", "SHIFTR") and fields and fields[0] in state:
        # The implementation deliberately does not encode a shift-semantics
        # assumption into constant propagation; the destination is clobbered.
        state[fields[0]] = None
        return state

    if mnemonic == "COMP":
        if operand.startswith("#") and not operand.endswith(",X") and target is not None and state["A"] is not None:
            state["CC"] = _compare24(state["A"], target)
        else:
            state["CC"] = None
        return state

    if mnemonic == "COMPR" and len(fields) == 2:
        left = state.get(fields[0])
        right = state.get(fields[1])
        state["CC"] = _compare24(left, right) if left is not None and right is not None else None
        return state

    if mnemonic == "TIX":
        state["X"] = None if state["X"] is None else (state["X"] + 1) & REGISTER_MASK
        if operand.startswith("#") and not operand.endswith(",X") and target is not None and state["X"] is not None:
            state["CC"] = _compare24(state["X"], target)
        else:
            state["CC"] = None
        return state

    if mnemonic == "TIXR":
        state["X"] = None if state["X"] is None else (state["X"] + 1) & REGISTER_MASK
        compare_register = fields[0] if len(fields) == 1 else None
        compare_value = state.get(compare_register) if compare_register is not None else None
        state["CC"] = _compare24(state["X"], compare_value) if state["X"] is not None and compare_value is not None else None
        return state

    if mnemonic == "JSUB":
        state["L"] = node["end"] & REGISTER_MASK
        return state

    accumulator_operations = {
        "ADD": "add",
        "SUB": "sub",
        "MUL": "mul",
        "DIV": "div",
        "AND": "and",
        "OR": "or",
    }
    if mnemonic in accumulator_operations:
        current = state["A"]
        if not operand.startswith("#") or operand.endswith(",X") or target is None or current is None:
            state["A"] = None
            return state
        operation = accumulator_operations[mnemonic]
        if operation == "add":
            value = current + target
        elif operation == "sub":
            value = current - target
        elif operation == "mul":
            value = current * target
        elif operation == "div":
            if target == 0:
                state["A"] = None
                return state
            value = int(current / target)
        elif operation == "and":
            value = current & target
        else:
            value = current | target
        state["A"] = value & REGISTER_MASK
        return state

    if mnemonic in ("RD", "FIX"):
        state["A"] = None
        return state
    if mnemonic in ("TD", "COMPF"):
        state["CC"] = None
        return state
    if mnemonic in ("LPS", "SVC"):
        return unknown_state()

    return state


def _written_registers(node):
    """Return registers that the instruction may write for preserve summaries."""
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
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
        return {load_registers[mnemonic]}
    if mnemonic in ("LDCH", "ADD", "SUB", "MUL", "DIV", "AND", "OR", "RD", "FIX"):
        return {"A"}
    if mnemonic == "CLEAR" and len(fields) == 1 and fields[0] in TRACKED_REGISTERS:
        return {fields[0]}
    if mnemonic in ("RMO", "ADDR", "SUBR", "MULR", "DIVR") and len(fields) == 2 and fields[1] in TRACKED_REGISTERS:
        return {fields[1]}
    if mnemonic in ("SHIFTL", "SHIFTR") and fields and fields[0] in TRACKED_REGISTERS:
        return {fields[0]}
    if mnemonic in ("TIX", "TIXR"):
        return {"X"}
    if mnemonic == "JSUB":
        # Nested calls are opaque to this deliberately local summary model.
        return set(TRACKED_REGISTERS)
    if mnemonic in ("LPS", "SVC"):
        return set(TRACKED_REGISTERS)
    return set()


def summarize_subroutines(nodes, edges):
    """Build conservative may-clobber/preserve summaries for resolved callees.

    A register is preserved only when no instruction reachable from the callee
    entry through non-call control flow may write it. Nested calls are treated
    as opaque and therefore may clobber every tracked register.
    """
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if not edge.get("resolved") or edge.get("target") not in by_address:
            continue
        outgoing.setdefault(edge["source"], []).append(edge)

    entries = sorted({
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call" and edge.get("resolved") and edge.get("target") in by_address
    })
    summaries = {}
    for entry in entries:
        visited = set()
        pending = [entry]
        clobbered = set()
        returns = []
        while pending:
            address = pending.pop()
            if address in visited or address not in by_address:
                continue
            visited.add(address)
            node = by_address[address]
            clobbered |= _written_registers(node)
            if node["base_mnemonic"] == "RSUB":
                returns.append(address)
                continue
            for edge in outgoing.get(address, ()):
                if edge.get("kind") == "call":
                    continue
                pending.append(edge["target"])

        preserved = sorted(set(TRACKED_REGISTERS) - clobbered)
        summaries[entry] = {
            "entry": entry,
            "symbols": list(by_address[entry].get("symbols") or ()),
            "preserved": preserved,
            "may_clobber": sorted(clobbered),
            "return_sites": sorted(returns),
            "instruction_addresses": sorted(visited),
            "may_return": bool(returns),
        }
    return summaries


def _conditional_edge_feasible(source_node, edge, state):
    required = CONDITIONAL_MNEMONICS.get(source_node["base_mnemonic"])
    if required is None or edge.get("kind") not in ("branch", "fallthrough"):
        return True
    cc = None if state is None else state.get("CC")
    if cc not in CONDITION_VALUES:
        return True
    taken = cc == required
    return taken if edge["kind"] == "branch" else not taken


def _apply_subroutine_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_state()
    preserved = set(summary.get("preserved") or ())
    result = _copy_state(outgoing)
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    # A callee may modify condition code even when general registers are
    # preserved; condition preservation is not claimed by this summary model.
    result["CC"] = None
    return result


def _edge_state(source_node, edge, outgoing, subroutine_summaries):
    if source_node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
        summary = subroutine_summaries.get(source_node.get("target"))
        return _apply_subroutine_summary(outgoing, summary)
    return _copy_state(outgoing)


def analyze_register_constants(nodes, edges, entry_address, initial_registers=None):
    """Compute must-constant register/condition facts over resolved CFG edges.

    The function also marks statically impossible conditional edges as
    unresolved with a `condition-false` reason, so downstream reachability,
    dominator, loop, and complexity analysis automatically consumes the
    condition-sensitive graph.
    """
    by_address = {node["address"]: node for node in nodes}
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}

    subroutine_summaries = summarize_subroutines(nodes, edges)
    for node in nodes:
        if node["base_mnemonic"] == "JSUB":
            summary = subroutine_summaries.get(node.get("target"))
            if summary is None:
                node.pop("call_summary", None)
            else:
                node["call_summary"] = summary

    entry_state = unknown_state()
    for register, value in (initial_registers or {}).items():
        if register in TRACKED_REGISTERS:
            entry_state[register] = None if value is None else value & REGISTER_MASK
    incoming[entry_address] = entry_state

    outgoing_edges = {}
    for edge in edges:
        if edge.get("resolved") and edge.get("target") in by_address:
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
        state_out = transfer_register_state(node, state_in)
        if not _state_equal(outgoing[address], state_out):
            outgoing[address] = state_out
        for edge in outgoing_edges.get(address, ()):
            if not _conditional_edge_feasible(node, edge, state_out):
                continue
            target = edge["target"]
            candidate = _edge_state(node, edge, state_out, subroutine_summaries)
            merged = _join_states(incoming[target], candidate)
            if not _state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    # Prune only when the source condition is actually proven. Structural
    # unresolved edges remain unresolved for their original reason.
    for edge in edges:
        source = by_address.get(edge.get("source"))
        state_out = outgoing.get(edge.get("source"))
        if source is None or source["base_mnemonic"] not in CONDITIONAL_MNEMONICS:
            continue
        cc = None if state_out is None else state_out.get("CC")
        if cc not in CONDITION_VALUES or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        edge["condition_code"] = cc
        edge["condition_required"] = CONDITIONAL_MNEMONICS[source["base_mnemonic"]]
        feasible = _conditional_edge_feasible(source, edge, state_out)
        edge["feasible"] = feasible
        if not feasible:
            edge["resolved"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "abstract-condition"

    return {
        address: {
            "in": None if incoming[address] is None else _copy_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_state(outgoing[address]),
        }
        for address in by_address
    }


def resolve_dynamic_base_targets(nodes, register_facts):
    """Re-decode b-relative typed instructions using the proven incoming B value.

    Returns True when any decoded target/operand/base annotation changed.
    """
    changed = False
    for node in nodes:
        flags = node.get("flags") or ""
        if len(flags) != 6 or flags[3] != "1" or flags[4] != "0" or flags[5] != "0":
            node.pop("base_value", None)
            node.pop("target_resolution", None)
            continue
        facts = register_facts.get(node["address"], {})
        state_in = facts.get("in")
        base_value = None if state_in is None else state_in.get("B")
        raw = bytes.fromhex(node["bytes"])
        decoded = decode_instruction(raw, address=node["address"], base_register=base_value)
        new_resolution = "dataflow-base" if base_value is not None and decoded.target is not None else None
        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base_value
            or node.get("target_resolution") != new_resolution
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            if base_value is None:
                node.pop("base_value", None)
            else:
                node["base_value"] = base_value
            if new_resolution is None:
                node.pop("target_resolution", None)
            else:
                node["target_resolution"] = new_resolution
            changed = True
    return changed


def known_registers(state):
    if state is None:
        return {}
    return {
        register: state.get(register)
        for register in TRACKED_REGISTERS
        if state.get(register) is not None
    }


def known_condition(state):
    if state is None:
        return None
    value = state.get("CC")
    return value if value in CONDITION_VALUES else None
