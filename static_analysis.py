from disassembler import decode_instruction


TRACKED_REGISTERS = ("A", "X", "L", "B", "S", "T")
REGISTER_MASK = 0xFFFFFF


class StaticAnalysisError(ValueError):
    pass


def unknown_state():
    return {register: None for register in TRACKED_REGISTERS}


def _copy_state(state):
    return {register: state.get(register) for register in TRACKED_REGISTERS}


def _join_states(left, right):
    if left is None:
        return _copy_state(right)
    result = {}
    for register in TRACKED_REGISTERS:
        lhs = left.get(register)
        rhs = right.get(register)
        result[register] = lhs if lhs is not None and lhs == rhs else None
    return result


def _state_equal(left, right):
    if left is None or right is None:
        return left is right
    return all(left.get(register) == right.get(register) for register in TRACKED_REGISTERS)


def _parse_register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


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

    The analysis proves only constants. Unsupported or memory-dependent writes
    become unknown rather than being guessed.
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

    if mnemonic in ("TIX", "TIXR"):
        state["X"] = None if state["X"] is None else (state["X"] + 1) & REGISTER_MASK
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
    if mnemonic in ("LPS", "SVC"):
        return unknown_state()

    return state


def _edge_state(source_node, edge, outgoing):
    if source_node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
        # Returning from a subroutine may clobber any caller-visible register.
        return unknown_state()
    return _copy_state(outgoing)


def analyze_register_constants(nodes, edges, entry_address, initial_registers=None):
    """Compute must-constant register facts over currently resolved CFG edges."""
    by_address = {node["address"]: node for node in nodes}
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}

    entry_state = unknown_state()
    for register, value in (initial_registers or {}).items():
        if register in entry_state:
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
            target = edge["target"]
            candidate = _edge_state(node, edge, state_out)
            merged = _join_states(incoming[target], candidate)
            if not _state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

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
        register: value
        for register, value in state.items()
        if value is not None
    }
