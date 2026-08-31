from static_analysis import TRACKED_REGISTERS


LIVE_VALUES = TRACKED_REGISTERS + ("CC",)
_ALL_VALUES = set(LIVE_VALUES)
_GENERAL_REGISTERS = set(TRACKED_REGISTERS)


class LivenessAnalysisError(ValueError):
    pass


def _parse_register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


def _address_register_uses(node):
    flags = node.get("flags") or ""
    uses = set()
    if len(flags) == 6:
        if flags[2] == "1":
            uses.add("X")
        if flags[3] == "1":
            uses.add("B")
    return uses


def _summary_by_entry(summaries):
    if summaries is None:
        return {}
    if isinstance(summaries, dict):
        return summaries
    return {
        summary["entry"]: summary
        for summary in summaries
        if summary.get("entry") is not None
    }


def instruction_use_def(node, summaries=None):
    """Return conservative use/def and side-effect facts for one typed instruction.

    Only A/X/L/B/S/T and the condition code participate in liveness. Memory,
    device, floating-point, PC, and SW state are represented only as side-effect
    annotations. Unknown privileged operations conservatively use and define all
    tracked values so dead-write analysis cannot optimize across them.
    """
    summaries = _summary_by_entry(summaries)
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    fields = _parse_register_operands(operand)
    uses = _address_register_uses(node)
    defs = set()
    memory_read = False
    memory_write = False
    side_effects = False
    opaque = False

    load_registers = {
        "LDA": "A",
        "LDB": "B",
        "LDL": "L",
        "LDS": "S",
        "LDT": "T",
        "LDX": "X",
    }
    store_registers = {
        "STA": "A",
        "STB": "B",
        "STL": "L",
        "STS": "S",
        "STT": "T",
        "STX": "X",
    }

    if mnemonic in load_registers:
        defs.add(load_registers[mnemonic])
        memory_read = not operand.startswith("#")
    elif mnemonic == "LDCH":
        # LDCH replaces only the low byte, so the previous upper A bits remain
        # semantically relevant even though the exact-value analyzer clobbers A.
        uses.add("A")
        defs.add("A")
        memory_read = True
    elif mnemonic in store_registers:
        uses.add(store_registers[mnemonic])
        memory_write = True
        side_effects = True
    elif mnemonic == "STCH":
        uses.add("A")
        memory_write = True
        side_effects = True
    elif mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        uses.add("A")
        defs.add("A")
        memory_read = not operand.startswith("#")
    elif mnemonic == "COMP":
        uses.add("A")
        defs.add("CC")
        memory_read = not operand.startswith("#")
    elif mnemonic == "TIX":
        uses.add("X")
        defs.update(("X", "CC"))
        memory_read = not operand.startswith("#")
    elif mnemonic in ("JEQ", "JGT", "JLT"):
        uses.add("CC")
        side_effects = True
    elif mnemonic == "J":
        side_effects = True
    elif mnemonic == "JSUB":
        # Without a calling convention, a callee may consume any incoming
        # general register. The resolved summary still lets us limit which
        # registers may be overwritten on return.
        uses.update(TRACKED_REGISTERS)
        summary = summaries.get(node.get("target"))
        if summary is None:
            defs.update(_ALL_VALUES)
            opaque = True
        else:
            defs.update(summary.get("may_clobber") or ())
            defs.update(("L", "CC"))
        side_effects = True
    elif mnemonic == "RSUB":
        uses.add("L")
        side_effects = True
    elif mnemonic == "CLEAR" and len(fields) == 1:
        if fields[0] in _GENERAL_REGISTERS:
            defs.add(fields[0])
    elif mnemonic == "RMO" and len(fields) == 2:
        if fields[0] in _GENERAL_REGISTERS:
            uses.add(fields[0])
        if fields[1] in _GENERAL_REGISTERS:
            defs.add(fields[1])
    elif mnemonic in ("ADDR", "SUBR", "MULR", "DIVR") and len(fields) == 2:
        if fields[0] in _GENERAL_REGISTERS:
            uses.add(fields[0])
        if fields[1] in _GENERAL_REGISTERS:
            uses.add(fields[1])
            defs.add(fields[1])
    elif mnemonic == "COMPR" and len(fields) == 2:
        uses.update(field for field in fields if field in _GENERAL_REGISTERS)
        defs.add("CC")
    elif mnemonic in ("SHIFTL", "SHIFTR") and fields:
        if fields[0] in _GENERAL_REGISTERS:
            uses.add(fields[0])
            defs.add(fields[0])
    elif mnemonic == "TIXR" and len(fields) == 1:
        uses.add("X")
        if fields[0] in _GENERAL_REGISTERS:
            uses.add(fields[0])
        defs.update(("X", "CC"))
    elif mnemonic == "RD":
        # RD replaces the low byte of A and interacts with an external device.
        uses.add("A")
        defs.add("A")
        side_effects = True
    elif mnemonic == "WD":
        uses.add("A")
        side_effects = True
    elif mnemonic == "TD":
        defs.add("CC")
        side_effects = True
    elif mnemonic == "FIX":
        defs.add("A")
    elif mnemonic == "FLOAT":
        uses.add("A")
    elif mnemonic == "COMPF":
        defs.add("CC")
        memory_read = True
    elif mnemonic in ("ADDF", "DIVF", "MULF", "SUBF", "LDF"):
        memory_read = True
    elif mnemonic == "STF":
        memory_write = True
        side_effects = True
    elif mnemonic in ("STSW", "STI"):
        memory_write = True
        side_effects = True
    elif mnemonic == "SSK":
        uses.add("A")
        memory_write = True
        side_effects = True
    elif mnemonic in ("LPS", "SVC", "HIO", "SIO", "TIO"):
        uses.update(_ALL_VALUES)
        defs.update(_ALL_VALUES)
        side_effects = True
        opaque = True
    elif mnemonic in ("NORM",):
        # Floating-point state is intentionally outside this liveness domain.
        pass

    uses &= _ALL_VALUES
    defs &= _ALL_VALUES
    return {
        "uses": sorted(uses),
        "defs": sorted(defs),
        "memory_read": memory_read,
        "memory_write": memory_write,
        "side_effects": side_effects,
        "opaque": opaque,
    }


def _successors(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    successors = {address: set() for address in by_address}
    unresolved_control = {address: False for address in by_address}
    for edge in edges:
        source = edge.get("source")
        if source not in by_address:
            continue
        if edge.get("kind") == "call" or edge.get("synthetic_return"):
            # Calls are summarized as one instruction. Context-specific return
            # edges are structural CFG evidence, not ordinary liveness edges.
            continue
        if edge.get("resolved") and edge.get("target") in by_address:
            successors[source].add(edge["target"])
        elif edge.get("kind") in ("jump", "branch", "return"):
            unresolved_control[source] = True
    return successors, unresolved_control


def analyze_liveness(nodes, edges, summaries=None):
    """Compute backward must-not-assume-dead liveness over the typed CFG.

    Unknown exits and RSUB boundaries conservatively expose every tracked value
    to the outside world. Consequently a reported dead register write is one
    whose value is killed before any represented successor can observe it; the
    analysis never relies on an invented ABI or on opaque return behavior.
    """
    by_address = {node["address"]: node for node in nodes}
    semantics = {
        address: instruction_use_def(node, summaries=summaries)
        for address, node in by_address.items()
    }
    successors, unresolved_control = _successors(nodes, edges)
    live_in = {address: set() for address in by_address}
    live_out = {address: set() for address in by_address}

    ordered = sorted(by_address, reverse=True)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            node = by_address[address]
            out = set()
            for target in successors[address]:
                out |= live_in[target]
            if (
                node["base_mnemonic"] == "RSUB"
                or unresolved_control[address]
                or not successors[address]
            ):
                out |= _ALL_VALUES
            facts = semantics[address]
            uses = set(facts["uses"])
            defs = set(facts["defs"])
            incoming = uses | (out - defs)
            if out != live_out[address] or incoming != live_in[address]:
                live_out[address] = out
                live_in[address] = incoming
                changed = True

    result = {}
    for address in sorted(by_address):
        node = by_address[address]
        facts = semantics[address]
        dead_registers = sorted(
            register
            for register in set(facts["defs"]) & _GENERAL_REGISTERS
            if register not in live_out[address]
        )
        result[address] = {
            **facts,
            "live_in": sorted(live_in[address]),
            "live_out": sorted(live_out[address]),
            "dead_writes": dead_registers if node.get("reachable", True) else [],
            "dead_condition_write": (
                "CC" in facts["defs"]
                and "CC" not in live_out[address]
                and node.get("reachable", True)
            ),
        }
    return result
