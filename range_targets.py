from disassembler import decode_instruction
from static_analysis import REGISTER_MASK


def resolve_singleton_base_targets(nodes, range_facts):
    """Resolve b-relative instructions when incoming B is a singleton interval.

    Exact-constant dataflow remains authoritative. This helper only fills the
    gap where B is not exact in the must-constant lattice but interval analysis
    has narrowed it to one value.
    """
    changed = False
    for node in nodes:
        flags = node.get("flags") or ""
        if len(flags) != 6 or flags[3] != "1" or flags[4] != "0" or flags[5] != "0":
            continue
        if node.get("target_resolution") == "dataflow-base":
            continue
        facts = range_facts.get(node["address"], {})
        state_in = facts.get("in")
        interval = None if state_in is None else state_in.get("B")
        if interval is None or interval[0] != interval[1]:
            continue
        base_value = interval[0] & REGISTER_MASK
        raw = bytes.fromhex(node["bytes"])
        decoded = decode_instruction(raw, address=node["address"], base_register=base_value)
        if decoded.target is None:
            continue
        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base_value
            or node.get("target_resolution") != "range-singleton-base"
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            node["base_value"] = base_value
            node["target_resolution"] = "range-singleton-base"
            changed = True
    return changed
