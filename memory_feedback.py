from memory_analysis import (
    LOAD_DESTINATION_REGISTERS,
    OPAQUE_MEMORY_BARRIERS,
    READ_WIDTHS,
    STORE_SOURCE_REGISTERS,
    WORD_BYTES,
    WRITE_WIDTHS,
    _cell_id,
    _cell_key,
    _function_entries,
    _ranges_overlap,
)
from range_analysis import (
    _copy_state as _copy_range_state,
    _interval_add,
    _interval_bitwise_and,
    _interval_bitwise_or,
    _interval_div,
    _interval_mul,
    _interval_sub,
    _join_states as _join_range_states,
    _possible_compare,
    _state_equal as _range_state_equal,
    transfer_range_state,
)
from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    _compare24,
    _copy_state as _copy_exact_state,
    _join_states as _join_exact_states,
    _state_equal as _exact_state_equal,
    summarize_subroutines,
    transfer_register_state,
    unknown_state,
)


class MemoryFeedbackError(ValueError):
    pass


def _signed24(value):
    value &= REGISTER_MASK
    return value if value < 0x800000 else value - 0x1000000


def _memory_operation(node):
    mnemonic = node["base_mnemonic"]
    read_width = READ_WIDTHS.get(mnemonic)
    write_width = WRITE_WIDTHS.get(mnemonic)
    operand = node.get("operand") or ""
    immediate = operand.startswith("#")
    unsafe = (
        node.get("target") is None
        or operand.startswith("@")
        or operand.endswith(",X")
    )
    read = None
    write = None
    unknown_read = False
    unknown_write = False
    if read_width is not None and not immediate:
        if unsafe:
            unknown_read = True
        else:
            read = _cell_key(node["target"], read_width)
    if write_width is not None:
        if unsafe:
            unknown_write = True
        else:
            write = _cell_key(node["target"], write_width)
    return {
        "read": read,
        "write": write,
        "unknown_read": unknown_read,
        "unknown_write": unknown_write,
        "barrier": mnemonic in OPAQUE_MEMORY_BARRIERS,
    }


def _tracked_cells(nodes):
    cells = set()
    operations = {}
    for node in nodes:
        operation = _memory_operation(node)
        operations[node["address"]] = operation
        if operation["read"] is not None:
            cells.add(operation["read"])
        if operation["write"] is not None:
            cells.add(operation["write"])
    return sorted(cells), operations


def _call_targets(edges, by_address):
    targets = {}
    unresolved = set()
    for edge in edges:
        if edge.get("kind") != "call":
            continue
        source = edge.get("source")
        if edge.get("resolved") and edge.get("target") in by_address:
            targets.setdefault(source, set()).add(edge["target"])
        else:
            unresolved.add(source)
    return targets, unresolved


def summarize_memory_effects(nodes, edges, cells=None, operations=None):
    """Build compositional may-read/may-write summaries for resolved callees."""
    by_address = {node["address"]: node for node in nodes}
    if cells is None or operations is None:
        cells, operations = _tracked_cells(nodes)
    call_targets, unresolved_calls = _call_targets(edges, by_address)

    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("target") in by_address
            and edge.get("source") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], set()).add(edge["target"])

    entries = sorted({
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call"
        and edge.get("resolved")
        and edge.get("target") in by_address
    })
    shapes = {}
    for entry in entries:
        pending = [entry]
        visited = set()
        direct_reads = set()
        direct_writes = set()
        nested = set()
        unknown_read = False
        unknown_write = False
        returns = []
        while pending:
            address = pending.pop()
            if address in visited or address not in by_address:
                continue
            visited.add(address)
            node = by_address[address]
            operation = operations[address]
            mnemonic = node["base_mnemonic"]

            if operation["read"] is not None:
                for cell in cells:
                    if _ranges_overlap(cell, operation["read"]):
                        direct_reads.add(cell)
            if operation["write"] is not None:
                for cell in cells:
                    if _ranges_overlap(cell, operation["write"]):
                        direct_writes.add(cell)
            unknown_read = unknown_read or operation["unknown_read"]
            unknown_write = unknown_write or operation["unknown_write"]

            if mnemonic == "JSUB":
                nested.update(call_targets.get(address, ()))
                if address in unresolved_calls or not call_targets.get(address):
                    unknown_read = True
                    unknown_write = True
            elif operation["barrier"]:
                unknown_read = True
                unknown_write = True

            if mnemonic == "RSUB":
                returns.append(address)
                continue
            pending.extend(outgoing.get(address, ()))

        shapes[entry] = {
            "entry": entry,
            "instruction_addresses": sorted(visited),
            "return_sites": sorted(returns),
            "direct_reads": direct_reads,
            "direct_writes": direct_writes,
            "nested_callees": nested,
            "unknown_read": unknown_read,
            "unknown_write": unknown_write,
        }

    summaries = {}
    all_cells = set(cells)
    for entry, shape in shapes.items():
        summaries[entry] = {
            "entry": entry,
            "instruction_addresses": list(shape["instruction_addresses"]),
            "return_sites": list(shape["return_sites"]),
            "may_read_cells": sorted(_cell_id(cell) for cell in shape["direct_reads"]),
            "may_write_cells": sorted(_cell_id(cell) for cell in shape["direct_writes"]),
            "unknown_read": bool(shape["unknown_read"]),
            "unknown_write": bool(shape["unknown_write"]),
            "nested_callees": sorted(shape["nested_callees"]),
            "preserved_cells": sorted(
                _cell_id(cell) for cell in (all_cells - shape["direct_writes"])
            ) if not shape["unknown_write"] else [],
        }

    changed = True
    while changed:
        changed = False
        for entry, shape in shapes.items():
            reads = set(shape["direct_reads"])
            writes = set(shape["direct_writes"])
            unknown_read = bool(shape["unknown_read"])
            unknown_write = bool(shape["unknown_write"])
            for callee in shape["nested_callees"]:
                nested = summaries.get(callee)
                if nested is None:
                    unknown_read = True
                    unknown_write = True
                    continue
                reads.update(
                    cell for cell in cells if _cell_id(cell) in set(nested["may_read_cells"])
                )
                writes.update(
                    cell for cell in cells if _cell_id(cell) in set(nested["may_write_cells"])
                )
                unknown_read = unknown_read or nested["unknown_read"]
                unknown_write = unknown_write or nested["unknown_write"]
            new = {
                "may_read_cells": sorted(_cell_id(cell) for cell in reads),
                "may_write_cells": sorted(_cell_id(cell) for cell in writes),
                "unknown_read": unknown_read,
                "unknown_write": unknown_write,
                "preserved_cells": sorted(
                    _cell_id(cell) for cell in (all_cells - writes)
                ) if not unknown_write else [],
            }
            summary = summaries[entry]
            if any(summary[key] != new[key] for key in new):
                summary.update(new)
                changed = True
    return summaries


def _predecessors_and_successors(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    predecessors = {address: set() for address in by_address}
    successors = {address: set() for address in by_address}
    unresolved_exit = {address: False for address in by_address}
    for edge in edges:
        source = edge.get("source")
        if source not in by_address or edge.get("kind") == "call" or edge.get("synthetic_return"):
            continue
        if edge.get("resolved") and edge.get("target") in by_address:
            predecessors[edge["target"]].add(source)
            successors[source].add(edge["target"])
        elif edge.get("kind") in ("jump", "branch", "return"):
            unresolved_exit[source] = True
    return predecessors, successors, unresolved_exit


def _empty_memory_state(cells):
    return {cell: set() for cell in cells}


def _copy_memory_state(state, cells):
    return {cell: set(state.get(cell, ())) for cell in cells}


def _memory_state_equal(left, right, cells):
    return all(set(left.get(cell, ())) == set(right.get(cell, ())) for cell in cells)


def _initial_definition_id(entry, cell):
    return f"MI{entry:05X}:{_cell_id(cell)}"


def _store_definition_id(address, cell):
    return f"MS{address:05X}:{_cell_id(cell)}"


def _clobber_definition_id(address, cell, tag=None):
    suffix = "" if tag is None else f":{tag}"
    return f"MC{address:05X}:{_cell_id(cell)}{suffix}"


def _known_register(node, register):
    state = node.get("registers_in")
    if state is None:
        return None
    return state.get(register)


def _known_register_range(node, register):
    state = node.get("ranges_in")
    if state is None:
        return None
    value = state.get(register)
    return None if value is None else tuple(value)


def _stored_constant(node, source_register):
    if source_register is None:
        return None
    value = _known_register(node, source_register)
    if value is None:
        return None
    if node["base_mnemonic"] == "STCH":
        return value & 0xFF
    return value & REGISTER_MASK


def _stored_range(node, source_register, width):
    if source_register is None or width != WORD_BYTES:
        return None
    interval = _known_register_range(node, source_register)
    return None if interval is None else tuple(interval)


def _ensure_clobber(definitions, address, cell, reason, tag=None):
    definition_id = _clobber_definition_id(address, cell, tag)
    definitions.setdefault(definition_id, {
        "id": definition_id,
        "kind": "clobber",
        "address": address,
        "cell": _cell_id(cell),
        "start": cell[0],
        "width": cell[1],
        "constant": None,
        "range": None,
        "reason": reason,
    })
    return definition_id


def _store_definition(node, cell):
    source_register = STORE_SOURCE_REGISTERS.get(node["base_mnemonic"])
    return {
        "id": _store_definition_id(node["address"], cell),
        "kind": "store",
        "address": node["address"],
        "cell": _cell_id(cell),
        "start": cell[0],
        "width": cell[1],
        "source_register": source_register,
        "source_definitions": list(
            (node.get("use_definitions") or {}).get(source_register, ())
        ) if source_register is not None else [],
        "constant": _stored_constant(node, source_register),
        "range": _stored_range(node, source_register, cell[1]),
        "mnemonic": node["base_mnemonic"],
    }


def _cell_lookup(cells):
    return {_cell_id(cell): cell for cell in cells}


def _call_effect(node, summaries, cells_by_id):
    if node["base_mnemonic"] != "JSUB":
        return None
    target = node.get("target")
    summary = summaries.get(target)
    if summary is None:
        return {
            "read_cells": set(cells_by_id.values()),
            "write_cells": set(cells_by_id.values()),
            "unknown_read": True,
            "unknown_write": True,
        }
    read_cells = {
        cells_by_id[cell_id]
        for cell_id in summary["may_read_cells"]
        if cell_id in cells_by_id
    }
    write_cells = {
        cells_by_id[cell_id]
        for cell_id in summary["may_write_cells"]
        if cell_id in cells_by_id
    }
    if summary["unknown_read"]:
        read_cells = set(cells_by_id.values())
    if summary["unknown_write"]:
        write_cells = set(cells_by_id.values())
    return {
        "read_cells": read_cells,
        "write_cells": write_cells,
        "unknown_read": summary["unknown_read"],
        "unknown_write": summary["unknown_write"],
    }


def _transfer_memory(node, incoming, cells, operation, definitions, summaries, cells_by_id):
    outgoing = _copy_memory_state(incoming, cells)
    address = node["address"]
    call_effect = _call_effect(node, summaries, cells_by_id)

    weak_writes = set()
    reason = None
    if call_effect is not None:
        weak_writes = set(call_effect["write_cells"])
        reason = "callee-memory-effect"
    elif operation["unknown_write"]:
        weak_writes = set(cells)
        reason = "unknown-alias-write"
    elif operation["barrier"]:
        weak_writes = set(cells)
        reason = "opaque-operation"

    for cell in weak_writes:
        outgoing[cell].add(
            _ensure_clobber(
                definitions,
                address,
                cell,
                reason,
                tag=f"C{node.get('target'):05X}" if call_effect is not None and node.get("target") is not None else None,
            )
        )

    write = operation["write"]
    if write is not None:
        store = _store_definition(node, write)
        definitions[store["id"]] = store
        for cell in cells:
            if not _ranges_overlap(cell, write):
                continue
            if cell == write:
                outgoing[cell] = {store["id"]}
            else:
                outgoing[cell] = {
                    _ensure_clobber(
                        definitions,
                        address,
                        cell,
                        "partial-overlap-store",
                    )
                }
    return outgoing


def _constant_from_sources(source_ids, definitions):
    if not source_ids:
        return None
    values = []
    for definition_id in source_ids:
        definition = definitions.get(definition_id)
        if definition is None or definition.get("constant") is None:
            return None
        values.append(definition["constant"])
    return values[0] if values and all(value == values[0] for value in values) else None


def _range_from_sources(source_ids, definitions):
    if not source_ids:
        return None
    intervals = []
    for definition_id in source_ids:
        definition = definitions.get(definition_id)
        if definition is None:
            return None
        interval = definition.get("range")
        if interval is None:
            constant = definition.get("constant")
            if constant is None:
                return None
            signed = _signed24(constant)
            interval = (signed, signed)
        intervals.append(tuple(interval))
    return (
        min(interval[0] for interval in intervals),
        max(interval[1] for interval in intervals),
    )


def analyze_effect_aware_memory(nodes, edges, entry_address):
    """Reaching-store analysis whose call clobbers are guided by callee summaries."""
    by_address = {node["address"]: node for node in nodes}
    if len(by_address) != len(nodes):
        raise MemoryFeedbackError("Duplicate typed instruction address")
    cells, operations = _tracked_cells(nodes)
    cells_by_id = _cell_lookup(cells)
    summaries = summarize_memory_effects(nodes, edges, cells, operations)
    entries = _function_entries(nodes, edges, entry_address)
    predecessors, successors, unresolved_exit = _predecessors_and_successors(nodes, edges)

    definitions = {}
    entry_definitions = {}
    for entry in entries:
        entry_definitions[entry] = {}
        for cell in cells:
            definition_id = _initial_definition_id(entry, cell)
            entry_definitions[entry][cell] = definition_id
            definitions[definition_id] = {
                "id": definition_id,
                "kind": "initial",
                "address": entry,
                "function_entry": entry,
                "cell": _cell_id(cell),
                "start": cell[0],
                "width": cell[1],
                "constant": None,
                "range": None,
            }

    reaching_in = {address: _empty_memory_state(cells) for address in by_address}
    reaching_out = {address: _empty_memory_state(cells) for address in by_address}
    ordered = sorted(by_address)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            incoming = _empty_memory_state(cells)
            for predecessor in predecessors[address]:
                for cell in cells:
                    incoming[cell] |= reaching_out[predecessor][cell]
            for cell, definition_id in entry_definitions.get(address, {}).items():
                incoming[cell].add(definition_id)
            outgoing = _transfer_memory(
                by_address[address], incoming, cells, operations[address], definitions, summaries, cells_by_id
            )
            if (
                not _memory_state_equal(incoming, reaching_in[address], cells)
                or not _memory_state_equal(outgoing, reaching_out[address], cells)
            ):
                reaching_in[address] = incoming
                reaching_out[address] = outgoing
                changed = True

    def_use = {definition_id: [] for definition_id in definitions}
    observable = {definition_id: [] for definition_id in definitions}
    unresolved_reads = []
    same_value = []
    instruction_facts = {}

    for address in ordered:
        node = by_address[address]
        operation = operations[address]
        read = operation["read"]
        sources = []
        load_from_stores = []
        memory_constant = None
        memory_range = None
        if read is not None:
            sources = sorted(reaching_in[address][read])
            load_from_stores = [
                definition_id for definition_id in sources
                if definitions.get(definition_id, {}).get("kind") == "store"
            ]
            memory_constant = _constant_from_sources(sources, definitions)
            memory_range = _range_from_sources(sources, definitions)
            if not sources:
                unresolved_reads.append({
                    "address": address,
                    "cell": _cell_id(read),
                    "reason": "no-reaching-memory-definition",
                })
            for definition_id in sources:
                def_use.setdefault(definition_id, []).append({
                    "address": address,
                    "cell": _cell_id(read),
                    "mnemonic": node["base_mnemonic"],
                })

        observed_cells = set()
        call_effect = _call_effect(node, summaries, cells_by_id)
        if call_effect is not None:
            observed_cells.update(call_effect["read_cells"])
        elif operation["unknown_read"] or operation["barrier"]:
            observed_cells.update(cells)
        for cell in observed_cells:
            for definition_id in reaching_in[address][cell]:
                observable.setdefault(definition_id, []).append({
                    "address": address,
                    "reason": "callee-memory-read" if call_effect is not None else "opaque-memory-read",
                    "cell": _cell_id(cell),
                })

        write = operation["write"]
        store_id = None
        stored_constant = None
        stored_range = None
        if write is not None:
            store_id = _store_definition_id(address, write)
            definition = definitions.get(store_id)
            if definition is not None:
                stored_constant = definition.get("constant")
                stored_range = definition.get("range")
                previous = sorted(reaching_in[address][write])
                previous_constant = _constant_from_sources(previous, definitions)
                if stored_constant is not None and previous and previous_constant == stored_constant:
                    same_value.append({
                        "address": address,
                        "definition_id": store_id,
                        "cell": _cell_id(write),
                        "constant": stored_constant,
                        "previous_definitions": previous,
                    })

        destination = LOAD_DESTINATION_REGISTERS.get(node["base_mnemonic"])
        loaded_constant = None
        loaded_range = None
        if destination is not None and read is not None and read[1] == WORD_BYTES:
            if memory_constant is not None:
                loaded_constant = {"register": destination, "value": memory_constant & REGISTER_MASK}
            if memory_range is not None:
                loaded_range = {"register": destination, "range": list(memory_range)}

        instruction_facts[address] = {
            "memory_read": None if read is None else _cell_id(read),
            "memory_write": None if write is None else _cell_id(write),
            "memory_sources": sources,
            "load_from_stores": load_from_stores,
            "memory_constant": memory_constant,
            "memory_range": None if memory_range is None else list(memory_range),
            "loaded_register_constant": loaded_constant,
            "loaded_register_range": loaded_range,
            "store_definition_id": store_id,
            "stored_constant": stored_constant,
            "stored_range": None if stored_range is None else list(stored_range),
            "unknown_memory_read": bool(operation["unknown_read"]),
            "unknown_memory_write": bool(operation["unknown_write"]),
            "memory_barrier": bool(operation["barrier"]),
            "reaching_memory_in": {
                _cell_id(cell): sorted(reaching_in[address][cell])
                for cell in cells if reaching_in[address][cell]
            },
            "reaching_memory_out": {
                _cell_id(cell): sorted(reaching_out[address][cell])
                for cell in cells if reaching_out[address][cell]
            },
        }

    for address in ordered:
        node = by_address[address]
        is_exit = (
            node["base_mnemonic"] == "RSUB"
            or unresolved_exit[address]
            or not successors[address]
        )
        if not is_exit:
            continue
        for cell in cells:
            for definition_id in reaching_out[address][cell]:
                observable.setdefault(definition_id, []).append({
                    "address": address,
                    "reason": "represented-exit",
                    "cell": _cell_id(cell),
                })

    chains = []
    overwritten = []
    for definition_id in sorted(definitions):
        definition = definitions[definition_id]
        uses = sorted(
            def_use.get(definition_id, ()),
            key=lambda item: (item["address"], item["cell"], item["mnemonic"]),
        )
        observations = sorted(
            observable.get(definition_id, ()),
            key=lambda item: (item["address"], item["reason"], item["cell"]),
        )
        chains.append({**definition, "use_sites": uses, "observable_sites": observations})
        if definition.get("kind") == "store" and not uses and not observations:
            overwritten.append({
                "definition_id": definition_id,
                "address": definition["address"],
                "cell": definition["cell"],
                "constant": definition.get("constant"),
            })

    return {
        "cells": [{"id": _cell_id(cell), "start": cell[0], "width": cell[1]} for cell in cells],
        "entries": entries,
        "entry_definitions": {
            entry: {_cell_id(cell): definition_id for cell, definition_id in mapping.items()}
            for entry, mapping in entry_definitions.items()
        },
        "definitions": [definitions[key] for key in sorted(definitions)],
        "chains": chains,
        "instruction_facts": instruction_facts,
        "unresolved_reads": sorted(unresolved_reads, key=lambda item: (item["address"], item["cell"])),
        "overwritten_stores": sorted(overwritten, key=lambda item: (item["address"], item["cell"])),
        "same_value_store_candidates": sorted(same_value, key=lambda item: (item["address"], item["cell"])),
        "memory_summaries": [summaries[key] for key in sorted(summaries)],
    }


def _memory_aware_exact_transfer(node, incoming):
    outgoing = transfer_register_state(node, incoming)
    constant = node.get("memory_constant")
    if constant is None or node.get("memory_cell_read") is None:
        return outgoing
    mnemonic = node["base_mnemonic"]
    if mnemonic in LOAD_DESTINATION_REGISTERS:
        outgoing[LOAD_DESTINATION_REGISTERS[mnemonic]] = constant & REGISTER_MASK
        return outgoing
    if mnemonic == "LDCH":
        if incoming.get("A") is not None:
            outgoing["A"] = (incoming["A"] & 0xFFFF00) | (constant & 0xFF)
        return outgoing
    if mnemonic == "COMP":
        outgoing["CC"] = _compare24(incoming.get("A"), constant) if incoming.get("A") is not None else None
        return outgoing
    if mnemonic == "TIX":
        if outgoing.get("X") is not None:
            outgoing["CC"] = _compare24(outgoing["X"], constant)
        return outgoing
    if mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        current = incoming.get("A")
        if current is None:
            outgoing["A"] = None
            return outgoing
        if mnemonic == "ADD":
            value = current + constant
        elif mnemonic == "SUB":
            value = current - constant
        elif mnemonic == "MUL":
            value = current * constant
        elif mnemonic == "DIV":
            if constant == 0:
                outgoing["A"] = None
                return outgoing
            value = int(current / constant)
        elif mnemonic == "AND":
            value = current & constant
        else:
            value = current | constant
        outgoing["A"] = value & REGISTER_MASK
    return outgoing


def _memory_aware_range_transfer(node, incoming):
    outgoing = transfer_range_state(node, incoming)
    raw_range = node.get("memory_range")
    if raw_range is None or node.get("memory_cell_read") is None:
        return outgoing
    interval = tuple(raw_range)
    mnemonic = node["base_mnemonic"]
    if mnemonic in LOAD_DESTINATION_REGISTERS:
        outgoing[LOAD_DESTINATION_REGISTERS[mnemonic]] = interval
        return outgoing
    if mnemonic == "COMP":
        outgoing["CC"] = _possible_compare(incoming.get("A"), interval)
        return outgoing
    if mnemonic == "TIX":
        outgoing["CC"] = _possible_compare(outgoing.get("X"), interval)
        return outgoing
    if mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        left = incoming.get("A")
        if mnemonic == "ADD":
            outgoing["A"] = _interval_add(left, interval)
        elif mnemonic == "SUB":
            outgoing["A"] = _interval_sub(left, interval)
        elif mnemonic == "MUL":
            outgoing["A"] = _interval_mul(left, interval)
        elif mnemonic == "DIV":
            outgoing["A"] = _interval_div(left, interval)
        elif interval[0] == interval[1]:
            raw = interval[0] & REGISTER_MASK
            outgoing["A"] = (
                _interval_bitwise_and(left, raw)
                if mnemonic == "AND"
                else _interval_bitwise_or(left, raw)
            )
        else:
            outgoing["A"] = None
    return outgoing


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
    return required in possible if edge["kind"] == "branch" else any(value != required for value in possible)


def _apply_exact_call_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return unknown_state()
    result = _copy_exact_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None
    return result


def _apply_range_call_summary(outgoing, summary):
    if summary is None or not summary.get("may_return"):
        return {register: None for register in TRACKED_REGISTERS + ("CC",)}
    result = _copy_range_state(outgoing)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result[register] = None
    result["CC"] = None
    return result


def _resolved_outgoing(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    outgoing = {}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("target") in by_address
            and not edge.get("synthetic_return")
        ):
            outgoing.setdefault(edge["source"], []).append(edge)
    return by_address, outgoing


def analyze_memory_aware_constants(nodes, edges, entry_address, initial_registers=None):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}
    summaries = summarize_subroutines(nodes, edges)
    entry_state = unknown_state()
    for register, value in (initial_registers or {}).items():
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
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_exact_call_summary(state_out, summaries.get(node.get("target")))
            target = edge["target"]
            merged = _join_exact_states(incoming[target], candidate)
            if not _exact_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        if not edge.get("resolved"):
            continue
        source = by_address.get(edge.get("source"))
        if source is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        state = outgoing.get(source["address"])
        if source["base_mnemonic"] in CONDITIONAL_MNEMONICS and not _exact_edge_feasible(source, edge, state):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "memory-feedback-condition"
    return {
        address: {
            "in": None if incoming[address] is None else _copy_exact_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_exact_state(outgoing[address]),
        }
        for address in by_address
    }


def analyze_memory_aware_ranges(nodes, edges, entry_address, initial_registers=None):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return {address: {"in": None, "out": None} for address in by_address}
    summaries = summarize_subroutines(nodes, edges)
    entry_state = {register: None for register in TRACKED_REGISTERS + ("CC",)}
    for register, value in (initial_registers or {}).items():
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
            if node["base_mnemonic"] == "JSUB" and edge["kind"] == "fallthrough":
                candidate = _apply_range_call_summary(state_out, summaries.get(node.get("target")))
            target = edge["target"]
            merged = _join_range_states(incoming[target], candidate)
            if not _range_state_equal(incoming[target], merged):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    for edge in edges:
        if not edge.get("resolved"):
            continue
        source = by_address.get(edge.get("source"))
        if source is None or edge.get("kind") not in ("branch", "fallthrough"):
            continue
        state = outgoing.get(source["address"])
        if source["base_mnemonic"] in CONDITIONAL_MNEMONICS and not _range_edge_feasible(source, edge, state):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "memory-feedback-range-condition"
    return {
        address: {
            "in": None if incoming[address] is None else _copy_range_state(incoming[address]),
            "out": None if outgoing[address] is None else _copy_range_state(outgoing[address]),
        }
        for address in by_address
    }


def _attach_memory_facts(nodes, memory):
    facts_by_address = memory.get("instruction_facts", {})
    for node in nodes:
        facts = facts_by_address.get(node["address"], {})
        node["memory_cell_read"] = facts.get("memory_read")
        node["memory_cell_write"] = facts.get("memory_write")
        node["memory_sources"] = list(facts.get("memory_sources") or ())
        node["load_from_stores"] = list(facts.get("load_from_stores") or ())
        node["memory_constant"] = facts.get("memory_constant")
        node["memory_range"] = facts.get("memory_range")
        node["loaded_register_constant"] = facts.get("loaded_register_constant")
        node["loaded_register_range"] = facts.get("loaded_register_range")
        node["store_definition_id"] = facts.get("store_definition_id")
        node["stored_constant"] = facts.get("stored_constant")
        node["stored_range"] = facts.get("stored_range")
        node["unknown_memory_read"] = bool(facts.get("unknown_memory_read"))
        node["unknown_memory_write"] = bool(facts.get("unknown_memory_write"))
        node["memory_barrier"] = bool(facts.get("memory_barrier"))
        node["reaching_memory_in"] = dict(facts.get("reaching_memory_in") or {})
        node["reaching_memory_out"] = dict(facts.get("reaching_memory_out") or {})


def _feedback_signature(nodes, edges, memory):
    return (
        tuple(
            (
                node["address"],
                repr(node.get("registers_in")),
                repr(node.get("registers_out")),
                repr(node.get("ranges_in")),
                repr(node.get("ranges_out")),
                node.get("memory_constant"),
                repr(node.get("memory_range")),
            )
            for node in nodes
        ),
        tuple(
            (edge.get("source"), edge.get("target"), edge.get("kind"), bool(edge.get("resolved")), edge.get("resolution"))
            for edge in edges
        ),
        tuple(
            (item["id"], item.get("constant"), repr(item.get("range")))
            for item in memory.get("definitions", ())
        ),
    )


def refine_memory_feedback(nodes, edges, entry_address, base_register=None):
    """Iterate memory facts back into register/range/CC analysis until stable."""
    initial = {} if base_register is None else {"B": base_register}
    previous = None
    max_iterations = max(3, len(nodes) + 3)
    memory = None
    for iteration in range(1, max_iterations + 1):
        memory = analyze_effect_aware_memory(nodes, edges, entry_address)
        _attach_memory_facts(nodes, memory)
        exact = analyze_memory_aware_constants(nodes, edges, entry_address, initial)
        ranges = analyze_memory_aware_ranges(nodes, edges, entry_address, initial)
        for node in nodes:
            node["registers_in"] = exact[node["address"]]["in"]
            node["registers_out"] = exact[node["address"]]["out"]
            node["ranges_in"] = ranges[node["address"]]["in"]
            node["ranges_out"] = ranges[node["address"]]["out"]
        signature = _feedback_signature(nodes, edges, memory)
        if signature == previous:
            memory["feedback_iterations"] = iteration
            memory["feedback_converged"] = True
            return memory
        previous = signature
    raise MemoryFeedbackError("Integrated memory/register feedback did not converge")
