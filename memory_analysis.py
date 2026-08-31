from liveness_analysis import instruction_use_def
from static_analysis import known_registers


WORD_BYTES = 3
FLOAT_BYTES = 6

READ_WIDTHS = {
    "LDA": WORD_BYTES,
    "LDB": WORD_BYTES,
    "LDL": WORD_BYTES,
    "LDS": WORD_BYTES,
    "LDT": WORD_BYTES,
    "LDX": WORD_BYTES,
    "LDCH": 1,
    "LDF": FLOAT_BYTES,
    "ADD": WORD_BYTES,
    "SUB": WORD_BYTES,
    "MUL": WORD_BYTES,
    "DIV": WORD_BYTES,
    "AND": WORD_BYTES,
    "OR": WORD_BYTES,
    "COMP": WORD_BYTES,
    "TIX": WORD_BYTES,
    "ADDF": FLOAT_BYTES,
    "SUBF": FLOAT_BYTES,
    "MULF": FLOAT_BYTES,
    "DIVF": FLOAT_BYTES,
    "COMPF": FLOAT_BYTES,
}

WRITE_WIDTHS = {
    "STA": WORD_BYTES,
    "STB": WORD_BYTES,
    "STL": WORD_BYTES,
    "STS": WORD_BYTES,
    "STT": WORD_BYTES,
    "STX": WORD_BYTES,
    "STCH": 1,
    "STF": FLOAT_BYTES,
    "STI": WORD_BYTES,
    "STSW": WORD_BYTES,
}

STORE_SOURCE_REGISTERS = {
    "STA": "A",
    "STB": "B",
    "STL": "L",
    "STS": "S",
    "STT": "T",
    "STX": "X",
    "STCH": "A",
}

LOAD_DESTINATION_REGISTERS = {
    "LDA": "A",
    "LDB": "B",
    "LDL": "L",
    "LDS": "S",
    "LDT": "T",
    "LDX": "X",
}

OPAQUE_MEMORY_BARRIERS = {"JSUB", "LPS", "SVC", "HIO", "SIO", "TIO"}


class MemoryAnalysisError(ValueError):
    pass


def _cell_key(start, width):
    return (int(start), int(width))


def _cell_id(cell):
    start, width = cell
    return f"{start:05X}+{width}"


def _ranges_overlap(left, right):
    left_start, left_width = left
    right_start, right_width = right
    return left_start < right_start + right_width and right_start < left_start + left_width


def _function_entries(nodes, edges, entry_address):
    by_address = {node["address"]: node for node in nodes}
    entries = set()
    if entry_address in by_address:
        entries.add(entry_address)
    entries.update(
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call"
        and edge.get("resolved")
        and edge.get("target") in by_address
    )
    return sorted(entries)


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


def _memory_operation(node):
    mnemonic = node["base_mnemonic"]
    read_width = READ_WIDTHS.get(mnemonic)
    write_width = WRITE_WIDTHS.get(mnemonic)
    if read_width is None and write_width is None:
        return {
            "read": None,
            "write": None,
            "unknown_read": False,
            "unknown_write": False,
            "barrier": mnemonic in OPAQUE_MEMORY_BARRIERS,
        }

    operand = node.get("operand") or ""
    immediate = operand.startswith("#")
    unsafe_address = (
        node.get("target") is None
        or operand.startswith("@")
        or operand.endswith(",X")
    )

    read = None
    write = None
    unknown_read = False
    unknown_write = False
    if read_width is not None and not immediate:
        if unsafe_address:
            unknown_read = True
        else:
            read = _cell_key(node["target"], read_width)
    if write_width is not None:
        if unsafe_address:
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


def _empty_state(cells):
    return {cell: set() for cell in cells}


def _copy_state(state, cells):
    return {cell: set(state.get(cell, ())) for cell in cells}


def _state_equal(left, right, cells):
    return all(set(left.get(cell, ())) == set(right.get(cell, ())) for cell in cells)


def _initial_definition_id(entry, cell):
    return f"MI{entry:05X}:{_cell_id(cell)}"


def _store_definition_id(address, cell):
    return f"MS{address:05X}:{_cell_id(cell)}"


def _clobber_definition_id(address, cell):
    return f"MC{address:05X}:{_cell_id(cell)}"


def _stored_constant(node, source_register):
    if source_register is None:
        return None
    registers = known_registers(node.get("registers_in"))
    value = registers.get(source_register)
    if value is None:
        return None
    if node["base_mnemonic"] == "STCH":
        return value & 0xFF
    return value & 0xFFFFFF


def _definition_for_clobber(definitions, address, cell, reason):
    definition_id = _clobber_definition_id(address, cell)
    if definition_id not in definitions:
        definitions[definition_id] = {
            "id": definition_id,
            "kind": "clobber",
            "address": address,
            "cell": _cell_id(cell),
            "start": cell[0],
            "width": cell[1],
            "constant": None,
            "reason": reason,
        }
    return definition_id


def _store_definition(node, cell):
    source_register = STORE_SOURCE_REGISTERS.get(node["base_mnemonic"])
    definition_id = _store_definition_id(node["address"], cell)
    source_definitions = []
    if source_register is not None:
        source_definitions = list((node.get("use_definitions") or {}).get(source_register, ()))
    return {
        "id": definition_id,
        "kind": "store",
        "address": node["address"],
        "cell": _cell_id(cell),
        "start": cell[0],
        "width": cell[1],
        "source_register": source_register,
        "source_definitions": source_definitions,
        "constant": _stored_constant(node, source_register),
        "mnemonic": node["base_mnemonic"],
    }


def _transfer(node, incoming, cells, operation, definitions):
    outgoing = _copy_state(incoming, cells)
    address = node["address"]

    if operation["barrier"] or operation["unknown_write"]:
        reason = "opaque-call-or-operation" if operation["barrier"] else "unknown-alias-write"
        for cell in cells:
            # Weak update: an opaque/aliased writer may change this cell, but it
            # is not proven to do so. Keep previous definitions and add clobber.
            outgoing[cell].add(_definition_for_clobber(definitions, address, cell, reason))

    write = operation["write"]
    if write is not None:
        store_definition = _store_definition(node, write)
        definitions[store_definition["id"]] = store_definition
        for cell in cells:
            if not _ranges_overlap(cell, write):
                continue
            if cell == write:
                outgoing[cell] = {store_definition["id"]}
            else:
                # A proven overlapping store definitely invalidates the old
                # full-cell value, but a differently-sized overlap cannot be
                # represented as a clean definition of the tracked cell.
                clobber = _definition_for_clobber(definitions, address, cell, "partial-overlap-store")
                outgoing[cell] = {clobber}
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


def analyze_memory_dataflow(nodes, edges, entry_address):
    """Compute may-reaching memory definitions for statically addressed cells.

    Exact direct accesses use strong updates. Indexed/indirect writes and calls
    use weak clobbers so a may-alias event never erases an older definition that
    could still survive. The domain is finite because only exact cells referenced
    by typed instructions are tracked.
    """
    by_address = {node["address"]: node for node in nodes}
    if len(by_address) != len(nodes):
        raise MemoryAnalysisError("Duplicate typed instruction address")

    cells, operations = _tracked_cells(nodes)
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
            }

    reaching_in = {address: _empty_state(cells) for address in by_address}
    reaching_out = {address: _empty_state(cells) for address in by_address}
    ordered = sorted(by_address)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            incoming = _empty_state(cells)
            for predecessor in predecessors[address]:
                for cell in cells:
                    incoming[cell] |= reaching_out[predecessor][cell]
            for cell, definition_id in entry_definitions.get(address, {}).items():
                incoming[cell].add(definition_id)

            outgoing = _transfer(by_address[address], incoming, cells, operations[address], definitions)
            if not _state_equal(incoming, reaching_in[address], cells) or not _state_equal(outgoing, reaching_out[address], cells):
                reaching_in[address] = incoming
                reaching_out[address] = outgoing
                changed = True

    def_use = {definition_id: [] for definition_id in definitions}
    observable = {definition_id: [] for definition_id in definitions}
    instruction_facts = {}
    unresolved_reads = []
    same_value_store_candidates = []

    for address in ordered:
        node = by_address[address]
        operation = operations[address]
        memory_sources = []
        load_from_stores = []
        memory_constant = None
        read = operation["read"]
        if read is not None:
            memory_sources = sorted(reaching_in[address][read])
            load_from_stores = [
                definition_id
                for definition_id in memory_sources
                if definitions.get(definition_id, {}).get("kind") == "store"
            ]
            memory_constant = _constant_from_sources(memory_sources, definitions)
            if not memory_sources:
                unresolved_reads.append({
                    "address": address,
                    "cell": _cell_id(read),
                    "reason": "no-reaching-memory-definition",
                })
            for definition_id in memory_sources:
                def_use.setdefault(definition_id, []).append({
                    "address": address,
                    "cell": _cell_id(read),
                    "mnemonic": node["base_mnemonic"],
                })

        if operation["unknown_read"] or operation["barrier"]:
            reason = "unknown-alias-read" if operation["unknown_read"] else "opaque-call-or-operation"
            for cell in cells:
                for definition_id in reaching_in[address][cell]:
                    observable.setdefault(definition_id, []).append({
                        "address": address,
                        "reason": reason,
                        "cell": _cell_id(cell),
                    })

        write = operation["write"]
        store_definition_id = None
        stored_constant = None
        if write is not None:
            store_definition_id = _store_definition_id(address, write)
            definition = definitions.get(store_definition_id)
            if definition is not None:
                stored_constant = definition.get("constant")
                previous = sorted(reaching_in[address][write])
                previous_constant = _constant_from_sources(previous, definitions)
                if stored_constant is not None and previous and previous_constant == stored_constant:
                    same_value_store_candidates.append({
                        "address": address,
                        "definition_id": store_definition_id,
                        "cell": _cell_id(write),
                        "constant": stored_constant,
                        "previous_definitions": previous,
                    })

        loaded_register_constant = None
        destination = LOAD_DESTINATION_REGISTERS.get(node["base_mnemonic"])
        if destination is not None and read is not None and read[1] == WORD_BYTES and memory_constant is not None:
            loaded_register_constant = {
                "register": destination,
                "value": memory_constant & 0xFFFFFF,
            }

        instruction_facts[address] = {
            "memory_read": None if read is None else _cell_id(read),
            "memory_write": None if write is None else _cell_id(write),
            "memory_sources": memory_sources,
            "load_from_stores": load_from_stores,
            "memory_constant": memory_constant,
            "loaded_register_constant": loaded_register_constant,
            "store_definition_id": store_definition_id,
            "stored_constant": stored_constant,
            "unknown_memory_read": bool(operation["unknown_read"]),
            "unknown_memory_write": bool(operation["unknown_write"]),
            "memory_barrier": bool(operation["barrier"]),
            "reaching_memory_in": {
                _cell_id(cell): sorted(reaching_in[address][cell])
                for cell in cells
                if reaching_in[address][cell]
            },
            "reaching_memory_out": {
                _cell_id(cell): sorted(reaching_out[address][cell])
                for cell in cells
                if reaching_out[address][cell]
            },
        }

    # Memory values surviving a represented exit may be externally observable.
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
    overwritten_stores = []
    for definition_id in sorted(definitions):
        definition = definitions[definition_id]
        use_sites = sorted(
            def_use.get(definition_id, ()),
            key=lambda item: (item["address"], item["cell"], item["mnemonic"]),
        )
        observable_sites = sorted(
            observable.get(definition_id, ()),
            key=lambda item: (item["address"], item["reason"], item["cell"]),
        )
        chain = {
            **definition,
            "use_sites": use_sites,
            "observable_sites": observable_sites,
        }
        chains.append(chain)
        if definition.get("kind") == "store" and not use_sites and not observable_sites:
            overwritten_stores.append({
                "definition_id": definition_id,
                "address": definition["address"],
                "cell": definition["cell"],
                "constant": definition.get("constant"),
            })

    return {
        "cells": [
            {"id": _cell_id(cell), "start": cell[0], "width": cell[1]}
            for cell in cells
        ],
        "entries": entries,
        "entry_definitions": {
            entry: {_cell_id(cell): definition_id for cell, definition_id in mapping.items()}
            for entry, mapping in entry_definitions.items()
        },
        "definitions": [definitions[key] for key in sorted(definitions)],
        "chains": chains,
        "instruction_facts": instruction_facts,
        "unresolved_reads": sorted(unresolved_reads, key=lambda item: (item["address"], item["cell"])),
        "overwritten_stores": sorted(overwritten_stores, key=lambda item: (item["address"], item["cell"])),
        "same_value_store_candidates": sorted(same_value_store_candidates, key=lambda item: (item["address"], item["cell"])),
    }


def enrich_function_memory_contracts(functions, memory):
    """Attach represented memory input/output facts to discovered functions."""
    facts = memory.get("instruction_facts", {})
    definitions = {item["id"]: item for item in memory.get("definitions", ())}
    entry_definitions = memory.get("entry_definitions", {})

    for function in functions:
        entry = function["entry"]
        body = set(function.get("instruction_addresses") or ())
        returns = list(function.get("return_sites") or ())
        entry_defs = entry_definitions.get(entry, {})
        reads = set()
        writes = set()
        input_cells = set()
        input_use_sites = {}

        for address in body:
            node_facts = facts.get(address, {})
            read_cell = node_facts.get("memory_read")
            write_cell = node_facts.get("memory_write")
            if read_cell:
                reads.add(read_cell)
                sources = set(node_facts.get("memory_sources") or ())
                initial = entry_defs.get(read_cell)
                if initial is not None and initial in sources:
                    input_cells.add(read_cell)
                    input_use_sites.setdefault(read_cell, []).append(address)
            if write_cell:
                writes.add(write_cell)

        passthrough = []
        overwritten_inputs = []
        partial_inputs = []
        outputs = set()
        output_definitions = {}
        if returns:
            for cell, initial_definition in sorted(entry_defs.items()):
                reaches = [
                    initial_definition in set(facts.get(site, {}).get("reaching_memory_in", {}).get(cell, ()))
                    for site in returns
                ]
                if all(reaches):
                    passthrough.append(cell)
                elif any(reaches):
                    partial_inputs.append(cell)
                else:
                    overwritten_inputs.append(cell)

            for cell in sorted({item["id"] for item in memory.get("cells", ())}):
                local_defs = set()
                for site in returns:
                    for definition_id in facts.get(site, {}).get("reaching_memory_in", {}).get(cell, ()):
                        definition = definitions.get(definition_id)
                        if (
                            definition is not None
                            and definition.get("kind") == "store"
                            and definition.get("address") in body
                        ):
                            local_defs.add(definition_id)
                if local_defs:
                    outputs.add(cell)
                    output_definitions[cell] = sorted(local_defs)

        function["memory_reads"] = sorted(reads)
        function["memory_writes"] = sorted(writes)
        function["memory_inputs"] = sorted(input_cells)
        function["memory_input_use_sites"] = {
            cell: sorted(set(sites))
            for cell, sites in sorted(input_use_sites.items())
        }
        function["memory_passthrough_inputs"] = sorted(passthrough)
        function["memory_partially_preserved_inputs"] = sorted(partial_inputs)
        function["memory_overwritten_inputs"] = sorted(overwritten_inputs)
        function["memory_outputs"] = sorted(outputs)
        function["memory_output_definitions"] = output_definitions
    return functions
