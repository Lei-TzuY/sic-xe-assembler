import memory_analysis as legacy
from memory_effects import summarize_memory_effects


def _clobber_cells(node, cells, effects, operation):
    if node["base_mnemonic"] == "JSUB":
        summary = effects.get(node.get("target"))
        if summary is None or summary.get("unknown_write"):
            return list(cells), "unknown-callee-memory-effect"
        return list(summary.get("may_write_cells") or ()), "callee-memory-effect"
    if operation.get("barrier"):
        return list(cells), "opaque-call-or-operation"
    if operation.get("unknown_write"):
        return list(cells), "unknown-alias-write"
    return [], None


def _observable_cells(node, cells, effects, operation):
    if node["base_mnemonic"] == "JSUB":
        summary = effects.get(node.get("target"))
        if summary is None or summary.get("unknown_read"):
            return list(cells), "unknown-callee-memory-read"
        return list(summary.get("may_read_cells") or ()), "callee-memory-read"
    if operation.get("unknown_read"):
        return list(cells), "unknown-alias-read"
    if operation.get("barrier"):
        return list(cells), "opaque-call-or-operation"
    return [], None


def _transfer(node, incoming, cells, operation, definitions, effects):
    outgoing = legacy._copy_state(incoming, cells)
    address = node["address"]

    clobbered, reason = _clobber_cells(node, cells, effects, operation)
    for cell in clobbered:
        outgoing[cell].add(legacy._definition_for_clobber(definitions, address, cell, reason))

    write = operation["write"]
    if write is not None:
        store_definition = legacy._store_definition(node, write)
        definitions[store_definition["id"]] = store_definition
        for cell in cells:
            if not legacy._ranges_overlap(cell, write):
                continue
            if cell == write:
                outgoing[cell] = {store_definition["id"]}
            else:
                clobber = legacy._definition_for_clobber(
                    definitions,
                    address,
                    cell,
                    "partial-overlap-store",
                )
                outgoing[cell] = {clobber}
    return outgoing


def _serializable_effects(effects):
    result = []
    for entry in sorted(effects):
        item = effects[entry]
        result.append({
            "entry": entry,
            "symbols": list(item.get("symbols") or ()),
            "instruction_addresses": list(item.get("instruction_addresses") or ()),
            "return_sites": list(item.get("return_sites") or ()),
            "direct_reads": [legacy._cell_id(cell) for cell in item.get("direct_reads") or ()],
            "direct_writes": [legacy._cell_id(cell) for cell in item.get("direct_writes") or ()],
            "may_read_cells": [legacy._cell_id(cell) for cell in item.get("may_read_cells") or ()],
            "may_write_cells": [legacy._cell_id(cell) for cell in item.get("may_write_cells") or ()],
            "preserved_cells": [legacy._cell_id(cell) for cell in item.get("preserved_cells") or ()],
            "nested_callees": list(item.get("nested_callees") or ()),
            "unresolved_calls": list(item.get("unresolved_calls") or ()),
            "unknown_read": bool(item.get("unknown_read")),
            "unknown_write": bool(item.get("unknown_write")),
            "may_return": bool(item.get("may_return")),
        })
    return result


def analyze_memory_dataflow(nodes, edges, entry_address):
    """Interprocedural alias-aware reaching stores with selective call clobbers."""
    by_address = {node["address"]: node for node in nodes}
    if len(by_address) != len(nodes):
        raise legacy.MemoryAnalysisError("Duplicate typed instruction address")

    cells, operations = legacy._tracked_cells(nodes)
    effects = summarize_memory_effects(nodes, edges, cells, operations)
    entries = legacy._function_entries(nodes, edges, entry_address)
    predecessors, successors, unresolved_exit = legacy._predecessors_and_successors(nodes, edges)
    definitions = {}
    entry_definitions = {}

    for entry in entries:
        entry_definitions[entry] = {}
        for cell in cells:
            definition_id = legacy._initial_definition_id(entry, cell)
            entry_definitions[entry][cell] = definition_id
            definitions[definition_id] = {
                "id": definition_id,
                "kind": "initial",
                "address": entry,
                "function_entry": entry,
                "cell": legacy._cell_id(cell),
                "start": cell[0],
                "width": cell[1],
                "constant": None,
            }

    reaching_in = {address: legacy._empty_state(cells) for address in by_address}
    reaching_out = {address: legacy._empty_state(cells) for address in by_address}
    ordered = sorted(by_address)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            incoming = legacy._empty_state(cells)
            for predecessor in predecessors[address]:
                for cell in cells:
                    incoming[cell] |= reaching_out[predecessor][cell]
            for cell, definition_id in entry_definitions.get(address, {}).items():
                incoming[cell].add(definition_id)

            outgoing = _transfer(
                by_address[address],
                incoming,
                cells,
                operations[address],
                definitions,
                effects,
            )
            if (
                not legacy._state_equal(incoming, reaching_in[address], cells)
                or not legacy._state_equal(outgoing, reaching_out[address], cells)
            ):
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
            memory_constant = legacy._constant_from_sources(memory_sources, definitions)
            if not memory_sources:
                unresolved_reads.append({
                    "address": address,
                    "cell": legacy._cell_id(read),
                    "reason": "no-reaching-memory-definition",
                })
            for definition_id in memory_sources:
                def_use.setdefault(definition_id, []).append({
                    "address": address,
                    "cell": legacy._cell_id(read),
                    "mnemonic": node["base_mnemonic"],
                })

        visible_cells, visible_reason = _observable_cells(node, cells, effects, operation)
        for cell in visible_cells:
            for definition_id in reaching_in[address][cell]:
                observable.setdefault(definition_id, []).append({
                    "address": address,
                    "reason": visible_reason,
                    "cell": legacy._cell_id(cell),
                })

        write = operation["write"]
        store_definition_id = None
        stored_constant = None
        if write is not None:
            store_definition_id = legacy._store_definition_id(address, write)
            definition = definitions.get(store_definition_id)
            if definition is not None:
                stored_constant = definition.get("constant")
                previous = sorted(reaching_in[address][write])
                previous_constant = legacy._constant_from_sources(previous, definitions)
                if stored_constant is not None and previous and previous_constant == stored_constant:
                    same_value_store_candidates.append({
                        "address": address,
                        "definition_id": store_definition_id,
                        "cell": legacy._cell_id(write),
                        "constant": stored_constant,
                        "previous_definitions": previous,
                    })

        loaded_register_constant = None
        destination = legacy.LOAD_DESTINATION_REGISTERS.get(node["base_mnemonic"])
        if (
            destination is not None
            and read is not None
            and read[1] == legacy.WORD_BYTES
            and memory_constant is not None
        ):
            loaded_register_constant = {
                "register": destination,
                "value": memory_constant & 0xFFFFFF,
            }

        call_summary = effects.get(node.get("target")) if node["base_mnemonic"] == "JSUB" else None
        instruction_facts[address] = {
            "memory_read": None if read is None else legacy._cell_id(read),
            "memory_write": None if write is None else legacy._cell_id(write),
            "memory_sources": memory_sources,
            "load_from_stores": load_from_stores,
            "memory_constant": memory_constant,
            "loaded_register_constant": loaded_register_constant,
            "store_definition_id": store_definition_id,
            "stored_constant": stored_constant,
            "unknown_memory_read": bool(operation["unknown_read"]),
            "unknown_memory_write": bool(operation["unknown_write"]),
            "memory_barrier": bool(operation["barrier"]),
            "memory_call_effect": None if call_summary is None else {
                "unknown_read": bool(call_summary.get("unknown_read")),
                "unknown_write": bool(call_summary.get("unknown_write")),
                "may_read_cells": [legacy._cell_id(cell) for cell in call_summary.get("may_read_cells") or ()],
                "may_write_cells": [legacy._cell_id(cell) for cell in call_summary.get("may_write_cells") or ()],
                "preserved_cells": [legacy._cell_id(cell) for cell in call_summary.get("preserved_cells") or ()],
            },
            "reaching_memory_in": {
                legacy._cell_id(cell): sorted(reaching_in[address][cell])
                for cell in cells
                if reaching_in[address][cell]
            },
            "reaching_memory_out": {
                legacy._cell_id(cell): sorted(reaching_out[address][cell])
                for cell in cells
                if reaching_out[address][cell]
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
                    "cell": legacy._cell_id(cell),
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
        chains.append({**definition, "use_sites": use_sites, "observable_sites": observable_sites})
        if definition.get("kind") == "store" and not use_sites and not observable_sites:
            overwritten_stores.append({
                "definition_id": definition_id,
                "address": definition["address"],
                "cell": definition["cell"],
                "constant": definition.get("constant"),
            })

    return {
        "cells": [
            {"id": legacy._cell_id(cell), "start": cell[0], "width": cell[1]}
            for cell in cells
        ],
        "entries": entries,
        "entry_definitions": {
            entry: {legacy._cell_id(cell): definition_id for cell, definition_id in mapping.items()}
            for entry, mapping in entry_definitions.items()
        },
        "definitions": [definitions[key] for key in sorted(definitions)],
        "chains": chains,
        "instruction_facts": instruction_facts,
        "unresolved_reads": sorted(unresolved_reads, key=lambda item: (item["address"], item["cell"])),
        "overwritten_stores": sorted(overwritten_stores, key=lambda item: (item["address"], item["cell"])),
        "same_value_store_candidates": sorted(
            same_value_store_candidates,
            key=lambda item: (item["address"], item["cell"]),
        ),
        "subroutine_effects": _serializable_effects(effects),
    }


enrich_function_memory_contracts = legacy.enrich_function_memory_contracts
