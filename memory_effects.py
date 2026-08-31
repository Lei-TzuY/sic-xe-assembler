def _ranges_overlap(left, right):
    left_start, left_width = left
    right_start, right_width = right
    return left_start < right_start + right_width and right_start < left_start + left_width


def _call_edges(edges):
    calls = {}
    outgoing = {}
    for edge in edges:
        source = edge.get("source")
        if edge.get("kind") == "call":
            calls.setdefault(source, []).append(edge)
            continue
        if (
            edge.get("resolved")
            and not edge.get("synthetic_return")
            and edge.get("target") is not None
        ):
            outgoing.setdefault(source, []).append(edge)
    return calls, outgoing


def summarize_memory_effects(nodes, edges, cells, operations):
    """Build compositional may-read/may-write summaries for resolved callees.

    Exact direct accesses contribute only overlapping tracked cells. Indexed or
    indirect accesses, unresolved calls, and opaque operations set unknown read/
    write flags. Nested resolved callees compose through a monotone fixed point.
    The result is deliberately may-effect information: a listed cell may be
    touched on some represented path, not necessarily on every call.
    """
    by_address = {node["address"]: node for node in nodes}
    calls_by_source, outgoing = _call_edges(edges)
    entries = sorted({
        edge.get("target")
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
        nested_callees = set()
        return_sites = []
        unknown_read = False
        unknown_write = False
        unresolved_calls = []

        while pending:
            address = pending.pop()
            if address in visited or address not in by_address:
                continue
            visited.add(address)
            node = by_address[address]
            mnemonic = node["base_mnemonic"]
            operation = operations.get(address, {})

            if mnemonic == "RSUB":
                return_sites.append(address)
                continue

            if mnemonic == "JSUB":
                call_edges = calls_by_source.get(address, ())
                resolved = {
                    edge.get("target")
                    for edge in call_edges
                    if edge.get("resolved") and edge.get("target") in by_address
                }
                nested_callees.update(resolved)
                if not call_edges or any(not edge.get("resolved") for edge in call_edges):
                    unresolved_calls.append(address)
                    unknown_read = True
                    unknown_write = True
            else:
                read = operation.get("read")
                write = operation.get("write")
                if read is not None:
                    direct_reads.update(cell for cell in cells if _ranges_overlap(cell, read))
                if write is not None:
                    direct_writes.update(cell for cell in cells if _ranges_overlap(cell, write))
                if operation.get("unknown_read") or operation.get("barrier"):
                    unknown_read = True
                if operation.get("unknown_write") or operation.get("barrier"):
                    unknown_write = True

            for edge in outgoing.get(address, ()):
                target = edge.get("target")
                if target in by_address:
                    pending.append(target)

        shapes[entry] = {
            "entry": entry,
            "symbols": list(by_address[entry].get("symbols") or ()),
            "instruction_addresses": sorted(visited),
            "return_sites": sorted(return_sites),
            "direct_reads": set(direct_reads),
            "direct_writes": set(direct_writes),
            "nested_callees": set(nested_callees),
            "unresolved_calls": sorted(set(unresolved_calls)),
            "unknown_read": unknown_read,
            "unknown_write": unknown_write,
        }

    summaries = {}
    for entry, shape in shapes.items():
        summaries[entry] = {
            "entry": entry,
            "symbols": list(shape["symbols"]),
            "instruction_addresses": list(shape["instruction_addresses"]),
            "return_sites": list(shape["return_sites"]),
            "direct_reads": set(shape["direct_reads"]),
            "direct_writes": set(shape["direct_writes"]),
            "may_read_cells": set(shape["direct_reads"]),
            "may_write_cells": set(shape["direct_writes"]),
            "nested_callees": set(shape["nested_callees"]),
            "unresolved_calls": list(shape["unresolved_calls"]),
            "unknown_read": bool(shape["unknown_read"]),
            "unknown_write": bool(shape["unknown_write"]),
            "may_return": bool(shape["return_sites"]),
        }

    changed = True
    while changed:
        changed = False
        for entry, shape in shapes.items():
            summary = summaries[entry]
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
                reads |= set(nested["may_read_cells"])
                writes |= set(nested["may_write_cells"])
                unknown_read = unknown_read or bool(nested["unknown_read"])
                unknown_write = unknown_write or bool(nested["unknown_write"])
            new_value = (reads, writes, unknown_read, unknown_write)
            old_value = (
                set(summary["may_read_cells"]),
                set(summary["may_write_cells"]),
                bool(summary["unknown_read"]),
                bool(summary["unknown_write"]),
            )
            if new_value != old_value:
                summary["may_read_cells"] = reads
                summary["may_write_cells"] = writes
                summary["unknown_read"] = unknown_read
                summary["unknown_write"] = unknown_write
                changed = True

    result = {}
    all_cells = set(cells)
    for entry in sorted(summaries):
        summary = summaries[entry]
        result[entry] = {
            "entry": entry,
            "symbols": list(summary["symbols"]),
            "instruction_addresses": list(summary["instruction_addresses"]),
            "return_sites": list(summary["return_sites"]),
            "direct_reads": sorted(summary["direct_reads"]),
            "direct_writes": sorted(summary["direct_writes"]),
            "may_read_cells": sorted(summary["may_read_cells"]),
            "may_write_cells": sorted(summary["may_write_cells"]),
            "preserved_cells": [] if summary["unknown_write"] else sorted(all_cells - set(summary["may_write_cells"])),
            "nested_callees": sorted(summary["nested_callees"]),
            "unresolved_calls": list(summary["unresolved_calls"]),
            "unknown_read": bool(summary["unknown_read"]),
            "unknown_write": bool(summary["unknown_write"]),
            "may_return": bool(summary["may_return"]),
        }
    return result
