from disassembler import decode_instruction
from memory_analysis import LOAD_DESTINATION_REGISTERS, STORE_SOURCE_REGISTERS, WORD_BYTES, _cell_id, _ranges_overlap
from memory_feedback import _memory_aware_exact_transfer, _memory_aware_range_transfer, _tracked_cells
from memory_postconditions import (
    _attach_value_facts,
    _copy_state as _copy_value_state,
    _empty_state as _empty_value_state,
    _join_state as _join_value_state,
    _register_store_value,
    _state_equal as _value_state_equal,
    _unknown_value,
    seed_initialized_memory,
)
from range_analysis import (
    SIGNED_MAX,
    SIGNED_MIN,
    _copy_state as _copy_range_state,
    _join_states as _join_range_states,
    _state_equal as _range_state_equal,
    unknown_range_state,
)
from sparse_linear_transfers import (
    MODULUS,
    _apply_exact_call,
    _apply_range_call,
    _base_relative,
    _exact_edge_feasible,
    _range_edge_feasible,
    _rebuild_edges,
    _signed24,
)
from static_analysis import (
    CONDITION_VALUES,
    CONDITIONAL_MNEMONICS,
    REGISTER_MASK,
    TRACKED_REGISTERS,
    _copy_state as _copy_exact_state,
    _join_states as _join_exact_states,
    _state_equal as _exact_state_equal,
    unknown_state,
)
from symbolic_memory_transfers import _apply_concrete_call_memory


MAX_SYMBOLIC_INPUT_TERMS = 4
SYMBOLIC_MEMORY_INPUT_BASE_RESOLUTIONS = {
    "symbolic-memory-input-base",
    "symbolic-memory-input-range-base",
}
SYMBOLIC_MEMORY_INPUT_CONDITION_RESOLUTIONS = {
    "symbolic-memory-input-condition",
    "symbolic-memory-input-range-condition",
}


class SymbolicMemoryInputError(ValueError):
    pass


def _signed_coefficient(value):
    value %= MODULUS
    return value if value < (MODULUS // 2) else value - MODULUS


def _register_atom(register):
    return ("register", register)


def _memory_atom(cell_id):
    return ("memory", cell_id)


def _normalize(terms, offset=0):
    merged = {}
    for atom, coefficient in terms:
        kind, name = atom
        if kind == "register":
            if name not in TRACKED_REGISTERS:
                return None
        elif kind == "memory":
            if not isinstance(name, str) or not name:
                return None
        else:
            return None
        coefficient = _signed_coefficient(coefficient)
        if coefficient:
            merged[atom] = _signed_coefficient(merged.get(atom, 0) + coefficient)
            if merged[atom] == 0:
                merged.pop(atom, None)
    if len(merged) > MAX_SYMBOLIC_INPUT_TERMS:
        return None
    return (tuple(sorted(merged.items())), int(offset) % MODULUS)


def _const(value):
    return _normalize((), value)


def _source_register(register):
    return _normalize(((_register_atom(register), 1),), 0)


def _source_memory(cell_id):
    return _normalize(((_memory_atom(cell_id), 1),), 0)


def _is_const(expression):
    return expression is not None and not expression[0]


def _scale(expression, factor):
    if expression is None:
        return None
    factor = _signed_coefficient(factor)
    terms, offset = expression
    return _normalize(
        ((atom, coefficient * factor) for atom, coefficient in terms),
        offset * factor,
    )


def _add(left, right):
    if left is None or right is None:
        return None
    left_terms, left_offset = left
    right_terms, right_offset = right
    return _normalize(
        tuple(left_terms) + tuple(right_terms),
        left_offset + right_offset,
    )


def _sub(left, right):
    return _add(left, _scale(right, -1))


def _mul(left, right):
    if left is None or right is None:
        return None
    if _is_const(left):
        return _scale(right, _signed24(left[1]))
    if _is_const(right):
        return _scale(left, _signed24(right[1]))
    return None


def _trunc_div(value, divisor):
    quotient = abs(value) // abs(divisor)
    return -quotient if (value < 0) != (divisor < 0) else quotient


def _div(left, right):
    if left is None or right is None or not _is_const(right):
        return None
    divisor = _signed24(right[1])
    if divisor == 1:
        return left
    if divisor == -1:
        return _scale(left, -1)
    if _is_const(left) and divisor != 0:
        return _const(_trunc_div(_signed24(left[1]), divisor))
    return None


def _has_memory_input(expression):
    return (
        expression is not None
        and any(atom[0] == "memory" for atom, _ in expression[0])
    )


def _identity_memory(expression, cell_id):
    return expression == _source_memory(cell_id)


def _serialize(expression):
    if expression is None:
        return None
    register_coefficients = {}
    memory_coefficients = {}
    for (kind, name), coefficient in expression[0]:
        if kind == "register":
            register_coefficients[name] = coefficient
        else:
            memory_coefficients[name] = coefficient
    return {
        "kind": "symbolic-linear",
        "register_coefficients": register_coefficients,
        "memory_coefficients": memory_coefficients,
        "offset": _signed24(expression[1]),
        "modulus": MODULUS,
    }


def _deserialize(spec):
    if not spec or spec.get("kind") != "symbolic-linear":
        return None
    terms = []
    for register, coefficient in (spec.get("register_coefficients") or {}).items():
        terms.append((_register_atom(register), coefficient))
    for cell_id, coefficient in (spec.get("memory_coefficients") or {}).items():
        terms.append((_memory_atom(cell_id), coefficient))
    return _normalize(terms, spec.get("offset", 0))


def _from_sparse_spec(spec):
    if not spec:
        return None
    kind = spec.get("kind")
    if kind == "constant":
        return _const(spec.get("value", 0))
    if kind == "affine":
        source = spec.get("source")
        if source not in TRACKED_REGISTERS:
            return None
        return _normalize(
            ((_register_atom(source), spec.get("scale", 1)),),
            spec.get("offset", 0),
        )
    if kind == "linear":
        return _normalize(
            (
                (_register_atom(register), coefficient)
                for register, coefficient in (
                    spec.get("coefficients") or {}
                ).items()
            ),
            spec.get("offset", 0),
        )
    return None


def _substitute(expression, register_inputs, memory_inputs):
    if expression is None:
        return None
    result = _const(expression[1])
    for (kind, name), coefficient in expression[0]:
        source = (
            register_inputs.get(name)
            if kind == "register"
            else memory_inputs.get(name)
        )
        if source is None:
            return None
        result = _add(result, _scale(source, coefficient))
        if result is None:
            return None
    return result


def _evaluate_exact(spec, register_inputs, memory_inputs):
    expression = _deserialize(spec)
    if expression is None:
        return None
    value = expression[1]
    for (kind, name), coefficient in expression[0]:
        source = (
            register_inputs.get(name)
            if kind == "register"
            else memory_inputs.get(name)
        )
        if source is None:
            return None
        value += coefficient * source
    return value & REGISTER_MASK


def _evaluate_range(spec, register_inputs, memory_inputs):
    expression = _deserialize(spec)
    if expression is None:
        return None
    low = high = _signed24(expression[1])
    for (kind, name), coefficient in expression[0]:
        interval = (
            register_inputs.get(name)
            if kind == "register"
            else memory_inputs.get(name)
        )
        if interval is None:
            return None
        candidates = (
            coefficient * interval[0],
            coefficient * interval[1],
        )
        low += min(candidates)
        high += max(candidates)
        if low < SIGNED_MIN or high > SIGNED_MAX:
            return None
    return (low, high)


def _copy_symbolic_registers(state):
    return {register: state.get(register) for register in TRACKED_REGISTERS}


def _entry_registers():
    return {
        register: _source_register(register)
        for register in TRACKED_REGISTERS
    }


def _entry_memory(cells):
    return {
        cell: _source_memory(_cell_id(cell))
        for cell in cells
    }


def _copy_symbolic_memory(state, cells):
    return {cell: state.get(cell) for cell in cells}


def _join_symbolic_registers(left, right):
    if left is None:
        return _copy_symbolic_registers(right)
    return {
        register: (
            left.get(register)
            if left.get(register) is not None
            and left.get(register) == right.get(register)
            else None
        )
        for register in TRACKED_REGISTERS
    }


def _join_symbolic_memory(left, right, cells):
    if left is None:
        return _copy_symbolic_memory(right, cells)
    return {
        cell: (
            left.get(cell)
            if left.get(cell) is not None
            and left.get(cell) == right.get(cell)
            else None
        )
        for cell in cells
    }


def _symbolic_registers_equal(left, right):
    if left is None or right is None:
        return left is right
    return all(
        left.get(register) == right.get(register)
        for register in TRACKED_REGISTERS
    )


def _symbolic_memory_equal(left, right, cells):
    if left is None or right is None:
        return left is right
    return all(left.get(cell) == right.get(cell) for cell in cells)


def _register_operands(operand):
    if not operand:
        return ()
    return tuple(part.strip() for part in operand.split(","))


def _read_expression(operation, memory):
    read = operation.get("read")
    if read is None or read[1] != WORD_BYTES:
        return None
    return memory.get(read)


def _hybrid_register_transfer(node, incoming, memory, operation):
    state = _copy_symbolic_registers(incoming)
    mnemonic = node["base_mnemonic"]
    operand = node.get("operand") or ""
    target = node.get("target")
    fields = _register_operands(operand)

    if mnemonic in LOAD_DESTINATION_REGISTERS:
        destination = LOAD_DESTINATION_REGISTERS[mnemonic]
        if (
            operand.startswith("#")
            and not operand.endswith(",X")
            and target is not None
        ):
            state[destination] = _const(target)
        else:
            state[destination] = _read_expression(operation, memory)
        return state

    if mnemonic == "LDCH":
        state["A"] = None
        return state

    if (
        mnemonic == "CLEAR"
        and len(fields) == 1
        and fields[0] in TRACKED_REGISTERS
    ):
        state[fields[0]] = _const(0)
        return state

    if (
        mnemonic == "RMO"
        and len(fields) == 2
        and fields[1] in TRACKED_REGISTERS
    ):
        state[fields[1]] = state.get(fields[0])
        return state

    if (
        mnemonic in ("ADDR", "SUBR", "MULR", "DIVR")
        and len(fields) == 2
        and fields[1] in TRACKED_REGISTERS
    ):
        source = state.get(fields[0])
        destination = state.get(fields[1])
        operation_fn = {
            "ADDR": _add,
            "SUBR": _sub,
            "MULR": _mul,
            "DIVR": _div,
        }[mnemonic]
        state[fields[1]] = operation_fn(destination, source)
        return state

    if (
        mnemonic in ("SHIFTL", "SHIFTR")
        and fields
        and fields[0] in TRACKED_REGISTERS
    ):
        expression = state.get(fields[0])
        count = None
        if len(fields) > 1:
            try:
                count = int(fields[1])
            except ValueError:
                count = None
        if _is_const(expression) and count is not None:
            value = expression[1]
            if mnemonic == "SHIFTL":
                value = (value << count) & REGISTER_MASK
            else:
                value = (value & REGISTER_MASK) >> count
            state[fields[0]] = _const(value)
        else:
            state[fields[0]] = None
        return state

    if mnemonic in ("TIX", "TIXR"):
        state["X"] = _add(state.get("X"), _const(1))
        return state

    if mnemonic == "JSUB":
        state["L"] = _const(node["end"])
        return state

    if mnemonic in ("ADD", "SUB", "MUL", "DIV", "AND", "OR"):
        current = state.get("A")
        if (
            operand.startswith("#")
            and not operand.endswith(",X")
            and target is not None
        ):
            right = _const(target)
        else:
            right = _read_expression(operation, memory)

        if mnemonic == "ADD":
            state["A"] = _add(current, right)
        elif mnemonic == "SUB":
            state["A"] = _sub(current, right)
        elif mnemonic == "MUL":
            state["A"] = _mul(current, right)
        elif mnemonic == "DIV":
            state["A"] = _div(current, right)
        elif mnemonic == "AND":
            if _is_const(right):
                mask = right[1] & REGISTER_MASK
                if mask == 0:
                    state["A"] = _const(0)
                elif mask == REGISTER_MASK:
                    state["A"] = current
                elif _is_const(current):
                    state["A"] = _const(current[1] & mask)
                else:
                    state["A"] = None
            else:
                state["A"] = None
        else:
            if _is_const(right):
                mask = right[1] & REGISTER_MASK
                if mask == 0:
                    state["A"] = current
                elif _is_const(current):
                    state["A"] = _const(current[1] | mask)
                else:
                    state["A"] = None
            else:
                state["A"] = None
        return state

    if mnemonic in ("RD", "FIX"):
        state["A"] = None
        return state

    if mnemonic in ("LPS", "SVC"):
        return {register: None for register in TRACKED_REGISTERS}

    return state


def _hybrid_memory_transfer(
    node,
    incoming_registers,
    incoming_memory,
    cells,
    operation,
):
    outgoing = _copy_symbolic_memory(incoming_memory, cells)
    if node["base_mnemonic"] == "JSUB":
        return outgoing

    if operation.get("unknown_write") or operation.get("barrier"):
        outgoing = {cell: None for cell in cells}

    write = operation.get("write")
    if write is None:
        return outgoing

    source_register = STORE_SOURCE_REGISTERS.get(node["base_mnemonic"])
    expression = (
        None
        if source_register is None
        else incoming_registers.get(source_register)
    )
    for cell in cells:
        if not _ranges_overlap(cell, write):
            continue
        outgoing[cell] = None
        if cell != write or expression is None:
            continue
        if cell[1] == WORD_BYTES:
            outgoing[cell] = expression
        elif node["base_mnemonic"] == "STCH" and _is_const(expression):
            outgoing[cell] = _const(expression[1] & 0xFF)
    return outgoing


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


def _merge_summary_layers(
    register_summaries,
    memory_summaries,
    hints,
):
    entries = set(register_summaries or {}) | set(memory_summaries or {})
    result = {}
    for entry in entries:
        register = (register_summaries or {}).get(entry) or {}
        memory = (memory_summaries or {}).get(entry) or {}
        hint = (hints or {}).get(entry) or {}
        merged = dict(memory)
        for key in (
            "entry",
            "instruction_addresses",
            "return_sites",
            "may_return",
            "link_register_preserved",
            "preserved",
            "may_clobber",
        ):
            if key in register:
                merged[key] = register[key]
        merged["register_return_constants"] = dict(
            register.get("return_constants") or {}
        )
        merged["register_return_linear_transfers"] = dict(
            register.get("return_linear_transfers") or {}
        )
        merged["memory_return_constants"] = dict(
            memory.get("return_constants") or {}
        )
        merged["memory_return_ranges"] = {
            key: list(value)
            for key, value in (memory.get("return_ranges") or {}).items()
        }
        merged["memory_return_linear_transfers"] = dict(
            memory.get("return_memory_linear_transfers") or {}
        )
        merged["return_register_memory_transfers"] = dict(
            hint.get("return_register_memory_transfers") or {}
        )
        merged["return_memory_input_transfers"] = dict(
            hint.get("return_memory_input_transfers") or {}
        )
        result[entry] = merged
    return result


def _apply_hybrid_summary(
    registers,
    memory,
    summary,
    cells,
    cells_by_id,
):
    if summary is None or not summary.get("may_return"):
        return (
            {register: None for register in TRACKED_REGISTERS},
            {cell: None for cell in cells},
        )

    input_registers = _copy_symbolic_registers(registers)
    input_memory = _copy_symbolic_memory(memory, cells)
    memory_inputs_by_id = {
        _cell_id(cell): expression
        for cell, expression in input_memory.items()
    }

    result_registers = _copy_symbolic_registers(registers)
    preserved = set(summary.get("preserved") or ())
    for register in TRACKED_REGISTERS:
        if register not in preserved:
            result_registers[register] = None

    result_memory = _copy_symbolic_memory(memory, cells)
    if summary.get("unknown_write"):
        result_memory = {cell: None for cell in cells}
    else:
        for cell_id in summary.get("may_write_cells") or ():
            cell = cells_by_id.get(cell_id)
            if cell is not None:
                result_memory[cell] = None

    for cell_id, value in (
        summary.get("memory_return_constants") or {}
    ).items():
        cell = cells_by_id.get(cell_id)
        if cell is not None:
            result_memory[cell] = _const(value)

    if not summary.get("link_register_preserved"):
        return result_registers, result_memory

    for register, value in (
        summary.get("register_return_constants") or {}
    ).items():
        if register in TRACKED_REGISTERS:
            result_registers[register] = _const(value)

    for register, spec in (
        summary.get("register_return_linear_transfers") or {}
    ).items():
        if register not in TRACKED_REGISTERS:
            continue
        expression = _from_sparse_spec(spec)
        result_registers[register] = _substitute(
            expression,
            input_registers,
            memory_inputs_by_id,
        )

    for cell_id, spec in (
        summary.get("memory_return_linear_transfers") or {}
    ).items():
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        expression = _from_sparse_spec(spec)
        result_memory[cell] = _substitute(
            expression,
            input_registers,
            memory_inputs_by_id,
        )

    for register, spec in (
        summary.get("return_register_memory_transfers") or {}
    ).items():
        if register not in TRACKED_REGISTERS:
            continue
        result_registers[register] = _substitute(
            _deserialize(spec),
            input_registers,
            memory_inputs_by_id,
        )

    for cell_id, spec in (
        summary.get("return_memory_input_transfers") or {}
    ).items():
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        result_memory[cell] = _substitute(
            _deserialize(spec),
            input_registers,
            memory_inputs_by_id,
        )
    return result_registers, result_memory


def _analyze_function_symbolically(
    nodes,
    edges,
    entry,
    summaries,
    cells,
    operations,
):
    by_address, outgoing_edges = _intraprocedural_outgoing(nodes, edges)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    register_in = {address: None for address in by_address}
    register_out = {address: None for address in by_address}
    memory_in = {address: None for address in by_address}
    memory_out = {address: None for address in by_address}
    if entry not in by_address:
        return register_out, memory_out

    register_in[entry] = _entry_registers()
    memory_in[entry] = _entry_memory(cells)
    pending = [entry]
    queued = {entry}

    while pending:
        address = pending.pop(0)
        queued.discard(address)
        registers = register_in[address]
        memory = memory_in[address]
        if registers is None or memory is None:
            continue

        node = by_address[address]
        registers_after = _hybrid_register_transfer(
            node,
            registers,
            memory,
            operations[address],
        )
        memory_after = _hybrid_memory_transfer(
            node,
            registers,
            memory,
            cells,
            operations[address],
        )
        register_out[address] = registers_after
        memory_out[address] = memory_after

        for edge in outgoing_edges.get(address, ()):
            candidate_registers = _copy_symbolic_registers(
                registers_after
            )
            candidate_memory = _copy_symbolic_memory(
                memory_after,
                cells,
            )
            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate_registers, candidate_memory = (
                    _apply_hybrid_summary(
                        candidate_registers,
                        candidate_memory,
                        summaries.get(node.get("target")),
                        cells,
                        cells_by_id,
                    )
                )

            target = edge["target"]
            merged_registers = _join_symbolic_registers(
                register_in[target],
                candidate_registers,
            )
            merged_memory = _join_symbolic_memory(
                memory_in[target],
                candidate_memory,
                cells,
            )
            changed = (
                not _symbolic_registers_equal(
                    register_in[target],
                    merged_registers,
                )
                or not _symbolic_memory_equal(
                    memory_in[target],
                    merged_memory,
                    cells,
                )
            )
            if changed:
                register_in[target] = merged_registers
                memory_in[target] = merged_memory
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    return register_out, memory_out


def _derive_summary(shape, register_out, memory_out, cells):
    summary = dict(shape)
    returns = list(summary.get("return_sites") or ())
    register_transfers = {}
    memory_transfers = {}

    if returns and all(register_out.get(site) is not None for site in returns):
        for register in TRACKED_REGISTERS:
            expressions = [
                register_out[site].get(register)
                for site in returns
            ]
            if (
                expressions[0] is None
                or any(expr != expressions[0] for expr in expressions)
            ):
                continue
            expression = expressions[0]
            if _has_memory_input(expression):
                register_transfers[register] = _serialize(expression)

    if returns and all(memory_out.get(site) is not None for site in returns):
        for cell in cells:
            expressions = [
                memory_out[site].get(cell)
                for site in returns
            ]
            if (
                expressions[0] is None
                or any(expr != expressions[0] for expr in expressions)
            ):
                continue
            expression = expressions[0]
            cell_id = _cell_id(cell)
            if (
                _has_memory_input(expression)
                and not _identity_memory(expression, cell_id)
            ):
                memory_transfers[cell_id] = _serialize(expression)

    all_specs = list(register_transfers.values()) + list(
        memory_transfers.values()
    )
    summary["return_register_memory_transfers"] = register_transfers
    summary["return_memory_input_transfers"] = memory_transfers
    summary["memory_input_cells"] = sorted({
        cell_id
        for spec in all_specs
        for cell_id in (
            spec.get("memory_coefficients") or {}
        )
    })
    summary["memory_input_registers"] = sorted({
        register
        for spec in all_specs
        for register in (
            spec.get("register_coefficients") or {}
        )
    })
    summary["memory_dependent_return_registers"] = sorted(
        register_transfers
    )
    summary["memory_dependent_return_cells"] = sorted(memory_transfers)
    summary["mixed_memory_input_outputs"] = sorted(
        [
            "register:" + register
            for register, spec in register_transfers.items()
            if spec.get("register_coefficients")
            and spec.get("memory_coefficients")
        ]
        + [
            "memory:" + cell_id
            for cell_id, spec in memory_transfers.items()
            if spec.get("register_coefficients")
            and spec.get("memory_coefficients")
        ]
    )
    return summary


def _summary_signature(summaries):
    def spec_signature(spec):
        return (
            tuple(sorted(
                (spec.get("register_coefficients") or {}).items()
            )),
            tuple(sorted(
                (spec.get("memory_coefficients") or {}).items()
            )),
            spec.get("offset"),
        )

    return tuple(
        (
            entry,
            tuple(
                (register, spec_signature(spec))
                for register, spec in sorted(
                    summary.get(
                        "return_register_memory_transfers",
                        {},
                    ).items()
                )
            ),
            tuple(
                (cell_id, spec_signature(spec))
                for cell_id, spec in sorted(
                    summary.get(
                        "return_memory_input_transfers",
                        {},
                    ).items()
                )
            ),
        )
        for entry, summary in sorted(summaries.items())
    )


def infer_symbolic_memory_inputs(
    nodes,
    edges,
    register_summaries=None,
    memory_summaries=None,
):
    """Infer sparse formulas rooted in function-entry memory cells."""
    cells, operations = _tracked_cells(nodes)
    hints = {}
    previous = None
    max_iterations = max(
        4,
        (len(register_summaries or {}) + len(memory_summaries or {}))
        * 2
        + 4,
    )

    for iteration in range(1, max_iterations + 1):
        available = _merge_summary_layers(
            register_summaries or {},
            memory_summaries or {},
            hints,
        )
        derived = {}
        for entry, shape in available.items():
            register_out, memory_out = _analyze_function_symbolically(
                nodes,
                edges,
                entry,
                available,
                cells,
                operations,
            )
            derived[entry] = _derive_summary(
                shape,
                register_out,
                memory_out,
                cells,
            )

        signature = _summary_signature(derived)
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "cells": cells,
                "summary_map": derived,
                "summaries": [
                    derived[key]
                    for key in sorted(derived)
                ],
            }
        previous = signature
        hints = derived

    raise SymbolicMemoryInputError(
        "Symbolic memory-input inference did not converge"
    )


def _memory_value_inputs(memory_state):
    exact = {}
    ranges = {}
    for cell, value in (memory_state or {}).items():
        cell_id = _cell_id(cell)
        if value is None:
            continue
        constant = value.get("constant")
        interval = value.get("range")
        if constant is not None:
            exact[cell_id] = constant & REGISTER_MASK
        if interval is not None:
            ranges[cell_id] = tuple(interval)
        elif constant is not None and cell[1] == WORD_BYTES:
            signed = _signed24(constant)
            ranges[cell_id] = (signed, signed)
    return exact, ranges


def _instantiate_calls(
    nodes,
    summaries,
    exact_out,
    range_out,
    memory_in,
):
    result = {}
    for node in nodes:
        if node["base_mnemonic"] != "JSUB":
            continue
        summary = summaries.get(node.get("target"))
        if (
            summary is None
            or not summary.get("link_register_preserved")
        ):
            node.pop("symbolic_memory_input_instantiation", None)
            continue

        register_exact = exact_out.get(node["address"])
        register_ranges = range_out.get(node["address"])
        memory_exact, memory_ranges = _memory_value_inputs(
            memory_in.get(node["address"])
        )

        exact_registers = {}
        range_registers = {}
        exact_memory = {}
        range_memory = {}

        for register, spec in (
            summary.get(
                "return_register_memory_transfers"
            ) or {}
        ).items():
            value = (
                None
                if register_exact is None
                else _evaluate_exact(
                    spec,
                    register_exact,
                    memory_exact,
                )
            )
            interval = (
                None
                if register_ranges is None
                else _evaluate_range(
                    spec,
                    register_ranges,
                    memory_ranges,
                )
            )
            if value is not None:
                exact_registers[register] = value
            if interval is not None:
                range_registers[register] = list(interval)

        for cell_id, spec in (
            summary.get("return_memory_input_transfers") or {}
        ).items():
            value = (
                None
                if register_exact is None
                else _evaluate_exact(
                    spec,
                    register_exact,
                    memory_exact,
                )
            )
            interval = (
                None
                if register_ranges is None
                else _evaluate_range(
                    spec,
                    register_ranges,
                    memory_ranges,
                )
            )
            if value is not None:
                exact_memory[cell_id] = value
            if interval is not None:
                range_memory[cell_id] = list(interval)

        item = {
            "callee_entry": node.get("target"),
            "exact_registers": exact_registers,
            "range_registers": range_registers,
            "exact_memory": exact_memory,
            "range_memory": range_memory,
            "register_transfers": dict(
                summary.get(
                    "return_register_memory_transfers"
                ) or {}
            ),
            "memory_transfers": dict(
                summary.get("return_memory_input_transfers") or {}
            ),
        }
        node["symbolic_memory_input_instantiation"] = item
        result[node["address"]] = item
    return result


def _predecessors(nodes, edges):
    by_address = {node["address"]: node for node in nodes}
    predecessors = {address: set() for address in by_address}
    for edge in edges:
        if (
            edge.get("resolved")
            and edge.get("source") in by_address
            and edge.get("target") in by_address
            and edge.get("kind") != "call"
            and not edge.get("synthetic_return")
        ):
            predecessors[edge["target"]].add(edge["source"])
    return predecessors


def _function_entries(nodes, edges, entry_address):
    by_address = {node["address"]: node for node in nodes}
    entries = (
        {entry_address}
        if entry_address in by_address
        else set()
    )
    entries.update(
        edge["target"]
        for edge in edges
        if edge.get("kind") == "call"
        and edge.get("resolved")
        and edge.get("target") in by_address
    )
    return sorted(entries)


def _apply_input_memory_effect(
    outgoing,
    summary,
    instantiation,
    cells,
    cells_by_id,
):
    result = _copy_value_state(outgoing, cells)
    if summary is None or instantiation is None:
        return result

    exact = instantiation.get("exact_memory") or {}
    ranges = instantiation.get("range_memory") or {}
    for cell_id in set(exact) | set(ranges):
        cell = cells_by_id.get(cell_id)
        if cell is None:
            continue
        constant = exact.get(cell_id)
        raw_range = ranges.get(cell_id)
        interval = (
            None if raw_range is None else tuple(raw_range)
        )
        if (
            constant is not None
            and interval is None
            and cell[1] == WORD_BYTES
        ):
            signed = _signed24(constant)
            interval = (signed, signed)
        result[cell] = {
            "constant": constant,
            "range": interval,
            "origin": (
                "memory-input-callee-return@"
                f"{summary['entry']:05X}"
            ),
        }
    return result


def _transfer_concrete_memory(
    node,
    incoming,
    cells,
    operation,
    base_summaries,
    base_instantiations,
    summaries,
    instantiations,
    cells_by_id,
):
    outgoing = _copy_value_state(incoming, cells)
    if node["base_mnemonic"] == "JSUB":
        outgoing = _apply_concrete_call_memory(
            outgoing,
            base_summaries.get(node.get("target")),
            base_instantiations.get(node["address"]),
            cells,
            cells_by_id,
        )
        return _apply_input_memory_effect(
            outgoing,
            summaries.get(node.get("target")),
            instantiations.get(node["address"]),
            cells,
            cells_by_id,
        )

    if operation.get("unknown_write") or operation.get("barrier"):
        outgoing = _empty_value_state(cells)

    write = operation.get("write")
    if write is not None:
        value = _register_store_value(node, write)
        for cell in cells:
            if not _ranges_overlap(cell, write):
                continue
            outgoing[cell] = (
                value if cell == write else _unknown_value()
            )
    return outgoing


def analyze_symbolic_input_memory_values(
    nodes,
    edges,
    entry_address,
    seeds,
    base_summaries,
    base_instantiations,
    summaries,
    instantiations,
):
    by_address = {node["address"]: node for node in nodes}
    cells, operations = _tracked_cells(nodes)
    cells_by_id = {_cell_id(cell): cell for cell in cells}
    predecessors = _predecessors(nodes, edges)
    entries = _function_entries(nodes, edges, entry_address)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}

    for function_entry in entries:
        state = _empty_value_state(cells)
        if function_entry == entry_address:
            for cell, value in seeds.items():
                if cell in state:
                    state[cell] = dict(value)
        incoming[function_entry] = _join_value_state(
            incoming[function_entry],
            state,
            cells,
        )

    ordered = sorted(by_address)
    changed = True
    while changed:
        changed = False
        for address in ordered:
            candidate = incoming[address]
            for predecessor in predecessors[address]:
                predecessor_state = outgoing.get(predecessor)
                if predecessor_state is not None:
                    candidate = _join_value_state(
                        candidate,
                        predecessor_state,
                        cells,
                    )
            if candidate is None:
                continue
            state_out = _transfer_concrete_memory(
                by_address[address],
                candidate,
                cells,
                operations[address],
                base_summaries,
                base_instantiations,
                summaries,
                instantiations,
                cells_by_id,
            )
            if (
                incoming[address] is None
                or not _value_state_equal(
                    incoming[address],
                    candidate,
                    cells,
                )
            ):
                incoming[address] = candidate
                changed = True
            if (
                outgoing[address] is None
                or not _value_state_equal(
                    outgoing[address],
                    state_out,
                    cells,
                )
            ):
                outgoing[address] = state_out
                changed = True

    instruction_facts = {}
    for address in ordered:
        read = operations[address].get("read")
        value = None
        if read is not None and incoming[address] is not None:
            value = incoming[address].get(read)
        instruction_facts[address] = {
            "memory_read": (
                None if read is None else _cell_id(read)
            ),
            "constant": (
                None if value is None else value.get("constant")
            ),
            "range": (
                None
                if value is None or value.get("range") is None
                else list(value["range"])
            ),
            "origin": (
                None if value is None else value.get("origin")
            ),
        }

    return {
        "cells": cells,
        "operations": operations,
        "incoming": incoming,
        "outgoing": outgoing,
        "instruction_facts": instruction_facts,
    }


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


def _global_exact(
    nodes,
    edges,
    entry_address,
    base_register_summaries,
    instantiations,
    initial,
):
    by_address, outgoing_edges = _resolved_outgoing(nodes, edges)
    incoming = {address: None for address in by_address}
    outgoing = {address: None for address in by_address}
    if entry_address not in by_address:
        return incoming, outgoing

    entry_state = unknown_state()
    for register, value in initial.items():
        if register in TRACKED_REGISTERS:
            entry_state[register] = (
                None if value is None
                else value & REGISTER_MASK
            )
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
        state_out = _memory_aware_exact_transfer(
            node,
            state_in,
        )
        outgoing[address] = state_out

        for edge in outgoing_edges.get(address, ()):
            if not _exact_edge_feasible(
                node,
                edge,
                state_out,
            ):
                continue
            candidate = _copy_exact_state(state_out)
            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate = _apply_exact_call(
                    state_out,
                    base_register_summaries.get(
                        node.get("target")
                    ),
                )
                instantiation = instantiations.get(
                    node["address"]
                )
                if instantiation is not None:
                    for register, value in (
                        instantiation.get(
                            "exact_registers"
                        ) or {}
                    ).items():
                        if register in TRACKED_REGISTERS:
                            candidate[register] = (
                                value & REGISTER_MASK
                            )

            target = edge["target"]
            merged = _join_exact_states(
                incoming[target],
                candidate,
            )
            if not _exact_state_equal(
                incoming[target],
                merged,
            ):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    return incoming, outgoing


def _global_ranges(
    nodes,
    edges,
    entry_address,
    base_register_summaries,
    instantiations,
    initial,
):
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
        state_out = _memory_aware_range_transfer(
            node,
            state_in,
        )
        outgoing[address] = state_out

        for edge in outgoing_edges.get(address, ()):
            if not _range_edge_feasible(
                node,
                edge,
                state_out,
            ):
                continue
            candidate = _copy_range_state(state_out)
            if (
                node["base_mnemonic"] == "JSUB"
                and edge.get("kind") == "fallthrough"
            ):
                candidate = _apply_range_call(
                    state_out,
                    base_register_summaries.get(
                        node.get("target")
                    ),
                )
                instantiation = instantiations.get(
                    node["address"]
                )
                if instantiation is not None:
                    for register, interval in (
                        instantiation.get(
                            "range_registers"
                        ) or {}
                    ).items():
                        if register in TRACKED_REGISTERS:
                            candidate[register] = tuple(
                                interval
                            )

            target = edge["target"]
            merged = _join_range_states(
                incoming[target],
                candidate,
            )
            if not _range_state_equal(
                incoming[target],
                merged,
            ):
                incoming[target] = merged
                if target not in queued:
                    pending.append(target)
                    queued.add(target)

    return incoming, outgoing


def _clear_base(node):
    decoded = decode_instruction(
        bytes.fromhex(node["bytes"]),
        address=node["address"],
        base_register=None,
    )
    changed = (
        node.get("operand") != decoded.operand
        or node.get("target") != decoded.target
        or node.get("target_resolution")
        in SYMBOLIC_MEMORY_INPUT_BASE_RESOLUTIONS
        or "base_value" in node
    )
    node["operand"] = decoded.operand
    node["target"] = decoded.target
    node["warning"] = decoded.warning
    node.pop("base_value", None)
    node.pop("target_resolution", None)
    return changed


def _resolve_base_targets(nodes, exact_in, range_in):
    changed = False
    for node in nodes:
        if not _base_relative(node):
            continue
        resolution = node.get("target_resolution")
        if (
            resolution is not None
            and resolution
            not in SYMBOLIC_MEMORY_INPUT_BASE_RESOLUTIONS
        ):
            continue

        exact_state = exact_in.get(node["address"])
        range_state = range_in.get(node["address"])
        base = (
            None
            if exact_state is None
            else exact_state.get("B")
        )
        new_resolution = None
        if base is not None:
            new_resolution = "symbolic-memory-input-base"
        elif range_state is not None:
            interval = range_state.get("B")
            if (
                interval is not None
                and interval[0] == interval[1]
            ):
                base = interval[0] & REGISTER_MASK
                new_resolution = (
                    "symbolic-memory-input-range-base"
                )

        if base is None:
            if (
                resolution
                in SYMBOLIC_MEMORY_INPUT_BASE_RESOLUTIONS
            ):
                changed = _clear_base(node) or changed
            continue

        decoded = decode_instruction(
            bytes.fromhex(node["bytes"]),
            address=node["address"],
            base_register=base,
        )
        if decoded.target is None:
            if (
                resolution
                in SYMBOLIC_MEMORY_INPUT_BASE_RESOLUTIONS
            ):
                changed = _clear_base(node) or changed
            continue

        if (
            node.get("operand") != decoded.operand
            or node.get("target") != decoded.target
            or node.get("base_value") != base
            or node.get("target_resolution")
            != new_resolution
        ):
            node["operand"] = decoded.operand
            node["target"] = decoded.target
            node["warning"] = decoded.warning
            node["base_value"] = base
            node["target_resolution"] = new_resolution
            changed = True
    return changed


def _mark_impossible_edges(nodes, edges, exact_out, range_out):
    by_address = {node["address"]: node for node in nodes}
    for edge in edges:
        if (
            not edge.get("resolved")
            or edge.get("kind")
            not in ("branch", "fallthrough")
        ):
            continue
        node = by_address.get(edge.get("source"))
        if (
            node is None
            or node["base_mnemonic"]
            not in CONDITIONAL_MNEMONICS
        ):
            continue

        exact_state = exact_out.get(node["address"])
        if (
            exact_state is not None
            and exact_state.get("CC")
            in CONDITION_VALUES
            and not _exact_edge_feasible(
                node,
                edge,
                exact_state,
            )
        ):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = "symbolic-memory-input-condition"
            continue

        range_state = range_out.get(node["address"])
        if (
            range_state is not None
            and range_state.get("CC") is not None
            and not _range_edge_feasible(
                node,
                edge,
                range_state,
            )
        ):
            edge["resolved"] = False
            edge["feasible"] = False
            edge["reason"] = "condition-false"
            edge["resolution"] = (
                "symbolic-memory-input-range-condition"
            )


def _refinement_signature(
    nodes,
    edges,
    summaries,
    instantiations,
    value_analysis,
):
    return (
        _summary_signature(summaries),
        tuple(
            (
                address,
                repr(item.get("exact_registers")),
                repr(item.get("range_registers")),
                repr(item.get("exact_memory")),
                repr(item.get("range_memory")),
            )
            for address, item in sorted(
                instantiations.items()
            )
        ),
        tuple(
            (
                node["address"],
                repr(node.get("registers_in")),
                repr(node.get("ranges_in")),
                node.get("memory_constant"),
                repr(node.get("memory_range")),
                node.get("target"),
                node.get("target_resolution"),
            )
            for node in nodes
        ),
        tuple(
            (
                edge.get("source"),
                edge.get("target"),
                edge.get("kind"),
                bool(edge.get("resolved")),
                edge.get("resolution"),
                edge.get("reason"),
            )
            for edge in edges
        ),
        tuple(
            (
                address,
                fact.get("constant"),
                repr(fact.get("range")),
                fact.get("origin"),
            )
            for address, fact in sorted(
                value_analysis[
                    "instruction_facts"
                ].items()
            )
        ),
    )


def refine_symbolic_memory_inputs(
    nodes,
    edges,
    entry_address,
    image,
    image_start,
    debug_map,
    register_summaries=None,
    memory_summaries=None,
    memory_instantiations=None,
    base_register=None,
):
    """Close memory-input formulas with concrete call-site state and CFG feedback."""
    base_register_summaries = register_summaries or {}
    base_memory_summaries = memory_summaries or {}
    base_memory_instantiations = memory_instantiations or {}
    initial = (
        {}
        if base_register is None
        else {"B": base_register}
    )

    exact_in = {
        node["address"]: node.get("registers_in")
        for node in nodes
    }
    exact_out = {
        node["address"]: node.get("registers_out")
        for node in nodes
    }
    range_in = {
        node["address"]: node.get("ranges_in")
        for node in nodes
    }
    range_out = {
        node["address"]: node.get("ranges_out")
        for node in nodes
    }

    cells, _ = _tracked_cells(nodes)
    seeds = seed_initialized_memory(
        image,
        image_start,
        debug_map,
        cells,
    )
    value_analysis = analyze_symbolic_input_memory_values(
        nodes,
        edges,
        entry_address,
        seeds,
        base_memory_summaries,
        base_memory_instantiations,
        {},
        {},
    )

    previous = None
    max_iterations = max(5, len(nodes) + 5)
    for iteration in range(1, max_iterations + 1):
        inferred = infer_symbolic_memory_inputs(
            nodes,
            edges,
            register_summaries=base_register_summaries,
            memory_summaries=base_memory_summaries,
        )
        summaries = inferred["summary_map"]
        current_cells, _ = _tracked_cells(nodes)
        if current_cells != value_analysis["cells"]:
            seeds = seed_initialized_memory(
                image,
                image_start,
                debug_map,
                current_cells,
            )
            value_analysis = analyze_symbolic_input_memory_values(
                nodes,
                edges,
                entry_address,
                seeds,
                base_memory_summaries,
                base_memory_instantiations,
                summaries,
                {},
            )

        instantiations = _instantiate_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
            value_analysis["incoming"],
        )
        seeds = seed_initialized_memory(
            image,
            image_start,
            debug_map,
            current_cells,
        )
        value_analysis = analyze_symbolic_input_memory_values(
            nodes,
            edges,
            entry_address,
            seeds,
            base_memory_summaries,
            base_memory_instantiations,
            summaries,
            instantiations,
        )
        _attach_value_facts(nodes, value_analysis)

        exact_in, exact_out = _global_exact(
            nodes,
            edges,
            entry_address,
            base_register_summaries,
            instantiations,
            initial,
        )
        range_in, range_out = _global_ranges(
            nodes,
            edges,
            entry_address,
            base_register_summaries,
            instantiations,
            initial,
        )

        for node in nodes:
            address = node["address"]
            node["registers_in"] = (
                None
                if exact_in[address] is None
                else _copy_exact_state(
                    exact_in[address]
                )
            )
            node["registers_out"] = (
                None
                if exact_out[address] is None
                else _copy_exact_state(
                    exact_out[address]
                )
            )
            node["ranges_in"] = (
                None
                if range_in[address] is None
                else _copy_range_state(
                    range_in[address]
                )
            )
            node["ranges_out"] = (
                None
                if range_out[address] is None
                else _copy_range_state(
                    range_out[address]
                )
            )
            if node["base_mnemonic"] == "JSUB":
                node[
                    "symbolic_memory_input_summary"
                ] = summaries.get(node.get("target"))

        if _resolve_base_targets(
            nodes,
            exact_in,
            range_in,
        ):
            edges[:] = _rebuild_edges(nodes)
            previous = None
            continue

        _mark_impossible_edges(
            nodes,
            edges,
            exact_out,
            range_out,
        )

        final_instantiations = _instantiate_calls(
            nodes,
            summaries,
            exact_out,
            range_out,
            value_analysis["incoming"],
        )
        signature = _refinement_signature(
            nodes,
            edges,
            summaries,
            final_instantiations,
            value_analysis,
        )
        if signature == previous:
            return {
                "iterations": iteration,
                "converged": True,
                "summaries": [
                    summaries[key]
                    for key in sorted(summaries)
                ],
                "summary_map": summaries,
                "instantiations": final_instantiations,
                "value_analysis": value_analysis,
                "seeds": [
                    seeds[cell]
                    for cell in sorted(seeds)
                ],
                "base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution")
                    == "symbolic-memory-input-base"
                ),
                "range_base_resolutions": sum(
                    1
                    for node in nodes
                    if node.get("target_resolution")
                    == "symbolic-memory-input-range-base"
                ),
                "return_register_transfers": sum(
                    len(
                        summary.get(
                            "return_register_memory_transfers"
                        ) or {}
                    )
                    for summary in summaries.values()
                ),
                "return_memory_transfers": sum(
                    len(
                        summary.get(
                            "return_memory_input_transfers"
                        ) or {}
                    )
                    for summary in summaries.values()
                ),
            }
        previous = signature

    raise SymbolicMemoryInputError(
        "Symbolic memory-input/CFG refinement did not converge"
    )
