from errors import AssemblyError
from expressions import evaluate_expression, evaluate_link_expression
from opcodes import FORMAT2_SIGNATURES, OPCODES, REGISTERS
from pass1 import encode_byte_operand, parse_line, parse_literal


def _parse_register(token):
    register = token.strip().upper()
    if register not in REGISTERS:
        raise ValueError(f"Invalid register: {token}")
    return REGISTERS[register]


def _parse_decimal(token, description):
    try:
        return int(token, 10)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {description}: {token}") from exc


def encode_format2(opcode, operand):
    """Encode the operand byte for a format-2 SIC/XE instruction."""
    signature = FORMAT2_SIGNATURES.get(opcode)
    if signature is None:
        raise ValueError(f"Unsupported format-2 instruction: {opcode}")

    operands = [] if operand is None else [part.strip() for part in operand.split(',')]
    if len(operands) != len(signature) or any(not part for part in operands):
        expected = len(signature)
        raise ValueError(f"{opcode} expects {expected} operand(s), got {len(operands)}")

    fields = []
    for kind, token in zip(signature, operands):
        if kind == 'register':
            fields.append(_parse_register(token))
        elif kind == 'shift_count':
            count = _parse_decimal(token, "shift count")
            if not 1 <= count <= 16:
                raise ValueError(f"{opcode} shift count must be between 1 and 16")
            fields.append(count - 1)
        elif kind == 'nibble':
            value = _parse_decimal(token, "service code")
            if not 0 <= value <= 15:
                raise ValueError(f"{opcode} service code must be between 0 and 15")
            fields.append(value)
        else:
            raise ValueError(f"Unknown format-2 operand kind: {kind}")

    if len(fields) == 1:
        fields.append(0)
    return (fields[0] << 4) | fields[1]


def run_pass2(int_file, obj_file, lst_file, csects, start_addr):
    base_register = -1

    def fail(line_number, message):
        raise AssemblyError(message, phase="pass 2", line_number=line_number)

    with open(int_file, 'r') as f_in, open(lst_file, 'w') as f_lst, open(obj_file, 'w') as f_obj:
        current_csect = ""
        text_record = ""
        text_start = -1
        mod_records = []
        lines = f_in.readlines()

        first_csect = next(iter(csects))
        first_data = csects[first_csect]
        execution_address = first_data['start']
        end_error = None

        for idx, source_line in enumerate(lines):
            parts = source_line.strip('\n').split('\t', 1)
            original = parts[1] if len(parts) == 2 else source_line
            _, opcode, operand, is_comment = parse_line(original)
            if not is_comment and opcode == 'END':
                if operand:
                    if operand == first_csect:
                        execution_address = first_data['start']
                    elif operand in first_data['symtab']:
                        execution_address = first_data['symtab'][operand]
                    else:
                        end_error = (
                            idx + 1,
                            f"END execution symbol is not defined in {first_csect}: {operand}",
                        )
                break

        def flush_text_record():
            nonlocal text_record, text_start
            if text_record:
                length = len(text_record) // 2
                f_obj.write(f"T{text_start:06X}{length:02X}{text_record}\n")
                text_record = ""
                text_start = -1

        def start_csect(name):
            nonlocal current_csect, mod_records
            current_csect = name
            data = csects[name]
            name_str = (name + "      ")[:6]
            f_obj.write(f"H{name_str}{data['start']:06X}{data['length']:06X}\n")

            extdefs = data['extdef']
            if extdefs:
                d_rec = "D"
                for symbol in extdefs:
                    if symbol not in data['symtab']:
                        raise AssemblyError(
                            f"EXTDEF symbol is not defined locally: {symbol}",
                            phase="pass 2",
                        )
                    if symbol not in data['relocatable']:
                        raise AssemblyError(
                            f"EXTDEF symbol must be relocatable: {symbol}",
                            phase="pass 2",
                        )
                    relative = data['symtab'][symbol] - data['start']
                    if not 0 <= relative <= 0xFFFFFF:
                        raise AssemblyError(
                            f"EXTDEF symbol is outside its control section: {symbol}",
                            phase="pass 2",
                        )
                    d_rec += f"{symbol.ljust(6)[:6]}{relative:06X}"
                f_obj.write(d_rec + "\n")

            extrefs = data['extref']
            if extrefs:
                r_rec = "R"
                for symbol in extrefs:
                    r_rec += f"{symbol.ljust(6)[:6]}"
                f_obj.write(r_rec + "\n")

            mod_records = []

        def end_csect():
            flush_text_record()
            for record in mod_records:
                f_obj.write(f"{record}\n")
            if current_csect == first_csect:
                f_obj.write(f"E{execution_address:06X}\n")
            else:
                f_obj.write("E\n")

        def append_link_modifications(address, half_bytes, result):
            if result.local_relocation_factor:
                sign = '+' if result.local_relocation_factor > 0 else '-'
                for _ in range(abs(result.local_relocation_factor)):
                    mod_records.append(
                        f"M{address:06X}{half_bytes:02X}{sign}{current_csect.ljust(6)[:6]}"
                    )
            for term_sign, symbol in result.external_terms:
                sign = '+' if term_sign > 0 else '-'
                mod_records.append(
                    f"M{address:06X}{half_bytes:02X}{sign}{symbol.ljust(6)[:6]}"
                )

        for idx, line in enumerate(lines):
            line_number = idx + 1
            parts = line.strip('\n').split('\t', 1)
            if len(parts) != 2:
                if "END" in line:
                    if end_error is not None:
                        fail(*end_error)
                    f_lst.write(f"\t\t\t{line.strip()}\n")
                    end_csect()
                    break
                continue

            addr_str = parts[0].strip()
            orig_line = parts[1].strip()
            current_pc = int(addr_str, 16) if addr_str else 0

            label, opcode, operand, is_comment = parse_line(orig_line)
            if is_comment:
                continue

            obj_code = ""

            if opcode == 'START':
                start_csect(label if label else "DEFAULT")
                f_lst.write(f"{addr_str}\t\t{orig_line}\n")
                continue

            if opcode == 'CSECT':
                end_csect()
                start_csect(label if label else "UNNAMED")
                base_register = -1
                f_lst.write(f"{addr_str}\t\t{orig_line}\n")
                continue

            if opcode == 'END':
                if end_error is not None:
                    fail(*end_error)
                f_lst.write(f"\t\t\t{orig_line}\n")
                end_csect()
                break

            data = csects[current_csect]
            csect_start = data['start']

            if opcode == 'EXTDEF':
                undefined = [symbol for symbol in data['extdef'] if symbol not in data['symtab']]
                if undefined:
                    fail(line_number, f"EXTDEF symbol is not defined locally: {undefined[0]}")
                absolute = [symbol for symbol in data['extdef'] if symbol not in data['relocatable']]
                if absolute:
                    fail(line_number, f"EXTDEF symbol must be relocatable: {absolute[0]}")
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'EXTREF':
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'BASE':
                if not operand:
                    fail(line_number, "BASE requires an operand")
                try:
                    result = evaluate_link_expression(
                        operand,
                        current_pc,
                        csect_start,
                        data['symtab'],
                        data['relocatable'],
                        data['extref'],
                    )
                except ValueError as exc:
                    fail(line_number, str(exc))
                if result.external_terms:
                    fail(line_number, f"BASE cannot use an external reference expression: {operand}")
                base_register = result.value + (
                    csect_start if result.local_relocation_factor == 1 else 0
                )
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'NOBASE':
                if operand:
                    fail(line_number, "NOBASE does not take an operand")
                base_register = -1
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'LTORG':
                if operand:
                    fail(line_number, "LTORG does not take an operand")
                f_lst.write(f"{addr_str}\t\t\t{orig_line}\n")
                continue

            raw_opcode = opcode[1:] if opcode and opcode.startswith('+') else opcode

            if raw_opcode in OPCODES:
                op_val = int(OPCODES[raw_opcode][0], 16)
                fmt = OPCODES[raw_opcode][1]
                is_format4 = opcode.startswith('+')

                if fmt == 1:
                    if operand:
                        fail(line_number, f"{raw_opcode} does not take an operand")
                    obj_code = f"{op_val:02X}"

                elif fmt == 2:
                    try:
                        operand_byte = encode_format2(raw_opcode, operand)
                    except ValueError as exc:
                        fail(line_number, str(exc))
                    obj_code = f"{op_val:02X}{operand_byte:02X}"

                elif fmt == 3:
                    n, i, x, b, p, e = 1, 1, 0, 0, 0, 0
                    disp = 0
                    next_pc = current_pc + (4 if is_format4 else 3)

                    if is_format4:
                        e = 1

                    if not operand:
                        if raw_opcode != 'RSUB':
                            fail(line_number, f"{raw_opcode} requires an operand")
                    elif raw_opcode == 'RSUB':
                        fail(line_number, "RSUB does not take an operand")
                    else:
                        op_symbol = operand
                        if operand.startswith('#'):
                            n, i = 0, 1
                            op_symbol = operand[1:].strip()
                        elif operand.startswith('@'):
                            n, i = 1, 0
                            op_symbol = operand[1:].strip()

                        if op_symbol.endswith(',X'):
                            if (n, i) != (1, 1):
                                fail(line_number, "Indexed addressing cannot be combined with # or @")
                            x = 1
                            op_symbol = op_symbol[:-2].strip()

                        if op_symbol.startswith('='):
                            try:
                                canonical, _ = parse_literal(op_symbol)
                            except ValueError as exc:
                                fail(line_number, str(exc))
                            entry = data['literals'].get(canonical)
                            if entry is None or entry['address'] is None:
                                fail(line_number, f"Literal is not assigned in {current_csect}: {op_symbol}")
                            target_addr = entry['address']
                            if e:
                                relative = target_addr - csect_start
                                if not 0 <= relative <= 0xFFFFF:
                                    fail(line_number, f"Format-4 relocatable address out of range: {target_addr}")
                                disp = relative
                                mod_records.append(
                                    f"M{current_pc + 1:06X}05+{current_csect.ljust(6)[:6]}"
                                )
                            else:
                                disp_val = target_addr - next_pc
                                if -2048 <= disp_val <= 2047:
                                    p = 1
                                    disp = disp_val & 0xFFF
                                elif base_register != -1:
                                    disp_val = target_addr - base_register
                                    if 0 <= disp_val <= 4095:
                                        b = 1
                                        disp = disp_val & 0xFFF
                                    else:
                                        fail(line_number, f"Displacement out of bounds for {opcode} {operand}")
                                else:
                                    fail(
                                        line_number,
                                        f"Displacement out of bounds and BASE is not set for {opcode} {operand}",
                                    )
                        else:
                            try:
                                link_result = evaluate_link_expression(
                                    op_symbol,
                                    current_pc,
                                    csect_start,
                                    data['symtab'],
                                    data['relocatable'],
                                    data['extref'],
                                )
                            except ValueError as exc:
                                fail(line_number, str(exc))

                            if e:
                                if not -(1 << 19) <= link_result.value <= 0xFFFFF:
                                    fail(
                                        line_number,
                                        f"Format-4 expression value out of 20-bit range: {link_result.value}",
                                    )
                                disp = link_result.value & 0xFFFFF
                                append_link_modifications(
                                    current_pc + 1,
                                    5,
                                    link_result,
                                )
                            else:
                                if link_result.external_terms:
                                    fail(
                                        line_number,
                                        f"External expression requires Format 4: {op_symbol}",
                                    )
                                if link_result.local_relocation_factor == 0:
                                    target_addr = link_result.value
                                    if not -2048 <= target_addr <= 4095:
                                        fail(
                                            line_number,
                                            f"Format-3 constant out of 12-bit range: {target_addr}",
                                        )
                                    disp = target_addr & 0xFFF
                                else:
                                    target_addr = link_result.value + csect_start
                                    disp_val = target_addr - next_pc
                                    if -2048 <= disp_val <= 2047:
                                        p = 1
                                        disp = disp_val & 0xFFF
                                    elif base_register != -1:
                                        disp_val = target_addr - base_register
                                        if 0 <= disp_val <= 4095:
                                            b = 1
                                            disp = disp_val & 0xFFF
                                        else:
                                            fail(
                                                line_number,
                                                f"Displacement out of bounds for {opcode} {operand}",
                                            )
                                    else:
                                        fail(
                                            line_number,
                                            f"Displacement out of bounds and BASE is not set for {opcode} {operand}",
                                        )

                    byte1 = (op_val & 0xFC) | (n << 1) | i
                    byte2 = (x << 7) | (b << 6) | (p << 5) | (e << 4)

                    if e == 1:
                        byte2 |= (disp >> 16) & 0x0F
                        obj_code = f"{byte1:02X}{byte2:02X}{disp & 0xFFFF:04X}"
                    else:
                        byte2 |= (disp >> 8) & 0x0F
                        obj_code = f"{byte1:02X}{byte2:02X}{disp & 0xFF:02X}"

            elif opcode == 'WORD':
                try:
                    result = evaluate_link_expression(
                        operand,
                        current_pc,
                        csect_start,
                        data['symtab'],
                        data['relocatable'],
                        data['extref'],
                    )
                except ValueError as exc:
                    fail(line_number, str(exc))

                value = result.value
                append_link_modifications(current_pc, 6, result)

                if not -(1 << 23) <= value <= 0xFFFFFF:
                    fail(line_number, f"WORD value out of 24-bit range: {value}")
                if value < 0:
                    value = (1 << 24) + value
                obj_code = f"{value:06X}"

            elif opcode == 'BYTE':
                try:
                    obj_code = encode_byte_operand(operand)
                except ValueError as exc:
                    fail(line_number, str(exc))

            elif opcode == 'EQU':
                f_lst.write(f"{addr_str}\t\t\t{orig_line}\n")
                continue

            elif opcode in ['RESW', 'RESB']:
                pass

            if obj_code:
                f_lst.write(f"{addr_str}\t{obj_code.ljust(10)}\t{orig_line}\n")

                if text_start == -1:
                    text_start = int(addr_str, 16)

                if len(text_record) + len(obj_code) > 60:
                    flush_text_record()
                    text_start = int(addr_str, 16)

                text_record += obj_code
            else:
                f_lst.write(f"{addr_str}\t\t\t{orig_line}\n")
                flush_text_record()
