from errors import AssemblyError
from opcodes import FORMAT2_SIGNATURES, OPCODES, REGISTERS
from pass1 import encode_byte_operand, parse_line


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

        def flush_text_record():
            nonlocal text_record, text_start
            if text_record:
                length = len(text_record) // 2
                f_obj.write(f"T{text_start:06X}{length:02X}{text_record}\n")
                text_record = ""
                text_start = -1

        def start_csect(name, addr):
            nonlocal current_csect, mod_records
            current_csect = name
            csect_len = csects[name]['length']

            name_str = (name + "      ")[:6]
            f_obj.write(f"H{name_str}{addr:06X}{csect_len:06X}\n")

            extdefs = csects[name]['extdef']
            if extdefs:
                d_rec = "D"
                for symbol in extdefs:
                    if symbol in csects[name]['symtab']:
                        d_addr = csects[name]['symtab'][symbol]
                        d_rec += f"{symbol.ljust(6)[:6]}{d_addr:06X}"
                f_obj.write(d_rec + "\n")

            extrefs = csects[name]['extref']
            if extrefs:
                r_rec = "R"
                for symbol in extrefs:
                    r_rec += f"{symbol.ljust(6)[:6]}"
                f_obj.write(r_rec + "\n")

            mod_records = []

        def end_csect(write_e=False, exec_addr=None):
            flush_text_record()
            for record in mod_records:
                f_obj.write(f"{record}\n")
            if write_e and exec_addr is not None:
                f_obj.write(f"E{exec_addr:06X}\n")
            else:
                f_obj.write("E\n")

        lines = f_in.readlines()

        for idx, line in enumerate(lines):
            line_number = idx + 1
            parts = line.strip('\n').split('\t', 1)
            if len(parts) != 2:
                if "END" in line:
                    _, _, operand, _ = parse_line(line)
                    f_lst.write(f"\t\t\t{line.strip()}\n")
                    first_exec_addr = start_addr
                    if operand and operand in csects[current_csect]['symtab']:
                        first_exec_addr = csects[current_csect]['symtab'][operand]
                    end_csect(write_e=True, exec_addr=first_exec_addr)
                    break
                continue

            addr_str = parts[0].strip()
            orig_line = parts[1].strip()
            current_pc = int(addr_str, 16) if addr_str else 0

            next_pc = current_pc
            if idx + 1 < len(lines):
                next_parts = lines[idx + 1].strip('\n').split('\t', 1)
                if len(next_parts) == 2 and next_parts[0].strip():
                    next_pc = int(next_parts[0].strip(), 16)

            label, opcode, operand, is_comment = parse_line(orig_line)
            if is_comment:
                continue

            obj_code = ""

            if opcode == 'START':
                start_csect(label if label else "DEFAULT", current_pc)
                f_lst.write(f"{addr_str}\t\t{orig_line}\n")
                continue

            if opcode == 'CSECT':
                end_csect()
                start_csect(label if label else "UNNAMED", 0)
                base_register = -1
                f_lst.write(f"{addr_str}\t\t{orig_line}\n")
                continue

            if opcode == 'END':
                f_lst.write(f"\t\t\t{orig_line}\n")
                first_exec_addr = start_addr
                if operand and operand in csects[current_csect]['symtab']:
                    first_exec_addr = csects[current_csect]['symtab'][operand]
                end_csect(write_e=True, exec_addr=first_exec_addr)
                break

            if opcode == 'EXTDEF':
                undefined = [
                    symbol for symbol in csects[current_csect]['extdef']
                    if symbol not in csects[current_csect]['symtab']
                ]
                if undefined:
                    fail(line_number, f"EXTDEF symbol is not defined locally: {undefined[0]}")
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'EXTREF':
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'BASE':
                if not operand or operand not in csects[current_csect]['symtab']:
                    fail(line_number, f"BASE requires a defined local symbol: {operand}")
                base_register = csects[current_csect]['symtab'][operand]
                f_lst.write(f"\t\t\t{orig_line}\n")
                continue

            if opcode == 'NOBASE':
                if operand:
                    fail(line_number, "NOBASE does not take an operand")
                base_register = -1
                f_lst.write(f"\t\t\t{orig_line}\n")
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
                            op_symbol = operand[1:]
                        elif operand.startswith('@'):
                            n, i = 1, 0
                            op_symbol = operand[1:]

                        if op_symbol.endswith(',X'):
                            if (n, i) != (1, 1):
                                fail(line_number, "Indexed addressing cannot be combined with # or @")
                            x = 1
                            op_symbol = op_symbol[:-2].strip()

                        target_addr = 0
                        is_absolute = False
                        is_extref = False

                        if op_symbol.startswith('*'):
                            offset = 0
                            if len(op_symbol) > 1:
                                try:
                                    offset = int(op_symbol[1:])
                                except ValueError:
                                    fail(line_number, f"Invalid location-counter expression: {op_symbol}")
                            target_addr = next_pc + offset
                        elif op_symbol.isdigit() or (
                            op_symbol.startswith('-') and op_symbol[1:].isdigit()
                        ):
                            target_addr = int(op_symbol)
                            is_absolute = True
                        elif op_symbol in csects[current_csect]['symtab']:
                            target_addr = csects[current_csect]['symtab'][op_symbol]
                        elif op_symbol in csects[current_csect]['extref']:
                            is_extref = True
                            target_addr = 0
                        else:
                            fail(
                                line_number,
                                f"Undefined symbol {op_symbol} in CSECT {current_csect}",
                            )

                        if is_absolute:
                            if e:
                                if not -(1 << 19) <= target_addr <= 0xFFFFF:
                                    fail(line_number, f"Format-4 constant out of 20-bit range: {target_addr}")
                                disp = target_addr & 0xFFFFF
                            else:
                                if not -2048 <= target_addr <= 4095:
                                    fail(line_number, f"Format-3 constant out of 12-bit range: {target_addr}")
                                disp = target_addr & 0xFFF
                        elif is_extref:
                            if e == 1:
                                disp = 0
                                mod_records.append(
                                    f"M{current_pc + 1:06X}05+{op_symbol.ljust(6)[:6]}"
                                )
                            else:
                                fail(
                                    line_number,
                                    f"External reference {op_symbol} requires Format 4",
                                )
                        else:
                            if e == 1:
                                if not 0 <= target_addr <= 0xFFFFF:
                                    fail(line_number, f"Format-4 address out of range: {target_addr}")
                                disp = target_addr
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
                val = 0
                if operand in csects[current_csect]['extref']:
                    mod_records.append(f"M{current_pc:06X}06+{operand.ljust(6)[:6]}")
                else:
                    try:
                        val = int(operand, 10)
                    except (TypeError, ValueError):
                        fail(line_number, f"Unsupported WORD operand {operand}")
                if not -(1 << 23) <= val <= 0xFFFFFF:
                    fail(line_number, f"WORD value out of 24-bit range: {val}")
                if val < 0:
                    val = (1 << 24) + val
                obj_code = f"{val:06X}"

            elif opcode == 'BYTE':
                try:
                    obj_code = encode_byte_operand(operand)
                except ValueError as exc:
                    fail(line_number, str(exc))

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
