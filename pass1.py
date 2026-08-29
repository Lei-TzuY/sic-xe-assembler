from opcodes import OPCODES, DIRECTIVES


def parse_line(line):
    if '.' in line:
        line = line[:line.index('.')]
    line = line.strip()
    if not line:
        return None, None, None, True

    tokens = line.split()
    label = None
    opcode = None
    operand = None

    def is_opcode(t):
        raw = t[1:] if t.startswith('+') else t
        return raw in OPCODES or t in DIRECTIVES

    if is_opcode(tokens[0]):
        opcode = tokens[0]
        if len(tokens) > 1:
            operand = tokens[1]
    else:
        label = tokens[0]
        if len(tokens) > 1:
            opcode = tokens[1]
        if len(tokens) > 2:
            operand = tokens[2]

    return label, opcode, operand, False


def instruction_size(opcode):
    """Return the encoded size for an instruction, validating extended format use."""
    raw_opcode = opcode[1:] if opcode.startswith('+') else opcode
    if raw_opcode not in OPCODES:
        return None

    fmt = OPCODES[raw_opcode][1]
    if opcode.startswith('+'):
        if fmt != 3:
            raise ValueError(
                f"Extended format is only valid for format 3/4 instructions: {opcode}"
            )
        return 4
    return fmt


def run_pass1(asm_file, int_file, sym_file):
    csects = {}
    current_csect = ""
    locctr = 0
    start_address = 0

    with open(asm_file, 'r') as f_in, open(int_file, 'w') as f_out:
        lines = f_in.readlines()
        first_line = True

        for line in lines:
            label, opcode, operand, is_comment = parse_line(line)

            if is_comment:
                continue

            if first_line and opcode == 'START':
                start_address = int(operand, 16) if operand else 0
                locctr = start_address
                current_csect = label if label else "DEFAULT"
                csects[current_csect] = {'symtab': {}, 'extdef': [], 'extref': [], 'length': 0}
                f_out.write(f"{locctr:04X}\t{line.strip()}\n")
                first_line = False
                continue

            first_line = False

            if not current_csect:
                current_csect = label if label else "DEFAULT"
                csects[current_csect] = {'symtab': {}, 'extdef': [], 'extref': [], 'length': 0}

            if opcode == 'CSECT':
                csects[current_csect]['length'] = locctr
                current_csect = label if label else "UNNAMED"
                csects[current_csect] = {'symtab': {}, 'extdef': [], 'extref': [], 'length': 0}
                locctr = 0
                f_out.write(f"{locctr:04X}\t{line.strip()}\n")
                continue

            if opcode == 'END':
                csects[current_csect]['length'] = locctr
                f_out.write(f"\t\t{line.strip()}\n")
                break

            f_out.write(f"{locctr:04X}\t{line.strip()}\n")

            if opcode == 'EXTDEF':
                if operand:
                    csects[current_csect]['extdef'].extend([p.strip() for p in operand.split(',')])
                continue

            if opcode == 'EXTREF':
                if operand:
                    csects[current_csect]['extref'].extend([p.strip() for p in operand.split(',')])
                continue

            if label:
                if label in csects[current_csect]['symtab']:
                    print(f"Error: Duplicate label {label} in {current_csect}")
                else:
                    csects[current_csect]['symtab'][label] = locctr

            size = instruction_size(opcode) if opcode else None
            if size is not None:
                locctr += size
            elif opcode == 'WORD':
                locctr += 3
            elif opcode == 'RESW':
                locctr += 3 * int(operand)
            elif opcode == 'RESB':
                locctr += int(operand)
            elif opcode == 'BYTE':
                if operand.startswith("C'") and operand.endswith("'"):
                    locctr += len(operand) - 3
                elif operand.startswith("X'") and operand.endswith("'"):
                    locctr += (len(operand) - 3) // 2
            elif opcode in ['BASE', 'NOBASE', 'EQU']:
                pass
            else:
                if opcode:
                    print(f"Error: Invalid opcode {opcode}")

    with open(sym_file, 'w') as f_sym:
        for cs_name, cs_data in csects.items():
            f_sym.write(f"CS: {cs_name}\n")
            for lbl, addr in cs_data['symtab'].items():
                f_sym.write(f"  {lbl}\t{addr:04X}\n")

    return csects, start_address
