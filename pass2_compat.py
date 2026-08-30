from object_format import SYNTHETIC_DEFAULT_CSECT


def prepare_pass2_inputs(int_file, csects, parse_line):
    """Create an explicit START view for the legacy no-START default CSECT."""
    first_csect = next(iter(csects))
    if first_csect != "DEFAULT":
        return int_file, csects, None

    with open(int_file, 'r') as intermediate:
        lines = intermediate.readlines()

    for line in lines:
        parts = line.rstrip('\n').split('\t', 1)
        original = parts[1] if len(parts) == 2 else line
        _, opcode, _, is_comment = parse_line(original)
        if is_comment:
            continue
        if opcode == 'START':
            return int_file, csects, None
        break

    first_data = csects[first_csect]
    pass2_csects = {SYNTHETIC_DEFAULT_CSECT: first_data}
    for name, data in list(csects.items())[1:]:
        pass2_csects[name] = data

    pass2_int_file = int_file + ".pass2"
    start = first_data['start']
    with open(pass2_int_file, 'w') as intermediate:
        intermediate.write(
            f"{start:04X}\t{SYNTHETIC_DEFAULT_CSECT} START {start:X}\n"
        )
        intermediate.writelines(lines)

    return pass2_int_file, pass2_csects, pass2_int_file
