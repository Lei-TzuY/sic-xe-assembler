import os
import sys


class LoaderError(Exception):
    pass


def parse_obj_file(filepath):
    records = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                records.append(line.strip('\n'))
    return records


def pass1(obj_files, progaddr):
    estab = {}
    csaddr = progaddr

    for file in obj_files:
        records = parse_obj_file(file)
        current_cslth = 0
        saw_header = False

        for record in records:
            if record.startswith('H'):
                if len(record) < 19:
                    raise LoaderError(f"Malformed H record in {file}: {record}")
                csect_name = record[1:7].strip()
                current_cslth = int(record[13:19], 16)
                saw_header = True

                if csect_name in estab:
                    raise LoaderError(f"Duplicate external symbol {csect_name}")
                estab[csect_name] = csaddr

            elif record.startswith('D'):
                if not saw_header:
                    raise LoaderError(f"D record before H record in {file}")
                payload = record[1:]
                if len(payload) % 12:
                    raise LoaderError(f"Malformed D record in {file}: {record}")
                for idx in range(0, len(payload), 12):
                    sym_name = payload[idx:idx + 6].strip()
                    sym_addr = int(payload[idx + 6:idx + 12], 16)
                    if not sym_name:
                        raise LoaderError(f"Empty symbol in D record: {record}")
                    if sym_name in estab:
                        raise LoaderError(f"Duplicate external symbol {sym_name}")
                    estab[sym_name] = csaddr + sym_addr

            elif record.startswith('E'):
                if not saw_header:
                    raise LoaderError(f"E record before H record in {file}")
                csaddr += current_cslth
                saw_header = False
                current_cslth = 0

        if saw_header:
            raise LoaderError(f"Missing E record in {file}")

    return estab


def _check_memory_range(memory, start, length, description):
    if start < 0 or length < 0 or start + length > len(memory):
        raise LoaderError(f"{description} exceeds loader memory")


def pass2(obj_files, progaddr, estab):
    csaddr = progaddr
    exec_addr = progaddr
    memory = bytearray(65536)

    for file in obj_files:
        records = parse_obj_file(file)
        current_cslth = 0
        header_start = 0
        saw_header = False

        for record in records:
            if record.startswith('H'):
                if len(record) < 19:
                    raise LoaderError(f"Malformed H record in {file}: {record}")
                header_start = int(record[7:13], 16)
                current_cslth = int(record[13:19], 16)
                saw_header = True
                _check_memory_range(memory, csaddr, current_cslth, "Control section")

            elif record.startswith('T'):
                if not saw_header or len(record) < 9:
                    raise LoaderError(f"Malformed T record in {file}: {record}")
                record_start = int(record[1:7], 16)
                length = int(record[7:9], 16)
                code_hex = record[9:]
                if len(code_hex) != length * 2:
                    raise LoaderError(f"T record length mismatch in {file}: {record}")
                offset = record_start - header_start
                if offset < 0 or offset + length > current_cslth:
                    raise LoaderError(f"T record lies outside control section: {record}")
                start_addr = csaddr + offset
                _check_memory_range(memory, start_addr, length, "Text record")

                try:
                    code = bytes.fromhex(code_hex)
                except ValueError as exc:
                    raise LoaderError(f"Invalid hexadecimal data in T record: {record}") from exc
                memory[start_addr:start_addr + length] = code

            elif record.startswith('M'):
                if not saw_header or len(record) < 11:
                    raise LoaderError(f"Malformed M record in {file}: {record}")
                record_addr = int(record[1:7], 16)
                mod_len = int(record[7:9], 16)
                sign = record[9]
                sym_name = record[10:].strip()
                if mod_len not in (5, 6):
                    raise LoaderError(f"Unsupported modification length {mod_len}: {record}")
                if sign not in '+-':
                    raise LoaderError(f"Invalid modification sign: {record}")
                if sym_name not in estab:
                    raise LoaderError(f"Undefined external symbol {sym_name}")

                offset = record_addr - header_start
                if offset < 0 or offset + 3 > current_cslth:
                    raise LoaderError(f"M record lies outside control section: {record}")
                mod_addr = csaddr + offset
                _check_memory_range(memory, mod_addr, 3, "Modification record")

                val = (
                    (memory[mod_addr] << 16)
                    | (memory[mod_addr + 1] << 8)
                    | memory[mod_addr + 2]
                )
                if mod_len == 5:
                    target = val & 0x0FFFFF
                    keep_mask = 0xF00000
                    width_mask = 0x0FFFFF
                else:
                    target = val & 0xFFFFFF
                    keep_mask = 0
                    width_mask = 0xFFFFFF

                sym_val = estab[sym_name]
                target = target + sym_val if sign == '+' else target - sym_val
                target &= width_mask
                val = (val & keep_mask) | target

                memory[mod_addr] = (val >> 16) & 0xFF
                memory[mod_addr + 1] = (val >> 8) & 0xFF
                memory[mod_addr + 2] = val & 0xFF

            elif record.startswith('E'):
                if not saw_header:
                    raise LoaderError(f"E record before H record in {file}")
                if len(record) > 1:
                    source_exec = int(record[1:7], 16)
                    offset = source_exec - header_start
                    if not 0 <= offset <= current_cslth:
                        raise LoaderError(f"Execution address lies outside control section: {record}")
                    exec_addr = csaddr + offset
                csaddr += current_cslth
                saw_header = False
                current_cslth = 0
                header_start = 0

        if saw_header:
            raise LoaderError(f"Missing E record in {file}")

    return memory, exec_addr


def print_estab(estab):
    print("\n" + "=" * 30)
    print("External Symbol Table (ESTAB)")
    print("-" * 30)
    print(f"{'Symbol Name':<15} {'Address':<10}")
    print("-" * 30)
    for sym, addr in estab.items():
        print(f"{sym:<15} {addr:04X}")
    print("=" * 30 + "\n")


def dump_memory(memory, start_addr, length):
    print("=" * 65)
    print(f"Memory Dump ({start_addr:04X} - {start_addr + length - 1:04X})")
    print("-" * 65)

    end_addr = min(start_addr + length, len(memory))
    dump_start = start_addr & ~0x0F
    dump_end = min((end_addr + 15) & ~0x0F, len(memory))

    for addr in range(dump_start, dump_end, 16):
        row = memory[addr:min(addr + 16, len(memory))]
        hex_data = " ".join(f"{byte:02X}" for byte in row).ljust(47)
        ascii_data = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in row)
        print(f"{addr:04X}  {hex_data}  |{ascii_data}|")
    print("=" * 65 + "\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: python loader.py <obj_file1> [obj_file2 ...] [PROGADDR]")
        return 1

    args = sys.argv[1:]
    progaddr = 0x4000
    obj_files = []

    for arg in args:
        if os.path.exists(arg):
            obj_files.append(arg)
        else:
            try:
                progaddr = int(arg, 16)
            except ValueError:
                pass

    if not obj_files:
        print("Error: No valid object files provided.", file=sys.stderr)
        return 1

    try:
        print(f"Loading {len(obj_files)} object files starting at PROGADDR {progaddr:04X}...")
        estab = pass1(obj_files, progaddr)
        print_estab(estab)
        memory, exec_addr = pass2(obj_files, progaddr, estab)
        print(f"Load complete. Execution start address: {exec_addr:04X}\n")

        total_len = 0
        for file in obj_files:
            for record in parse_obj_file(file):
                if record.startswith('H'):
                    total_len += int(record[13:19], 16)
        dump_memory(memory, progaddr, total_len)
        return 0
    except (LoaderError, OSError, ValueError) as exc:
        print(f"Load failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
