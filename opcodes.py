OPCODES = {
    # Format 1
    'FIX': ('C4', 1),
    'FLOAT': ('C0', 1),
    'HIO': ('F4', 1),
    'NORM': ('C8', 1),
    'SIO': ('F0', 1),
    'TIO': ('F8', 1),

    # Format 2
    'ADDR': ('90', 2),
    'CLEAR': ('B4', 2),
    'COMPR': ('A0', 2),
    'DIVR': ('9C', 2),
    'MULR': ('98', 2),
    'RMO': ('AC', 2),
    'SHIFTL': ('A4', 2),
    'SHIFTR': ('A8', 2),
    'SUBR': ('94', 2),
    'SVC': ('B0', 2),
    'TIXR': ('B8', 2),

    # Format 3/4
    'ADD': ('18', 3),
    'ADDF': ('58', 3),
    'AND': ('40', 3),
    'COMP': ('28', 3),
    'COMPF': ('88', 3),
    'DIV': ('24', 3),
    'DIVF': ('64', 3),
    'J': ('3C', 3),
    'JEQ': ('30', 3),
    'JGT': ('34', 3),
    'JLT': ('38', 3),
    'JSUB': ('48', 3),
    'LDA': ('00', 3),
    'LDB': ('68', 3),
    'LDCH': ('50', 3),
    'LDF': ('70', 3),
    'LDL': ('08', 3),
    'LDS': ('6C', 3),
    'LDT': ('74', 3),
    'LDX': ('04', 3),
    'LPS': ('D0', 3),
    'MUL': ('20', 3),
    'MULF': ('60', 3),
    'OR': ('44', 3),
    'RD': ('D8', 3),
    'RSUB': ('4C', 3),
    'SSK': ('EC', 3),
    'STA': ('0C', 3),
    'STB': ('78', 3),
    'STCH': ('54', 3),
    'STF': ('80', 3),
    'STI': ('D4', 3),
    'STL': ('14', 3),
    'STS': ('7C', 3),
    'STSW': ('E8', 3),
    'STT': ('84', 3),
    'STX': ('10', 3),
    'SUB': ('1C', 3),
    'SUBF': ('5C', 3),
    'TD': ('E0', 3),
    'TIX': ('2C', 3),
    'WD': ('DC', 3),
}

DIRECTIVES = {
    'START', 'END', 'WORD', 'BYTE', 'RESW', 'RESB', 'BASE', 'NOBASE',
    'MACRO', 'MEND', 'CSECT', 'EXTDEF', 'EXTREF', 'EQU', 'LTORG', 'ORG'
}

REGISTERS = {
    'A': 0, 'X': 1, 'L': 2, 'B': 3, 'S': 4, 'T': 5, 'F': 6, 'PC': 8, 'SW': 9
}

FORMAT2_SIGNATURES = {
    'ADDR': ('register', 'register'),
    'CLEAR': ('register',),
    'COMPR': ('register', 'register'),
    'DIVR': ('register', 'register'),
    'MULR': ('register', 'register'),
    'RMO': ('register', 'register'),
    'SHIFTL': ('register', 'shift_count'),
    'SHIFTR': ('register', 'shift_count'),
    'SUBR': ('register', 'register'),
    'SVC': ('nibble',),
    'TIXR': ('register',),
}
