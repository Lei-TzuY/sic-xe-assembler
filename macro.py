from dataclasses import dataclass
import re

from errors import AssemblyError
from pass1 import parse_line


PARAMETER_RE = re.compile(r"&[A-Za-z_][A-Za-z0-9_]*")
LOCAL_LABEL_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class MacroDefinition:
    name: str
    parameters: tuple
    body: tuple
    line_number: int


def _fail(line_number, message):
    raise AssemblyError(message, phase="macro", line_number=line_number)


def _split_arguments(operand):
    """Split comma-separated macro operands while preserving commas in quotes."""
    if operand is None or not operand.strip():
        return []

    arguments = []
    current = []
    in_quote = False

    for char in operand:
        if char == "'":
            in_quote = not in_quote
            current.append(char)
        elif char == ',' and not in_quote:
            value = ''.join(current).strip()
            if not value:
                raise ValueError("Empty macro argument")
            arguments.append(value)
            current = []
        else:
            current.append(char)

    if in_quote:
        raise ValueError("Unterminated quote in macro arguments")

    value = ''.join(current).strip()
    if not value:
        raise ValueError("Empty macro argument")
    arguments.append(value)
    return arguments


def _split_comment(line):
    """Return code/comment portions without treating periods in quotes as comments."""
    in_quote = False
    for index, char in enumerate(line):
        if char == "'":
            in_quote = not in_quote
        elif char == '.' and not in_quote and (index == 0 or line[index - 1].isspace()):
            return line[:index], line[index:]
    return line, ""


def _rewrite_code(code, replacements, local_prefix):
    """Substitute exact macro tokens outside quoted constants."""
    output = []
    index = 0
    in_quote = False

    while index < len(code):
        char = code[index]
        if char == "'":
            in_quote = not in_quote
            output.append(char)
            index += 1
            continue

        if not in_quote and char == '&':
            match = PARAMETER_RE.match(code, index)
            if match:
                token = match.group(0)
                output.append(replacements.get(token, token))
                index = match.end()
                continue

        if not in_quote and char == '$':
            match = LOCAL_LABEL_RE.match(code, index)
            if match:
                token = match.group(0)[1:]
                output.append(f"{local_prefix}{token}")
                index = match.end()
                continue

        output.append(char)
        index += 1

    return ''.join(output)


def _substitute_line(line, replacements, local_prefix):
    code, comment = _split_comment(line)
    return _rewrite_code(code, replacements, local_prefix) + comment


def _parameter_tokens(line):
    code, _ = _split_comment(line)
    tokens = []
    index = 0
    in_quote = False

    while index < len(code):
        char = code[index]
        if char == "'":
            in_quote = not in_quote
            index += 1
            continue
        if not in_quote and char == '&':
            match = PARAMETER_RE.match(code, index)
            if match:
                tokens.append(match.group(0))
                index = match.end()
                continue
        index += 1
    return tokens


def _parse_parameters(macro_name, operand, line_number):
    try:
        parameters = _split_arguments(operand)
    except ValueError as exc:
        _fail(line_number, f"Invalid parameter list for {macro_name}: {exc}")

    seen = set()
    for parameter in parameters:
        if not PARAMETER_RE.fullmatch(parameter):
            _fail(
                line_number,
                f"Macro parameter must use &NAME syntax in {macro_name}: {parameter}",
            )
        if parameter in seen:
            _fail(line_number, f"Duplicate macro parameter {parameter} in {macro_name}")
        seen.add(parameter)
    return tuple(parameters)


def _collect_definition(lines, start_index, macros):
    header = lines[start_index]
    label, opcode, operand, _ = parse_line(header)
    line_number = start_index + 1

    if opcode != 'MACRO':
        _fail(line_number, "Internal macro parser error")
    if not label:
        _fail(line_number, "MACRO requires a name label")
    if label in macros:
        _fail(line_number, f"Duplicate macro definition: {label}")

    parameters = _parse_parameters(label, operand, line_number)
    body = []
    index = start_index + 1

    while index < len(lines):
        line = lines[index]
        nested_label, nested_opcode, _, is_comment = parse_line(line)

        if not is_comment and nested_opcode == 'MACRO':
            index = _collect_definition(lines, index, macros)
            continue

        if not is_comment and nested_opcode == 'MEND':
            declared = set(parameters)
            for body_line, body_line_number in body:
                for token in _parameter_tokens(body_line):
                    if token not in declared:
                        _fail(
                            body_line_number,
                            f"Macro {label} references undeclared parameter {token}",
                        )

            macros[label] = MacroDefinition(
                name=label,
                parameters=parameters,
                body=tuple(body),
                line_number=line_number,
            )
            return index + 1

        body.append((line.rstrip('\n'), index + 1))
        index += 1

    _fail(line_number, f"Unterminated MACRO definition: {label}")


def _expand_macro(definition, label, operand, line_number, macros, counter, stack):
    if definition.name in stack:
        chain = " -> ".join(stack + [definition.name])
        _fail(line_number, f"Recursive macro expansion detected: {chain}")

    try:
        arguments = _split_arguments(operand)
    except ValueError as exc:
        _fail(line_number, f"Invalid arguments for {definition.name}: {exc}")

    expected = len(definition.parameters)
    if len(arguments) != expected:
        _fail(
            line_number,
            f"{definition.name} expects {expected} argument(s), got {len(arguments)}",
        )

    replacements = dict(zip(definition.parameters, arguments))
    counter[0] += 1
    local_prefix = f"__{definition.name}_{counter[0]:04d}_"
    expanded = [f". Macro Expansion: {definition.name}"]

    # Preserve the historical standalone invocation label so existing fixtures and
    # pass-1 label semantics remain stable.
    if label:
        expanded.append(label)

    next_stack = stack + [definition.name]
    for body_line, body_line_number in definition.body:
        substituted = _substitute_line(body_line, replacements, local_prefix)
        nested_label, nested_opcode, nested_operand, is_comment = parse_line(substituted)

        if not is_comment and nested_opcode in macros:
            expanded.extend(
                _expand_macro(
                    macros[nested_opcode],
                    nested_label,
                    nested_operand,
                    body_line_number,
                    macros,
                    counter,
                    next_stack,
                )
            )
        else:
            expanded.append(substituted)

    return expanded


def run_macro_processor(input_asm, output_asm):
    """Expand SIC/XE macros with validated parameters and deterministic local labels."""
    macros = {}
    counter = [0]

    with open(input_asm, 'r') as f_in:
        lines = f_in.readlines()

    with open(output_asm, 'w') as f_out:
        index = 0
        while index < len(lines):
            line = lines[index]
            label, opcode, operand, is_comment = parse_line(line)
            line_number = index + 1

            if not is_comment and opcode == 'MACRO':
                index = _collect_definition(lines, index, macros)
                continue

            if not is_comment and opcode == 'MEND':
                _fail(line_number, "Unexpected MEND without matching MACRO")

            if not is_comment and opcode in macros:
                expanded = _expand_macro(
                    macros[opcode],
                    label,
                    operand,
                    line_number,
                    macros,
                    counter,
                    [],
                )
                for expanded_line in expanded:
                    f_out.write(expanded_line + "\n")
            else:
                f_out.write(line)

            index += 1
