from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from errors import AssemblyError
from pass1 import parse_line


PARAMETER_RE = re.compile(r"&[A-Za-z_][A-Za-z0-9_]*")
LOCAL_LABEL_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
MACRO_PROVENANCE_SCHEMA = "sicxe-macro-provenance-v1"


@dataclass(frozen=True)
class MacroDefinition:
    name: str
    parameters: tuple
    body: tuple
    line_number: int


def _fail(line_number, message):
    raise AssemblyError(message, phase="macro", line_number=line_number)


def default_macro_provenance_path(expanded_path):
    return str(Path(expanded_path).with_suffix(".provenance.json"))


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _fingerprint_provenance(value):
    digest = hashlib.sha256()
    digest.update(b"SICXE-MACRO-PROVENANCE-v1\0")
    digest.update(_canonical_json(value))
    return digest.hexdigest()


def _write_atomic_text(path, text):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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


def _provenance(kind, source_line, root_invocation_line, macro_stack):
    return {
        "kind": kind,
        "source_line": source_line,
        "invocation_line": root_invocation_line,
        "macro_stack": tuple(macro_stack),
    }


def _expand_macro(
    definition,
    label,
    operand,
    line_number,
    macros,
    counter,
    stack,
    trace_stack=None,
    root_invocation_line=None,
):
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
    instance = counter[0]
    local_prefix = f"__{definition.name}_{instance:04d}_"
    trace_stack = list(trace_stack or ())
    root_invocation_line = line_number if root_invocation_line is None else root_invocation_line
    scope_frame = {
        "name": definition.name,
        "instance": instance,
        "definition_line": definition.line_number,
        "invocation_line": line_number,
        "body_line": None,
    }
    expanded = [
        {
            "text": f". Macro Expansion: {definition.name}",
            "provenance": _provenance(
                "macro-marker",
                line_number,
                root_invocation_line,
                trace_stack + [scope_frame],
            ),
        }
    ]

    if label:
        expanded.append(
            {
                "text": label,
                "provenance": _provenance(
                    "macro-invocation-label",
                    line_number,
                    root_invocation_line,
                    trace_stack + [scope_frame],
                ),
            }
        )

    next_stack = stack + [definition.name]
    for body_line, body_line_number in definition.body:
        substituted = _substitute_line(body_line, replacements, local_prefix)
        nested_label, nested_opcode, nested_operand, is_comment = parse_line(substituted)
        body_frame = dict(scope_frame)
        body_frame["body_line"] = body_line_number
        line_trace = trace_stack + [body_frame]

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
                    trace_stack=line_trace,
                    root_invocation_line=root_invocation_line,
                )
            )
        else:
            expanded.append(
                {
                    "text": substituted,
                    "provenance": _provenance(
                        "macro-body",
                        body_line_number,
                        root_invocation_line,
                        line_trace,
                    ),
                }
            )

    return expanded


def _write_provenance(input_asm, output_asm, entries, provenance_path):
    source_bytes = Path(input_asm).read_bytes()
    expanded_bytes = Path(output_asm).read_bytes()
    lines = []
    for index, item in enumerate(entries, 1):
        line = dict(item)
        line["expanded_line"] = index
        lines.append(line)
    payload = {
        "schema": MACRO_PROVENANCE_SCHEMA,
        "original_source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "expanded_source_sha256": hashlib.sha256(expanded_bytes).hexdigest(),
        "lines": lines,
    }
    payload["macro_provenance_fingerprint"] = _fingerprint_provenance(payload)
    _write_atomic_text(
        provenance_path,
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
    )
    return payload


def load_macro_provenance(path, expanded_sha256=None):
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Invalid macro provenance {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("schema") != MACRO_PROVENANCE_SCHEMA:
        raise ValueError("Unsupported macro provenance schema")
    required = (
        "original_source_sha256",
        "expanded_source_sha256",
        "lines",
        "macro_provenance_fingerprint",
    )
    missing = [key for key in required if key not in payload]
    if missing:
        raise ValueError("Macro provenance missing required field(s): " + ", ".join(missing))
    unsigned = dict(payload)
    fingerprint = unsigned.pop("macro_provenance_fingerprint")
    if fingerprint != _fingerprint_provenance(unsigned):
        raise ValueError("Macro provenance fingerprint mismatch")
    if expanded_sha256 is not None and payload["expanded_source_sha256"] != expanded_sha256:
        raise ValueError("Macro provenance does not match expanded source bytes")
    for expected_line, item in enumerate(payload["lines"], 1):
        if item.get("expanded_line") != expected_line:
            raise ValueError("Macro provenance line numbers must be contiguous and ordered")
    return payload


def run_macro_processor(input_asm, output_asm, provenance_path=None):
    """Expand macros and optionally persist path-independent line provenance."""
    macros = {}
    counter = [0]
    provenance_entries = []

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
                for item in expanded:
                    f_out.write(item["text"] + "\n")
                    provenance_entries.append(item["provenance"])
            else:
                f_out.write(line)
                provenance_entries.append(
                    _provenance("source", line_number, None, ())
                )

            index += 1

    if provenance_path is not None:
        return _write_provenance(
            input_asm,
            output_asm,
            provenance_entries,
            provenance_path,
        )
    return None
