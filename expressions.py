from dataclasses import dataclass


@dataclass(frozen=True)
class ExpressionValue:
    value: int
    relocatable: bool


def parse_integer(token):
    text = token.strip()
    if text.lower().startswith('0x'):
        return int(text, 16)
    if text.lower().startswith('-0x'):
        return -int(text[1:], 16)
    return int(text, 10)


def evaluate_expression(expression, current_location, symtab, relocatable_symbols):
    """Evaluate SYMBOL/*/integer optionally followed by a numeric +/- offset."""
    if not expression:
        raise ValueError("Expression is required")

    text = ''.join(expression.split())
    if not text:
        raise ValueError("Expression is required")

    try:
        return ExpressionValue(parse_integer(text), False)
    except ValueError:
        pass

    operator_index = None
    for index, char in enumerate(text[1:], 1):
        if char in '+-':
            operator_index = index
            break

    if operator_index is None:
        base_text = text
        offset = 0
    else:
        base_text = text[:operator_index]
        offset_text = text[operator_index + 1:]
        if not offset_text:
            raise ValueError(f"Missing offset in expression: {expression}")
        try:
            offset = parse_integer(offset_text)
        except ValueError as exc:
            raise ValueError(f"Expression offset must be an integer: {expression}") from exc
        if text[operator_index] == '-':
            offset = -offset

    if base_text == '*':
        base = ExpressionValue(current_location, True)
    elif base_text in symtab:
        base = ExpressionValue(
            symtab[base_text],
            base_text in relocatable_symbols,
        )
    else:
        raise ValueError(f"Undefined symbol {base_text}")

    return ExpressionValue(base.value + offset, base.relocatable)
