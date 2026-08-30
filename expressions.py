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
    if text.lower().startswith('+0x'):
        return int(text[1:], 16)
    return int(text, 10)


def _split_terms(expression):
    """Split a simple SIC/XE additive expression into signed terms."""
    text = ''.join(expression.split())
    if not text:
        raise ValueError("Expression is required")

    terms = []
    index = 0
    sign = 1
    if text[0] in '+-':
        sign = -1 if text[0] == '-' else 1
        index = 1
        if index == len(text):
            raise ValueError(f"Missing term in expression: {expression}")

    start = index
    while index <= len(text):
        if index == len(text) or text[index] in '+-':
            token = text[start:index]
            if not token:
                raise ValueError(f"Missing term in expression: {expression}")
            terms.append((sign, token))
            if index == len(text):
                break
            sign = -1 if text[index] == '-' else 1
            start = index + 1
        index += 1

    return terms


def _resolve_term(token, current_location, symtab, relocatable_symbols):
    if token == '*':
        return current_location, 1

    try:
        return parse_integer(token), 0
    except ValueError:
        pass

    if token not in symtab:
        raise ValueError(f"Undefined symbol {token}")

    return symtab[token], 1 if token in relocatable_symbols else 0


def evaluate_expression(expression, current_location, symtab, relocatable_symbols):
    """Evaluate additive SIC/XE expressions and enforce relocation algebra.

    Absolute terms contribute no relocation factor; relocatable symbols and `*`
    contribute +1 or -1 according to their sign. A final relocation factor of 0
    is absolute and +1 is relocatable. Any other factor is illegal.
    """
    if not expression:
        raise ValueError("Expression is required")

    value = 0
    relocation_factor = 0
    for sign, token in _split_terms(expression):
        term_value, term_factor = _resolve_term(
            token,
            current_location,
            symtab,
            relocatable_symbols,
        )
        value += sign * term_value
        relocation_factor += sign * term_factor

    if relocation_factor not in (0, 1):
        raise ValueError(
            f"Illegal relocatable expression (relative term balance {relocation_factor}): {expression}"
        )

    return ExpressionValue(value, relocation_factor == 1)
