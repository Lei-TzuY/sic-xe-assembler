from dataclasses import dataclass


@dataclass(frozen=True)
class ExpressionValue:
    value: int
    relocatable: bool


@dataclass(frozen=True)
class LinkExpressionValue:
    """An object-field value plus the relocation terms the linker must apply."""

    value: int
    local_relocation_factor: int
    external_terms: tuple


@dataclass(frozen=True)
class _AlgebraValue:
    value: int
    relocation_factor: int = 0
    external_terms: tuple = ()


def parse_integer(token):
    text = token.strip()
    if text.lower().startswith('0x'):
        return int(text, 16)
    if text.lower().startswith('-0x'):
        return -int(text[1:], 16)
    if text.lower().startswith('+0x'):
        return int(text[1:], 16)
    return int(text, 10)


def _tokenize(expression):
    text = expression or ""
    tokens = []
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace():
            index += 1
            continue
        if char in "+-*/()":
            tokens.append(char)
            index += 1
            continue
        if char.isdigit():
            start = index
            if text.startswith(("0x", "0X"), index):
                index += 2
                hex_start = index
                while index < len(text) and text[index] in "0123456789abcdefABCDEF":
                    index += 1
                if index == hex_start:
                    raise ValueError(f"Invalid hexadecimal integer in expression: {expression}")
            else:
                while index < len(text) and text[index].isdigit():
                    index += 1
            tokens.append(text[start:index])
            continue
        if char.isalpha() or char in "_$":
            start = index
            index += 1
            while index < len(text) and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            tokens.append(text[start:index])
            continue
        raise ValueError(f"Invalid character {char!r} in expression: {expression}")

    if not tokens:
        raise ValueError("Expression is required")
    return tuple(tokens)


def _combine_additive(left, right, sign):
    return _AlgebraValue(
        value=left.value + sign * right.value,
        relocation_factor=left.relocation_factor + sign * right.relocation_factor,
        external_terms=left.external_terms
        + tuple((term_sign * sign, symbol) for term_sign, symbol in right.external_terms),
    )


def _negate(value):
    return _AlgebraValue(
        value=-value.value,
        relocation_factor=-value.relocation_factor,
        external_terms=tuple((-sign, symbol) for sign, symbol in value.external_terms),
    )


def _require_absolute_binary(left, right, operator):
    if (
        left.relocation_factor != 0
        or right.relocation_factor != 0
        or left.external_terms
        or right.external_terms
    ):
        raise ValueError(
            f"Operator {operator} requires absolute operands; relocatable/external terms cannot be multiplied or divided"
        )


def _truncating_division(left, right):
    if right == 0:
        raise ValueError("Division by zero in expression")
    quotient = abs(left) // abs(right)
    return -quotient if (left < 0) != (right < 0) else quotient


class _ExpressionParser:
    def __init__(self, expression, resolve_primary):
        self.expression = expression
        self.tokens = _tokenize(expression)
        self.index = 0
        self.resolve_primary = resolve_primary

    def _peek(self):
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def _take(self):
        token = self._peek()
        if token is not None:
            self.index += 1
        return token

    def parse(self):
        result = self._parse_additive()
        extra = self._peek()
        if extra is not None:
            raise ValueError(
                f"Unexpected token {extra!r} in expression: {self.expression}"
            )
        return result

    def _parse_additive(self):
        value = self._parse_multiplicative()
        while self._peek() in ("+", "-"):
            operator = self._take()
            right = self._parse_multiplicative()
            value = _combine_additive(value, right, 1 if operator == "+" else -1)
        return value

    def _parse_multiplicative(self):
        value = self._parse_unary()
        while self._peek() in ("*", "/"):
            operator = self._take()
            right = self._parse_unary()
            _require_absolute_binary(value, right, operator)
            if operator == "*":
                value = _AlgebraValue(value.value * right.value)
            else:
                value = _AlgebraValue(_truncating_division(value.value, right.value))
        return value

    def _parse_unary(self):
        token = self._peek()
        if token in ("+", "-"):
            self._take()
            value = self._parse_unary()
            return value if token == "+" else _negate(value)
        return self._parse_primary()

    def _parse_primary(self):
        token = self._take()
        if token is None:
            raise ValueError(f"Missing term in expression: {self.expression}")
        if token == "(":
            value = self._parse_additive()
            if self._take() != ")":
                raise ValueError(f"Missing ')' in expression: {self.expression}")
            return value
        if token == ")":
            raise ValueError(f"Unexpected ')' in expression: {self.expression}")
        if token in ("+", "-", "/"):
            raise ValueError(f"Missing term before {token!r} in expression: {self.expression}")
        return self.resolve_primary(token)


def _evaluate(expression, resolve_primary):
    return _ExpressionParser(expression, resolve_primary).parse()


def evaluate_expression(expression, current_location, symtab, relocatable_symbols):
    """Evaluate local SIC/XE expressions with precedence and relocation algebra.

    Supported syntax includes parentheses, unary +/- and binary +, -, *, /.  The
    multiplicative operators are intentionally restricted to absolute operands;
    relocatable terms may only participate in additive algebra. Division uses
    integer truncation toward zero.
    """
    relocatable_symbols = set(relocatable_symbols)

    def resolve(token):
        if token == '*':
            return _AlgebraValue(current_location, 1)
        try:
            return _AlgebraValue(parse_integer(token))
        except ValueError:
            pass
        if token not in symtab:
            raise ValueError(f"Undefined symbol {token}")
        return _AlgebraValue(
            symtab[token],
            1 if token in relocatable_symbols else 0,
        )

    result = _evaluate(expression, resolve)
    if result.relocation_factor not in (0, 1):
        raise ValueError(
            f"Illegal relocatable expression (relative term balance {result.relocation_factor}): {expression}"
        )
    return ExpressionValue(result.value, result.relocation_factor == 1)


def evaluate_link_expression(
    expression,
    current_location,
    csect_start,
    symtab,
    relocatable_symbols,
    external_symbols,
):
    """Evaluate a relocatable object-field expression with full additive syntax.

    Local relocatable values are represented section-relative plus a current-
    section relocation factor. External symbols are represented as signed M
    terms. Parentheses and unary signs may rearrange additive terms, while * and
    / remain absolute-only so object records never need scaled relocation terms.
    """
    relocatable_symbols = set(relocatable_symbols)
    external_symbols = set(external_symbols)

    def resolve(token):
        if token in external_symbols:
            return _AlgebraValue(0, 0, ((1, token),))
        if token == '*':
            return _AlgebraValue(current_location - csect_start, 1)
        try:
            return _AlgebraValue(parse_integer(token))
        except ValueError:
            pass
        if token not in symtab:
            raise ValueError(f"Undefined symbol {token}")
        if token in relocatable_symbols:
            return _AlgebraValue(symtab[token] - csect_start, 1)
        return _AlgebraValue(symtab[token])

    result = _evaluate(expression, resolve)
    if not result.external_terms and result.relocation_factor not in (0, 1):
        raise ValueError(
            f"Illegal relocatable expression (relative term balance {result.relocation_factor}): {expression}"
        )

    return LinkExpressionValue(
        result.value,
        result.relocation_factor,
        tuple(result.external_terms),
    )
