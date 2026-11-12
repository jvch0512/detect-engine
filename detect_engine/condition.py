"""Tiny boolean expression parser for rule conditions.

Grammar:  expr := term ('or' term)* ; term := factor ('and' factor)* ;
          factor := 'not' factor | '(' expr ')' | NAME
"""
from __future__ import annotations

import re
from typing import Callable

_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z_][A-Za-z0-9_]*)")


def tokenize(text: str) -> list[str]:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = _TOKEN.match(text, pos)
        if not m:
            raise ValueError(f"Unexpected character in condition at {pos}: {text[pos:pos+10]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


def compile_condition(text: str) -> Callable[[dict[str, bool]], bool]:
    tokens = tokenize(text)
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else None

    def eat(expected=None):
        nonlocal i
        tok = peek()
        if tok is None or (expected and tok != expected):
            raise ValueError(f"Expected {expected!r} but found {tok!r}")
        i += 1
        return tok

    def parse_expr():
        node = parse_term()
        while peek() == "or":
            eat()
            left, right = node, parse_term()
            node = (lambda l, r: lambda env: l(env) or r(env))(left, right)
        return node

    def parse_term():
        node = parse_factor()
        while peek() == "and":
            eat()
            left, right = node, parse_factor()
            node = (lambda l, r: lambda env: l(env) and r(env))(left, right)
        return node

    def parse_factor():
        tok = peek()
        if tok == "not":
            eat()
            inner = parse_factor()
            return lambda env: not inner(env)
        if tok == "(":
            eat("(")
            inner = parse_expr()
            eat(")")
            return inner
        if tok is None or tok in ("and", "or", ")"):
            raise ValueError(f"Unexpected token {tok!r}")
        name = eat()
        return lambda env: bool(env.get(name, False))

    root = parse_expr()
    if i != len(tokens):
        raise ValueError(f"Trailing tokens in condition: {tokens[i:]}")
    return root


def referenced_names(text: str) -> set[str]:
    return {t for t in tokenize(text) if t not in ("and", "or", "not", "(", ")")}
