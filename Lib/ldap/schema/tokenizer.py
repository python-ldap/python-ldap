"""
ldap.schema.tokenizer - Low-level parsing functions for schema element strings

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Union

from ldap._types import TypeAlias


LDAPTokenDictValue: TypeAlias = Union[tuple[()], tuple[str, ...]]
"""The kind of values which may be found in a token dict."""

LDAPTokenDict: TypeAlias = Mapping[str, LDAPTokenDictValue]
"""The type of the dict used to keep track of tokens while parsing schema
(Mapping because of variance)."""

TOKENS_FINDALL = re.compile(
    r'(\()'  # opening parenthesis
    r'|'  # or
    r'(\))'  # closing parenthesis
    r'|'  # or
    r"([^'$()\s]+)"  # string of length >= 1 without '$() or whitespace
    r'|'  # or
    r"('(?:[^'\\]|\\.)*'(?!\w))"
    # any string or empty string surrounded by unescaped
    # single quotes except if right quote is succeeded by
    # alphanumeric char
    r'|'  # or
    r'([^\s]+?)',  # residue, all non-whitespace strings
).findall

UNESCAPE_PATTERN = re.compile(r'\\(.)')


def split_tokens(s: str) -> list[str]:
    """
    Returns list of syntax elements with quotes and spaces stripped.
    """
    parts = []
    parens = 0
    for opar, cpar, unquoted, quoted, residue in TOKENS_FINDALL(s):
        if unquoted:
            parts.append(unquoted)
        elif quoted:
            parts.append(UNESCAPE_PATTERN.sub(r'\1', quoted[1:-1]))
        elif opar:
            parens += 1
            parts.append(opar)
        elif cpar:
            parens -= 1
            parts.append(cpar)
        elif residue == '$':
            if not parens:
                raise ValueError(f"'$' outside parenthesis in {s!r}")
        else:
            raise ValueError(residue, s)
    if parens:
        raise ValueError(f'Unbalanced parenthesis in {s!r}')
    return parts


def extract_tokens(
    tokens: list[str],
    known_tokens: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Return a dictionary of known tokens with their parsed values.

    The dictionary is initialized with the provided default values.
    Unknown tokens are ignored.
    """
    if len(tokens) < 3 or tokens[0] != '(' or tokens[-1] != ')':
        raise ValueError(tokens)

    result = dict(known_tokens)
    i = 2
    end = len(tokens) - 1

    while i < end:
        token = tokens[i]
        i += 1
        next_token = tokens[i]

        if token not in result:
            # Skip unrecognized token
            continue

        value: LDAPTokenDictValue
        if i >= end or next_token in result:
            # non-valued token
            value = ()
        elif next_token == '(':
            # multi-valued token
            i += 1  # Consume left parentheses
            start = i

            while i < end and tokens[i] != ')':
                i += 1

            value = tuple(value for value in tokens[start:i] if value != '$')
            i += 1  # Consume right parentheses
        else:
            # single-valued token
            value = (next_token,)
            i += 1  # Consume single value

        result[token] = value

    return result
