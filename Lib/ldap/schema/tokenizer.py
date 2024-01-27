"""
ldap.schema.tokenizer - Low-level parsing functions for schema element strings

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

import re
import warnings

from typing import Any, Mapping, Union

LDAPTokenDictValue = Union[tuple[()], tuple[str, ...]]
"""The kind of values which may be found in a token dict."""

LDAPTokenDict = Mapping[str, LDAPTokenDictValue]
"""The type of the dict used to keep track of tokens while parsing schema
(Mapping because of variance)."""

TOKENS_FINDALL = re.compile(
    r"(\()"           # opening parenthesis
    r"|"              # or
    r"(\))"           # closing parenthesis
    r"|"              # or
    r"([^'$()\s]+)"   # string of length >= 1 without '$() or whitespace
    r"|"              # or
    r"('(?:[^'\\]|\\.)*'(?!\w))"
                      # any string or empty string surrounded by unescaped
                      # single quotes except if right quote is succeeded by
                      # alphanumeric char
    r"|"              # or
    r"([^\s]+?)",     # residue, all non-whitespace strings
).findall

UNESCAPE_PATTERN = re.compile(r"\\(.)")


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
                raise ValueError("'$' outside parenthesis in %r" % (s))
        else:
            raise ValueError(residue, s)
    if parens:
        raise ValueError("Unbalanced parenthesis in %r" % (s))
    return parts


def parse_tokens(
    tokens: list[str],
    known_tokens: list[str]
) -> tuple[str, LDAPTokenDict]:
    """
    Process a list of tokens and return a dictionary of known tokens with all
    values

    Arguments:

    tokens
        A list of tokens to process.

    known_tokens
        A list of known tokens, unknown tokens will be ignored

    Returns:

    A tuple of the oid of the schema element and a dictionary mapping the
    found tokens to their value(s).
    """

    assert len(tokens) > 2, ValueError(tokens)
    assert tokens[0].strip() == "(", ValueError(tokens)
    assert tokens[-1].strip() == ")", ValueError(tokens)

    oid = tokens[1]
    result = {}

    i = 2
    while i < len(tokens):
        token = tokens[i]
        i += 1

        if token not in known_tokens:
            # Skip unrecognized token
            continue

        if i >= len(tokens):
            break

        next_token = tokens[i]

        if next_token in known_tokens:
            # non-valued
            value: LDAPTokenDictValue = (())

        elif next_token == "(":
            # multi-valued
            i += 1 # Consume left parentheses
            start = i
            while i < len(tokens) and tokens[i] != ")":
                i += 1
            value = tuple(filter(lambda v: v != '$', tokens[start:i]))
            i += 1 # Consume right parentheses

        else:
            # single-valued
            value = (next_token,)
            i += 1 # Consume single value

        result[token] = value

    return oid, result


def extract_tokens(
    l: list[str],
    known_tokens: Mapping[str, Any],
) -> dict[str, Any]:
    """
    Returns dictionary of known tokens with all values

    Deprecated since 3.5.0, use parse_tokens() instead. Unlike
    parse_tokens(), the returned dict is pre-populated with the defaults
    from known_tokens and the OID is not returned.
    """
    warnings.warn(
        'ldap.schema.tokenizer.extract_tokens() is deprecated, '
        'use parse_tokens() instead',
        category=DeprecationWarning,
        stacklevel=2,
    )
    result = dict(known_tokens)
    if len(l) > 2:
        result.update(parse_tokens(l, list(known_tokens))[1])
    else:
        assert l[0].strip() == "(" and l[-1].strip() == ")", ValueError(l)
    return result
