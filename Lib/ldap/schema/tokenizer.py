"""
ldap.schema.tokenizer - Low-level parsing functions for schema element strings

See https://www.python-ldap.org/ for details.
"""

import re

TOKENS_FINDALL = re.compile(
    r"(\()"           # opening parenthesis
    r"|"              # or
    r"(\))"           # closing parenthesis
    r"|"              # or
    r"([^'$()\s]+)"   # string of length >= 1 without '$() or whitespace
    r"|"              # or
    r"('.*?'(?!\w))"  # any string or empty string surrounded by single quotes
                      # except if right quote is succeeded by alphanumeric char
    r"|"              # or
    r"([^\s]+?)",     # residue, all non-whitespace strings
).findall


def split_tokens(sch_str):
    """
    Returns list of syntax elements with quotes and spaces stripped.
    """
    parts = []
    parens = 0
    for opar, cpar, unquoted, quoted, residue in TOKENS_FINDALL(sch_str):
        if unquoted:
            parts.append(unquoted)
        elif quoted:
            parts.append(quoted[1:-1])
        elif opar:
            parens += 1
            parts.append(opar)
        elif cpar:
            parens -= 1
            parts.append(cpar)
        elif residue == '$':
            if not parens:
                raise ValueError("'$' outside parenthesis in %r" % (sch_str))
        else:
            raise ValueError(residue, sch_str)
    if parens:
        raise ValueError("Unbalanced parenthesis in %r" % (sch_str))
    return parts

def extract_tokens(tkl, known_tokens):
    """
    Returns dictionary of known tokens with all values
    """
    assert tkl[0].strip() == "(" and tkl[-1].strip() == ")", ValueError(tkl)
    result = dict(known_tokens)
    i = 0
    l_len = len(tkl)
    while i < l_len:
        if tkl[i] in result:
            token = tkl[i]
            i += 1 # Consume token
            if i < l_len:
                if tkl[i] in result:
                    # non-valued
                    result[token] = (())
                elif tkl[i] == "(":
                    # multi-valued
                    i += 1 # Consume left parentheses
                    start = i
                    while i < l_len and tkl[i] != ")":
                        i += 1
                    result[token] = tuple([
                        v for v in tkl[start:i] if v != '$'
                    ])
                    i += 1 # Consume right parentheses
                else:
                    # single-valued
                    result[token] = tkl[i],
                    i += 1 # Consume single value
        else:
            i += 1 # Consume unrecognized item
    return result
