"""
filters.py - misc stuff for handling LDAP filter strings (see RFC2254)

See https://www.python-ldap.org/ for details.

Compatibility:
- Tested with Python 2.0+
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from ldap import _ldap
from ldap.functions import strf_secs
from ldap.pkginfo import __version__  # noqa: F401


def escape_filter_chars(assertion_value: str, escape_mode: int = 0) -> str:
    """
    Replace all special characters found in assertion_value
    by quoted notation.

    escape_mode
        If 0 only special chars mentioned in RFC 4515 are escaped.
        If 1 all NON-ASCII chars are escaped.
        If 2 all chars are escaped.
    """
    if not isinstance(assertion_value, str):
        raise TypeError('assertion_value must be of type str.')
    if escape_mode:
        r = []
        if escape_mode == 1:
            for c in assertion_value:
                if c < '0' or c > 'z' or c in '\\*()':
                    c = f'\\{ord(c):02x}'
                r.append(c)
        elif escape_mode == 2:
            for c in assertion_value:
                r.append(f'\\{ord(c):02x}')
        else:
            raise ValueError('escape_mode must be 0, 1 or 2.')
        s = ''.join(r)
    else:
        s = assertion_value.replace('\\', r'\5c')
        s = s.replace(r'*', r'\2a')
        s = s.replace(r'(', r'\28')
        s = s.replace(r')', r'\29')
        s = s.replace('\x00', r'\00')
    return s


def filter_format(filter_template: str, assertion_values: Iterable[str]) -> str:
    """
    filter_template
          String containing %s as placeholder for assertion values.
    assertion_values
          List or tuple of assertion values. Length must match
          count of %s in filter_template.
    """
    return filter_template % tuple(escape_filter_chars(v) for v in assertion_values)


def time_span_filter(
    filterstr: str = '',
    from_timestamp: float = 0,
    until_timestamp: float | None = None,
    delta_attr: str = 'modifyTimestamp',
) -> str:
    """
    If last_run_timestr is non-zero filterstr will be extended
    """
    if until_timestamp is None:
        until_timestamp = time.time()
        if from_timestamp < 0:
            from_timestamp = until_timestamp + from_timestamp
    if from_timestamp > until_timestamp:
        raise ValueError(
            f'from_timestamp {from_timestamp!r} must not be greater than until_timestamp {until_timestamp!r}'
        )
    return f'(&{filterstr}({delta_attr}>={strf_secs(from_timestamp)})(!({delta_attr}>={strf_secs(until_timestamp)})))'
    # end of time_span_filter()


def is_filter(ldap_filter: str) -> bool:
    """Returns True if `ldap_filter' can be parsed as a valid LDAP filter, otherwise False is returned."""
    return _ldap.is_filter(ldap_filter)
