"""
types - type annotations which are shared across modules

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations
from ldap.pkginfo import __version__

from typing import MutableMapping, Optional, Sequence, Union

__all__ = [
    'LDAPModListAddEntry',
    'LDAPModListModifyEntry',
    'LDAPModListEntry',
    'LDAPAddModList',
    'LDAPModifyModList',
    'LDAPModList',
    'LDAPEntryDict',
    'LDAPControlTuple',
    'LDAPControlTuples',
    'LDAPSearchResult',
]

LDAPModListAddEntry = tuple[str, list[bytes]]
"""The type of an addition entry in a modlist."""

LDAPModListModifyEntry = tuple[
    int, str, Optional[Union[bytes, list[bytes]]]
]
"""The type of a modification entry in a modlist."""

LDAPModListEntry = Union[LDAPModListAddEntry, LDAPModListModifyEntry]
"""The type of any kind of entry in a modlist."""

LDAPAddModList = Sequence[LDAPModListAddEntry]
"""The type of an add modlist."""

LDAPModifyModList = Sequence[LDAPModListModifyEntry]
"""The type of a modify modlist."""

LDAPModList = Sequence[LDAPModListEntry]
"""The type of a mixed modlist."""

LDAPEntryDict = MutableMapping[str, list[bytes]]
"""The type used to store attribute-value mappings for a given LDAP entry
(attribute name, list of binary values)."""

LDAPControlTuple = tuple[str, str, Optional[str]]
"""The type used to store controls (type, criticality, value)."""

LDAPControlTuples = list[LDAPControlTuple]
"""The type used to store control lists."""

LDAPSearchResult = tuple[str, LDAPEntryDict]
"""The type of a search result, a tuple with a DN string and a dict of
attributes."""
