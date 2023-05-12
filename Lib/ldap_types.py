"""
types - type annotations which are shared across modules

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

from ldap.pkginfo import __version__

from ldap.schema.models import ObjectClass, AttributeType

from typing import TYPE_CHECKING, BinaryIO, Dict, List, TextIO, Tuple, Type, Sequence, cast
if TYPE_CHECKING:
  from typing_extensions import TypeAlias

__all__ = [
    'LDAPModListAddEntry',
    'LDAPModListModifyEntry',
    'LDAPModListEntry',
    'LDAPAddModList',
    'LDAPModifyModList',
    'LDAPModList',
    'LDAPEntryDict',
    'LDAPControl',
    'LDAPControls',
    'LDAPSchemaElementClass',
    'LDAPSearchResult',
]

LDAPModListAddEntry: TypeAlias = "Tuple[str, List[bytes]]"
"""The type of an addition entry in a modlist."""

LDAPModListModifyEntry: TypeAlias = "Tuple[int, str, List[bytes] | None]"
"""The type of a modification entry in a modlist."""

LDAPModListEntry: TypeAlias = "LDAPModListAddEntry | LDAPModListModifyEntry"
"""The type of any kind of entry in a modlist."""

# FIXME: Diff between what is acceptable and what is an actual variable
LDAPAddModList: TypeAlias = "Sequence[LDAPModListAddEntry]"
"""The type of an add modlist."""

LDAPModifyModList: TypeAlias = "Sequence[LDAPModListModifyEntry]"
"""The type of a modify modlist."""

LDAPModList: TypeAlias = "Sequence[LDAPModListEntry]"
"""The type of a mixed modlist."""

LDAPEntryDict: TypeAlias = "Dict[str, List[bytes]]"
"""The type used to store attribute-value mappings for a given LDAP entry (attribute name, list of binary values)."""

LDAPControl: TypeAlias = "Tuple[str, str, str | None]"
"""The type used to store controls (type, criticality, value)."""

LDAPControls: TypeAlias = "List[LDAPControl]"
"""The type used to store control lists."""

LDAPSchemaElementClass: TypeAlias = "Type[ObjectClass] | Type[AttributeType]"
"""The possible class types for a schema element."""

LDAPSearchResult: TypeAlias = "Tuple[str, LDAPEntryDict]"
"""The type of a search result, a tuple with a DN string and a dict of attributes."""
