"""
ldap.schema -  LDAPv3 schema handling

See https://www.python-ldap.org/ for details.
"""
from ldap.pkginfo import __version__

from ldap.schema.subentry import SubSchema,SCHEMA_ATTRS,SCHEMA_CLASS_MAPPING,SCHEMA_ATTR_MAPPING,urlfetch
from ldap.schema.models import *

from typing import TYPE_CHECKING, Mapping, Tuple
if TYPE_CHECKING:
    from typing_extensions import TypeAlias


__all__ = [
    'LDAPTokenDictValue',
    'LDAPTokenValue',
    'LDAPTokenDict',
    'SCHEMA_ATTRS',
]

LDAPTokenDictValue: TypeAlias = "Tuple[()] | Tuple[str, ...]"
"""The kind of values which may be found in a token dict."""

LDAPTokenValue: TypeAlias = "Tuple[()] | Tuple[str, ...]"
"""The kind of values which may be found in a token dict."""

LDAPTokenDict: TypeAlias = "Mapping[str, LDAPTokenDictValue]"
"""The type of the dict used to keep track of tokens while parsing schema (Mapping because of variance)."""
