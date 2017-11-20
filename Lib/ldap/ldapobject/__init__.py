"""
ldap.ldapobject - wraps class _ldap.LDAPObject

See https://www.python-ldap.org/ for details.
"""

import sys
import time
from os import strerror

if __debug__:
    # Tracing is only supported in debugging mode
    import pprint
    import traceback

from ldap.pkginfo import __version__, __author__, __license__

import _ldap
import ldap
import ldap.sasl
import ldap.functions
from ldap import LDAPError

from ldap.schema import SCHEMA_ATTRS
from ldap.controls import DecodeControlTuples, RequestControlTuples


__all__ = [
    'NO_UNIQUE_ENTRY',
    'LDAPObject',
    'SimpleLDAPObject',
    'ReconnectLDAPObject',
]


class NO_UNIQUE_ENTRY(ldap.NO_SUCH_OBJECT):
    """
    Exception raised if a LDAP search returned more than entry entry
    although assumed to return a unique single search result.
    """

# For back-ward compability import ReconnectLDAPObject here
from simple import SimpleLDAPObject
from reconnect import ReconnectLDAPObject
# Used as default for ldap.open() and ldap.initialize()
LDAPObject = SimpleLDAPObject
