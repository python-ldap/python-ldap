# modules without any tests

import os

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

# FIXME: Remove in 5.0
from _ldap import (
    __version__,  # noqa: F401
    initialize,  # noqa: F401
    LDAPError,  # noqa: F401
    MOD_ADD,  # noqa: F401
    OPT_URI,  # noqa: F401
    SUCCESS,  # noqa: F401
)

import ldap.controls.deref  # noqa: F401
import ldap.controls.openldap  # noqa: F401
import ldap.controls.ppolicy  # noqa: F401
import ldap.controls.psearch  # noqa: F401
import ldap.controls.pwdpolicy  # noqa: F401
import ldap.controls.readentry  # noqa: F401
import ldap.controls.sessiontrack  # noqa: F401
import ldap.controls.sss  # noqa: F401
import ldap.controls.vlv  # noqa: F401
import ldap.constants  # noqa: F401
import ldap.logger  # noqa: F401
import ldap.resiter  # noqa: F401
import ldap.syncrepl  # noqa: F401
