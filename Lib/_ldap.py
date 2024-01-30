# Keep names available pre-3.5.0 around
"""
Stub module exposing what used to be available at _ldap.

It will go away evetually, use ldap._ldap if you need it.
"""

# FIXME: raise a warning in 4.0, remove this in 5.0
from ldap._ldap import *
from ldap._ldap import (
        __version__, __license__, __author__,
)
# _VENDOR_VERSION_RUNTIME is missing above, this is intentional as it never
# existed in a released version, import it from ldap._ldap
