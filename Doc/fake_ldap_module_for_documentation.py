"""
A module that mocks `ldap._ldap` for the purposes of generating documentation

This module provides placeholders for the contents of `ldap._ldap`, making it
possible to generate documentation even if ldap._ldap is not compiled.
It should also make the documentation independent of which features are
available in the system OpenLDAP library.

The overly long module name will show up in AttributeError messages,
hinting that this is not the actual ldap._ldap.

See https://www.python-ldap.org/ for details.
"""

import sys

# Cause `import ldap._ldap` to import this module instead of the actual module.
sys.modules['ldap._ldap'] = sys.modules[__name__]

from constants import CONSTANTS
from pkginfo import __version__

for constant in CONSTANTS:
    globals()[constant.name] = constant

def get_option(num):
    pass

class LDAPError:
    pass
