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

import importlib.util
import pathlib
import sys

from types import ModuleType

# Cause `import ldap._ldap` to import this module instead of the actual module.
sys.modules['ldap._ldap'] = sys.modules[__name__]

_lib_dir = pathlib.Path(__file__).parent.parent / 'Lib'


def _load_our_module(name: str) -> ModuleType:
    """Load a module from Lib/ without importing the intermediate packages

    Working around "circular" imports that putting `Lib/ldap` into sys.path
    would cause e.g. with ldap.ldif module.
    """
    path = (_lib_dir / name.replace('.', '/')).with_suffix('.py')
    spec = importlib.util.spec_from_file_location(
        f'_fake_ldap_bootstrap.{name}', path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONSTANTS = _load_our_module('ldap.constants').CONSTANTS
__version__ = _load_our_module('ldap.pkginfo').__version__

for constant in CONSTANTS:
    globals()[constant.name] = constant

def get_option(num):
    pass

class LDAPError:
    pass
