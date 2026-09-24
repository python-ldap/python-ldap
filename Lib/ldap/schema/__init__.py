"""
ldap.schema -  LDAPv3 schema handling

See https://www.python-ldap.org/ for details.
"""

from ldap.pkginfo import __version__  # noqa: F401, I001
from ldap.schema.subentry import (  # noqa: F401
    SCHEMA_ATTR_MAPPING,
    SCHEMA_ATTRS,
    SCHEMA_CLASS_MAPPING,
    SubSchema,
    urlfetch,
)
from ldap.schema.models import *
