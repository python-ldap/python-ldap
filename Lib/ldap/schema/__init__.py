"""
ldap.schema -  LDAPv3 schema handling

See https://www.python-ldap.org/ for details.
"""

from ldap.pkginfo import __version__  # noqa: F401

from ldap.schema.subentry import SubSchema,SCHEMA_ATTRS,SCHEMA_CLASS_MAPPING,SCHEMA_ATTR_MAPPING,urlfetch  # noqa: F401
from ldap.schema.models import *
