"""
slapdtest - module for spawning test instances of OpenLDAP's slapd server

See https://www.python-ldap.org/ for details.
"""

__version__ = '3.4.7'

from logging.handlers import SysLogHandler  # noqa: F401

from slapdtest._slapdtest import (  # noqa: F401  # noqa: F401
    SlapdObject,
    SlapdTestCase,
    requires_init_fd,
    requires_ldapi,
    requires_sasl,
    requires_tls,
    skip_unless_ci,
)
