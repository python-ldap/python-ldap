"""
slapdtest - module for spawning test instances of OpenLDAP's slapd server

See https://www.python-ldap.org/ for details.
"""

__version__ = '3.4.7'

from logging.handlers import SysLogHandler  # noqa: F401
from slapdtest._slapdtest import SlapdObject, SlapdTestCase  # noqa: F401
from slapdtest._slapdtest import requires_ldapi, requires_sasl, requires_tls  # noqa: F401
from slapdtest._slapdtest import requires_init_fd  # noqa: F401
from slapdtest._slapdtest import skip_unless_ci  # noqa: F401
