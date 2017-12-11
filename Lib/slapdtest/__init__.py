# -*- coding: utf-8 -*-
"""
slapdtest - module for spawning test instances of OpenLDAP's slapd server

See https://www.python-ldap.org/ for details.
"""

__version__ = '3.0.0b2'

from slapdtest._slapdtest import SlapdObject, SlapdTestCase, SysLogHandler
from slapdtest._slapdtest import skip_unless_ci, requires_sasl, requires_tls
