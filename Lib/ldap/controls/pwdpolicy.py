# -*- coding: utf-8 -*-
"""
ldap.controls.pwdpolicy - classes for Password Policy controls
(see http://tools.ietf.org/html/draft-vchu-ldap-pwd-policy)

See http://www.python-ldap.org/ for project details.

$Id: pwdpolicy.py,v 1.1 2012/02/21 16:51:55 stroeder Exp $
"""

__all__ = [
  'ExpirationWarningControl'
]

# Imports from python-ldap 2.4+
import ldap.controls
from ldap.controls import RequestControl,ResponseControl,ValueLessRequestControl,KNOWN_RESPONSE_CONTROLS


class PasswordExpiringControl(OctetStringInteger):
  """
  Indicates time in seconds when password will expire
  """
  controlType = '2.16.840.1.113730.3.4.5'

  def decodeControlValue(self,encodedControlValue):
    self.gracePeriod = struct.unpack('!Q',encodedControlValue)[0]

KNOWN_RESPONSE_CONTROLS[PasswordExpiringControl.controlType] = PasswordExpiringControl


class PasswordExpiredControl(ResponseControl):
  """
  Indicates that password is expired
  """
  controlType = '2.16.840.1.113730.3.4.4'

  def decodeControlValue(self,encodedControlValue):
    self.passwordExpired = encodedControlValue=='0'

KNOWN_RESPONSE_CONTROLS[PasswordExpiredControl.controlType] = PasswordExpiredControl
