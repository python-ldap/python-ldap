"""
ldap.controls.pwdpolicy - classes for Password Policy controls
(see https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy)

See https://www.python-ldap.org/ for project details.
"""

__all__ = [
  'PasswordExpiredControl',
  'PasswordExpiringControl',
]

from ldap.controls import KNOWN_RESPONSE_CONTROLS, ResponseControl


class PasswordExpiringControl(ResponseControl):
  """
  Indicates time in seconds when password will expire
  """
  controlType = '2.16.840.1.113730.3.4.5'

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    self.gracePeriod = int(encodedControlValue)

KNOWN_RESPONSE_CONTROLS[PasswordExpiringControl.controlType] = PasswordExpiringControl


class PasswordExpiredControl(ResponseControl):
  """
  Indicates that password is expired
  """
  controlType = '2.16.840.1.113730.3.4.4'

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    self.passwordExpired = encodedControlValue == b'0'

KNOWN_RESPONSE_CONTROLS[PasswordExpiredControl.controlType] = PasswordExpiredControl
