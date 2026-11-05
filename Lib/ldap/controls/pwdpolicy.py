"""
ldap.controls.pwdpolicy - classes for Password Policy controls
(see https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy)

See https://www.python-ldap.org/ for project details.
"""

from ldap.controls import ResponseControl


__all__ = [
    'PasswordExpiredControl',
    'PasswordExpiringControl',
]


class PasswordExpiringControl(ResponseControl):
    """
    Indicates time in seconds when password will expire
    """

    controlType = '2.16.840.1.113730.3.4.5'

    def decode(self, value: bytes) -> None:
        self.gracePeriod = int(value)


class PasswordExpiredControl(ResponseControl):
    """
    Indicates that password is expired
    """

    controlType = '2.16.840.1.113730.3.4.4'

    def decode(self, value: bytes) -> None:
        self.passwordExpired = value == b'0'
