"""
controls.py - support classes for LDAPv3 extended operations

See https://www.python-ldap.org/ for details.

Description:
The ldap.extop module provides base classes for LDAPv3 extended operations.
Each class provides support for a certain extended operation request and
response.
"""
from __future__ import annotations

from ldap.pkginfo import __version__

from typing import Any


__all__ = [
  # dds
  'RefreshRequest',
  'RefreshResponse',
  # passwd
  'PasswordModifyResponse',
]


class ExtendedRequest:
  """
  Generic base class for a LDAPv3 extended operation request

  requestName
      OID as string of the LDAPv3 extended operation request
  requestValue
      value of the LDAPv3 extended operation request
      (here it is the BER-encoded ASN.1 request value)
  """

  def __init__(self, requestName: str, requestValue: bytes) -> None:
    self.requestName = requestName
    self.requestValue = requestValue

  def __repr__(self) -> str:
    return f'{self.__class__.__name__}({self.requestName},{self.requestValue!r})'

  def encodedRequestValue(self) -> bytes:
    """
    returns the BER-encoded ASN.1 request value composed by class attributes
    set before
    """
    return self.requestValue


class ExtendedResponse:
  """
  Generic base class for a LDAPv3 extended operation response

  requestName
      OID as string of the LDAPv3 extended operation response
  encodedResponseValue
      BER-encoded ASN.1 value of the LDAPv3 extended operation response
  """

  def __init__(
    self,
    responseName: str | None,
    encodedResponseValue: bytes
  ) -> None:
    self.responseName = responseName
    self.responseValue = self.decodeResponseValue(encodedResponseValue)

  def __repr__(self) -> str:
    return f'{self.__class__.__name__}({self.responseName},{self.responseValue!r})'

  def decodeResponseValue(self, value: bytes) -> Any:
    """
    decodes the BER-encoded ASN.1 extended operation response value and
    sets the appropriate class attributes
    """
    return value


# Import sub-modules
from ldap.extop.dds import RefreshRequest, RefreshResponse
from ldap.extop.passwd import PasswordModifyResponse
