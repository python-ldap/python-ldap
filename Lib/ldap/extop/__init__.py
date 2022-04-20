"""
controls.py - support classes for LDAPv3 extended operations

See https://www.python-ldap.org/ for details.

Description:
The ldap.extop module provides base classes for LDAPv3 extended operations.
Each class provides support for a certain extended operation request and
response.
"""

from ldap import __version__
from ldap import KNOWN_EXTENDED_RESPONSES, KNOWN_INTERMEDIATE_RESPONSES

import ldap
import ldap.response

from typing import Optional

_NOTSET = object()


class ExtendedRequest:
  """
  Generic base class for a LDAPv3 extended operation request

  requestName
      OID as string of the LDAPv3 extended operation request
  requestValue
      value of the LDAPv3 extended operation request
      (here it is the BER-encoded ASN.1 request value)
  """

  def __init__(self,requestName,requestValue):
    self.requestName = requestName
    self.requestValue = requestValue

  def __repr__(self):
    return f'{self.__class__.__name__}({self.requestName},{self.requestValue})'

  def encodedRequestValue(self):
    """
    returns the BER-encoded ASN.1 request value composed by class attributes
    set before
    """
    return self.requestValue


class ExtendedResponse(ldap.response.ExtendedResult):
  """
  Generic base class for a LDAPv3 extended operation response

  responseName
      OID as string of the LDAPv3 extended operation response or None
  encodedResponseValue
      BER-encoded ASN.1 value of the LDAPv3 extended operation response
  """

  def __init_subclass__(cls):
    if not getattr(cls, 'responseName', None):
      return

    KNOWN_EXTENDED_RESPONSES.setdefault(cls.responseName, cls)

  @classmethod
  def __convert_old_api(cls, responseName_or_msgid=_NOTSET,
                        encodedResponseValue_or_msgtype=_NOTSET,
                        controls=None, *,
                        result=_NOTSET, matcheddn=_NOTSET, message=_NOTSET,
                        referrals=_NOTSET, name=None, value=None,
                        defaultClass: Optional[type['ExtendedResult']] = None,
                        msgid=_NOTSET, msgtype=_NOTSET,
                        responseName=_NOTSET, encodedResponseValue=_NOTSET,
                        **kwargs):
    """
    Implements both old and new API:
    __init__(self, responseName, encodedResponseValue)
    and
    __init__/__new__(self, msgid, msgtype, controls=None, *,
                     result, matcheddn, message, referrals,
                     defaultClass=None, **kwargs)
    """
    if responseName is not _NOTSET:
        name = responseName
        value = encodedResponseValue
        msgid = None
        msgtype = ldap.RES_EXTENDED
        result = ldap.SUCCESS.errnum
    elif responseName_or_msgid is not _NOTSET and \
            isinstance(responseName_or_msgid, (str, type(None))):
        if responseName is not _NOTSET:
            raise TypeError("responseName passed twice")
        if encodedResponseValue_or_msgtype is not _NOTSET and \
                encodedResponseValue is not _NOTSET:
            raise TypeError("encodedResponseValue passed twice")
        name = responseName = responseName_or_msgid
        value = encodedResponseValue = encodedResponseValue_or_msgtype
        msgid = None
        msgtype = ldap.RES_EXTENDED
        result = ldap.SUCCESS.errnum
    else:
        responseName = name
        encodedResponseValue = value
        if msgid is _NOTSET:
            if responseName_or_msgid is _NOTSET:
                raise TypeError("msgid parameter not provided")
            msgid = responseName_or_msgid
        if msgtype is _NOTSET:
            if encodedResponseValue_or_msgtype is _NOTSET:
                raise TypeError("msgtype parameter not provided")
            msgtype = encodedResponseValue_or_msgtype or ldap.RES_EXTENDED
        if result is _NOTSET:
            raise TypeError("result parameter not provided")
        if matcheddn is _NOTSET:
            raise TypeError("matcheddn parameter not provided")
        if message is _NOTSET:
            raise TypeError("message parameter not provided")
        if referrals is _NOTSET:
            raise TypeError("referrals parameter not provided")

    return (
        responseName, encodedResponseValue,
        (msgid, msgtype, controls),
        {'result': result,
         'matcheddn': matcheddn,
         'message': message,
         'referrals': referrals,
         'name': name,
         'value': value,
         'defaultClass': defaultClass,
         **kwargs
         }
    )

  def __new__(cls, *args, **kwargs):
    """
    Has to support both old and new API:
    __new__(cls, responseName: Optional[str],
            encodedResponseValue: Optional[bytes])
    and
    __new__(cls, msgid: int, msgtype: int, controls: Controls = None, *,
            result: int, matcheddn: str, message: str, referrals: List[str],
            defaultClass: Optional[type[ExtendedResponse]] = None,
            **kwargs)

    The old API is deprecated and will be removed in 4.0.
    """
    # TODO: retire polymorhpism when old API is removed (4.0?)
    _, _, args, kwargs = __class__.__convert_old_api(*args, **kwargs)

    return super().__new__(cls, *args, **kwargs)

  def __init__(self, *args, **kwargs):
    """
    Supports both old and new API:
    __init__(self, responseName: Optional[str],
             encodedResponseValue: Optional[bytes])
    and
    __init__(self, msgid: int, msgtype: int, controls: Controls = None, *,
             result: int, matcheddn: str, message: str, referrals: List[str],
             defaultClass: Optional[type[ExtendedResponse]] = None,
             **kwargs)

    The old API is deprecated and will be removed in 4.0.
    """
    # TODO: retire polymorhpism when old API is removed (4.0?)
    responseName, encodedResponseValue, _, _ = \
        __class__.__convert_old_api(*args, **kwargs)

    self.responseName = responseName
    if encodedResponseValue is not None:
        self.responseValue = self.decodeResponseValue(encodedResponseValue)
    else:
        self.responseValue = None

  def decodeResponseValue(self,value):
    """
    decodes the BER-encoded ASN.1 extended operation response value and
    sets the appropriate class attributes
    """
    return value


class IntermediateResponse(ldap.response.IntermediateResponse):
  """
  Generic base class for a LDAPv3 intermediate response message

  responseName
      OID as string of the LDAPv3 intermediate response message or None
  encodedResponseValue
      BER-encoded ASN.1 value of the LDAPv3 intermediate response message
  """

  def __init_subclass__(cls):
    if not getattr(cls, 'responseName', None):
      return

    KNOWN_INTERMEDIATE_RESPONSES.setdefault(cls.responseName, cls)

  def decodeResponseValue(self,value):
    """
    decodes the BER-encoded ASN.1 extended operation response value and
    sets the appropriate class attributes
    """
    return value


# Import sub-modules
from ldap.extop.dds import *
from ldap.extop.passwd import PasswordModifyResponse
