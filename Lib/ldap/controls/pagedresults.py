"""
ldap.controls.paged - classes for Simple Paged control
(see RFC 2696)

See https://www.python-ldap.org/ for project details.
"""

__all__ = [
  'SimplePagedResultsControl'
]

# Imports from python-ldap 2.4+
import ldap.controls
from ldap.controls import RequestControl,ResponseControl,KNOWN_RESPONSE_CONTROLS

# Imports from pyasn1
from pyasn1.type import tag,namedtype,univ,constraint
from pyasn1.codec.ber import encoder,decoder
from pyasn1_modules.rfc2251 import LDAPString

from typing import Union


class PagedResultsControlValue(univ.Sequence):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('size',univ.Integer()),
    # FIXME: This should be univ.OctetString, not LDAPString()?
    namedtype.NamedType('cookie',LDAPString()),
  )


class SimplePagedResultsControl(RequestControl,ResponseControl):
  controlType = '1.2.840.113556.1.4.319'

  def __init__(
    self,
    criticality: bool = False,
    size: int = 10,
    cookie: Union[str, bytes] = '',
  ) -> None:
    self.criticality = criticality
    self.size = size

    if cookie is None:
      cookie = b''
    elif isinstance(cookie, str):
      self.cookie = cookie.encode('utf-8')
    else:
      self.cookie = cookie

  def encodeControlValue(self) -> bytes:
    pc = PagedResultsControlValue()
    pc.setComponentByName('size',univ.Integer(self.size))
    pc.setComponentByName('cookie',LDAPString(self.cookie))
    return encoder.encode(pc)  # type: ignore

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    decodedValue,_ = decoder.decode(encodedControlValue,asn1Spec=PagedResultsControlValue())
    self.size = int(decodedValue.getComponentByName('size'))
    self.cookie = bytes(decodedValue.getComponentByName('cookie'))


KNOWN_RESPONSE_CONTROLS[SimplePagedResultsControl.controlType] = SimplePagedResultsControl
