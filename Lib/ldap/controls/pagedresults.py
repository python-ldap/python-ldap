"""
ldap.controls.paged - classes for Simple Paged control
(see RFC 2696)

See https://www.python-ldap.org/ for project details.
"""

from __future__ import annotations


__all__ = ['SimplePagedResultsControl']

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import namedtype, univ
from pyasn1_modules.rfc2251 import LDAPString

from ldap.controls import KNOWN_RESPONSE_CONTROLS, RequestControl, ResponseControl


class PagedResultsControlValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('size', univ.Integer()),
        # FIXME: This should be univ.OctetString, not LDAPString()?
        namedtype.NamedType('cookie', LDAPString()),
    )


class SimplePagedResultsControl(RequestControl, ResponseControl):
    controlType = '1.2.840.113556.1.4.319'

    def __init__(
        self,
        criticality: bool = False,
        size: int = 10,
        cookie: str | bytes | None = '',
    ) -> None:
        self.criticality = criticality
        self.size = size

        if cookie is None:
            self.cookie = b''
        elif isinstance(cookie, str):
            self.cookie = cookie.encode('utf-8')
        else:
            self.cookie = cookie

    def encodeControlValue(self) -> bytes:
        pc = PagedResultsControlValue()
        pc.setComponentByName('size', univ.Integer(self.size))
        pc.setComponentByName('cookie', LDAPString(self.cookie))
        return encoder.encode(pc)  # type: ignore

    def decodeControlValue(self, encodedControlValue: bytes) -> None:
        decodedValue, _ = decoder.decode(encodedControlValue, asn1Spec=PagedResultsControlValue())
        self.size = int(decodedValue.getComponentByName('size'))
        self.cookie = bytes(decodedValue.getComponentByName('cookie'))


KNOWN_RESPONSE_CONTROLS[SimplePagedResultsControl.controlType] = SimplePagedResultsControl
