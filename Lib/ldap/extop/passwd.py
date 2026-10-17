"""
ldap.extop.passwd - Classes for Password Modify extended operation
(see RFC 3062)

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

from pyasn1.codec.der import decoder
from pyasn1.type import namedtype, tag, univ

from ldap.extop import ExtendedResponse


class PasswordModifyResponse(ExtendedResponse):
    """
    Password Modify extended response
    """

    responseName = None

    class PasswordModifyResponseValue(univ.Sequence):
        """
        PasswdModifyResponseValue ::= SEQUENCE {
           genPasswd [0] OCTET STRING OPTIONAL }
        """

        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType(
                'genPasswd',
                univ.OctetString().subtype(  # type: ignore[no-untyped-call]
                    implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
                ),
            )
        )

    def decodeResponseValue(self, value: bytes | None) -> bytes:
        passmod_resp, _ = decoder.decode(value, asn1Spec=self.PasswordModifyResponseValue())
        self.genPasswd = bytes(passmod_resp.getComponentByName('genPasswd'))
        return self.genPasswd
