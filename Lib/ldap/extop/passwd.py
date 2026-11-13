"""
ldap.extop.passwd - Classes for Password Modify extended operation
(see RFC 3062)

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, tag, univ
from pyasn1_modules.rfc2251 import LDAPString

from ldap.extop import ExtendedRequest, ExtendedResponse


class UserIdentity(LDAPString):  # type: ignore
    """
    userIdentity [0] OCTET STRING OPTIONAL
    """

    tagSet = LDAPString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))


class OldPassword(LDAPString):  # type: ignore
    """
    oldPasswd [1] OCTET STRING OPTIONAL
    """

    tagSet = LDAPString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))


class NewPassword(LDAPString):  # type: ignore
    """
    newPasswd [2] OCTET STRING OPTIONAL
    """

    tagSet = LDAPString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))


class PasswordModifyRequest(ExtendedRequest):
    """
    Password Modify extended request
    """

    __slots__ = (
        'new_password',
        'old_password',
        'user_identity',
    )
    requestName: str = '1.3.6.1.4.1.4203.1.11.1'

    class PasswdModifyRequestValue(univ.Sequence):
        """
        PasswdModifyRequestValue ::= SEQUENCE {
          userIdentity    [0]  OCTET STRING OPTIONAL,
          oldPasswd       [1]  OCTET STRING OPTIONAL,
          newPasswd       [2]  OCTET STRING OPTIONAL }
        """

        componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('userIdentity', UserIdentity()),
            namedtype.OptionalNamedType('oldPasswd', OldPassword()),
            namedtype.OptionalNamedType('newPasswd', NewPassword()),
        )

    def __init__(
        self, user_identity: str | None = None, old_password: str | None = None, new_password: str | None = None
    ) -> None:
        super().__init__(self.requestName, None)
        self.user_identity = user_identity
        self.old_password = old_password
        self.new_password = new_password

    def encodedRequestValue(self) -> bytes:
        req_value = self.PasswdModifyRequestValue()
        if self.user_identity is not None:
            req_value.setComponentByName('userIdentity', UserIdentity(self.user_identity.encode('UTF-8')))
        if self.old_password is not None:
            req_value.setComponentByName('oldPasswd', OldPassword(self.old_password.encode('UTF-8')))
        if self.new_password is not None:
            req_value.setComponentByName('newPasswd', NewPassword(self.new_password.encode('UTF-8')))
        return encoder.encode(req_value)  # type: ignore[no-any-return]


class GenPasswd(LDAPString):  # type: ignore
    """
    genPasswd       [0]     OCTET STRING OPTIONAL
    """

    tagSet = LDAPString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
    encoding = 'utf-8'


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
                GenPasswd(),
            )
        )

    def decodeResponseValue(self, value: bytes | None) -> bytes:
        passmod_resp, _ = decoder.decode(value, asn1Spec=self.PasswordModifyResponseValue())
        self.genPasswd = bytes(passmod_resp.getComponentByName('genPasswd'))
        return self.genPasswd
