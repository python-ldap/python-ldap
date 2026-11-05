"""
ldap.controls.simple - classes for some very simple LDAP controls

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

import struct

from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ

import ldap
from ldap.controls import LDAPControl, RequestControl, ResponseControl


__all__ = [
    'AuthorizationIdentityRequestControl',
    'AuthorizationIdentityResponseControl',
    'BooleanControl',
    'GetEffectiveRightsControl',
    'ManageDSAITControl',
    'OctetStringInteger',
    'ProxyAuthzControl',
    'RelaxRulesControl',
    'SubentriesControl',
    'ValueLessRequestControl',
]


class ValueLessRequestControl(RequestControl):
    """
    Base class for controls without a controlValue.
    The presence of the control in a LDAPv3 request changes the server's
    behaviour when processing the request simply based on the controlType.

    controlType
      OID of the request control
    criticality
      criticality request control
    """

    def __init__(self, controlType: str | None = None, criticality: bool = False) -> None:
        super().__init__(controlType, criticality)

    def encode(self) -> None:
        return None


class OctetStringInteger(LDAPControl):
    """
    Base class with controlValue being unsigend integer values

    integerValue
      Integer to be sent as OctetString
    """

    def __init__(
        self, controlType: str | None = None, criticality: bool = False, integerValue: int | None = None
    ) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.integerValue = integerValue

    def encode(self) -> bytes:
        return struct.pack('!Q', self.integerValue)

    def decode(self, value: bytes) -> None:
        self.integerValue = struct.unpack('!Q', value)[0]


class BooleanControl(LDAPControl):
    """
    Base class for simple request controls with boolean control value.

    Constructor argument and class attribute:

    booleanValue
      Boolean (True/False or 1/0) which is the boolean controlValue.
    """

    def __init__(self, controlType: str | None = None, criticality: bool = False, booleanValue: bool = False) -> None:
        self.controlType = controlType
        self.criticality = criticality
        self.booleanValue = booleanValue

    def encode(self) -> bytes:
        return encoder.encode(self.booleanValue, asn1Spec=univ.Boolean())  # type: ignore

    def decode(self, value: bytes) -> None:
        decodedValue, _ = decoder.decode(value, asn1Spec=univ.Boolean())
        self.booleanValue = bool(int(decodedValue))


class ManageDSAITControl(ValueLessRequestControl):
    """
    Manage DSA IT Control
    """

    controlType = ldap.CONTROL_MANAGEDSAIT

    def __init__(self, criticality: bool = False) -> None:
        super().__init__(self.controlType, criticality)


class RelaxRulesControl(ValueLessRequestControl):
    """
    Relax Rules Control
    """

    controlType = ldap.CONTROL_RELAX

    def __init__(self, criticality: bool = False) -> None:
        super().__init__(self.controlType, criticality)


class ProxyAuthzControl(RequestControl):
    """
    Proxy Authorization Control

    authzId
      string containing the authorization ID indicating the identity
      on behalf which the server should process the request
    """

    controlType = ldap.CONTROL_PROXY_AUTHZ

    def __init__(self, criticality: bool, authzId: str) -> None:
        if isinstance(authzId, str):
            encoded = authzId.encode('utf-8')
        else:
            encoded = authzId
        super().__init__(self.controlType, criticality, encoded)


class AuthorizationIdentityRequestControl(ValueLessRequestControl):
    """
    Authorization Identity Request and Response Controls
    """

    controlType = '2.16.840.1.113730.3.4.16'

    def __init__(self, criticality: bool) -> None:
        super().__init__(self.controlType, criticality)


class AuthorizationIdentityResponseControl(ResponseControl):
    """
    Authorization Identity Request and Response Controls

    Class attributes:

    authzId
      decoded authorization identity
    """

    controlType = '2.16.840.1.113730.3.4.15'

    def decode(self, value: bytes) -> None:
        self.authzId = value.decode('utf-8')


class GetEffectiveRightsControl(RequestControl):
    """
    Get Effective Rights Control
    """

    controlType = '1.3.6.1.4.1.42.2.27.9.5.2'

    def __init__(self, criticality: bool, authzId: str | None = None) -> None:
        encoded: bytes | None
        if isinstance(authzId, str):
            encoded = authzId.encode('utf-8')
        else:
            encoded = authzId
        super().__init__(self.controlType, criticality, encoded)


class SubentriesControl(BooleanControl):
    """
    Subentries Control (RFC 3672)
    https://tools.ietf.org/html/rfc3672#section-3
    """

    controlType: str = '1.3.6.1.4.1.4203.1.10.1'

    def __init__(self, criticality: bool = False, value: bool = False):
        super().__init__(self.controlType, criticality, value)
