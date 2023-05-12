"""
ldap.controls.ppolicy - classes for Password Policy controls
(see https://tools.ietf.org/html/draft-behera-ldap-password-policy)

See https://www.python-ldap.org/ for project details.
"""
from __future__ import annotations

__all__ = [
  'PasswordPolicyControl'
]

# Imports from python-ldap 2.4+
from ldap.controls import (
  ResponseControl, ValueLessRequestControl, KNOWN_RESPONSE_CONTROLS
)

# Imports from pyasn1
from pyasn1.type import tag,namedtype,namedval,univ,constraint
from pyasn1.codec.der import decoder


class PasswordPolicyWarning(univ.Choice):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('timeBeforeExpiration',univ.Integer().subtype(
      implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,0)
    )),
    namedtype.NamedType('graceAuthNsRemaining',univ.Integer().subtype(
      implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,1)
    )),
  )


class PasswordPolicyError(univ.Enumerated):  # type: ignore
  namedValues = namedval.NamedValues(
    ('passwordExpired',0),
    ('accountLocked',1),
    ('changeAfterReset',2),
    ('passwordModNotAllowed',3),
    ('mustSupplyOldPassword',4),
    ('insufficientPasswordQuality',5),
    ('passwordTooShort',6),
    ('passwordTooYoung',7),
    ('passwordInHistory',8),
    ('passwordTooLong',9),
  )
  subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(0,1,2,3,4,5,6,7,8,9)


class PasswordPolicyResponseValue(univ.Sequence):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType(
      'warning',
      PasswordPolicyWarning().subtype(
        implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,0)
      ),
    ),
    namedtype.OptionalNamedType(
      'error',PasswordPolicyError().subtype(
        implicitTag=tag.Tag(tag.tagClassContext,tag.tagFormatSimple,1)
      )
    ),
  )


class PasswordPolicyControl(ValueLessRequestControl,ResponseControl):
  """
  Indicates the errors and warnings about the password policy.

  Attributes
  ----------

  timeBeforeExpiration : int | None
      The time before the password expires.

  graceAuthNsRemaining : int | None
      The number of grace authentications remaining.

  error: int | None
      The password and authentication errors.
  """
  controlType = '1.3.6.1.4.1.42.2.27.8.5.1'

  def __init__(self, criticality: bool = False) -> None:
    self.criticality = criticality
    self.timeBeforeExpiration: int | None = None
    self.graceAuthNsRemaining: int | None = None
    self.error: int | None = None

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    ppolicyValue,_ = decoder.decode(encodedControlValue,asn1Spec=PasswordPolicyResponseValue())
    warning = ppolicyValue.getComponentByName('warning')
    if warning.hasValue():
      if 'timeBeforeExpiration' in warning:
        self.timeBeforeExpiration = int(
          warning.getComponentByName('timeBeforeExpiration'))
      if 'graceAuthNsRemaining' in warning:
        self.graceAuthNsRemaining = int(
          warning.getComponentByName('graceAuthNsRemaining'))

    error = ppolicyValue.getComponentByName('error')
    if error.hasValue():
      self.error = int(error)


KNOWN_RESPONSE_CONTROLS[PasswordPolicyControl.controlType] = PasswordPolicyControl
