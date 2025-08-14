"""
controls.py - support classes for LDAP controls

See https://www.python-ldap.org/ for details.

Description:
The ldap.controls module provides LDAPControl classes.
Each class provides support for a certain control.
"""

from ldap.pkginfo import __version__

import ldap._ldap as _ldap
assert _ldap.__version__==__version__, \
       ImportError(f'ldap {__version__} and _ldap {_ldap.__version__} version mismatch!')

import ldap

from pyasn1.error import PyAsn1Error

from typing import Dict, List, Tuple, Type, Optional


__all__ = [
  'KNOWN_RESPONSE_CONTROLS',
  # Classes
  'AssertionControl',
  'BooleanControl',
  'LDAPControl',
  'ManageDSAITControl',
  'MatchedValuesControl',
  'RelaxRulesControl',
  'RequestControl',
  'ResponseControl',
  'SimplePagedResultsControl',
  'ValueLessRequestControl',
  # Functions
  'RequestControlTuples',
  'DecodeControlTuples',
]

# response control OID to class registry
KNOWN_RESPONSE_CONTROLS: Dict[str, Type["ResponseControl"]] = {}


class RequestControl:
  """
  Base class for all request controls

  controlType
      OID as string of the LDAPv3 extended request control
  criticality
      sets the criticality of the control (boolean)
  encodedControlValue
      control value of the LDAPv3 extended request control
      (here it is the BER-encoded ASN.1 control value)
  """

  def __init__(
    self,
    controlType: Optional[str] = None,
    criticality: bool = False,
    encodedControlValue: Optional[bytes] = None
  ) -> None:
    self.controlType = controlType
    self.criticality = criticality
    self.encodedControlValue = encodedControlValue

  def encodeControlValue(self) -> Optional[bytes]:
    """
    sets class attribute encodedControlValue to the BER-encoded ASN.1
    control value composed by class attributes set before
    """
    return self.encodedControlValue


class ResponseControl:
  """
  Base class for all response controls

  controlType
      OID as string of the LDAPv3 extended response control
  criticality
      sets the criticality of the received control (boolean)
  """

  def __init__(
    self,
    controlType: Optional[str] = None,
    criticality: bool = False
  ) -> None:
    self.controlType = controlType
    self.criticality = criticality

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    """
    decodes the BER-encoded ASN.1 control value and sets the appropriate
    class attributes
    """
    # The type hint can be removed once class LDAPControl is removed
    self.encodedControlValue: Optional[bytes] = encodedControlValue


class LDAPControl(RequestControl, ResponseControl):
  """
  Base class for combined request/response controls mainly
  for backward-compatibility to python-ldap 2.3.x
  """

  def __init__(
    self,
    controlType: Optional[str] = None,
    criticality: bool = False,
    controlValue: Optional[str] = None,
    encodedControlValue: Optional[bytes] = None
  ) -> None:
    self.controlType = controlType
    self.criticality = criticality
    self.controlValue = controlValue
    self.encodedControlValue = encodedControlValue


def RequestControlTuples(
    ldapControls: Optional[List[RequestControl]]
  ) -> Optional[List[Tuple[Optional[str], bool, Optional[bytes]]]]:
  """
  Return list of readily encoded 3-tuples which can be directly
  passed to C module _ldap

  ldapControls
      sequence-type of RequestControl objects
  """
  if ldapControls is None:
    return None
  else:
    result = [
      (c.controlType,c.criticality,c.encodeControlValue())
      for c in ldapControls
    ]
    return result


def DecodeControlTuples(
    ldapControlTuples: Optional[List[Tuple[str, bool, bytes]]],
    knownLDAPControls: Optional[Dict[str, Type[ResponseControl]]] = None,
  ) -> List[ResponseControl]:
  """
  Returns list of readily decoded ResponseControl objects

  ldapControlTuples
      Sequence-type of 3-tuples returned by _ldap.result4() containing
      the encoded ASN.1 control values of response controls.
  knownLDAPControls
      Dictionary mapping extended control's OID to ResponseControl class
      of response controls known by the application. If None
      ldap.controls.KNOWN_RESPONSE_CONTROLS is used here.
  """
  knownLDAPControls = knownLDAPControls or KNOWN_RESPONSE_CONTROLS
  result = []
  for controlType,criticality,encodedControlValue in ldapControlTuples or []:
    try:
      control = knownLDAPControls[controlType]()
    except KeyError:
      if criticality:
        raise ldap.UNAVAILABLE_CRITICAL_EXTENSION('Received unexpected critical response control with controlType %s' % (repr(controlType)))
    else:
      control.controlType,control.criticality = controlType,criticality
      try:
        control.decodeControlValue(encodedControlValue)
      except PyAsn1Error:
        if criticality:
          raise
      else:
        result.append(control)
  return result


# Import the standard sub-modules
from ldap.controls.simple import *
from ldap.controls.libldap import *
