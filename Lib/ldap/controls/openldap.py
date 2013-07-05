"""
ldap.controls.openldap - classes for OpenLDAP-specific controls

See http://www.python-ldap.org/ for project details.

$Id: openldap.py,v 1.1 2013/07/05 16:57:25 stroeder Exp $
"""

import ldap.controls
from ldap.controls import ValueLessRequestControl,ResponseControl

from pyasn1.type import univ
from pyasn1.codec.ber import decoder


__all__ = [
  'SearchNoOpControl'
]


class SearchNoOpControl(ValueLessRequestControl,ResponseControl):
  """
  No-op control attached to search operations implementing sort of a
  count operation

  see http://www.openldap.org/its/index.cgi?findid=6598
  """
  controlType = '1.3.6.1.4.1.4203.666.5.18'

  def __init__(self,criticality=False):
    self.criticality = criticality

  class SearchNoOpControlValue(univ.Sequence):
    pass

  def decodeControlValue(self,encodedControlValue):
    decodedValue,_ = decoder.decode(encodedControlValue,asn1Spec=self.SearchNoOpControlValue())
    self.resultCode = int(decodedValue[0])
    self.numSearchResults = int(decodedValue[1])
    self.numSearchContinuations = int(decodedValue[2])


ldap.controls.KNOWN_RESPONSE_CONTROLS[SearchNoOpControl.controlType] = SearchNoOpControl

