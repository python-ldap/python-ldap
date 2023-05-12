"""
ldap.controls.deref - classes for
(see https://tools.ietf.org/html/draft-masarati-ldap-deref)

See https://www.python-ldap.org/ for project details.
"""
from __future__ import annotations

__all__ = [
  'DEREF_CONTROL_OID',
  'DereferenceControl',
]

import ldap.controls
from ldap.controls import LDAPControl,KNOWN_RESPONSE_CONTROLS

import pyasn1_modules.rfc2251
from pyasn1.type import namedtype,univ,tag
from pyasn1.codec.ber import encoder,decoder
from pyasn1_modules.rfc2251 import LDAPDN,AttributeDescription,AttributeDescriptionList,AttributeValue

from typing import Dict, List, Tuple

DEREF_CONTROL_OID = '1.3.6.1.4.1.4203.666.5.16'


# Request types
#---------------------------------------------------------------------------

# For compatibility with ASN.1 declaration in I-D
AttributeList = AttributeDescriptionList

class DerefSpec(univ.Sequence):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.NamedType(
      'derefAttr',
      AttributeDescription()
    ),
    namedtype.NamedType(
      'attributes',
      AttributeList()
    ),
  )

class DerefSpecs(univ.SequenceOf):  # type: ignore
  componentType = DerefSpec()

# Response types
#---------------------------------------------------------------------------


class AttributeValues(univ.SetOf):  # type: ignore
    componentType = AttributeValue()


class PartialAttribute(univ.Sequence):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', AttributeDescription()),
    namedtype.NamedType('vals', AttributeValues()),
  )


class PartialAttributeList(univ.SequenceOf):  # type: ignore
  componentType = PartialAttribute()
  tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassContext,tag.tagFormatConstructed,0)
  )


class DerefRes(univ.Sequence):  # type: ignore
  componentType = namedtype.NamedTypes(
    namedtype.NamedType('derefAttr', AttributeDescription()),
    namedtype.NamedType('derefVal', LDAPDN()),
    namedtype.OptionalNamedType('attrVals', PartialAttributeList()),
  )


class DerefResultControlValue(univ.SequenceOf):  # type: ignore
    componentType = DerefRes()


class DereferenceControl(LDAPControl):
  controlType = DEREF_CONTROL_OID

  def __init__(
    self,
    criticality: bool = False,
    derefSpecs: Dict[str, List[str]] | None = None,
  ) -> None:
    LDAPControl.__init__(self,self.controlType,criticality)
    self.derefSpecs = derefSpecs or {}

  def _derefSpecs(self) -> DerefSpecs:
    deref_specs = DerefSpecs()
    i = 0
    for deref_attr,deref_attribute_names in self.derefSpecs.items():
      deref_spec = DerefSpec()
      deref_attributes = AttributeList()
      for j in range(len(deref_attribute_names)):
        deref_attributes.setComponentByPosition(j,deref_attribute_names[j])
      deref_spec.setComponentByName('derefAttr',AttributeDescription(deref_attr))
      deref_spec.setComponentByName('attributes',deref_attributes)
      deref_specs.setComponentByPosition(i,deref_spec)
      i += 1
    return deref_specs

  def encodeControlValue(self) -> bytes:
    return encoder.encode(self._derefSpecs())  # type: ignore

  def decodeControlValue(self, encodedControlValue: bytes) -> None:
    decodedValue,_ = decoder.decode(encodedControlValue,asn1Spec=DerefResultControlValue())
    # Starting from the inside out:
    #   The innermost dict maps attribute names to lists of attribute values
    #       (note: the attribute values are encoded as str, not bytes)
    #   The tuple pairs a DN and one of the above dicts.
    #   The outermost dict maps the dereferenced attribute to a list of the above tuples
    self.derefRes: Dict[str, List[Tuple[str, Dict[str, List[str]]]]] = {}
    for deref_res in decodedValue:
      deref_attr,deref_val,deref_vals = deref_res[0],deref_res[1],deref_res[2]
      partial_attrs_dict = {
        str(tv[0]): [str(v) for v in tv[1]]
        for tv in deref_vals or []
      }
      try:
        self.derefRes[str(deref_attr)].append((str(deref_val),partial_attrs_dict))
      except KeyError:
        self.derefRes[str(deref_attr)] = [(str(deref_val),partial_attrs_dict)]

KNOWN_RESPONSE_CONTROLS[DereferenceControl.controlType] = DereferenceControl
