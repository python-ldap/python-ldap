"""
schema.py - support for subSchemaSubEntry information

See https://www.python-ldap.org/ for details.
"""

import sys

import collections
from ldap.cidict import cidict
from collections import UserDict

from ldap.schema.tokenizer import parse_tokens, split_tokens

from ldap.schema.subentry import SCHEMA_CLASS_MAPPING, SCHEMA_ATTR_MAPPING


NOT_HUMAN_READABLE_LDAP_SYNTAXES = {
  '1.3.6.1.4.1.1466.115.121.1.4',  # Audio
  '1.3.6.1.4.1.1466.115.121.1.5',  # Binary
  '1.3.6.1.4.1.1466.115.121.1.8',  # Certificate
  '1.3.6.1.4.1.1466.115.121.1.9',  # Certificate List
  '1.3.6.1.4.1.1466.115.121.1.10', # Certificate Pair
  '1.3.6.1.4.1.1466.115.121.1.23', # G3 FAX
  '1.3.6.1.4.1.1466.115.121.1.28', # JPEG
  '1.3.6.1.4.1.1466.115.121.1.40', # Octet String
  '1.3.6.1.4.1.1466.115.121.1.49', # Supported Algorithm
}


class SchemaElement:
  """
  Base class for all schema element classes. Not used directly!

  Arguments:

  schema_element_str
    String which contains the schema element description to be parsed.
    (Bytestrings are decoded using UTF-8)

  Instance attributes:

  oid
    OID assigned to the schema element
  names
    All NAMEs of the schema element (tuple of strings)
  desc
    Description text (DESC) of the schema element (string, or None if missing)

  Class attributes:

  schema_attribute
    LDAP attribute type containing a certain schema element description
  known_tokens
    List used internally containing the valid tokens
  """
  schema_attribute = 'SchemaElement (base class)'
  known_tokens = ['DESC', 'NAME']

  def __init__(self,schema_element_str=None):
    if isinstance(schema_element_str, bytes):
      schema_element_string = schema_element_str.decode('utf-8')
    elif isinstance(schema_element_str, str):
      schema_element_string = schema_element_str
    elif schema_element_str is None:
      return
    else:
      raise TypeError("schema_element_str must be str/bytes, was %r" % schema_element_str)

    if schema_element_string == '':
      return

    tokens = split_tokens(schema_element_string)
    oid, schema_element_attributes = parse_tokens(tokens, self.known_tokens)
    self.set_id(oid)
    self._set_attrs(tokens, schema_element_attributes)

  def _set_attrs(self,l,d):
    self.desc = d.get('DESC', (None,))[0]
    self.names = d.get('NAME', ())

  def set_id(self,element_id):
    self.oid = element_id

  def get_id(self):
    return self.oid

  def key_attr(self,key,value,quoted=0):
    if value is None:
      return ""
    elif not isinstance(value, str):
      raise TypeError("value has to be of str, was %r" % value)
    elif value == "":
      return ""
    elif quoted:
      return " {} '{}'".format(key,value.replace("'","\\'"))
    else:
      return f" {key} {value}"

  def key_list(self,key,values,sep=' ',quoted=0):
    assert isinstance(values, tuple),TypeError("values has to be a tuple, was %r" % values)
    if not values:
      return ''

    if quoted:
      quoted_values = [ "'%s'" % value.replace("'","\\'") for value in values ]
    else:
      quoted_values = list(values)

    if len(quoted_values)==1:
      return ' {} {}'.format(key,quoted_values[0])
    else:
      return ' {} ( {} )'.format(key,sep.join(quoted_values))

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    return '( %s )' % ''.join(result)


class ObjectClass(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an ObjectClassDescription

  Class attributes:

  oid
    OID assigned to the object class
  names
    All NAMEs of the object class (tuple of strings)
  desc
    Description text (DESC) of the object class (string, or None if missing)
  obsolete
    Boolean indicating whether the object class is marked as OBSOLETE in the
    schema
  must
    NAMEs or OIDs of all attributes an entry of the object class must have
    (tuple of strings)
  may
    NAMEs or OIDs of additional attributes an entry of the object class may
    have (tuple of strings)
  kind
    Kind of an object class:
    0 = STRUCTURAL,
    1 = ABSTRACT,
    2 = AUXILIARY
  sup
    NAMEs or OIDs of object classes this object class is derived from
    (tuple of strings)
  x_origin
    Value of the X-ORIGIN extension flag (tuple of strings)

    Although it's not official, X-ORIGIN is used in several LDAP server
    implementations to indicate the source of the associated schema
    element
  """
  schema_attribute = 'objectClasses'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'SUP',
    'STRUCTURAL',
    'AUXILIARY',
    'ABSTRACT',
    'MUST',
    'MAY',
    'X-ORIGIN',
  ]

  def _set_attrs(self, l: List[str], d: LDAPTokenDict) -> None:
    super()._set_attrs(l, d)
    self.obsolete = 'OBSOLETE' in d
    self.must = d.get('MUST', ())
    self.may = d.get('MAY', ())
    self.x_origin = d.get('X-ORIGIN', ())

    # Default is STRUCTURAL, see RFC2552 or draft-ietf-ldapbis-syntaxes
    self.kind = 0
    if 'ABSTRACT' in d:
      self.kind = 1
    elif 'AUXILIARY' in d:
      self.kind = 2

    if self.kind==0 and len(d.get('SUP', ())) == 0 and self.oid!='2.5.6.0':
      # STRUCTURAL object classes are sub-classes of 'top' by default
      self.sup = ('top',)
    else:
      self.sup = d.get('SUP', ())

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append(self.key_list('SUP',self.sup,sep=' $ '))
    result.append({False:'',True:' OBSOLETE'}[self.obsolete])
    result.append({0:' STRUCTURAL',1:' ABSTRACT',2:' AUXILIARY'}[self.kind])
    result.append(self.key_list('MUST',self.must,sep=' $ '))
    result.append(self.key_list('MAY',self.may,sep=' $ '))
    result.append(self.key_list('X-ORIGIN',self.x_origin,quoted=1))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[ObjectClass.schema_attribute] = ObjectClass
SCHEMA_ATTR_MAPPING[ObjectClass] = ObjectClass.schema_attribute

AttributeUsage = cidict({
  'userApplication':0, # work-around for non-compliant schema
  'userApplications':0,
  'directoryOperation':1,
  'distributedOperation':2,
  'dSAOperation':3,
})


class AttributeType(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an AttributeTypeDescription

  Class attributes:

  oid
    OID assigned to the attribute type (string)
  names
    All NAMEs of the attribute type (tuple of strings)
  desc
    Description text (DESC) of the attribute type (string, or None if missing)
  obsolete
    Boolean flag indicating whether the attribute type is marked as OBSOLETE in
    the schema
  single_value
    Boolean flag indicating whether the attribute must have only one value
  syntax
    OID of the LDAP syntax assigned to the attribute type
  no_user_mod
    Boolean flag indicating whether the attribute is modifiable by a client
    application
  equality
    NAME or OID of the matching rule used for checking whether attribute values
    are equal (string, or None if missing)
  substr
    NAME or OID of the matching rule used for checking whether an attribute
    value contains another value (string, or None if missing)
  ordering
    NAME or OID of the matching rule used for checking whether attribute values
    are lesser-equal than (string, or None if missing)
  usage
    USAGE of an attribute type:
    0 = userApplications
    1 = directoryOperation,
    2 = distributedOperation,
    3 = dSAOperation
  sup
    NAMEs or OIDs of attribute types this attribute type is derived from
    (tuple of strings)
  x_origin
    Value of the X-ORIGIN extension flag (tuple of strings).

    Although it's not official, X-ORIGIN is used in several LDAP server
    implementations to indicate the source of the associated schema
    element
  """
  schema_attribute = 'attributeTypes'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'SUP',
    'EQUALITY',
    'ORDERING',
    'SUBSTR',
    'SYNTAX',
    'SINGLE-VALUE',
    'COLLECTIVE',
    'NO-USER-MODIFICATION',
    'USAGE',
    'X-ORIGIN',
    'X-ORDERED',
  ]

  def _set_attrs(self, l: List[str], d: LDAPTokenDict) -> None:
    super()._set_attrs(l, d)
    self.obsolete = 'OBSOLETE' in d
    self.sup = d.get('SUP', ())
    self.equality = d.get('EQUALITY', (None,))[0]
    self.ordering = d.get('ORDERING', (None,))[0]
    self.substr = d.get('SUBSTR', (None,))[0]
    self.x_origin = d.get('X-ORIGIN', ())
    self.x_ordered = d.get('X-ORDERED', (None,))[0]

    try:
      syntax = d.get('SYNTAX', (None,))[0]
    except IndexError:
      self.syntax = None
      self.syntax_len = None
    else:
      if syntax is None:
        self.syntax = None
        self.syntax_len = None
      else:
        try:
          self.syntax,syntax_len = syntax.split("{")
        except ValueError:
          self.syntax = syntax
          self.syntax_len = None
          for i in l:
            if i.startswith("{") and i.endswith("}"):
              self.syntax_len = int(i[1:-1])
        else:
          self.syntax_len = int(syntax_len[:-1])
    self.single_value = 'SINGLE-VALUE' in d
    self.collective = 'COLLECTIVE' in d
    self.no_user_mod = 'NO-USER-MODIFICATION' in d
    self.usage = 0
    usage = d.get('USAGE', (None,))[0]
    if usage is not None:
        self.usage = AttributeUsage.get(usage, 0)

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append(self.key_list('SUP',self.sup,sep=' $ '))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_attr('EQUALITY',self.equality))
    result.append(self.key_attr('ORDERING',self.ordering))
    result.append(self.key_attr('SUBSTR',self.substr))
    result.append(self.key_attr('SYNTAX',self.syntax))
    if self.syntax_len is not None:
      result.append(('{%d}' % (self.syntax_len))*(self.syntax_len>0))
    result.append({0:'',1:' SINGLE-VALUE'}[self.single_value])
    result.append({0:'',1:' COLLECTIVE'}[self.collective])
    result.append({0:'',1:' NO-USER-MODIFICATION'}[self.no_user_mod])
    result.append(
      {
        0:"",
        1:" USAGE directoryOperation",
        2:" USAGE distributedOperation",
        3:" USAGE dSAOperation",
      }[self.usage]
    )
    result.append(self.key_list('X-ORIGIN',self.x_origin,quoted=1))
    result.append(self.key_attr('X-ORDERED',self.x_ordered,quoted=1))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[AttributeType.schema_attribute] = AttributeType
SCHEMA_ATTR_MAPPING[AttributeType] = AttributeType.schema_attribute


class LDAPSyntax(SchemaElement):
  """
  SyntaxDescription

  oid
    OID assigned to the LDAP syntax
  names
    All NAMEs of the LDAP syntax (tuple of strings)
  desc
    Description text (DESC) of the LDAP syntax (string, or None if missing)
  not_human_readable
    Boolean flag indicating whether the attribute type is marked as not
    human-readable (X-NOT-HUMAN-READABLE)
  """
  schema_attribute = 'ldapSyntaxes'
  known_tokens = [
    'NAME',
    'DESC',
    'X-NOT-HUMAN-READABLE',
    'X-BINARY-TRANSFER-REQUIRED',
    'X-SUBST',
  ]

  def _set_attrs(self,l,d):
    super()._set_attrs(l, d)
    self.x_subst = d.get('X-SUBST', (None,))[0]
    self.not_human_readable = \
      self.oid in NOT_HUMAN_READABLE_LDAP_SYNTAXES or \
      d.get('X-NOT-HUMAN-READABLE', (None,))[0] == 'TRUE'
    self.x_binary_transfer_required = d.get('X-BINARY-TRANSFER-REQUIRED', (None,))[0] == 'TRUE'

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append(self.key_attr('X-SUBST',self.x_subst,quoted=1))
    result.append(
      {0:'',1:" X-NOT-HUMAN-READABLE 'TRUE'"}[self.not_human_readable]
    )
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[LDAPSyntax.schema_attribute] = LDAPSyntax
SCHEMA_ATTR_MAPPING[LDAPSyntax] = LDAPSyntax.schema_attribute


class MatchingRule(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an MatchingRuleDescription

  Class attributes:

  oid
    OID assigned to the matching rule
  names
    All NAMEs of the matching rule (tuple of strings)
  desc
    Description text (DESC) of the matching rule
  obsolete
    Boolean flag indicating whether the matching rule is marked as OBSOLETE in
    the schema
  syntax
    OID of the LDAP syntax this matching rule is usable with
    (string, or None if missing)
  """
  schema_attribute = 'matchingRules'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'SYNTAX',
  ]

  def _set_attrs(self,l,d) -> None:
    super()._set_attrs(l, d)
    self.obsolete = 'OBSOLETE' in d
    self.syntax = d.get('SYNTAX', (None,))[0]
    return

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_attr('SYNTAX',self.syntax))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[MatchingRule.schema_attribute] = MatchingRule
SCHEMA_ATTR_MAPPING[MatchingRule] = MatchingRule.schema_attribute


class MatchingRuleUse(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an MatchingRuleUseDescription

  Class attributes:

  oid
    OID of the accompanying matching rule
  names
    All NAMEs of the matching rule (tuple of strings)
  desc
    Description text (DESC) of the matching rule (string, or None if missing)
  obsolete
    Boolean flag indicating whether the matching rule is marked
    as OBSOLETE in the schema
  applies
    NAMEs or OIDs of attribute types for which this matching rule is used
    (tuple of strings)
  """
  schema_attribute = 'matchingRuleUse'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'APPLIES',
  ]

  def _set_attrs(self,l,d):
    super()._set_attrs(l, d)
    self.obsolete = 'OBSOLETE' in d
    self.applies = d.get('APPLIES', ())
    return

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_list('APPLIES',self.applies,sep=' $ '))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[MatchingRuleUse.schema_attribute] = MatchingRuleUse
SCHEMA_ATTR_MAPPING[MatchingRuleUse] = MatchingRuleUse.schema_attribute


class DITContentRule(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an DITContentRuleDescription

  Class attributes:

  oid
    OID of the accompanying structural object class
  names
    All NAMEs of the DIT content rule (tuple of strings)
  desc
    Description text (DESC) of the DIT content rule
    (string, or None if missing)
  obsolete
    Boolean flag indicating whether the DIT content rule is marked
    as OBSOLETE in the schema
  aux
    NAMEs or OIDs of all auxiliary object classes usable in an entry of the
    object class (tuple of strings)
  must
    NAMEs or OIDs of all attributes an entry of the object class must
    have, which may extend the list of required attributes of the object
    classes of an entry.
    (tuple of strings)
  may
    NAMEs or OIDs of additional attributes an entry of the object class may
    have. which may extend the list of optional attributes of the object
    classes of an entry.
    (tuple of strings)
  nots
    NAMEs or OIDs of attributes which may not be present in an entry of the
    object class. (tuple of strings)
  """
  schema_attribute = 'dITContentRules'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'AUX',
    'MUST',
    'MAY',
    'NOT',
  ]

  def _set_attrs(self,l,d):
    super()._set_attrs(l ,d)
    self.obsolete = 'OBSOLETE' in d
    self.aux = d.get('AUX', ())
    self.must = d.get('MUST', ())
    self.may = d.get('MAY', ())
    self.nots = d.get('NOT', ())

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_list('AUX',self.aux,sep=' $ '))
    result.append(self.key_list('MUST',self.must,sep=' $ '))
    result.append(self.key_list('MAY',self.may,sep=' $ '))
    result.append(self.key_list('NOT',self.nots,sep=' $ '))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[DITContentRule.schema_attribute] = DITContentRule
SCHEMA_ATTR_MAPPING[DITContentRule] = DITContentRule.schema_attribute


class DITStructureRule(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an DITStructureRuleDescription

  Class attributes:

  ruleid
    rule ID of the DIT structure rule (only locally unique)
  names
    All NAMEs of the DIT structure rule (tuple of strings)
  desc
    Description text (DESC) of the DIT structure rule
    (string, or None if missing)
  obsolete
    Boolean flag indicating whether the DIT content rule is marked
    as OBSOLETE in the schema
  form
    NAMEs or OIDs of associated name forms (string)
  sup
    NAMEs or OIDs of allowed structural object classes
    of superior entries in the DIT (tuple of strings)
  """
  schema_attribute = 'dITStructureRules'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'FORM',
    'SUP',
  ]

  def set_id(self,element_id):
    self.ruleid = element_id

  def get_id(self):
    return self.ruleid

  def _set_attrs(self,l,d):
    super()._set_attrs(l ,d)
    self.obsolete = 'OBSOLETE' in d
    self.form = d.get('FORM', (None,))[0]
    self.sup = d.get('SUP', ())
    return

  def __str__(self):
    result = [str(self.ruleid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_attr('FORM',self.form,quoted=0))
    result.append(self.key_list('SUP',self.sup,sep=' $ '))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[DITStructureRule.schema_attribute] = DITStructureRule
SCHEMA_ATTR_MAPPING[DITStructureRule] = DITStructureRule.schema_attribute


class NameForm(SchemaElement):
  """
  Arguments:

  schema_element_str
    String containing an NameFormDescription

  Class attributes:

  oid
    OID of the name form
  names
    All NAMEs of the name form (tuple of strings)
  desc
    Description text (DESC) of the name form (string, or None if missing)
  obsolete
    Boolean flag indicating whether the name form is marked as OBSOLETE in the
    schema
  form
    NAMEs or OIDs of associated name forms (tuple of strings)
  oc
    NAME or OID of structural object classes this name form
    is usable with (string)
  must
    NAMEs or OIDs of all attributes an RDN must contain (tuple of strings)
  may
    NAMEs or OIDs of additional attributes an RDN may contain
    (tuple of strings)
  """
  schema_attribute = 'nameForms'
  known_tokens = [
    'NAME',
    'DESC',
    'OBSOLETE',
    'OC',
    'MUST',
    'MAY',
  ]

  def _set_attrs(self,l,d):
    super()._set_attrs(l ,d)
    self.obsolete = 'OBSOLETE' in d
    self.oc = d.get('OC', (None,))[0]
    self.must = d.get('MUST', ())
    self.may = d.get('MAY', ())

  def __str__(self):
    result = [str(self.oid)]
    result.append(self.key_list('NAME',self.names,quoted=1))
    result.append(self.key_attr('DESC',self.desc,quoted=1))
    result.append({0:'',1:' OBSOLETE'}[self.obsolete])
    result.append(self.key_attr('OC',self.oc))
    result.append(self.key_list('MUST',self.must,sep=' $ '))
    result.append(self.key_list('MAY',self.may,sep=' $ '))
    return '( %s )' % ''.join(result)

SCHEMA_CLASS_MAPPING[NameForm.schema_attribute] = NameForm
SCHEMA_ATTR_MAPPING[NameForm] = NameForm.schema_attribute


class Entry(UserDict):
  """
  Schema-aware implementation of an LDAP entry class.

  Mainly it holds the attributes in a string-keyed dictionary with
  the OID as key.
  """

  def __init__(self,schema,dn,entry):
    self._keytuple2attrtype: Dict[Tuple[str, ...], str] = {}
    self._attrtype2keytuple: Dict[str, Tuple[str, ...]] = {}
    # This class wants to act like it's a string-keyed dict, but under the
    # hood it uses the tuple of OID and sub-types of an attribute type
    # as the key, so we can't use the self.data dict and stay type-safe.
    self._data: Dict[Tuple[str, ...], List[bytes]] = {}
    self._s = schema
    self.dn = dn
    super().__init__()
    self.update(entry)

  def _at2key(self,nameoroid):
    """
    Return tuple of OID and all sub-types of attribute type specified
    in nameoroid.
    """
    try:
      # Mapping already in cache
      return self._attrtype2keytuple[nameoroid]
    except KeyError:
      # Mapping has to be constructed
      oid = self._s.getoid(AttributeType,nameoroid)
      l = nameoroid.lower().split(';')
      l[0] = oid
      t = tuple(l)
      self._attrtype2keytuple[nameoroid] = t
      return t

  def update(self,dict):
    for key, value in dict.items():
      self[key] = value

  def __contains__(self,nameoroid):
    if not isinstance(nameoroid, str):
      return False
    return self._at2key(nameoroid) in self._data

  def __getitem__(self,nameoroid):
    if not isinstance(nameoroid, str):
      raise KeyError
    k = self._at2key(nameoroid)
    return self._data[k]

  def __setitem__(self,nameoroid,attr_values):
    if not isinstance(nameoroid, str):
      raise KeyError
    k = self._at2key(nameoroid)
    self._keytuple2attrtype[k] = nameoroid
    self._data[k] = attr_values

  def __delitem__(self,nameoroid):
    if not isinstance(nameoroid, str):
      raise KeyError
    k = self._at2key(nameoroid)
    del self._data[k]
    del self._attrtype2keytuple[nameoroid]
    del self._keytuple2attrtype[k]

  def has_key(self,nameoroid):
    k = self._at2key(nameoroid)
    return k in self._data

  def keys(self):
    return self._keytuple2attrtype.values()

  def items(self):
    return [
      (k,self[k])
      for k in self.keys()
    ]

  def attribute_types(
    self,attr_type_filter=None,raise_keyerror=1
  ):
    """
    Convenience wrapper around SubSchema.attribute_types() which
    passes object classes of this particular entry as argument to
    SubSchema.attribute_types()
    """
    bin_ocs = self.get('objectClass', [])
    ocs = [oc.decode("utf-8") for oc in bin_ocs]

    return self._s.attribute_types(ocs,attr_type_filter,raise_keyerror)
