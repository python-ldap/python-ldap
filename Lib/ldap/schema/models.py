"""
schema.py - support for subSchemaSubEntry information

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, MutableMapping
from typing import TYPE_CHECKING, ClassVar, TypedDict, cast


if TYPE_CHECKING:
    from typing_extensions import Self

from typing import Optional

import ldap.schema
from ldap._types import LDAPEntryDict, TypeAlias
from ldap.cidict import cidict
from ldap.schema.subentry import SCHEMA_ATTR_MAPPING, SCHEMA_CLASS_MAPPING
from ldap.schema.tokenizer import extract_tokens, split_tokens


EntryBase: TypeAlias = MutableMapping[str, list[bytes]]

TokenDefaults = Mapping[str, object]

TokenStringValues: TypeAlias = tuple[str, ...]
TokenOptionalValue: TypeAlias = tuple[Optional[str]]
TokenFlag: TypeAlias = Optional[tuple[str, ...]]

SchemaElementTokens = TypedDict(
    'SchemaElementTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
    },
)

ObjectClassTokens = TypedDict(
    'ObjectClassTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'SUP': TokenStringValues,
        'STRUCTURAL': TokenFlag,
        'AUXILIARY': TokenFlag,
        'ABSTRACT': TokenFlag,
        'MUST': TokenStringValues,
        'MAY': TokenStringValues,
        'X-ORIGIN': TokenStringValues,
    },
)

AttributeTypeTokens = TypedDict(
    'AttributeTypeTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'SUP': TokenStringValues,
        'EQUALITY': TokenOptionalValue,
        'ORDERING': TokenOptionalValue,
        'SUBSTR': TokenOptionalValue,
        'SYNTAX': TokenOptionalValue,
        'SINGLE-VALUE': TokenFlag,
        'COLLECTIVE': TokenFlag,
        'NO-USER-MODIFICATION': TokenFlag,
        'USAGE': TokenStringValues,
        'X-ORIGIN': TokenStringValues,
        'X-ORDERED': TokenOptionalValue,
    },
)

LDAPSyntaxTokens = TypedDict(
    'LDAPSyntaxTokens',
    {
        'DESC': TokenOptionalValue,
        'X-NOT-HUMAN-READABLE': TokenOptionalValue,
        'X-BINARY-TRANSFER-REQUIRED': TokenOptionalValue,
        'X-SUBST': TokenOptionalValue,
    },
)

MatchingRuleTokens = TypedDict(
    'MatchingRuleTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'SYNTAX': TokenOptionalValue,
    },
)

MatchingRuleUseTokens = TypedDict(
    'MatchingRuleUseTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'APPLIES': TokenStringValues,
    },
)

DITContentRuleTokens = TypedDict(
    'DITContentRuleTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'AUX': TokenStringValues,
        'MUST': TokenStringValues,
        'MAY': TokenStringValues,
        'NOT': TokenStringValues,
    },
)

DITStructureRuleTokens = TypedDict(
    'DITStructureRuleTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'FORM': TokenOptionalValue,
        'SUP': TokenStringValues,
    },
)

NameFormTokens = TypedDict(
    'NameFormTokens',
    {
        'NAME': TokenStringValues,
        'DESC': TokenOptionalValue,
        'OBSOLETE': TokenFlag,
        'OC': TokenOptionalValue,
        'MUST': TokenStringValues,
        'MAY': TokenStringValues,
    },
)

NOT_HUMAN_READABLE_LDAP_SYNTAXES = {
    '1.3.6.1.4.1.1466.115.121.1.4',  # Audio
    '1.3.6.1.4.1.1466.115.121.1.5',  # Binary
    '1.3.6.1.4.1.1466.115.121.1.8',  # Certificate
    '1.3.6.1.4.1.1466.115.121.1.9',  # Certificate List
    '1.3.6.1.4.1.1466.115.121.1.10',  # Certificate Pair
    '1.3.6.1.4.1.1466.115.121.1.23',  # G3 FAX
    '1.3.6.1.4.1.1466.115.121.1.28',  # JPEG
    '1.3.6.1.4.1.1466.115.121.1.40',  # Octet String
    '1.3.6.1.4.1.1466.115.121.1.49',  # Supported Algorithm
}

ATTRIBUTE_USAGE = cidict(
    {
        'userApplication': 0,  # work-around for non-compliant schema
        'userApplications': 0,
        'directoryOperation': 1,
        'distributedOperation': 2,
        'dSAOperation': 3,
    }
)

AttributeUsage = ATTRIBUTE_USAGE  # Backwards-compatible module alias

OBJECTCLASS_KIND_STR = {0: 'STRUCTURAL', 1: 'ABSTRACT', 2: 'AUXILIARY'}


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
    token_defaults
      Dictionary internally used by the schema element parser
      containing the defaults for certain schema description key-words
    """

    schema_attribute: ClassVar[str]
    oid: str
    names: tuple[str, ...]
    desc: str | None

    token_defaults: ClassVar[TokenDefaults] = cast(
        SchemaElementTokens,
        {
            'NAME': (),
            'DESC': (None,),
        },
    )

    def __init__(self, schema_element_str: str | bytes | None = None) -> None:
        if isinstance(schema_element_str, bytes):
            schema_element_string = schema_element_str.decode('utf-8')
        elif isinstance(schema_element_str, str):
            schema_element_string = schema_element_str
        elif schema_element_str is None:
            return
        else:
            raise TypeError(f'schema_element_str must be str/bytes, was {schema_element_str!r}')
        if not schema_element_str:
            return

        tokens = split_tokens(schema_element_string)
        self.set_id(tokens[1])
        opts = extract_tokens(tokens, self.token_defaults)
        self._set_attrs(opts)

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(SchemaElementTokens, opts)
        self.names = opts['NAME']
        self.desc = opts['DESC'][0]

    def set_id(self, element_id: str) -> None:
        self.oid = element_id

    def get_id(self) -> str:
        return self.oid

    def key_attr(self, key: str, value: str | None, quoted: int = 0) -> str:
        if value is None:
            return ''
        elif not isinstance(value, str):
            raise TypeError(f'value has to be of str, was {value!r}')
        elif value == '':
            return ''
        elif quoted:
            return " {} '{}'".format(key, value.replace("'", "\\'"))
        else:
            return f' {key} {value}'

    def key_list(self, key: str, values: tuple[str, ...], sep: str = ' ', quoted: int = 0) -> str:
        assert isinstance(values, tuple), TypeError(f'values has to be a tuple, was {values!r}')
        if not values:
            return ''

        if quoted:
            quoted_values = ["'{}'".format(value.replace("'", "\\'")) for value in values]
        else:
            quoted_values = list(values)

        if len(quoted_values) == 1:
            return f' {key} {quoted_values[0]}'
        else:
            return f' {key} ( {sep.join(quoted_values)} )'

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.append(self.key_attr('DESC', self.desc, quoted=1))
        return '( {} )'.format(''.join(result))


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

    obsolete: bool
    must: tuple[str, ...]
    may: tuple[str, ...]
    kind: int
    sup: tuple[str, ...]
    x_origin: tuple[str, ...]

    schema_attribute = 'objectClasses'
    token_defaults: ClassVar[TokenDefaults] = cast(
        ObjectClassTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'SUP': (()),
            'STRUCTURAL': None,
            'AUXILIARY': None,
            'ABSTRACT': None,
            'MUST': (()),
            'MAY': (),
            'X-ORIGIN': (),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(ObjectClassTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.must = opts['MUST']
        self.may = opts['MAY']
        self.x_origin = opts['X-ORIGIN']
        # Default is STRUCTURAL, see RFC2552 or draft-ietf-ldapbis-syntaxes
        self.kind = 0
        if opts['ABSTRACT'] is not None:
            self.kind = 1
        elif opts['AUXILIARY'] is not None:
            self.kind = 2

        if self.kind == 0 and not opts['SUP'] and self.oid != '2.5.6.0':
            # STRUCTURAL object classes are sub-classes of 'top' by default
            self.sup: tuple[str, ...] = ('top',)
        else:
            self.sup = opts['SUP']

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                self.key_list('SUP', self.sup, sep=' $ '),
                {False: '', True: ' OBSOLETE'}[self.obsolete],
                f' {OBJECTCLASS_KIND_STR[self.kind]}',
                self.key_list('MUST', self.must, sep=' $ '),
                self.key_list('MAY', self.may, sep=' $ '),
                self.key_list('X-ORIGIN', self.x_origin, quoted=1),
            )
        )
        return '( {} )'.format(''.join(result))


SCHEMA_CLASS_MAPPING[ObjectClass.schema_attribute] = ObjectClass
SCHEMA_ATTR_MAPPING[ObjectClass] = ObjectClass.schema_attribute


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
    x_ordered
      Value of the X-ORDERED extension flag (string, or None if missing).

      X-ORDERED is an OpenLDAP extension used to indicate that ordering is
      significant. "VALUES" indicates that the values of a multi-valued
      attribute are ordered, while "SIBLINGS" indicates that entries using
      the attribute as their RDN are ordered among their siblings.
    """

    obsolete: bool
    single_value: bool
    collective: bool
    syntax: str | None
    syntax_len: int | None
    no_user_mod: bool
    usage: int
    sup: tuple[str, ...]
    equality: str | None
    ordering: str | None
    substr: str | None
    x_origin: tuple[str, ...]
    x_ordered: str | None

    schema_attribute = 'attributeTypes'
    token_defaults: ClassVar[TokenDefaults] = cast(
        AttributeTypeTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'SUP': (()),
            'EQUALITY': (None,),
            'ORDERING': (None,),
            'SUBSTR': (None,),
            'SYNTAX': (None,),
            'SINGLE-VALUE': None,
            'COLLECTIVE': None,
            'NO-USER-MODIFICATION': None,
            'USAGE': ('userApplications',),
            'X-ORIGIN': (),
            'X-ORDERED': (None,),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(AttributeTypeTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.sup = opts['SUP']
        self.equality = opts['EQUALITY'][0]
        self.ordering = opts['ORDERING'][0]
        self.substr = opts['SUBSTR'][0]
        self.x_origin = opts['X-ORIGIN']
        self.x_ordered = opts['X-ORDERED'][0]
        try:
            syntax = opts['SYNTAX'][0]
        except IndexError:
            self.syntax = None
            self.syntax_len = None
        else:
            if syntax is None:
                self.syntax = None
                self.syntax_len = None
            else:
                try:
                    self.syntax, syntax_len = syntax.split('{')
                except ValueError:
                    self.syntax = syntax
                    self.syntax_len = None
                else:
                    self.syntax_len = int(syntax_len[:-1])
        self.single_value = opts['SINGLE-VALUE'] is not None
        self.collective = opts['COLLECTIVE'] is not None
        self.no_user_mod = opts['NO-USER-MODIFICATION'] is not None
        self.usage = ATTRIBUTE_USAGE.get(opts['USAGE'][0], 0)

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                self.key_list('SUP', self.sup, sep=' $ '),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_attr('EQUALITY', self.equality),
                self.key_attr('ORDERING', self.ordering),
                self.key_attr('SUBSTR', self.substr),
                self.key_attr('SYNTAX', self.syntax),
            )
        )
        if self.syntax_len is not None:
            result.append(('{%d}' % (self.syntax_len)) * (self.syntax_len > 0))
        result.extend(
            (
                {0: '', 1: ' SINGLE-VALUE'}[self.single_value],
                {0: '', 1: ' COLLECTIVE'}[self.collective],
                {0: '', 1: ' NO-USER-MODIFICATION'}[self.no_user_mod],
                {0: '', 1: ' USAGE directoryOperation', 2: ' USAGE distributedOperation', 3: ' USAGE dSAOperation'}[
                    self.usage
                ],
                self.key_list('X-ORIGIN', self.x_origin, quoted=1),
                self.key_attr('X-ORDERED', self.x_ordered, quoted=1),
            )
        )
        return '( {} )'.format(''.join(result))


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

    not_human_readable: bool
    x_subst: str | None
    x_binary_transfer_required: bool

    schema_attribute = 'ldapSyntaxes'
    token_defaults: ClassVar[TokenDefaults] = cast(
        LDAPSyntaxTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'X-NOT-HUMAN-READABLE': (None,),
            'X-BINARY-TRANSFER-REQUIRED': (None,),
            'X-SUBST': (None,),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(LDAPSyntaxTokens, opts)
        super()._set_attrs(opts)
        self.x_subst = opts['X-SUBST'][0]
        self.not_human_readable = (
            self.oid in NOT_HUMAN_READABLE_LDAP_SYNTAXES or opts['X-NOT-HUMAN-READABLE'][0] == 'TRUE'
        )
        self.x_binary_transfer_required = opts['X-BINARY-TRANSFER-REQUIRED'][0] == 'TRUE'

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_attr('DESC', self.desc, quoted=1),
                self.key_attr('X-SUBST', self.x_subst, quoted=1),
                {0: '', 1: " X-NOT-HUMAN-READABLE 'TRUE'"}[self.not_human_readable],
                {0: '', 1: " X-BINARY-TRANSFER-REQUIRED 'TRUE'"}[self.x_binary_transfer_required],
            )
        )
        return '( {} )'.format(''.join(result))


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

    obsolete: bool
    syntax: str | None

    schema_attribute = 'matchingRules'
    token_defaults: ClassVar[TokenDefaults] = cast(
        MatchingRuleTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'SYNTAX': (None,),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(MatchingRuleTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.syntax = opts['SYNTAX'][0]

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_attr('SYNTAX', self.syntax),
            )
        )
        return '( {} )'.format(''.join(result))


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

    obsolete: bool
    applies: tuple[str, ...]

    schema_attribute = 'matchingRuleUse'
    token_defaults: ClassVar[TokenDefaults] = cast(
        MatchingRuleUseTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'APPLIES': (()),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(MatchingRuleUseTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.applies = opts['APPLIES']

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_list('APPLIES', self.applies, sep=' $ '),
            )
        )
        return '( {} )'.format(''.join(result))


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

    obsolete: bool
    aux: tuple[str, ...]
    must: tuple[str, ...]
    may: tuple[str, ...]
    nots: tuple[str, ...]

    schema_attribute = 'dITContentRules'
    token_defaults: ClassVar[TokenDefaults] = cast(
        DITContentRuleTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'AUX': (()),
            'MUST': (()),
            'MAY': (()),
            'NOT': (()),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(DITContentRuleTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.aux = opts['AUX']
        self.must = opts['MUST']
        self.may = opts['MAY']
        self.nots = opts['NOT']

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_list('AUX', self.aux, sep=' $ '),
                self.key_list('MUST', self.must, sep=' $ '),
                self.key_list('MAY', self.may, sep=' $ '),
                self.key_list('NOT', self.nots, sep=' $ '),
            )
        )
        return '( {} )'.format(''.join(result))


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

    ruleid: str
    obsolete: bool
    form: str | None
    sup: tuple[str, ...]
    schema_attribute = 'dITStructureRules'

    token_defaults: ClassVar[TokenDefaults] = cast(
        DITStructureRuleTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'FORM': (None,),
            'SUP': (()),
        },
    )

    def set_id(self, element_id: str) -> None:
        self.ruleid = element_id

    def get_id(self) -> str:
        return self.ruleid

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(DITStructureRuleTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.form = opts['FORM'][0]
        self.sup = opts['SUP']

    def __str__(self) -> str:
        result = [str(self.ruleid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_attr('FORM', self.form, quoted=0),
                self.key_list('SUP', self.sup, sep=' $ '),
            )
        )
        return '( {} )'.format(''.join(result))


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
    oc
      NAME or OID of structural object classes this name form
      is usable with (string)
    must
      NAMEs or OIDs of all attributes an RDN must contain (tuple of strings)
    may
      NAMEs or OIDs of additional attributes an RDN may contain
      (tuple of strings)
    """

    obsolete: bool
    oc: str | None
    must: tuple[str, ...]
    may: tuple[str, ...]
    schema_attribute = 'nameForms'

    token_defaults: ClassVar[TokenDefaults] = cast(
        NameFormTokens,
        {
            'NAME': (()),
            'DESC': (None,),
            'OBSOLETE': None,
            'OC': (None,),
            'MUST': (()),
            'MAY': (()),
        },
    )

    def _set_attrs(self, opts: TokenDefaults) -> None:
        opts = cast(NameFormTokens, opts)
        super()._set_attrs(opts)
        self.obsolete = opts['OBSOLETE'] is not None
        self.oc = opts['OC'][0]
        self.must = opts['MUST']
        self.may = opts['MAY']

    def __str__(self) -> str:
        result = [str(self.oid)]
        result.extend(
            (
                self.key_list('NAME', self.names, quoted=1),
                self.key_attr('DESC', self.desc, quoted=1),
                {0: '', 1: ' OBSOLETE'}[self.obsolete],
                self.key_attr('OC', self.oc),
                self.key_list('MUST', self.must, sep=' $ '),
                self.key_list('MAY', self.may, sep=' $ '),
            )
        )
        return '( {} )'.format(''.join(result))


SCHEMA_CLASS_MAPPING[NameForm.schema_attribute] = NameForm
SCHEMA_ATTR_MAPPING[NameForm] = NameForm.schema_attribute


class Entry(EntryBase):
    """
    Schema-aware implementation of an LDAP entry class.

    Mainly it holds the attributes in a string-keyed dictionary with
    the OID as key.
    """

    def __init__(self, schema: ldap.schema.subentry.SubSchema, dn: str, entry: LDAPEntryDict) -> None:
        self._keytuple2attrtype: dict[tuple[str, ...], str] = {}
        self._attrtype2keytuple: dict[str, tuple[str, ...]] = {}
        self.data: dict[tuple[str, ...], list[bytes]] = {}
        self._s = schema
        self.dn = dn
        super().__init__()
        self.update(entry)

    def _at2key(self, nameoroid: str) -> tuple[str, ...]:
        """
        Return tuple of OID and all sub-types of attribute type specified
        in nameoroid.
        """
        try:
            # Mapping already in cache
            return self._attrtype2keytuple[nameoroid]
        except KeyError:
            # Mapping has to be constructed
            oid = self._s.getoid(ldap.schema.AttributeType, nameoroid)
            l = nameoroid.lower().split(';')
            l[0] = oid
            t = tuple(l)
            self._attrtype2keytuple[nameoroid] = t
            return t

    def update(self, dict: MutableMapping[str, list[bytes]]) -> None:  # type: ignore
        for key, value in dict.items():
            self[key] = value

    def __contains__(self, nameoroid: object) -> bool:
        if not isinstance(nameoroid, str):
            return False
        return self._at2key(nameoroid) in self.data

    def __getitem__(self, nameoroid: object) -> list[bytes]:
        if not isinstance(nameoroid, str):
            raise KeyError
        k = self._at2key(nameoroid)
        return self.data[k]

    def __setitem__(self, nameoroid: object, attr_values: list[bytes]) -> None:
        if not isinstance(nameoroid, str):
            raise KeyError
        k = self._at2key(nameoroid)
        self._keytuple2attrtype[k] = nameoroid
        self.data[k] = attr_values

    def __delitem__(self, nameoroid: object) -> None:
        if not isinstance(nameoroid, str):
            raise KeyError
        k = self._at2key(nameoroid)
        del self.data[k]
        del self._attrtype2keytuple[nameoroid]
        del self._keytuple2attrtype[k]

    def __len__(self) -> int:
        return len(self.data)

    def has_key(self, nameoroid: str) -> bool:
        k = self._at2key(nameoroid)
        return k in self.data

    def keys(self) -> list[str]:  # type: ignore
        return self._keytuple2attrtype.values()  # type: ignore

    def items(self) -> list[tuple[str, list[bytes]]]:  # type: ignore
        return [(k, self[k]) for k in self.keys()]

    def __iter__(self) -> Iterator[str]:
        return iter(self.keys())

    def copy(self) -> Self:
        inst = self.__class__.__new__(self.__class__)
        inst._keytuple2attrtype = self._keytuple2attrtype.copy()
        inst._attrtype2keytuple = self._attrtype2keytuple.copy()
        inst.data = self.data.copy()
        inst._s = self._s
        inst.dn = self.dn
        return inst

    __copy__ = copy

    def attribute_types(
        self,
        attr_type_filter: list[tuple[str, list[str]]] | None = None,
        raise_keyerror: int = 1,
    ) -> tuple[cidict[ldap.schema.models.AttributeType | None], cidict[ldap.schema.models.AttributeType | None]]:
        """
        Convenience wrapper around SubSchema.attribute_types() which
        passes object classes of this particular entry as argument to
        SubSchema.attribute_types()
        """
        bin_ocs = self.get('objectClass', [])
        ocs = [oc if isinstance(oc, str) else oc.decode('utf-8') for oc in bin_ocs]

        return self._s.attribute_types(ocs, attr_type_filter, raise_keyerror)
