"""
Automatic tests for python-ldap's class ldap.schema.SubSchema

See https://www.python-ldap.org/ for details.
"""

import os

import pytest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap.schema
import ldif
from ldap.ldapobject import SimpleLDAPObject
from ldap.schema.models import AttributeType, ObjectClass
from slapdtest import SlapdTestCase, requires_ldapi


HERE = os.path.abspath(os.path.dirname(__file__))

TEST_SUBSCHEMA_FILES = (
    os.path.join(HERE, 'data', 'subschema-ipa.demo1.freeipa.org.ldif'),
    os.path.join(HERE, 'data', 'subschema-openldap-all.ldif'),
)


class TestSubschemaLDIF:
    """
    test ldap.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test_subschema_file(self):
        for test_file in TEST_SUBSCHEMA_FILES:
            # Read and parse LDIF file
            with open(test_file, 'rb') as ldif_file:
                ldif_parser = ldif.LDIFRecordList(ldif_file, max_entries=1)
                ldif_parser.parse()
            _, subschema_subentry = ldif_parser.all_records[0]
            sub_schema = ldap.schema.SubSchema(subschema_subentry)

            # Smoke-check for listall() and attribute_types()
            for objclass in sub_schema.listall(ObjectClass):
                must, may = sub_schema.attribute_types([objclass])

                for oid, attributetype in must.items():
                    assert attributetype.oid == oid
                for oid, attributetype in may.items():
                    assert attributetype.oid == oid


class TestSubschemaUrlfetch:
    def test_urlfetch_file(self):
        freeipa_uri = f'file://{TEST_SUBSCHEMA_FILES[0]}'
        dn, schema = ldap.schema.urlfetch(freeipa_uri)
        assert dn == 'cn=schema'
        assert isinstance(schema, ldap.schema.subentry.SubSchema)
        obj = schema.get_obj(ObjectClass, '2.5.6.9')
        assert str(obj) == (
            "( 2.5.6.9 NAME 'groupOfNames' SUP top STRUCTURAL MUST cn "
            'MAY ( member $ businessCategory $ seeAlso $ owner $ ou $ o '
            "$ description ) X-ORIGIN 'RFC 4519' )"
        )


class TestXOrigin:
    def get_attribute_type(self, oid):
        openldap_uri = f'file://{TEST_SUBSCHEMA_FILES[0]}'
        _dn, schema = ldap.schema.urlfetch(openldap_uri)
        return schema.get_obj(AttributeType, oid)

    def test_origin_none(self):
        assert self.get_attribute_type('2.16.840.1.113719.1.301.4.24.1').x_origin == ()

    def test_origin_string(self):
        assert self.get_attribute_type('2.16.840.1.113730.3.1.2091').x_origin == ('Netscape',)

    def test_origin_multi_valued(self):
        assert self.get_attribute_type('1.3.6.1.4.1.11.1.3.1.1.3').x_origin == ('RFC4876', 'user defined')

    def test_origin_none_str(self):
        """Check string representation of an attribute without X-ORIGIN"""
        # This should check that the representation:
        # - does not contain X-ORIGIN, and
        # - is still syntactically valid.
        # Checking the full output makes the test simpler,
        # though might need to be adjusted in the future.
        assert str(self.get_attribute_type('2.16.840.1.113719.1.301.4.24.1')) == (
            '( 2.16.840.1.113719.1.301.4.24.1 '
            + "NAME 'krbHostServer' "
            + 'EQUALITY caseExactIA5Match '
            + 'SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )'
        )

    def test_origin_string_str(self):
        """Check string representation of an attr with single-value X-ORIGIN"""
        # This should check that the representation:
        # - has the X-ORIGIN entry 'Netscape' with no parentheses, and
        # - is still syntactically valid.
        # Checking the full output makes the test simpler,
        # though might need to be adjusted in the future.
        assert str(self.get_attribute_type('2.16.840.1.113730.3.1.2091')) == (
            '( 2.16.840.1.113730.3.1.2091 '
            + "NAME 'nsslapd-suffix' "
            + "DESC 'Netscape defined attribute type' "
            + 'SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 '
            + "X-ORIGIN 'Netscape' )"
        )

    def test_origin_multi_valued_str(self):
        """Check string representation of an attr with multi-value X-ORIGIN"""
        # This should check that the representation:
        # - has a parenthesized X-ORIGIN entry, and
        # - is still syntactically valid.
        # Checking the full output makes the test simpler,
        # though might need to be adjusted in the future.
        assert str(self.get_attribute_type('1.3.6.1.4.1.11.1.3.1.1.3')) == (
            "( 1.3.6.1.4.1.11.1.3.1.1.3 NAME 'searchTimeLimit' "
            + "DESC 'Maximum time an agent or service allows for a search "
            + "to complete' "
            + 'EQUALITY integerMatch '
            + 'ORDERING integerOrderingMatch '
            + 'SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 '
            + 'SINGLE-VALUE '
            + "X-ORIGIN ( 'RFC4876' 'user defined' ) )"
        )

    def test_set_origin_str(self):
        """Check that setting X-ORIGIN to a string makes entry unusable"""
        attr = self.get_attribute_type('2.16.840.1.113719.1.301.4.24.1')
        attr.x_origin = 'Netscape'
        with pytest.raises(AssertionError):
            str(attr)

    def test_set_origin_list(self):
        """Check that setting X-ORIGIN to a list makes entry unusable"""
        attr = self.get_attribute_type('2.16.840.1.113719.1.301.4.24.1')
        attr.x_origin = []
        with pytest.raises(AssertionError):
            str(attr)

    def test_set_origin_tuple(self):
        """Check that setting X-ORIGIN to a tuple works"""
        attr = self.get_attribute_type('2.16.840.1.113719.1.301.4.24.1')
        attr.x_origin = ('user defined',)
        assert " X-ORIGIN 'user defined' " in str(attr)


class TestAttributes:
    def get_schema(self):
        openldap_uri = f'file://{TEST_SUBSCHEMA_FILES[0]}'
        _dn, schema = ldap.schema.urlfetch(openldap_uri)
        return schema

    def test_empty_attributetype_attrs(self):
        """Check types and values of attributes of a minimal AttributeType"""
        # (OID 2.999 is actually "/Example", for use in documentation)
        attr = AttributeType('( 2.999 )')
        assert attr.oid == '2.999'
        assert attr.names == ()
        assert attr.desc is None
        assert not attr.obsolete
        assert not attr.single_value
        assert attr.syntax is None
        assert not attr.no_user_mod
        assert attr.equality is None
        assert attr.substr is None
        assert attr.ordering is None
        assert attr.usage == 0
        assert attr.sup == ()
        assert attr.x_origin == ()

    def test_empty_objectclass_attrs(self):
        """Check types and values of attributes of a minimal ObjectClass"""
        # (OID 2.999 is actually "/Example", for use in documentation)
        cls = ObjectClass('( 2.999 )')
        assert cls.oid == '2.999'
        assert cls.names == ()
        assert cls.desc is None
        assert not cls.obsolete
        assert cls.must == ()
        assert cls.may == ()
        assert cls.kind == 0
        assert cls.sup == ('top',)
        assert cls.x_origin == ()

    def test_attributetype_attrs(self):
        """Check types and values of an AttributeType object's attributes"""
        schema = self.get_schema()
        attr = schema.get_obj(AttributeType, '1.3.6.1.4.1.11.1.3.1.1.3')
        expected_desc = 'Maximum time an agent or service allows for a search to complete'
        assert attr.oid == '1.3.6.1.4.1.11.1.3.1.1.3'
        assert attr.names == ('searchTimeLimit',)
        assert attr.desc == expected_desc
        assert not attr.obsolete
        assert attr.single_value
        assert attr.syntax == '1.3.6.1.4.1.1466.115.121.1.27'
        assert not attr.no_user_mod
        assert attr.equality == 'integerMatch'
        assert attr.ordering == 'integerOrderingMatch'
        assert attr.sup == ()
        assert attr.x_origin == ('RFC4876', 'user defined')

    def test_objectclass_attrs(self):
        """Check types and values of an ObjectClass object's attributes"""
        schema = self.get_schema()
        cls = schema.get_obj(ObjectClass, '2.5.6.9')
        expected_may = (
            'member',
            'businessCategory',
            'seeAlso',
            'owner',
            'ou',
            'o',
            'description',
        )
        assert cls.oid == '2.5.6.9'
        assert cls.names == ('groupOfNames',)
        assert cls.desc is None
        assert not cls.obsolete
        assert cls.must == ('cn',)
        assert cls.may == expected_may
        assert cls.kind == 0
        assert cls.sup == ('top',)
        assert cls.x_origin == ('RFC 4519',)


class TestSubschemaUrlfetchSlapd(SlapdTestCase):
    ldap_object_class = SimpleLDAPObject

    def check_slapd_schema(self, dn, schema):
        assert dn == 'cn=Subschema'
        assert isinstance(schema, ldap.schema.subentry.SubSchema)
        obj = schema.get_obj(ObjectClass, '1.3.6.1.1.3.1')
        assert str(obj) == "( 1.3.6.1.1.3.1 NAME 'uidObject' DESC 'RFC2377: uid object' SUP top AUXILIARY MUST uid )"
        entries = schema.ldap_entry()
        assert isinstance(entries, dict)
        assert sorted(entries) == [
            'attributeTypes',
            'ldapSyntaxes',
            'matchingRuleUse',
            'matchingRules',
            'objectClasses',
        ]

    def test_urlfetch_ldap(self):
        dn, schema = ldap.schema.urlfetch(self.server.ldap_uri)
        self.check_slapd_schema(dn, schema)

    @requires_ldapi()
    def test_urlfetch_ldapi(self):
        dn, schema = ldap.schema.urlfetch(self.server.ldapi_uri)
        self.check_slapd_schema(dn, schema)
