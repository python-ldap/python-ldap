# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.ldapobject

See https://www.python-ldap.org/ for details.
"""

import os
import unittest
from slapdtest import SlapdTestCase

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.ldapobject import SimpleLDAPObject, ReconnectLDAPObject

LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: dcObject
objectClass: organization
dc: %(dc)s
o: %(dc)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=user1,%(suffix)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: user1
userPassword: user1_pw

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

"""


class Test01_SimpleLDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """

    ldap_object_class = SimpleLDAPObject

    @classmethod
    def setUpClass(cls):
        SlapdTestCase.setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(
            LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'dc': cls.server.suffix.split(',')[0][3:],
            }
        )

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn()

    def test_search_subtree(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo4,ou=Container,'+self.server.suffix,
                    {'cn': ['Foo4'], 'objectClass': ['organizationalRole']}
                ),
            ]
        )

    def test_search_onelevel(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_ONELEVEL,
            '(cn=Foo*)',
            ['*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}
                ),
            ]
        )

    def test_search_oneattr(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_SUBTREE,
            '(cn=Foo4)',
            ['cn'],
        )
        result.sort()
        self.assertEqual(
            result,
            [('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': ['Foo4']})]
        )

    def test_errno107(self):
        l = self.ldap_object_class('ldap://127.0.0.1:42')
        try:
            m = l.simple_bind_s("", "")
            r = l.result4(m, ldap.MSG_ALL, self.timeout)
        except ldap.SERVER_DOWN, ldap_err:
            errno = ldap_err.args[0]['errno']
            if errno != 107:
                self.fail("expected errno=107, got %d" % errno)
            info = ldap_err.args[0]['info']
            if info != os.strerror(107):
                self.fail("expected info=%r, got %d" % (os.strerror(107), info))
        else:
            self.fail("expected SERVER_DOWN, got %r" % r)

    def test_invalid_credentials(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        # search with invalid filter
        try:
            m = l.simple_bind(self.server.root_dn, self.server.root_pw+'wrong')
            r = l.result4(m, ldap.MSG_ALL)
        except ldap.INVALID_CREDENTIALS:
            pass
        else:
            self.fail("expected INVALID_CREDENTIALS, got %r" % r)

    def test_sasl_extenal_bind_s(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s(authz_id=authz_id)
        self.assertEqual(l.whoami_s(), authz_id.lower())
        

class Test02_ReconnectLDAPObject(Test01_SimpleLDAPObject):
    """
    test ReconnectLDAPObject by restarting slapd
    """

    ldap_object_class = ReconnectLDAPObject

    def test_reconnect_sasl_external(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        authz_id = l.whoami_s()
        self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
        self.server.restart()
        self.assertEqual(l.whoami_s(), authz_id)

    def test_reconnect_simple_bind(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)
        self.server.restart()
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)


if __name__ == '__main__':
    unittest.main()
