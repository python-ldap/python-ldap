"""
test LDAP operations with ldap.ldapobject
"""

import os
import unittest
from slapdtest import SlapdTestCase

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.ldapobject import LDAPObject

LDIF_TEMPLATE = """dn: cn=Foo1,%(suffix)s
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


class TestLDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """

    ldap_object_class = LDAPObject

    @classmethod
    def setUpClass(cls):
        SlapdTestCase.setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(LDIF_TEMPLATE % {'suffix':cls.server.suffix})

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
        self.assertEquals(
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
        self.assertEquals(
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
        self.assertEquals(
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


if __name__ == '__main__':
    unittest.main()
