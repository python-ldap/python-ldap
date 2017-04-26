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


class TestSearch(SlapdTestCase):

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
        result = self._ldap_conn.search_s(self.server.suffix, ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo1,'+self.server.suffix,
               {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo2,'+self.server.suffix,
               {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo3,'+self.server.suffix,
               {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo4,ou=Container,'+self.server.suffix,
               {'cn': ['Foo4'], 'objectClass': ['organizationalRole']}),
            ]
        )

    def test_search_onelevel(self):
        result = self._ldap_conn.search_s(self.server.suffix, ldap.SCOPE_ONELEVEL, '(cn=Foo*)', ['*'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo1,'+self.server.suffix,
               {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo2,'+self.server.suffix,
               {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo3,'+self.server.suffix,
               {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}),
            ]
        )

    def test_search_oneattr(self):
        result = self._ldap_conn.search_s(self.server.suffix, ldap.SCOPE_SUBTREE, '(cn=Foo4)', ['cn'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': ['Foo4']})]
        )

if __name__ == '__main__':
    unittest.main()
