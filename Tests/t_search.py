import os
import unittest
from Tests.slapd import SlapdObject

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.ldapobject import LDAPObject

server = None

class TestSearch(unittest.TestCase):

    def setUp(self):
        global server
        if server is None:
            server = SlapdObject()
            server.start()
            base = server.suffix

            # insert some Foo* objects via ldapadd
            server.ldapadd("\n".join([
                "dn: cn=Foo1,"+base,
                "objectClass: organizationalRole",
                "cn: Foo1",
                "",
                "dn: cn=Foo2,"+base,
                "objectClass: organizationalRole",
                "cn: Foo2",
                "",
                "dn: cn=Foo3,"+base,
                "objectClass: organizationalRole",
                "cn: Foo3",
                "",
                "dn: ou=Container,"+base,
                "objectClass: organizationalUnit",
                "ou: Container",
                "",
                "dn: cn=Foo4,ou=Container,"+base,
                "objectClass: organizationalRole",
                "cn: Foo4",
                "",
            ])+"\n")

        l = LDAPObject(server.ldap_uri)
        l.protocol_version = 3
        l.set_option(ldap.OPT_REFERRALS,0)
        l.simple_bind_s(server.root_dn, 
                server.root_pw)
        self.ldap = l
        self.server = server

    def test_search_subtree(self):
        base = self.server.suffix
        l = self.ldap

        result = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo1,'+base,
               {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo2,'+base,
               {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo3,'+base,
               {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo4,ou=Container,'+base,
               {'cn': ['Foo4'], 'objectClass': ['organizationalRole']}),
            ]
        )

    def test_search_onelevel(self):
        base = self.server.suffix
        l = self.ldap

        result = l.search_s(base, ldap.SCOPE_ONELEVEL, '(cn=Foo*)', ['*'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo1,'+base,
               {'cn': ['Foo1'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo2,'+base,
               {'cn': ['Foo2'], 'objectClass': ['organizationalRole']}),
             ('cn=Foo3,'+base,
               {'cn': ['Foo3'], 'objectClass': ['organizationalRole']}),
            ]
        )

    def test_search_oneattr(self):
        base = self.server.suffix
        l = self.ldap

        result = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=Foo4)', ['cn'])
        result.sort()
        self.assertEquals(result,
            [('cn=Foo4,ou=Container,'+base, {'cn': ['Foo4']})]
        )


if __name__ == '__main__':
    unittest.main()
