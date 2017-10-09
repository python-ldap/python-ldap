# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.dn

See https://www.python-ldap.org/ for details.
"""

# from Python's standard lib
import unittest

# from python-ldap
import ldap.dn


class TestDN(unittest.TestCase):
    """
    test ldap.functions
    """

    def test_is_dn(self):
        """
        test function is_dn()
        """
        self.assertEqual(ldap.dn.is_dn('foobar,ou=ae-dir'), False)
        self.assertEqual(ldap.dn.is_dn('-cn=foobar,ou=ae-dir'), False)
        self.assertEqual(ldap.dn.is_dn(';cn=foobar,ou=ae-dir'), False)
        self.assertEqual(ldap.dn.is_dn(',cn=foobar,ou=ae-dir'), False)
        self.assertEqual(ldap.dn.is_dn('cn=foobar,ou=ae-dir,'), False)
        self.assertEqual(ldap.dn.is_dn('uid=xkcd,cn=foobar,ou=ae-dir'), True)
        self.assertEqual(
            ldap.dn.is_dn(
                'cn=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c.o=\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f'
            ),
            True
        )

if __name__ == '__main__':
    unittest.main()
