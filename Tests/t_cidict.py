# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.cidict

See https://www.python-ldap.org/ for details.
"""

# from Python's standard lib
import unittest

# from python-ldap
import ldap, ldap.cidict


class TestCidict(unittest.TestCase):
    """
    test ldap.cidict.cidict
    """

    def test_cidict(self):
        """
        test function is_dn()
        """
        self.assertEqual(ldap.dn.is_dn('foobar,ou=ae-dir'), False)
        data = {
            'AbCDeF':123,
        }
        cix = ldap.cidict.cidict(data)
        self.assertEqual(cix["ABCDEF"], 123)
        self.assertEqual(cix.get("ABCDEF", None), 123)
        self.assertEqual(cix.get("not existent", None), None)
        cix["xYZ"] = 987
        self.assertEqual(cix["XyZ"], 987)
        self.assertEqual(cix.get("xyz", None), 987)
        cix_keys = cix.keys()
        cix_keys.sort()
        self.assertEqual(cix_keys, ['AbCDeF','xYZ'])
        cix_items = cix.items()
        cix_items.sort()
        self.assertEqual(cix_items, [('AbCDeF',123), ('xYZ',987)])
        del cix["abcdEF"]
        self.assertEqual(cix._keys.has_key("abcdef"), False)
        self.assertEqual(cix._keys.has_key("AbCDef"), False)


if __name__ == '__main__':
    unittest.main()
