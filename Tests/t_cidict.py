# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.cidict

See https://www.python-ldap.org/ for details.
"""
from __future__ import unicode_literals

import sys
import unittest
import warnings

# from python-ldap
import ldap, ldap.cidict


if sys.version_info[0] <= 2:
    text_type = unicode
else:
    text_type = str


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
        cix_keys = sorted(cix.keys())
        self.assertEqual(cix_keys, ['AbCDeF','xYZ'])
        cix_items = sorted(cix.items())
        self.assertEqual(cix_items, [('AbCDeF',123), ('xYZ',987)])
        del cix["abcdEF"]
        self.assertEqual("abcdef" in cix._keys, False)
        self.assertEqual("AbCDef" in cix._keys, False)
        self.assertEqual("abcdef" in cix, False)
        self.assertEqual("AbCDef" in cix, False)
        with warnings.catch_warnings(record=True) as w:
            warnings.resetwarnings()
            warnings.simplefilter("always")
            self.assertEqual(cix.has_key("abcdef"), False)
        self.assertEqual(len(w), 1)
        msg = w[-1]
        self.assertIs(msg.category, DeprecationWarning)
        self.assertEqual(
            text_type(msg.message),
            "cidict.has_key() is deprecated and will be removed in a future version of "
            "python-ldap. Use the 'in' operator instead."
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.assertEqual(cix.has_key("AbCDef"), False)
        self.assertEqual(len(w), 1)
        msg = w[-1]
        self.assertIs(msg.category, DeprecationWarning)
        self.assertEqual(
            text_type(msg.message),
            "cidict.has_key() is deprecated and will be removed in a future version of "
            "python-ldap. Use the 'in' operator instead."
        )


if __name__ == '__main__':
    unittest.main()
