# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.cidict

See https://www.python-ldap.org/ for details.
"""

import os
import unittest
import warnings

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'
import ldap
import ldap.cidict


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
        self.assertIsNone(cix.get("not existent", None))
        cix["xYZ"] = 987
        self.assertEqual(cix["XyZ"], 987)
        self.assertEqual(cix.get("xyz", None), 987)
        cix_keys = sorted(cix.keys())
        self.assertEqual(cix_keys, ['AbCDeF','xYZ'])
        cix_keys = sorted(cix)
        self.assertEqual(cix_keys, ['AbCDeF','xYZ'])
        cix_items = sorted(cix.items())
        self.assertEqual(cix_items, [('AbCDeF',123), ('xYZ',987)])
        del cix["abcdEF"]
        self.assertEqual("abcdef" in cix._keys, False)
        self.assertEqual("AbCDef" in cix._keys, False)
        self.assertEqual("abcdef" in cix, False)
        self.assertEqual("AbCDef" in cix, False)
        self.assertEqual(cix.has_key("abcdef"), False)
        self.assertEqual(cix.has_key("AbCDef"), False)

    def test_strlist_deprecated(self):
        strlist_funcs = [
            ldap.cidict.strlist_intersection,
            ldap.cidict.strlist_minus,
            ldap.cidict.strlist_union
        ]
        for strlist_func in strlist_funcs:
            with warnings.catch_warnings(record=True) as w:
                warnings.resetwarnings()
                warnings.simplefilter("always", DeprecationWarning)
                strlist_func(["a"], ["b"])
            self.assertEqual(len(w), 1)

    def test_cidict_data(self):
        """test the deprecated data atrtribute"""
        d = ldap.cidict.cidict({'A': 1, 'B': 2})
        with warnings.catch_warnings(record=True) as w:
            warnings.resetwarnings()
            warnings.simplefilter('always', DeprecationWarning)
            data = d.data
        assert data == {'a': 1, 'b': 2}
        self.assertEqual(len(w), 1)


if __name__ == '__main__':
    unittest.main()
