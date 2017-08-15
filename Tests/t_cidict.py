# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.cidict

See https://www.python-ldap.org/ for details.

$Id: t_cidict.py,v 1.2 2017/08/15 16:14:04 stroeder Exp $
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
        self.assertEquals(ldap.dn.is_dn('foobar,ou=ae-dir'), False)
        data = {
            'AbCDeF':123,
        }
        cix = ldap.cidict.cidict(data)
        self.assertEquals(cix["ABCDEF"], 123)
        self.assertEquals(cix.get("ABCDEF", None), 123)
        self.assertEquals(cix.get("not existent", None), None)
        cix["xYZ"] = 987
        self.assertEquals(cix["XyZ"], 987)
        self.assertEquals(cix.get("xyz", None), 987)
        cix_keys = cix.keys()
        cix_keys.sort()
        self.assertEquals(cix_keys, ['AbCDeF','xYZ'])
        cix_items = cix.items()
        cix_items.sort()
        self.assertEquals(cix_items, [('AbCDeF',123), ('xYZ',987)])
        del cix["abcdEF"]
        self.assertEquals(cix._keys.has_key("abcdef"), False)
        self.assertEquals(cix._keys.has_key("AbCDef"), False)


if __name__ == '__main__':
    unittest.main()
