# -*- coding: utf-8 -*-
"""
Automatic tests for module ldap.filter
"""

# from Python's standard lib
import unittest

# from python-ldap
from ldap.filter import escape_filter_chars


class TestDN(unittest.TestCase):
    """
    test ldap.functions
    """

    def test_escape_filter_chars(self):
        """
        test function is_dn()
        """
        self.assertEquals(escape_filter_chars(r'foobar'), 'foobar')
        self.assertEquals(escape_filter_chars(r'foo\bar'), r'foo\5cbar')


if __name__ == '__main__':
    unittest.main()
