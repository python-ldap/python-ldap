"""
Automatic tests for python-ldap's module ldap.dn

See https://www.python-ldap.org/ for details.
"""
# from Python's standard lib
import os
import unittest

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'
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
        self.assertEqual(ldap.dn.is_dn('cn=äöüÄÖÜß,o=äöüÄÖÜß'), True)
        self.assertEqual(
            ldap.dn.is_dn(
                r'cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f,o=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f'
            ),
            True
        )

    def test_escape_dn_chars(self):
        """
        test function escape_dn_chars()
        """
        self.assertEqual(ldap.dn.escape_dn_chars('foobar'), 'foobar')
        self.assertEqual(ldap.dn.escape_dn_chars('foo,bar'), r'foo\,bar')
        self.assertEqual(ldap.dn.escape_dn_chars('foo=bar'), r'foo\=bar')
        self.assertEqual(ldap.dn.escape_dn_chars('foo#bar'), 'foo#bar')
        self.assertEqual(ldap.dn.escape_dn_chars('#foobar'), r'\#foobar')
        self.assertEqual(ldap.dn.escape_dn_chars('foo bar'), 'foo bar')
        self.assertEqual(ldap.dn.escape_dn_chars(' foobar'), r'\ foobar')
        self.assertEqual(ldap.dn.escape_dn_chars(' '), r'\ ')
        self.assertEqual(ldap.dn.escape_dn_chars('  '), r'\ \ ')
        self.assertEqual(ldap.dn.escape_dn_chars('foobar '), r'foobar\ ')
        self.assertEqual(ldap.dn.escape_dn_chars('f+o>o,b<a;r="\00"'), 'f\\+o\\>o\\,b\\<a\\;r\\=\\"\\\x00\\"')
        self.assertEqual(ldap.dn.escape_dn_chars(r'foo\,bar'), r'foo\\\,bar')

    def test_str2dn(self):
        """
        test function str2dn()
        """
        self.assertEqual(ldap.dn.str2dn(''), [])
        self.assertEqual(ldap.dn.str2dn(None), [])
        self.assertEqual(
            ldap.dn.str2dn('uid=test42,ou=Testing,dc=example,dc=com'),
            [
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn('uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'),
            [
                [('uid', 'test42', 1), ('uidNumber', '42', 1) ],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn('uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            [
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn('uid=test42; ou=Testing; dc=example; dc=com', flags=ldap.DN_FORMAT_LDAPV2),
            [
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn(r'uid=test\, 42,ou=Testing,dc=example,dc=com', flags=0),
            [
                [('uid', 'test, 42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn('cn=äöüÄÖÜß,dc=example,dc=com', flags=0),
            [
                [('cn', 'äöüÄÖÜß', ldap.AVA_NONPRINTABLE)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn(r'cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f,dc=example,dc=com', flags=0),
            [
                [('cn', 'äöüÄÖÜß', ldap.AVA_NONPRINTABLE)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )
        self.assertEqual(
            ldap.dn.str2dn('/dc=com/dc=example/ou=Testing/uid=test42', flags=ldap.DN_FORMAT_DCE),
            [
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]
        )

    def test_dn2str(self):
        """
        test function dn2str()
        """
        self.assertEqual(ldap.dn.dn2str([]), '')
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]),
            'uid=test42,ou=Testing,dc=example,dc=com',
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]),
            'uid=test42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1), ('uidNumber', '42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]),
            'uid=test42+uidNumber=42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test, 42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]),
            r'uid=test\, 42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test, 42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            r'uid=test\2C 42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_NONPRINTABLE)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ]),
            'cn=äöüÄÖÜß,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_NONPRINTABLE)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            r'cn=\C3\A4\C3\B6\C3\BC\C3\84\C3\96\C3\9C\C3\9F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1), ('cn', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_AD_CANONICAL),
            'example.com/Testing/test42,test42'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1), ('cn', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_UFN),
            'test42 + test42, Testing, example.com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('uid', 'test42', 1), ('cn', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_DCE),
            '/dc=com/dc=example/ou=Testing/uid=test42,cn=test42'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_BINARY)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            'cn=#C3A4C3B6C3BCC384C396C39CC39F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_NULL)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            r'cn=\C3\A4\C3\B6\C3\BC\C3\84\C3\96\C3\9C\C3\9F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_STRING)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            r'cn=\C3\A4\C3\B6\C3\BC\C3\84\C3\96\C3\9C\C3\9F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('cn', 'äöüÄÖÜß', ldap.AVA_NONPRINTABLE)],
                [('dc', 'example', 1)],
                [('dc', 'com', 1)]
            ], ldap.DN_FORMAT_LDAPV3),
            r'cn=\C3\A4\C3\B6\C3\BC\C3\84\C3\96\C3\9C\C3\9F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.dn2str([
                [('c', 'DEU', 1)],  # country code only allow two-letters
            ], ldap.DN_FORMAT_LDAPV3),
            r'c=DEU'
        )

    def test_dn_various_lengths(self):
        base = [
            [('dc', 'example', 1)],
            [('dc', 'com', 1)]
        ]

        test_lengths = [1, 10, 100, 500]
        for n in test_lengths:
            rdn_prefix = [
                [('ou', f'unit{i}', 1)] for i in range(n)
            ]
            full_dn = rdn_prefix + base
            full_dn.insert(0, [('uid', f'user{n}', 1)])

            result = ldap.dn.dn2str(full_dn, ldap.DN_FORMAT_LDAPV3)

            self.assertTrue(result.startswith(f'uid=user{n},'))
            self.assertTrue(result.endswith(',dc=example,dc=com'))
            self.assertEqual(result.count(','), n + 2)

    def test_dn2str_errors(self):
        """
        test error handling of function dn2str()
        """
        with self.assertRaises(RuntimeError):
            ldap.dn.dn2str([[('uid', 'test42', 1)]], 142)

        DN_FORMAT_LBER = 0xf0
        with self.assertRaises(RuntimeError):
            ldap.dn.dn2str([
                [('dc', 'com', 1)]
            ], DN_FORMAT_LBER)

        ldap_format = ldap.DN_FORMAT_LDAPV3

        with self.assertRaises(TypeError):
            ldap.dn.dn2str(None)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str(None, ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([1], ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([[1]], ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([[('uid', 'test42', '1')]], ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([[('uid', 'test42', 1.0)]], ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([[['uid', 'test42', 1]]], ldap_format)

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('uid', 'test42', 1), ('cn', 'test42', 1)],
                [('ou', 'Testing', 1)],
                [('dc', 'example', '1')],
                [('dc', 'com', 1)]
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('ou', 'Testing', 1)],
                [('dc', 'example', 1)],
                [('uid', 'test42', 1), ('cn', 'test42', '1')],
                [('dc', 'com', 1)]
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                [('dc', 'com', None)],
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                [('dc', None, 1)],
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                [(None, 'com', 1)],
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                [None],
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                None,
            ], ldap_format),

        with self.assertRaises(TypeError):
            ldap.dn.dn2str([
                [('dc', 'example', 1)],
                [('dc', 'com', 1), None],
            ], ldap_format),

    def test_explode_dn(self):
        """
        test function explode_dn()
        """
        self.assertEqual(ldap.dn.explode_dn(''), [])
        self.assertEqual(
            ldap.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com'),
            ['uid=test42', 'ou=Testing', 'dc=example', 'dc=com']
        )
        self.assertEqual(
            ldap.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com', flags=0),
            ['uid=test42', 'ou=Testing', 'dc=example', 'dc=com']
        )
        self.assertEqual(
            ldap.dn.explode_dn('uid=test42; ou=Testing; dc=example; dc=com', flags=ldap.DN_FORMAT_LDAPV2),
            ['uid=test42', 'ou=Testing', 'dc=example', 'dc=com']
        )
        self.assertEqual(
            ldap.dn.explode_dn('uid=test42,ou=Testing,dc=example,dc=com', notypes=True),
            ['test42', 'Testing', 'example', 'com']
        )
        self.assertEqual(
            ldap.dn.explode_dn(r'uid=test\, 42,ou=Testing,dc=example,dc=com', flags=0),
            [r'uid=test\, 42', 'ou=Testing', 'dc=example', 'dc=com']
        )
        self.assertEqual(
            ldap.dn.explode_dn('cn=äöüÄÖÜß,dc=example,dc=com', flags=0),
            ['cn=äöüÄÖÜß', 'dc=example', 'dc=com']
        )
        self.assertEqual(
            ldap.dn.explode_dn(r'cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f,dc=example,dc=com', flags=0),
            ['cn=äöüÄÖÜß', 'dc=example', 'dc=com']
        )

    def test_explode_rdn(self):
        """
        test function explode_rdn()
        """
        self.assertEqual(ldap.dn.explode_rdn(''), [])
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42'),
            ['uid=test42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42', notypes=False, flags=0),
            ['uid=test42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42', notypes=0, flags=0),
            ['uid=test42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42+uidNumber=42', flags=0),
            ['uid=test42', 'uidNumber=42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42', notypes=True),
            ['test42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('uid=test42', notypes=1),
            ['test42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn(r'uid=test\+ 42', flags=0),
            [r'uid=test\+ 42']
        )
        self.assertEqual(
            ldap.dn.explode_rdn('cn=äöüÄÖÜß', flags=0),
            ['cn=äöüÄÖÜß']
        )
        self.assertEqual(
            ldap.dn.explode_rdn(r'cn=\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f', flags=0),
            ['cn=äöüÄÖÜß']
        )

    def test_normalize(self):
        """
        test function normalize()
        """
        self.assertEqual(
            ldap.dn.normalize('uid = test42 , ou = Testing , dc = example , dc = com', flags=ldap.DN_FORMAT_LDAPV3),
            'uid=test42,ou=Testing,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.normalize('cn=äöüÄÖÜß,dc=example,dc=com', flags=0),
            'cn=äöüÄÖÜß,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.normalize('cn=#C3A4C3B6C3BCC384C396C39CC39F,dc=example,dc=com', flags=0),
            'cn=äöüÄÖÜß,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.normalize('cn=#C3A4C3B6C3BCC384C396C39CC39F,dc=example,dc=com', flags=ldap.DN_FORMAT_LDAPV3),
            'cn=#C3A4C3B6C3BCC384C396C39CC39F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.normalize('cn=äöüÄÖÜß,dc=example,dc=com', flags=ldap.DN_FORMAT_LDAPV3),
            r'cn=\C3\A4\C3\B6\C3\BC\C3\84\C3\96\C3\9C\C3\9F,dc=example,dc=com'
        )
        self.assertEqual(
            ldap.dn.normalize('/ dc = com / dc = example / ou = Testing / uid = test42 , cn = test42', flags=ldap.DN_FORMAT_DCE),
            '/dc=com/dc=example/ou=Testing/uid=test42,cn=test42'
        )


if __name__ == '__main__':
    unittest.main()
