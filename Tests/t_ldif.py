# -*- coding: utf-8 -*-

import unittest
import textwrap

import ldif


try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class TestParse(unittest.TestCase):
    maxDiff = None

    def check_ldif_to_records(self, ldif_string, expected):
        #import pdb; pdb.set_trace()
        got = ldif.ParseLDIF(StringIO(ldif_string))
        self.assertEqual(got, expected)

    def check_records_to_ldif(self, records, expected):
        f = StringIO()
        ldif_writer = ldif.LDIFWriter(f)
        for dn, attrs in records:
            ldif_writer.unparse(dn, attrs)
        got = f.getvalue()
        self.assertEqual(got, expected)

    def check_roundtrip(self, ldif_source, records, ldif_expected=None):
        ldif_source = textwrap.dedent(ldif_source).lstrip() + '\n'
        if ldif_expected is None:
            ldif_expected = ldif_source
        else:
            ldif_expected = textwrap.dedent(ldif_expected).lstrip() + '\n'

        self.check_ldif_to_records(ldif_source, records)
        self.check_records_to_ldif(records, ldif_expected)
        self.check_ldif_to_records(ldif_expected, records)

    def test_simple(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                attrib: value
                attrib: value2
            """, [
                ('cn=x,cn=y,cn=z', {'attrib': [b'value', b'value2']}),
            ])

    def test_multiple(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                a: v
                attrib: value
                attrib: value2

                dn: cn=a,cn=b,cn=c
                attrib: value2
                attrib: value3
                b: v
            """, [
                ('cn=x,cn=y,cn=z', {'attrib': [b'value', b'value2'], 'a': [b'v']}),
                ('cn=a,cn=b,cn=c', {'attrib': [b'value2', b'value3'], 'b': [b'v']}),
            ])

    def test_folded(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                attrib: very
                 long
                  value
                attrib2: %s
            """ % ('asdf.' * 20), [
                ('cn=x,cn=y,cn=z', {'attrib': [b'verylong value'],
                                    'attrib2': [b'asdf.' * 20]}),
            ], """
                dn: cn=x,cn=y,cn=z
                attrib: verylong value
                attrib2: asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.asdf.as
                 df.asdf.asdf.asdf.asdf.asdf.asdf.
            """)

    def test_empty(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                attrib: 
                attrib: foo
            """, [
                ('cn=x,cn=y,cn=z', {'attrib': [b'', b'foo']}),
            ])

    def test_binary(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                attrib:: CQAKOiVA
            """, [
                ('cn=x,cn=y,cn=z', {'attrib': [b'\t\0\n:%@']}),
            ])

    def test_unicode(self):
        self.check_roundtrip("""
                dn: cn=Michael Stroeder,dc=stroeder,dc=com
                lastname: Ströder
            """, [
                ('cn=Michael Stroeder,dc=stroeder,dc=com',
                 {'lastname': [b'Str\303\266der']}),
            ], """
                dn: cn=Michael Stroeder,dc=stroeder,dc=com
                lastname:: U3Ryw7ZkZXI=
            """)

    def test_sorted(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                b: value_b
                c: value_c
                a: value_a
            """, [
                ('cn=x,cn=y,cn=z', {'a': [b'value_a'],
                                    'b': [b'value_b'],
                                    'c': [b'value_c']}),
            ], """
                dn: cn=x,cn=y,cn=z
                a: value_a
                b: value_b
                c: value_c
            """)


if __name__ == '__main__':
    unittest.main()
