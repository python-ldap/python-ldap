# -*- coding: utf-8 -*-

import unittest
import textwrap

import ldif


try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class TestEntryRecords(unittest.TestCase):

    def _parse_entry_records(self, ldif_string, ignored_attr_types=None, max_entries=0):
        f = StringIO(ldif_string)
        ldif_parser = ldif.LDIFRecordList(
            f,
            ignored_attr_types=ignored_attr_types,
            max_entries=max_entries,
        )
        ldif_parser.parse_entry_records()
        return ldif_parser.all_records

    def _unparse_entry_records(self, records):
        f = StringIO()
        ldif_writer = ldif.LDIFWriter(f)
        for dn, attrs in records:
            ldif_writer.unparse(dn, attrs)
        return f.getvalue()

    def check_roundtrip(self, ldif_source, entry_records, ignored_attr_types=None, max_entries=0):
        ldif_source = textwrap.dedent(ldif_source).lstrip() + '\n'
        parsed_entry_records = self._parse_entry_records(
            ldif_source,
            ignored_attr_types=None,
            max_entries=max_entries,
        )
        parsed_entry_records2 = self._parse_entry_records(
            self._unparse_entry_records(entry_records),
            ignored_attr_types=None,
            max_entries=max_entries,
        )
        self.assertEqual(parsed_entry_records, entry_records)
        self.assertEqual(parsed_entry_records2, entry_records)

    def test_simple(self):
        self.check_roundtrip("""
                version: 1

                dn: cn=x,cn=y,cn=z
                attrib: value
                attrib: value2
            """, [
                ('cn=x,cn=y,cn=z', {'attrib': [b'value', b'value2']}),
            ])

    def test_simple2(self):
        self.check_roundtrip("""
                dn:cn=x,cn=y,cn=z
                attrib:value
                attrib:value2
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
            ])

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

    def test_binary2(self):
        self.check_roundtrip("""
                dn: cn=x,cn=y,cn=z
                attrib::CQAKOiVA
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
            ])

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
            ])

    def test_comments(self):
        self.check_roundtrip("""
                # comment #1 
                 with line-folding
                dn: cn=x1,cn=y1,cn=z1
                b1: value_b1
                c1: value_c1
                a1: value_a1

                # comment #2.1
                # comment #2.2
                dn: cn=x2,cn=y2,cn=z2
                b2: value_b2
                c2: value_c2
                a2: value_a2

            """, [
                ('cn=x1,cn=y1,cn=z1', {'a1': [b'value_a1'],
                                       'b1': [b'value_b1'],
                                       'c1': [b'value_c1']}),
                ('cn=x2,cn=y2,cn=z2', {'a2': [b'value_a2'],
                                       'b2': [b'value_b2'],
                                       'c2': [b'value_c2']}),
            ])

    def test_max_entries(self):
        self.check_roundtrip("""
                dn: cn=x1,cn=y1,cn=z1
                b1: value_b1
                a1: value_a1

                dn: cn=x2,cn=y2,cn=z2
                b2: value_b2
                a2: value_a2

                dn: cn=x3,cn=y3,cn=z3
                b3: value_b3
                a3: value_a3

                dn: cn=x4,cn=y4,cn=z4
                b2: value_b4
                a2: value_a4

            """, [
                ('cn=x1,cn=y1,cn=z1', {'a1': [b'value_a1'],
                                       'b1': [b'value_b1']}),
                ('cn=x2,cn=y2,cn=z2', {'a2': [b'value_a2'],
                                       'b2': [b'value_b2']}),
            ], max_entries=2)

    def test_multiple_empty_lines(self):
        """
        see http://sourceforge.net/p/python-ldap/feature-requests/18/
        """
        return # disabled
        self.check_roundtrip("""
                # silly example
                dn: uid=one,dc=tld
                uid: one


                # another silly example
                dn: uid=two,dc=tld
                uid: two
            """, [
                ('uid=one,dc=tld', {'uid': [b'one']}),
                ('uid=two,dc=tld', {'uid': [b'two']}),
            ])


if __name__ == '__main__':
    unittest.main()
