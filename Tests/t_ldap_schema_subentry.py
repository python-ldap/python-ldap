# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's class ldap.schema.SubSchema

See http://www.python-ldap.org/ for details.

$Id: t_ldap_schema_subentry.py,v 1.2 2017/04/28 07:30:59 stroeder Exp $
"""

import unittest
import time

import ldif
import ldap.schema

TEST_SUBSCHEMA_FILES = (
    'Tests/ldif/subschema-ipa.demo1.freeipa.org.ldif',
    'Tests/ldif/subschema-openldap-all.ldif',
)

class TestSubschemaLDIF(unittest.TestCase):
    """
    test ldap.schema.SubSchema with subschema subentries read from LDIF files
    """

    def test_subschema_file(self):
        for test_file in TEST_SUBSCHEMA_FILES:
            # Read and parse LDIF file
            ldif_file = open(test_file, 'rb')
            ldif_parser = ldif.LDIFRecordList(ldif_file,max_entries=1)
            ldif_parser.parse()
            _, subschema_subentry = ldif_parser.all_records[0]
            sub_schema = ldap.schema.SubSchema(subschema_subentry)


if __name__ == '__main__':
    unittest.main()
