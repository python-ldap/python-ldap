# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's class ldap.schema.SubSchema

See https://www.python-ldap.org/ for details.
"""

import unittest
import time

import ldif
import ldap.schema
from ldap.schema.models import ObjectClass

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

            # Smoke-check for listall() and attribute_types()
            for objclass in sub_schema.listall(ObjectClass):
                must, may = sub_schema.attribute_types([objclass])

                for oid, attributetype in must.items():
                    self.assertEqual(attributetype.oid, oid)
                for oid, attributetype in may.items():
                    self.assertEqual(attributetype.oid, oid)


if __name__ == '__main__':
    unittest.main()
