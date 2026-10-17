import os
import unittest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import readentry


PRC_ENC = (
    b'db\x04)uid=Administrator,cn=users,l=school,l=dev0503\x04\tentryUUID1&\x04$5d96cc2c-8e13-103a-8ca5-2f74868e0e44'
)
PRC_DEC = b'0\x0b\x04\tentryUUID'


class TestLibldapControls(unittest.TestCase):
    def test_pagedresults_encode(self):
        pr = readentry.PostReadControl(True, ['entryUUID'])
        self.assertEqual(pr.encodeControlValue(), PRC_DEC)

    def test_readentry_decode(self):
        pr = readentry.PostReadControl(True, ['entryUUID'])
        pr.decodeControlValue(PRC_ENC)
        self.assertIsInstance(pr.dn, str)
        self.assertEqual(pr.entry, {'entryUUID': [b'5d96cc2c-8e13-103a-8ca5-2f74868e0e44']})

    def test_readentry_decode_utf8_dn(self):
        dn = 'cn=Michael Ströder,dc=example,dc=org'
        encoded_dn = dn.encode('utf-8')

        # SearchResultEntry containing a UTF-8 DN and no attributes
        encoded = b'\x64' + bytes([len(encoded_dn) + 4]) + b'\x04' + bytes([len(encoded_dn)]) + encoded_dn + b'\x30\x00'

        pr = readentry.PostReadControl(True, ['entryUUID'])
        pr.decodeControlValue(encoded)

        self.assertEqual(pr.dn, dn)
        self.assertEqual(pr.entry, {})


if __name__ == '__main__':
    unittest.main()
