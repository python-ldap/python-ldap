import os
import unittest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import psearch


class TestControlsPSearch(unittest.TestCase):
    def test_entry_change_notification_decode_utf8_dn(self):
        dn = 'cn=Michael Ströder,dc=example,dc=org'
        encoded_dn = dn.encode('utf-8')

        # EntryChangeNotification ::= SEQUENCE {
        #     changeType ENUMERATED (modDN = 8),
        #     previousDN LDAPDN OPTIONAL,
        #     changeNumber INTEGER OPTIONAL
        # }
        encoded = (
            b'\x30'
            + bytes([len(encoded_dn) + 8])
            + b'\x0a\x01\x08'
            + b'\x04'
            + bytes([len(encoded_dn)])
            + encoded_dn
            + b'\x02\x01\x2a'
        )

        control = psearch.EntryChangeNotificationControl()
        control.decodeControlValue(encoded)

        self.assertEqual(control.changeType, 8)
        self.assertEqual(control.previousDN, dn)
        self.assertEqual(control.changeNumber, 42)


if __name__ == '__main__':
    unittest.main()
