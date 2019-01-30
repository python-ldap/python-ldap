import os
import unittest

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import sss


class TestControlsPPolicy(unittest.TestCase):
    def test_create_sss_request_control(self):
        control = sss.SSSRequestControl(ordering_rules=['-uidNumber'])
        self.assertEqual(control.ordering_rules, ['-uidNumber'])


if __name__ == '__main__':
    unittest.main()
