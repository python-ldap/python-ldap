import os


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import sss


class TestControlsPPolicy:
    def test_create_sss_request_control(self):
        control = sss.SSSRequestControl(ordering_rules=['-uidNumber'])
        assert control.ordering_rules == ['-uidNumber']
