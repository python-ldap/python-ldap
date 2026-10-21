import os


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import ppolicy


PP_GRACEAUTH = b'0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x81\x01\x02'
PP_TIMEBEFORE = b'0\x84\x00\x00\x00\t\xa0\x84\x00\x00\x00\x03\x80\x012'


class TestControlsPPolicy:
    def check_ppolicy(self, pp, timeBeforeExpiration=None, graceAuthNsRemaining=None, error=None):
        assert pp.timeBeforeExpiration == timeBeforeExpiration
        assert pp.graceAuthNsRemaining == graceAuthNsRemaining
        assert pp.error == error

    def test_ppolicy_graceauth(self):
        pp = ppolicy.PasswordPolicyControl()
        pp.decodeControlValue(PP_GRACEAUTH)
        self.check_ppolicy(pp, graceAuthNsRemaining=2)

    def test_ppolicy_timebefore(self):
        pp = ppolicy.PasswordPolicyControl()
        pp.decodeControlValue(PP_TIMEBEFORE)
        self.check_ppolicy(pp, timeBeforeExpiration=50)
