import os


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.controls import libldap, pagedresults


PRC_BER = b'0\x0b\x02\x01\x05\x04\x06cookie'
SIZE = 5
COOKIE = b'cookie'


class TestLibldapControls:
    def test_pagedresults_encode(self):
        pr = pagedresults.SimplePagedResultsControl(size=SIZE, cookie=COOKIE)
        lib = libldap.SimplePagedResultsControl(size=SIZE, cookie=COOKIE)
        assert pr.encodeControlValue() == lib.encodeControlValue()
        assert pr.encodeControlValue() == PRC_BER

    def test_pagedresults_decode(self):
        pr = pagedresults.SimplePagedResultsControl()
        pr.decodeControlValue(PRC_BER)
        assert pr.size == SIZE
        # LDAPString (OCTET STRING)
        assert isinstance(pr.cookie, bytes)
        assert pr.cookie == COOKIE

        lib = libldap.SimplePagedResultsControl()
        lib.decodeControlValue(PRC_BER)
        assert lib.size == SIZE
        assert isinstance(lib.cookie, bytes)
        assert lib.cookie == COOKIE

    def test_matchedvalues(self):
        mvc = libldap.MatchedValuesControl()
        # unverified
        assert mvc.encodeControlValue() == b'0\r\x87\x0bobjectClass'

    def test_assertioncontrol(self):
        ac = libldap.AssertionControl()
        # unverified
        assert ac.encodeControlValue() == b'\x87\x0bobjectClass'
