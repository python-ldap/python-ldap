import os
import unittest

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.controls import RequestControlTuples
from ldap.controls.pagedresults import SimplePagedResultsControl
from ldap.controls.openldap import SearchNoOpControl
from slapdtest import requires_tls


SENTINEL = object()

TEST_CTRL = RequestControlTuples([
    # with BER data
    SimplePagedResultsControl(criticality=0, size=5, cookie=b'cookie'),
    # value-less
    SearchNoOpControl(criticality=1),
])
TEST_CTRL_EXPECTED = [
    TEST_CTRL[0],
    # get_option returns empty bytes
    (TEST_CTRL[1][0], TEST_CTRL[1][1], b''),
]


class TestGlobalOptions(unittest.TestCase):
    def _check_option(self, option, value, expected=SENTINEL,
                      nonevalue=None):
        old = ldap.get_option(option)
        try:
            ldap.set_option(option, value)
            new = ldap.get_option(option)
            if expected is SENTINEL:
                self.assertEqual(new, value)
            else:
                self.assertEqual(new, expected)
        finally:
            ldap.set_option(option, old if old is not None else nonevalue)
            self.assertEqual(ldap.get_option(option), old)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            ldap.get_option(-1)
        with self.assertRaises(ValueError):
            ldap.set_option(-1, '')

    def test_timeout(self):
        self._check_option(ldap.OPT_TIMEOUT, 0, nonevalue=-1)
        self._check_option(ldap.OPT_TIMEOUT, 10.5, nonevalue=-1)
        with self.assertRaises(ValueError):
            self._check_option(ldap.OPT_TIMEOUT, -5, nonevalue=-1)
        with self.assertRaises(TypeError):
            ldap.set_option(ldap.OPT_TIMEOUT, object)

    def test_network_timeout(self):
        self._check_option(ldap.OPT_NETWORK_TIMEOUT, 0, nonevalue=-1)
        self._check_option(ldap.OPT_NETWORK_TIMEOUT, 10.5, nonevalue=-1)
        with self.assertRaises(ValueError):
            self._check_option(ldap.OPT_NETWORK_TIMEOUT, -5, nonevalue=-1)

    def _test_controls(self, option):
        self._check_option(option, [])
        self._check_option(option, TEST_CTRL, TEST_CTRL_EXPECTED)
        self._check_option(option, tuple(TEST_CTRL), TEST_CTRL_EXPECTED)
        with self.assertRaises(TypeError):
            ldap.set_option(option, object)

        with self.assertRaises(TypeError):
            # must contain a tuple
            ldap.set_option(option, [list(TEST_CTRL[0])])
        with self.assertRaises(TypeError):
            # data must be bytes or None
            ldap.set_option(
                option,
                [TEST_CTRL[0][0], TEST_CTRL[0][1], u'data']
            )

    def test_client_controls(self):
        self._test_controls(ldap.OPT_CLIENT_CONTROLS)

    def test_server_controls(self):
        self._test_controls(ldap.OPT_SERVER_CONTROLS)

    def test_uri(self):
        self._check_option(ldap.OPT_URI, "ldapi:///path/to/socket")
        with self.assertRaises(TypeError):
            ldap.set_option(ldap.OPT_URI, object)

    @requires_tls()
    def test_cafile(self):
        # None or a distribution or OS-specific path
        ldap.get_option(ldap.OPT_X_TLS_CACERTFILE)

    def test_readonly(self):
        value = ldap.get_option(ldap.OPT_API_INFO)
        self.assertIsInstance(value, dict)
        with self.assertRaises(ValueError) as e:
            ldap.set_option(ldap.OPT_API_INFO, value)
        self.assertIn('read-only', str(e.exception))


if __name__ == '__main__':
    unittest.main()
