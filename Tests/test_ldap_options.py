import os

import pytest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from pyasn1.error import PyAsn1Error

import ldap
from ldap.controls import RequestControl, RequestControlTuples
from ldap.controls.openldap import SearchNoOpControl
from ldap.controls.pagedresults import SimplePagedResultsControl
from ldap.ldapobject import SimpleLDAPObject
from slapdtest import SlapdTestCase, requires_tls


SENTINEL = object()

TEST_CTRL = RequestControlTuples(
    [
        # with BER data
        SimplePagedResultsControl(criticality=0, size=5, cookie=b'cookie'),
        # value-less
        SearchNoOpControl(criticality=1),
    ]
)
TEST_CTRL_EXPECTED = [
    TEST_CTRL[0],
    # Noop has no value
    (TEST_CTRL[1][0], TEST_CTRL[1][1], None),
]


class BaseTestOptions:
    """Common tests for getting/setting options

    Used in subclasses below
    """

    def get_option(self, option):
        raise NotImplementedError()

    def set_option(self, option, value):
        raise NotImplementedError()

    def _check_option(self, option, value, expected=SENTINEL):
        old = self.get_option(option)
        try:
            self.set_option(option, value)
            new = self.get_option(option)
            if expected is SENTINEL:
                assert new == value
            else:
                assert new == expected
        finally:
            self.set_option(option, old)
            assert self.get_option(option) == old

    def test_invalid(self):
        with pytest.raises(ValueError):
            self.get_option(-1)
        with pytest.raises(ValueError):
            self.set_option(-1, '')

    def _test_timeout(self, option):
        self._check_option(option, 10.5)
        self._check_option(option, 0)
        with pytest.raises(ValueError):
            self._check_option(option, -5)
        with pytest.raises(TypeError):
            self.set_option(option, object)
        with pytest.raises(OverflowError):
            self._check_option(option, 10**1000)
        old = self.get_option(option)
        try:
            self.set_option(option, None)
            assert self.get_option(option) is None
            self.set_option(option, -1)
            assert self.get_option(option) is None
        finally:
            self.set_option(option, old)

    def test_timeout(self):
        self._test_timeout(ldap.OPT_TIMEOUT)

    def test_network_timeout(self):
        self._test_timeout(ldap.OPT_NETWORK_TIMEOUT)

    def _test_controls(self, option):
        self._check_option(option, [])
        self._check_option(option, TEST_CTRL, TEST_CTRL_EXPECTED)
        self._check_option(option, tuple(TEST_CTRL), TEST_CTRL_EXPECTED)
        with pytest.raises(TypeError):
            self.set_option(option, object)

        with pytest.raises(TypeError):
            # must contain a tuple
            self.set_option(option, [list(TEST_CTRL[0])])
        with pytest.raises(TypeError):
            # data must be bytes or None
            self.set_option(option, [TEST_CTRL[0][0], TEST_CTRL[0][1], 'data'])

    def test_client_controls(self):
        self._test_controls(ldap.OPT_CLIENT_CONTROLS)

    def test_server_controls(self):
        self._test_controls(ldap.OPT_SERVER_CONTROLS)

    def test_uri(self):
        self._check_option(ldap.OPT_URI, 'ldapi:///path/to/socket')
        with pytest.raises(TypeError):
            self.set_option(ldap.OPT_URI, object)

    @requires_tls()
    def test_cafile(self):
        # None or a distribution or OS-specific path
        self.get_option(ldap.OPT_X_TLS_CACERTFILE)

    def test_readonly(self):
        value = self.get_option(ldap.OPT_API_INFO)
        assert isinstance(value, dict)
        with pytest.raises(ValueError) as e:
            self.set_option(ldap.OPT_API_INFO, value)
        assert 'read-only' in str(e.value)


class TestGlobalOptions(BaseTestOptions):
    """Test setting/getting options globally"""

    def get_option(self, option):
        return ldap.get_option(option)

    def set_option(self, option, value):
        return ldap.set_option(option, value)


class TestLDAPObjectOptions(BaseTestOptions, SlapdTestCase):
    """Test setting/getting connection-specific options"""

    ldap_object_class = SimpleLDAPObject

    def setup_method(self):
        self.conn = self._open_ldap_conn(who=self.server.root_dn, cred=self.server.root_pw)

    def teardown_method(self):
        self.conn.unbind_s()
        self.conn = None

    def get_option(self, option):
        return self.conn.get_option(option)

    def set_option(self, option, value):
        return self.conn.set_option(option, value)

    def test_network_timeout_attribute(self):
        option = ldap.OPT_NETWORK_TIMEOUT
        old = self.get_option(option)
        try:
            assert self.conn.network_timeout == old

            self.conn.network_timeout = 5
            assert self.conn.network_timeout == 5
            assert self.get_option(option) == 5

            self.conn.network_timeout = -1
            assert self.conn.network_timeout is None
            assert self.get_option(option) is None

            self.conn.network_timeout = 10.5
            assert self.conn.network_timeout == pytest.approx(10.5)
            assert self.get_option(option) == pytest.approx(10.5)

            self.conn.network_timeout = None
            assert self.conn.network_timeout is None
            assert self.get_option(option) is None
        finally:
            self.set_option(option, old)

    # These options hold request controls, but get_option() decodes them
    # with the response classes in KNOWN_RESPONSE_CONTROLS, so only
    # controls with identical request and response schemas round-trip.
    # Returning raw tuples like the module-level API is a 4.0 question, #643.
    def _test_controls(self, option):
        self._check_option(option, [])

        self.set_option(
            option,
            [
                SimplePagedResultsControl(criticality=0, size=5, cookie=b'cookie'),
            ],
        )
        try:
            (paged,) = self.get_option(option)
            assert isinstance(paged, SimplePagedResultsControl)
            assert paged.criticality == 0
            assert paged.size == 5
            assert paged.cookie == b'cookie'
        finally:
            self.set_option(option, [])

        # no request value, SEQUENCE response: critical raises,
        # non-critical is dropped
        self.set_option(option, [SearchNoOpControl(criticality=1)])
        try:
            with pytest.raises(PyAsn1Error):
                self.get_option(option)
        finally:
            self.set_option(option, [])
        self.set_option(option, [SearchNoOpControl(criticality=0)])
        try:
            assert self.get_option(option) == []
        finally:
            self.set_option(option, [])

        with pytest.raises(TypeError):
            self.set_option(option, object)
        with pytest.raises(TypeError):
            # data must be bytes or None
            self.set_option(
                option,
                [
                    RequestControl(TEST_CTRL[0][0], TEST_CTRL[0][1], 'data'),
                ],
            )
