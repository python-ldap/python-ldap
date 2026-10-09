"""
Automatic tests for python-ldap's C wrapper module _ldap

See https://www.python-ldap.org/ for details.
"""

import contextlib
import errno
import os
import socket

import pytest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

# import the plain C wrapper module
from ldap import _ldap
from slapdtest import SlapdTestCase, requires_init_fd, requires_tls


class TestLdapCExtension(SlapdTestCase):
    """
    These tests apply only to the ldap._ldap module and therefore bypass the
    LDAPObject wrapper completely.
    """

    timeout = 5

    @classmethod
    def setup_class(cls):
        super().setup_class()
        # add two initial objects after server was started and is still empty
        suffix_dc = cls.server.suffix.split(',')[0][3:]
        cls.server._log.debug(
            'adding %s and %s',
            cls.server.suffix,
            cls.server.root_dn,
        )
        cls.server.ldapadd(
            '\n'.join(
                [
                    'dn: ' + cls.server.suffix,
                    'objectClass: dcObject',
                    'objectClass: organization',
                    'dc: ' + suffix_dc,
                    'o: ' + suffix_dc,
                    '',
                    'dn: ' + cls.server.root_dn,
                    'objectClass: applicationProcess',
                    'cn: ' + cls.server.root_cn,
                    '',
                ]
            )
        )

    def setup_method(self):
        super().setup_method()
        self._writesuffix = None

    def teardown_method(self):
        # cleanup test subtree
        if self._writesuffix is not None:
            self.server.ldapdelete(self._writesuffix, recursive=True)
        super().teardown_method()

    @property
    def writesuffix(self):
        """Initialize writesuffix on demand

        Creates a clean subtree for tests that write to slapd. ldapdelete
        is not able to delete a Root DSE, therefore we need a temporary
        work space.

        :return: DN
        """
        if self._writesuffix is not None:
            return self._writesuffix
        self._writesuffix = f'ou=write tests,{self.server.suffix}'
        # Add writeable subtree
        self.server.ldapadd(
            '\n'.join(
                [
                    'dn: ' + self._writesuffix,
                    'objectClass: organizationalUnit',
                    'ou:' + self._writesuffix.split(',')[0][3:],
                    '',
                ]
            )
        )
        return self._writesuffix

    def _open_conn(self, bind=True):
        """
        Starts a server, and returns a LDAPObject bound to it
        """
        l = _ldap.initialize(self.server.ldap_uri)
        if bind:
            self._bind_conn(l)
        return l

    @contextlib.contextmanager
    def _open_conn_fd(self, bind=True):
        sock = socket.create_connection((self.server.hostname, self.server.port))
        try:
            l = _ldap.initialize_fd(sock.fileno(), self.server.ldap_uri)
        except Exception:
            sock.close()
            raise
        fd = sock.detach()
        if bind:
            self._bind_conn(l)
        yield fd, l

    def _bind_conn(self, l):
        # Perform a simple bind
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        m = l.simple_bind(self.server.root_dn, self.server.root_pw)
        result, _pmsg, msgid, _ctrls = l.result4(m, _ldap.MSG_ONE, self.timeout)
        assert result == _ldap.RES_BIND
        assert isinstance(msgid, int)

    # Test for the existence of a whole bunch of constants
    # that the C module is supposed to export
    def test_constants(self):
        """
        Test whether all libldap-derived constants are correct
        """
        assert _ldap.PORT == 389
        assert _ldap.VERSION1 == 1
        assert _ldap.VERSION2 == 2
        assert _ldap.VERSION3 == 3

        # constants for result4()
        assert _ldap.RES_BIND == 0x61
        assert _ldap.RES_SEARCH_ENTRY == 0x64
        assert _ldap.RES_SEARCH_RESULT == 0x65
        assert _ldap.RES_MODIFY == 0x67
        assert _ldap.RES_ADD == 0x69
        assert _ldap.RES_DELETE == 0x6B
        assert _ldap.RES_MODRDN == 0x6D
        assert _ldap.RES_COMPARE == 0x6F
        assert _ldap.RES_SEARCH_REFERENCE == 0x73  # v3
        assert _ldap.RES_EXTENDED == 0x78  # v3
        # assert _ldap.RES_INTERMEDIATE == 0x79     # v3
        assert _ldap.RES_ANY is not None
        assert _ldap.RES_UNSOLICITED is not None

        assert _ldap.AUTH_NONE is not None
        assert _ldap.AUTH_SIMPLE is not None

        assert _ldap.SCOPE_BASE is not None
        assert _ldap.SCOPE_ONELEVEL is not None
        assert _ldap.SCOPE_SUBTREE is not None

        assert _ldap.MOD_ADD is not None
        assert _ldap.MOD_DELETE is not None
        assert _ldap.MOD_REPLACE is not None
        assert _ldap.MOD_INCREMENT is not None
        assert _ldap.MOD_BVALUES is not None

        # for result4()
        assert _ldap.MSG_ONE is not None
        assert _ldap.MSG_ALL is not None
        assert _ldap.MSG_RECEIVED is not None

        # for OPT_DEFEF
        assert _ldap.DEREF_NEVER is not None
        assert _ldap.DEREF_SEARCHING is not None
        assert _ldap.DEREF_FINDING is not None
        assert _ldap.DEREF_ALWAYS is not None

        # for OPT_SIZELIMIT, OPT_TIMELIMIT
        assert _ldap.NO_LIMIT is not None

        # standard options
        assert _ldap.OPT_API_INFO is not None
        assert _ldap.OPT_DEREF is not None
        assert _ldap.OPT_SIZELIMIT is not None
        assert _ldap.OPT_TIMELIMIT is not None
        assert _ldap.OPT_REFERRALS is not None
        assert _ldap.OPT_RESTART is not None
        assert _ldap.OPT_PROTOCOL_VERSION is not None
        assert _ldap.OPT_SERVER_CONTROLS is not None
        assert _ldap.OPT_CLIENT_CONTROLS is not None
        assert _ldap.OPT_API_FEATURE_INFO is not None
        assert _ldap.OPT_HOST_NAME is not None
        assert _ldap.OPT_ERROR_NUMBER is not None  # = OPT_RESULT_CODE
        assert _ldap.OPT_ERROR_STRING is not None  # = OPT_DIAGNOSITIC_MESSAGE
        assert _ldap.OPT_MATCHED_DN is not None

        # OpenLDAP specific
        assert _ldap.OPT_DEBUG_LEVEL is not None
        assert _ldap.OPT_TIMEOUT is not None
        assert _ldap.OPT_REFHOPLIMIT is not None
        assert _ldap.OPT_NETWORK_TIMEOUT is not None
        assert _ldap.OPT_URI is not None
        # assert _ldap.OPT_REFERRAL_URLS is not None
        # assert _ldap.OPT_SOCKBUF is not None
        # assert _ldap.OPT_DEFBASE is not None
        # assert _ldap.OPT_CONNECT_ASYNC is not None

        # str2dn()
        assert _ldap.DN_FORMAT_LDAP is not None
        assert _ldap.DN_FORMAT_LDAPV3 is not None
        assert _ldap.DN_FORMAT_LDAPV2 is not None
        assert _ldap.DN_FORMAT_DCE is not None
        assert _ldap.DN_FORMAT_UFN is not None
        assert _ldap.DN_FORMAT_AD_CANONICAL is not None
        assert _ldap.DN_FORMAT_MASK is not None
        assert _ldap.DN_PRETTY is not None
        assert _ldap.DN_SKIP is not None
        assert _ldap.DN_P_NOLEADTRAILSPACES is not None
        assert _ldap.DN_P_NOSPACEAFTERRDN is not None
        assert _ldap.DN_PEDANTIC is not None
        assert _ldap.AVA_NULL is not None
        assert _ldap.AVA_STRING is not None
        assert _ldap.AVA_BINARY is not None
        assert _ldap.AVA_NONPRINTABLE is not None

        # these two constants are pointless? XXX
        assert _ldap.OPT_ON == 1
        assert _ldap.OPT_OFF == 0

        # these constants useless after ldap_url_parse() was dropped XXX
        assert _ldap.URL_ERR_BADSCOPE is not None
        assert _ldap.URL_ERR_MEM is not None

    def test_test_flags(self):
        # test flag, see slapdtest and tox.ini
        disabled = os.environ.get('CI_DISABLED')
        if not disabled:
            pytest.skip('No CI_DISABLED env var')
        disabled = set(disabled.split(':'))
        if 'TLS' in disabled:
            assert not _ldap.TLS_AVAIL
        else:
            assert _ldap.TLS_AVAIL
        if 'SASL' in disabled:
            assert not _ldap.SASL_AVAIL
        else:
            assert _ldap.SASL_AVAIL

    def test_ldap_type(self):
        ldap_type = type(self._open_conn())
        # Python 3.10+ versions use qualified class name
        assert repr(ldap_type) in {"<class 'LDAP'>", "<class '_ldap.LDAP'>"}
        with pytest.raises(TypeError, match=r"cannot create '.*LDAP' instances"):
            ldap_type()

    def test_simple_bind(self):
        self._open_conn()

    def test_simple_bind_fileno(self):
        with self._open_conn_fd() as (_fd, l):
            assert l.whoami_s() == 'dn:' + self.server.root_dn

    @requires_init_fd()
    def test_simple_bind_fileno_invalid(self):
        fd = os.open(os.devnull, os.O_RDWR)
        l = _ldap.initialize_fd(fd, self.server.ldap_uri)
        with pytest.raises(_ldap.SERVER_DOWN):
            self._bind_conn(l)
        l.unbind_ext()

    @requires_init_fd()
    def test_simple_bind_fileno_closed(self):
        with self._open_conn_fd() as (fd, l):
            assert l.whoami_s() == 'dn:' + self.server.root_dn

            sock = socket.socket(fileno=fd)
            sock.shutdown(socket.SHUT_RDWR)
            sock.detach()

            with pytest.raises(_ldap.SERVER_DOWN):
                l.whoami_s()

    @requires_init_fd()
    def test_simple_bind_fileno_rebind(self):
        with self._open_conn_fd() as (_fd, l):
            assert l.whoami_s() == 'dn:' + self.server.root_dn
            l.unbind_ext()
            with pytest.raises(_ldap.LDAPError):
                self._bind_conn(l)

    def test_simple_anonymous_bind(self):
        l = self._open_conn(bind=False)
        m = l.simple_bind('', '')
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_BIND
        assert msgid == m
        assert pmsg == []
        assert ctrls == []

    @pytest.mark.skipif(
        not (_ldap.VENDOR_VERSION >= 20500 and _ldap._VENDOR_VERSION_RUNTIME >= 20500),
        reason='Test requires libldap 2.5+',
    )
    def test_connect(self):
        l = self._open_conn(bind=False)
        invalid_fileno = l.get_option(_ldap.OPT_DESC)
        l.connect()
        fileno = l.get_option(_ldap.OPT_DESC)
        assert invalid_fileno != fileno

        self._bind_conn(l)

    @pytest.mark.skipif(not _ldap._VENDOR_VERSION_RUNTIME < 20500, reason='Test requires linking to libldap < 2.5')
    def test_connect_notimpl(self):
        l = self._open_conn(bind=False)
        with pytest.raises(NotImplementedError):
            l.connect()

    def test_anon_rootdse_search(self):
        l = self._open_conn(bind=False)
        # see if we can get the rootdse with anon search (without prior bind)
        m = l.search_ext(
            '',
            _ldap.SCOPE_BASE,
            '(objectClass=*)',
            ['objectClass', 'namingContexts'],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert pmsg[0][0] == ''  # rootDSE has no dn
        assert msgid == m
        assert ctrls == []
        root_dse = pmsg[0][1]
        assert 'objectClass' in root_dse
        assert b'OpenLDAProotDSE' in root_dse['objectClass']
        assert 'namingContexts' in root_dse
        assert root_dse['namingContexts'] == [self.server.suffix.encode('ascii')]

    def test_unbind(self):
        l = self._open_conn()
        m = l.unbind_ext()
        assert m is None
        # Second attempt to unbind should yield an exception
        with pytest.raises(_ldap.error):
            l.unbind_ext()

    def test_search_ext_individual(self):
        l = self._open_conn()
        # send search request
        m = l.search_ext(self.server.suffix, _ldap.SCOPE_SUBTREE, '(objectClass=dcObject)')
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ONE, self.timeout)
        # Expect to get just one object
        assert result == _ldap.RES_SEARCH_ENTRY
        assert len(pmsg) == 1
        assert len(pmsg[0]) == 2
        assert pmsg[0][0] == self.server.suffix
        assert pmsg[0][0] == self.server.suffix
        assert b'dcObject' in pmsg[0][1]['objectClass']
        assert b'organization' in pmsg[0][1]['objectClass']
        assert msgid == m
        assert ctrls == []

        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ONE, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert pmsg == []
        assert msgid == m
        assert ctrls == []

    def test_abandon(self):
        l = self._open_conn()
        m = l.search_ext(self.server.suffix, _ldap.SCOPE_SUBTREE, '(objectClass=*)')
        ret = l.abandon_ext(m)
        assert ret is None
        with pytest.raises(_ldap.TIMEOUT):
            l.result4(m, _ldap.MSG_ALL, 0.3)  # (timeout /could/ be longer)

    def test_search_ext_all(self):
        l = self._open_conn()
        # send search request
        m = l.search_ext(self.server.suffix, _ldap.SCOPE_SUBTREE, '(objectClass=*)')
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        # Expect to get some objects
        assert result == _ldap.RES_SEARCH_RESULT
        assert len(pmsg) >= 2
        assert msgid == m
        assert ctrls == []

    def test_invalid_search_filter(self):
        l = self._open_conn()
        with pytest.raises(_ldap.FILTER_ERROR):
            l.search_ext(self.server.suffix, _ldap.SCOPE_SUBTREE, 'bogus filter expr')

    def test_add(self):
        """
        test add operation
        """
        l = self._open_conn()
        m = l.add_ext(
            'cn=Foo,' + self.writesuffix,
            [
                ('objectClass', b'organizationalRole'),
                ('cn', b'Foo'),
                ('description', b'testing'),
            ],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD
        assert pmsg == []
        assert msgid == m
        assert ctrls == []
        # search for it back
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=Foo)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        # Expect to get the objects
        assert result == _ldap.RES_SEARCH_RESULT
        assert len(pmsg) == 1
        assert msgid == m
        assert ctrls == []
        assert pmsg[0] == (
            'cn=Foo,' + self.writesuffix,
            {
                'objectClass': [b'organizationalRole'],
                'cn': [b'Foo'],
                'description': [b'testing'],
            },
        )

    def test_compare(self):
        """
        test compare operation
        """
        l = self._open_conn()
        # first, add an object with a field we can compare on
        dn = 'cn=CompareTest,' + self.writesuffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', b'person'),
                ('sn', b'CompareTest'),
                ('cn', b'CompareTest'),
                ('userPassword', b'the_password'),
            ],
        )
        assert isinstance(m, int)
        result, _pmsg, _msgid, _ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD

        # try a false compare
        m = l.compare_ext(dn, 'userPassword', 'bad_string')
        with pytest.raises(_ldap.COMPARE_FALSE) as e:
            l.result4(m, _ldap.MSG_ALL, self.timeout)

        assert e.value.args[0]['msgid'] == m
        assert e.value.args[0]['msgtype'] == _ldap.RES_COMPARE
        assert e.value.args[0]['result'] == 5
        assert not e.value.args[0]['ctrls']

        # try a true compare
        m = l.compare_ext(dn, 'userPassword', 'the_password')
        with pytest.raises(_ldap.COMPARE_TRUE) as e:
            l.result4(m, _ldap.MSG_ALL, self.timeout)

        assert e.value.args[0]['msgid'] == m
        assert e.value.args[0]['msgtype'] == _ldap.RES_COMPARE
        assert e.value.args[0]['result'] == 6
        assert not e.value.args[0]['ctrls']

        # try a compare on bad attribute
        m = l.compare_ext(dn, 'badAttribute', 'ignoreme')
        with pytest.raises(_ldap.error) as e:
            l.result4(m, _ldap.MSG_ALL, self.timeout)

        assert e.value.args[0]['msgid'] == m
        assert e.value.args[0]['msgtype'] == _ldap.RES_COMPARE
        assert e.value.args[0]['result'] == 17
        assert not e.value.args[0]['ctrls']

    def test_delete_no_such_object(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.delete_ext('cn=DoesNotExist,' + self.server.suffix)
        with pytest.raises(_ldap.NO_SUCH_OBJECT):
            l.result4(m, _ldap.MSG_ALL, self.timeout)

    def test_delete(self):
        l = self._open_conn()
        # first, add an object we will delete
        dn = 'cn=Deleteme,' + self.writesuffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', b'organizationalRole'),
                ('cn', b'Deleteme'),
            ],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD

        m = l.delete_ext(dn)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_DELETE
        assert msgid == m
        assert pmsg == []
        assert ctrls == []

    def test_modify_no_such_object(self):
        l = self._open_conn()

        # try deleting an object that doesn't exist
        m = l.modify_ext(
            'cn=DoesNotExist,' + self.writesuffix,
            [
                (_ldap.MOD_ADD, 'description', [b'blah']),
            ],
        )
        with pytest.raises(_ldap.NO_SUCH_OBJECT):
            l.result4(m, _ldap.MSG_ALL, self.timeout)

    def test_modify_no_such_object_empty_attrs(self):
        """
        try deleting an object that doesn't exist
        """
        l = self._open_conn()
        m = l.modify_ext(
            'cn=DoesNotExist,' + self.server.suffix,
            [
                (_ldap.MOD_ADD, 'description', [b'dummy']),
            ],
        )
        assert isinstance(m, int)
        with pytest.raises(_ldap.NO_SUCH_OBJECT):
            l.result4(m, _ldap.MSG_ALL, self.timeout)

    def test_modify(self):
        """
        test modify operation
        """
        l = self._open_conn()
        # first, add an object we will delete
        dn = 'cn=AddToMe,' + self.writesuffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', b'person'),
                ('cn', b'AddToMe'),
                ('sn', b'Modify'),
                ('description', b'a description'),
            ],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD

        m = l.modify_ext(
            dn,
            [
                (_ldap.MOD_ADD, 'description', [b'b desc', b'c desc']),
            ],
        )
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_MODIFY
        assert pmsg == []
        assert msgid == m
        assert ctrls == []
        # search for it back
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=AddToMe)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        # Expect to get the objects
        assert result == _ldap.RES_SEARCH_RESULT
        assert len(pmsg) == 1
        assert msgid == m
        assert ctrls == []
        assert pmsg[0][0] == dn
        d = list(pmsg[0][1]['description'])
        d.sort()
        assert d == [b'a description', b'b desc', b'c desc']

    def test_rename(self):
        l = self._open_conn()
        dn = 'cn=RenameMe,' + self.writesuffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', b'organizationalRole'),
                ('cn', b'RenameMe'),
            ],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD

        # do the rename with same parent
        m = l.rename(dn, 'cn=IAmRenamed')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_MODRDN
        assert msgid == m
        assert pmsg == []
        assert ctrls == []

        # make sure the old one is gone
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=RenameMe)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert len(pmsg) == 0  # expect no results
        assert msgid == m
        assert ctrls == []

        # check that the new one looks right
        dn2 = 'cn=IAmRenamed,' + self.writesuffix
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert msgid == m
        assert ctrls == []
        assert len(pmsg) == 1
        assert pmsg[0][0] == dn2
        assert pmsg[0][1]['cn'] == [b'IAmRenamed']

        # create the container
        containerDn = 'ou=RenameContainer,' + self.writesuffix
        m = l.add_ext(
            containerDn,
            [
                ('objectClass', b'organizationalUnit'),
                ('ou', b'RenameContainer'),
            ],
        )
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD

        # now rename from dn2 to the conater
        dn3 = 'cn=IAmRenamedAgain,' + containerDn

        # Now try renaming dn2 across container (simultaneous name change)
        m = l.rename(dn2, 'cn=IAmRenamedAgain', containerDn)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_MODRDN
        assert msgid == m
        assert pmsg == []
        assert ctrls == []

        # make sure dn2 is gone
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=IAmRenamed)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert len(pmsg) == 0  # expect no results
        assert msgid == m
        assert ctrls == []

        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(objectClass=*)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)

        # make sure dn3 is there
        m = l.search_ext(self.writesuffix, _ldap.SCOPE_SUBTREE, '(cn=IAmRenamedAgain)')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_SEARCH_RESULT
        assert msgid == m
        assert ctrls == []
        assert len(pmsg) == 1
        assert pmsg[0][0] == dn3
        assert pmsg[0][1]['cn'] == [b'IAmRenamedAgain']

    def test_whoami(self):
        l = self._open_conn()
        r = l.whoami_s()
        assert 'dn:' + self.server.root_dn == r

    def test_whoami_unbound(self):
        l = self._open_conn(bind=False)
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        r = l.whoami_s()
        assert '' == r

    def test_whoami_anonymous(self):
        l = self._open_conn(bind=False)
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        # Anonymous bind
        m = l.simple_bind('', '')
        result, _pmsg, _msgid, _ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_BIND
        # check with Who Am I? extended operation
        r = l.whoami_s()
        assert '' == r

    def test_whoami_after_unbind(self):
        # https://github.com/pyldap/pyldap/issues/29
        l = self._open_conn(bind=True)
        l.unbind_ext()
        with pytest.raises(_ldap.LDAPError):
            l.whoami_s()

    def test_passwd(self):
        l = self._open_conn()
        # first, create a user to change password on
        dn = 'cn=PasswordTest,' + self.writesuffix
        m = l.add_ext(
            dn,
            [
                ('objectClass', b'person'),
                ('sn', b'PasswordTest'),
                ('cn', b'PasswordTest'),
                ('userPassword', b'initial'),
            ],
        )
        assert isinstance(m, int)
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert result == _ldap.RES_ADD
        # try changing password with a wrong old-pw
        m = l.passwd(dn, 'bogus', 'ignored')
        assert isinstance(m, int)
        with pytest.raises(_ldap.UNWILLING_TO_PERFORM):
            l.result4(m, _ldap.MSG_ALL, self.timeout)
        # try changing password with a correct old-pw
        m = l.passwd(dn, 'initial', 'changed')
        result, pmsg, msgid, ctrls = l.result4(m, _ldap.MSG_ALL, self.timeout)
        assert msgid == m
        assert pmsg == []
        assert result == _ldap.RES_EXTENDED
        assert ctrls == []

    def test_options(self):
        oldval = _ldap.get_option(_ldap.OPT_PROTOCOL_VERSION)
        try:
            with pytest.raises(TypeError):
                _ldap.set_option(_ldap.OPT_PROTOCOL_VERSION, '3')

            _ldap.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION2)
            v = _ldap.get_option(_ldap.OPT_PROTOCOL_VERSION)
            assert v == _ldap.VERSION2
            _ldap.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
            v = _ldap.get_option(_ldap.OPT_PROTOCOL_VERSION)
            assert v == _ldap.VERSION3
        finally:
            _ldap.set_option(_ldap.OPT_PROTOCOL_VERSION, oldval)

        l = self._open_conn()

        # Try changing some basic options and checking that they took effect

        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION2)
        v = l.get_option(_ldap.OPT_PROTOCOL_VERSION)
        assert v == _ldap.VERSION2

        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        v = l.get_option(_ldap.OPT_PROTOCOL_VERSION)
        assert v == _ldap.VERSION3

        # Try setting options that will yield a known error.
        with pytest.raises(ValueError):
            _ldap.get_option(_ldap.OPT_MATCHED_DN)

    def _require_attr(self, obj, attrname):
        """Returns true if the attribute exists on the object.
        This is to allow some tests to be optional, because
        _ldap is compiled with different properties depending
        on the underlying C library.
        This could me made to thrown an exception if you want the
        tests to be strict."""
        return hasattr(obj, attrname)

    def test_sasl(self):
        l = self._open_conn()
        if not self._require_attr(l, 'sasl_interactive_bind_s'):  # HAVE_SASL
            return
        # TODO

    def test_cancel(self):
        l = self._open_conn()
        if not self._require_attr(l, 'cancel'):  # FEATURE_CANCEL
            return

    def test_enotconn(self):
        l = _ldap.initialize('ldap://127.0.0.1:42')
        with pytest.raises(_ldap.SERVER_DOWN) as excinfo:
            l.simple_bind('', '')
            # l.result4(m, _ldap.MSG_ALL, self.timeout)
        errno_val = excinfo.value.args[0]['errno']
        assert errno_val == errno.ENOTCONN

    def test_invalid_filter(self):
        l = self._open_conn(bind=False)
        # search with invalid filter

        def search_invalid_filter():
            m = l.search_ext('', _ldap.SCOPE_BASE, '(|(objectClass=*)')
            l.result4(m, _ldap.MSG_ALL, self.timeout)

        with pytest.raises(_ldap.FILTER_ERROR):
            search_invalid_filter()

    def test_invalid_credentials(self):
        l = self._open_conn(bind=False)
        # search with invalid filter

        def bind_with_invalid_credentials():
            m = l.simple_bind(self.server.root_dn, self.server.root_pw + 'wrong')
            l.result4(m, _ldap.MSG_ALL, self.timeout)

        with pytest.raises(_ldap.INVALID_CREDENTIALS):
            bind_with_invalid_credentials()

    # TODO: test_extop

    def check_invalid_controls(self, func, *args, **kwargs):
        post = kwargs.pop('post', ())
        assert not kwargs
        # last two args are serverctrls, clientctrls
        with pytest.raises(TypeError) as e:
            func(*(args + (object, None) + post))
        assert e.value.args[0] == 'LDAPControls_from_object(): expected a list'
        with pytest.raises(TypeError) as e:
            func(*(args + (None, object) + post))
        assert e.value.args[0] == 'LDAPControls_from_object(): expected a list'

    def test_invalid_controls(self):
        l = self._open_conn()
        self.check_invalid_controls(l.simple_bind, '', '')
        self.check_invalid_controls(l.whoami_s)
        self.check_invalid_controls(l.passwd, 'dn', 'initial', 'changed')
        self.check_invalid_controls(l.add_ext, 'dn', [('cn', b'cn')])
        self.check_invalid_controls(l.modify_ext, 'dn', [(_ldap.MOD_ADD, 'attr', [b'value'])])
        self.check_invalid_controls(l.compare_ext, 'dn', 'val1', 'val2')
        self.check_invalid_controls(l.rename, 'dn', 'newdn', 'container', False)
        self.check_invalid_controls(l.search_ext, 'dn', _ldap.SCOPE_SUBTREE, '(objectClass=*)', None, 1)
        self.check_invalid_controls(l.delete_ext, 'dn')
        m = l.search_ext(self.server.suffix, _ldap.SCOPE_SUBTREE, '(objectClass=*)')
        self.check_invalid_controls(l.abandon_ext, m)
        self.check_invalid_controls(l.cancel, 0)
        self.check_invalid_controls(l.extop, 'oid', 'value')
        if hasattr(l, 'sasl_bind_s'):
            self.check_invalid_controls(l.sasl_bind_s, 'dn', 'MECH', 'CRED')
        if hasattr(l, 'sasl_bind'):
            self.check_invalid_controls(l.sasl_bind, 'dn', 'MECH', 'CRED')
        if hasattr(l, 'sasl_interactive_bind_s'):
            self.check_invalid_controls(l.sasl_interactive_bind_s, 'who', 'SASLObject', post=(1,))
        self.check_invalid_controls(l.unbind_ext)

    @requires_tls()
    def test_tls_ext(self):
        l = self._open_conn(bind=False)
        # StartTLS needs LDAPv3
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        l.set_option(_ldap.OPT_X_TLS_CACERTFILE, self.server.cafile)
        # re-create TLS context
        l.set_option(_ldap.OPT_X_TLS_NEWCTX, 0)
        l.start_tls_s()

    @requires_tls()
    def test_tls_require_cert(self):
        # libldap defaults to secure cert validation
        # see libraries/libldap/init.c
        #     gopts->ldo_tls_require_cert = LDAP_OPT_X_TLS_DEMAND;

        assert _ldap.get_option(_ldap.OPT_X_TLS_REQUIRE_CERT) == _ldap.OPT_X_TLS_DEMAND
        l = self._open_conn(bind=False)
        assert l.get_option(_ldap.OPT_X_TLS_REQUIRE_CERT) == _ldap.OPT_X_TLS_DEMAND

    @requires_tls()
    def test_tls_ext_noca(self):
        l = self._open_conn(bind=False)
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        # fails because libldap defaults to secure cert validation but
        # the test CA is not installed as trust anchor.
        with pytest.raises(_ldap.CONNECT_ERROR) as e:
            l.start_tls_s()
        # known resaons:
        # Ubuntu on Travis: '(unknown error code)'
        # OpenSSL 1.1: error:1416F086:SSL routines:\
        #    tls_process_server_certificate:certificate verify failed
        # NSS: TLS error -8172:Peer's certificate issuer has \
        #    been marked as not trusted by the user.
        msg = str(e.value)
        candidates = ('certificate', 'tls', '(unknown error code)')
        if not any(s in msg.lower() for s in candidates):
            pytest.fail(msg)

    @requires_tls()
    def test_tls_ext_clientcert(self):
        l = self._open_conn(bind=False)
        l.set_option(_ldap.OPT_PROTOCOL_VERSION, _ldap.VERSION3)
        l.set_option(_ldap.OPT_X_TLS_CACERTFILE, self.server.cafile)
        l.set_option(_ldap.OPT_X_TLS_CERTFILE, self.server.clientcert)
        l.set_option(_ldap.OPT_X_TLS_KEYFILE, self.server.clientkey)
        l.set_option(_ldap.OPT_X_TLS_REQUIRE_CERT, _ldap.OPT_X_TLS_HARD)
        l.set_option(_ldap.OPT_X_TLS_NEWCTX, 0)
        l.start_tls_s()

    @requires_tls()
    def test_tls_packages(self):
        # libldap has tls_g.c, tls_m.c, and tls_o.c with ldap_int_tls_impl
        package = _ldap.get_option(_ldap.OPT_X_TLS_PACKAGE)
        assert package in {'GnuTLS', 'MozNSS', 'OpenSSL'}

    @pytest.mark.skipif(not hasattr(_ldap, 'OPT_X_TLS_REQUIRE_SAN'), reason='Test requires OPT_X_TLS_REQUIRE_SAN')
    def test_require_san(self):
        l = self._open_conn(bind=False)
        value = l.get_option(_ldap.OPT_X_TLS_REQUIRE_SAN)
        assert value in {
            _ldap.OPT_X_TLS_NEVER,
            _ldap.OPT_X_TLS_ALLOW,
            _ldap.OPT_X_TLS_TRY,
            _ldap.OPT_X_TLS_DEMAND,
            _ldap.OPT_X_TLS_HARD,
        }
        l.set_option(_ldap.OPT_X_TLS_REQUIRE_SAN, _ldap.OPT_X_TLS_TRY)
        assert l.get_option(_ldap.OPT_X_TLS_REQUIRE_SAN) == _ldap.OPT_X_TLS_TRY

    def test_str2dn(self):
        assert _ldap.str2dn('') == []
        with pytest.raises(TypeError):
            _ldap.str2dn(None)
        with pytest.raises(TypeError):
            _ldap.str2dn(object)
