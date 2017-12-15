# -*- coding: utf-8 -*-
"""
Automatic tests for python-ldap's module ldap.ldapobject

See https://www.python-ldap.org/ for details.
"""

from __future__ import unicode_literals

import sys

if sys.version_info[0] <= 2:
    PY2 = True
    text_type = unicode
else:
    PY2 = False
    text_type = str

import contextlib
import linecache
import os
import unittest
import warnings
import pickle
import warnings
from slapdtest import SlapdTestCase, requires_sasl, requires_tls

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.ldapobject import SimpleLDAPObject, ReconnectLDAPObject

LDIF_TEMPLATE = """dn: %(suffix)s
objectClass: dcObject
objectClass: organization
dc: %(dc)s
o: %(dc)s

dn: %(rootdn)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: %(rootcn)s
userPassword: %(rootpw)s

dn: cn=user1,%(suffix)s
objectClass: applicationProcess
objectClass: simpleSecurityObject
cn: user1
userPassword: user1_pw

dn: cn=Foo1,%(suffix)s
objectClass: organizationalRole
cn: Foo1

dn: cn=Foo2,%(suffix)s
objectClass: organizationalRole
cn: Foo2

dn: cn=Foo3,%(suffix)s
objectClass: organizationalRole
cn: Foo3

dn: ou=Container,%(suffix)s
objectClass: organizationalUnit
ou: Container

dn: cn=Foo4,ou=Container,%(suffix)s
objectClass: organizationalRole
cn: Foo4

"""


class Test00_SimpleLDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """

    ldap_object_class = SimpleLDAPObject

    @classmethod
    def setUpClass(cls):
        super(Test00_SimpleLDAPObject, cls).setUpClass()
        # insert some Foo* objects via ldapadd
        cls.server.ldapadd(
            LDIF_TEMPLATE % {
                'suffix':cls.server.suffix,
                'rootdn':cls.server.root_dn,
                'rootcn':cls.server.root_cn,
                'rootpw':cls.server.root_pw,
                'dc': cls.server.suffix.split(',')[0][3:],
            }
        )

    def setUp(self):
        try:
            self._ldap_conn
        except AttributeError:
            # open local LDAP connection
            self._ldap_conn = self._open_ldap_conn(bytes_mode=False)

    def test_reject_bytes_base(self):
        base = self.server.suffix
        l = self._ldap_conn

        with self.assertRaises(TypeError):
            l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*'])
        with self.assertRaises(TypeError):
            l.search_s(base, ldap.SCOPE_SUBTREE, b'(cn=Foo*)', ['*'])
        with self.assertRaises(TypeError):
            l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=Foo*)', [b'*'])

    def test_search_keys_are_text(self):
        base = self.server.suffix
        l = self._ldap_conn
        result = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*'])
        result.sort()
        dn, fields = result[0]
        self.assertEqual(dn, 'cn=Foo1,%s' % base)
        self.assertEqual(type(dn), text_type)
        for key, values in fields.items():
            self.assertEqual(type(key), text_type)
            for value in values:
                self.assertEqual(type(value), bytes)

    def _get_bytes_ldapobject(self, explicit=True):
        if explicit:
            kwargs = {'bytes_mode': True}
        else:
            kwargs = {}
        return self._open_ldap_conn(
            who=self.server.root_dn.encode('utf-8'),
            cred=self.server.root_pw.encode('utf-8'),
            **kwargs
        )

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_bytesmode_search_requires_bytes(self):
        l = self._get_bytes_ldapobject()
        base = self.server.suffix

        with self.assertRaises(TypeError):
            l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, '(cn=Foo*)', [b'*'])
        with self.assertRaises(TypeError):
            l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, b'(cn=Foo*)', ['*'])
        with self.assertRaises(TypeError):
            l.search_s(base, ldap.SCOPE_SUBTREE, b'(cn=Foo*)', [b'*'])

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_bytesmode_search_results_have_bytes(self):
        l = self._get_bytes_ldapobject()
        base = self.server.suffix
        result = l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, b'(cn=Foo*)', [b'*'])
        result.sort()
        dn, fields = result[0]
        self.assertEqual(dn, b'cn=Foo1,%s' % base)
        self.assertEqual(type(dn), bytes)
        for key, values in fields.items():
            self.assertEqual(type(key), bytes)
            for value in values:
                self.assertEqual(type(value), bytes)

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_unset_bytesmode_search_warns_bytes(self):
        l = self._get_bytes_ldapobject(explicit=False)
        base = self.server.suffix

        l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, '(cn=Foo*)', [b'*'])
        l.search_s(base.encode('utf-8'), ldap.SCOPE_SUBTREE, b'(cn=Foo*)', ['*'])
        l.search_s(base, ldap.SCOPE_SUBTREE, b'(cn=Foo*)', [b'*'])

    def test_search_accepts_unicode_dn(self):
        base = self.server.suffix
        l = self._ldap_conn

        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            result = l.search_s("CN=abc\U0001f498def", ldap.SCOPE_SUBTREE)

    def test_filterstr_accepts_unicode(self):
        l = self._ldap_conn
        base = self.server.suffix
        result = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=abc\U0001f498def)', ['*'])
        self.assertEqual(result, [])

    def test_attrlist_accepts_unicode(self):
        base = self.server.suffix
        result = self._ldap_conn.search_s(
            base, ldap.SCOPE_SUBTREE,
            '(cn=Foo*)', ['abc', 'abc\U0001f498def'])
        result.sort()

        for dn, attrs in result:
            self.assertIsInstance(dn, text_type)
            self.assertEqual(attrs, {})

    def test001_search_subtree(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_SUBTREE,
            '(cn=Foo*)',
            attrlist=['*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': [b'Foo1'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': [b'Foo2'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': [b'Foo3'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo4,ou=Container,'+self.server.suffix,
                    {'cn': [b'Foo4'], 'objectClass': [b'organizationalRole']}
                ),
            ]
        )

    def test002_search_onelevel(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_ONELEVEL,
            '(cn=Foo*)',
            ['*'],
        )
        result.sort()
        self.assertEqual(
            result,
            [
                (
                    'cn=Foo1,'+self.server.suffix,
                    {'cn': [b'Foo1'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo2,'+self.server.suffix,
                    {'cn': [b'Foo2'], 'objectClass': [b'organizationalRole']}
                ),
                (
                    'cn=Foo3,'+self.server.suffix,
                    {'cn': [b'Foo3'], 'objectClass': [b'organizationalRole']}
                ),
            ]
        )

    def test003_search_oneattr(self):
        result = self._ldap_conn.search_s(
            self.server.suffix,
            ldap.SCOPE_SUBTREE,
            '(cn=Foo4)',
            ['cn'],
        )
        result.sort()
        self.assertEqual(
            result,
            [('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': [b'Foo4']})]
        )

    def test_search_subschema(self):
        l = self._ldap_conn
        dn = l.search_subschemasubentry_s()
        self.assertIsInstance(dn, text_type)
        self.assertEqual(dn, "cn=Subschema")

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_search_subschema_have_bytes(self):
        l = self._get_bytes_ldapobject(explicit=False)
        dn = l.search_subschemasubentry_s()
        self.assertIsInstance(dn, bytes)
        self.assertEqual(dn, b"cn=Subschema")

    def test004_errno107(self):
        l = self.ldap_object_class('ldap://127.0.0.1:42')
        try:
            m = l.simple_bind_s("", "")
            r = l.result4(m, ldap.MSG_ALL, self.timeout)
        except ldap.SERVER_DOWN as ldap_err:
            errno = ldap_err.args[0]['errno']
            if errno != 107:
                self.fail("expected errno=107, got %d" % errno)
            info = ldap_err.args[0]['info']
            if info != os.strerror(107):
                self.fail("expected info=%r, got %d" % (os.strerror(107), info))
        else:
            self.fail("expected SERVER_DOWN, got %r" % r)

    def test005_invalid_credentials(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        # search with invalid filter
        try:
            m = l.simple_bind(self.server.root_dn, self.server.root_pw+'wrong')
            r = l.result4(m, ldap.MSG_ALL)
        except ldap.INVALID_CREDENTIALS:
            pass
        else:
            self.fail("expected INVALID_CREDENTIALS, got %r" % r)

    @requires_sasl()
    def test006_sasl_extenal_bind_s(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s(authz_id=authz_id)
        self.assertEqual(l.whoami_s(), authz_id.lower())

    def test007_timeout(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        m = l.search_ext(self.server.suffix, ldap.SCOPE_SUBTREE, '(objectClass=*)')
        l.abandon(m)
        with self.assertRaises(ldap.TIMEOUT):
            result = l.result(m, timeout=0.001)

    def assertIsSubclass(self, cls, other):
        self.assertTrue(
            issubclass(cls, other),
            cls.__mro__
        )

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_ldapbyteswarning(self):
        self.assertIsSubclass(ldap.LDAPBytesWarning, BytesWarning)
        self.assertIsSubclass(ldap.LDAPBytesWarning, Warning)
        self.assertIsInstance(self.server.suffix, text_type)
        with warnings.catch_warnings(record=True) as w:
            warnings.resetwarnings()
            warnings.simplefilter('always', ldap.LDAPBytesWarning)
            conn = self._get_bytes_ldapobject(explicit=False)
            result = conn.search_s(
                self.server.suffix,
                ldap.SCOPE_SUBTREE,
                b'(cn=Foo*)',
                attrlist=[b'*'],
            )
            self.assertEqual(len(result), 4)

        # ReconnectLDAP only emits one warning
        self.assertGreaterEqual(len(w), 1, w)
        msg = w[-1]
        self.assertIs(msg.category, ldap.LDAPBytesWarning)
        self.assertEqual(
            text_type(msg.message),
            "Received non-bytes value u'%s' with default (disabled) bytes "
            "mode; please choose an explicit option for bytes_mode on your "
            "LDAP connection" % self.server.suffix
        )

    @contextlib.contextmanager
    def catch_byteswarnings(self, *args, **kwargs):
        with warnings.catch_warnings(record=True) as w:
            conn = self._get_bytes_ldapobject(*args, **kwargs)
            warnings.resetwarnings()
            warnings.simplefilter('always', ldap.LDAPBytesWarning)
            yield conn, w

    def _check_byteswarning(self, warning, expected_message):
        self.assertIs(warning.category, ldap.LDAPBytesWarning)
        self.assertIn(expected_message, text_type(warning.message))

        def _normalize(filename):
            # Python 2 likes to report the ".pyc" file in warnings,
            # tracebacks or __file__.
            # Use the corresponding ".py" in that case.
            if filename.endswith('.pyc'):
                return filename[:-1]
            return filename

        # Assert warning points to a line marked CORRECT LINE in this file
        self.assertEquals(_normalize(warning.filename), _normalize(__file__))
        self.assertIn(
            'CORRECT LINE',
            linecache.getline(warning.filename, warning.lineno)
        )

    def _test_byteswarning_level_search(self, methodname):
        with self.catch_byteswarnings(explicit=False) as (conn, w):
            method = getattr(conn, methodname)
            result = method(
                self.server.suffix.encode('utf-8'),
                ldap.SCOPE_SUBTREE,
                '(cn=Foo*)',
                attrlist=['*'],  # CORRECT LINE
            )
            self.assertEqual(len(result), 4)

        self.assertEqual(len(w), 2, w)

        self._check_byteswarning(
            w[0], u"Received non-bytes value u'(cn=Foo*)'")

        self._check_byteswarning(
            w[1], u"Received non-bytes value u'*'")

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_byteswarning_level_search(self):
        self._test_byteswarning_level_search('search_s')
        self._test_byteswarning_level_search('search_st')
        self._test_byteswarning_level_search('search_ext_s')

    @unittest.skipUnless(PY2, "no bytes_mode under Py3")
    def test_byteswarning_initialize(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.resetwarnings()
            warnings.simplefilter('always', ldap.LDAPBytesWarning)
            bytes_uri = self.server.ldap_uri.decode('utf-8')
            self.ldap_object_class(bytes_uri)  # CORRECT LINE

        self.assertEqual(len(w), 1, w)

        self._check_byteswarning(
            w[0], u"Under Python 2, python-ldap uses bytes by default.")

    @requires_tls()
    def test_multiple_starttls(self):
        # Test for openldap does not re-register nss shutdown callbacks
        # after nss_Shutdown is called
        # https://github.com/python-ldap/python-ldap/issues/60
        # https://bugzilla.redhat.com/show_bug.cgi?id=1520990
        for _ in range(10):
            l = self.ldap_object_class(self.server.ldap_uri)
            l.set_option(ldap.OPT_X_TLS_CACERTFILE, self.server.cafile)
            l.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            l.start_tls_s()
            l.simple_bind_s(self.server.root_dn, self.server.root_pw)
            self.assertEqual(l.whoami_s(), 'dn:' + self.server.root_dn)


class Test01_ReconnectLDAPObject(Test00_SimpleLDAPObject):
    """
    test ReconnectLDAPObject by restarting slapd
    """

    ldap_object_class = ReconnectLDAPObject

    @requires_sasl()
    def test101_reconnect_sasl_external(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        authz_id = l.whoami_s()
        self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
        self.server.restart()
        self.assertEqual(l.whoami_s(), authz_id)

    def test102_reconnect_simple_bind(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)
        self.server.restart()
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)

    def test103_reconnect_get_state(self):
        l1 = self.ldap_object_class(self.server.ldapi_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l1.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
        self.assertEqual(
            l1.__getstate__(),
            {
                str('_last_bind'): (
                    'simple_bind_s',
                    (bind_dn, 'user1_pw'),
                    {}
                ),
                str('_options'): [(17, 3)],
                str('_reconnects_done'): 0,
                str('_retry_delay'): 60.0,
                str('_retry_max'): 1,
                str('_start_tls'): 0,
                str('_trace_level'): 0,
                str('_trace_stack_limit'): 5,
                str('_uri'): self.server.ldapi_uri,
                str('bytes_mode'): l1.bytes_mode,
                str('bytes_mode_hardfail'): l1.bytes_mode_hardfail,
                str('timeout'): -1,
            },
        )

    def test104_reconnect_restore(self):
        l1 = self.ldap_object_class(self.server.ldapi_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l1.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
        l1_state = pickle.dumps(l1)
        del l1
        l2 = pickle.loads(l1_state)
        self.assertEqual(l2.whoami_s(), 'dn:'+bind_dn)


if __name__ == '__main__':
    unittest.main()
