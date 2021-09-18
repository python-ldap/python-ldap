"""
Automatic tests for python-ldap's module ldap.ldapobject

See https://www.python-ldap.org/ for details.
"""
import base64
import errno
import linecache
import os
import re
import socket
import unittest
import pickle

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldap
from ldap.ldapobject import SimpleLDAPObject, ReconnectLDAPObject

from slapdtest import SlapdTestCase
from slapdtest import requires_ldapi, requires_sasl, requires_tls
from slapdtest import requires_init_fd

PEM_CERT_RE = re.compile(
    b'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
    re.DOTALL
)


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

SCHEMA_TEMPLATE = """dn: cn=mySchema,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: mySchema
olcAttributeTypes: ( 1.3.6.1.4.1.56207.1.1.1 NAME 'myAttribute'
    DESC 'fobar attribute'
    EQUALITY caseExactMatch
    ORDERING caseExactOrderingMatch
    SUBSTR caseExactSubstringsMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15
    SINGLE-VALUE
    USAGE userApplications
    X-ORIGIN 'foobar' )
olcObjectClasses: ( 1.3.6.1.4.1.56207.1.2.2 NAME 'myClass'
    DESC 'foobar objectclass'
    SUP top
    STRUCTURAL
    MUST myAttribute
    X-ORIGIN 'foobar' )"""


class Test00_SimpleLDAPObject(SlapdTestCase):
    """
    test LDAP search operations
    """

    ldap_object_class = SimpleLDAPObject

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
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

    def tearDown(self):
        del self._ldap_conn

    def reset_connection(self):
        try:
            del self._ldap_conn
        except AttributeError:
            pass

        self._ldap_conn = self._open_ldap_conn(bytes_mode=False)

    def test_reject_bytes_base(self):
        base = self.server.suffix
        l = self._ldap_conn

        with self.assertRaises(TypeError) as e:
            l.search_s(
                base.encode('utf-8'), ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*']
            )
        # Python 3.4.x does not include 'search_ext()' in message
        self.assertEqual(
            "search_ext() argument 1 must be str, not bytes",
            str(e.exception)
        )

        with self.assertRaises(TypeError) as e:
            l.search_s(
                base, ldap.SCOPE_SUBTREE, b'(cn=Foo*)', ['*']
            )
        self.assertEqual(
            "search_ext() argument 3 must be str, not bytes",
            str(e.exception)
        )

        with self.assertRaises(TypeError) as e:
            l.search_s(
                base, ldap.SCOPE_SUBTREE, '(cn=Foo*)', [b'*']
            )
        self.assertEqual(
            ('attrs_from_List(): expected string in list', b'*'),
            e.exception.args
        )

    def test_search_keys_are_text(self):
        base = self.server.suffix
        l = self._ldap_conn
        result = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn=Foo*)', ['*'])
        result.sort()
        dn, fields = result[0]
        self.assertEqual(dn, 'cn=Foo1,%s' % base)
        self.assertEqual(type(dn), str)
        for key, values in fields.items():
            self.assertEqual(type(key), str)
            for value in values:
                self.assertEqual(type(value), bytes)

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
            self.assertIsInstance(dn, str)
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

    def test_find_unique_entry(self):
        result = self._ldap_conn.find_unique_entry(
            self.server.suffix,
            ldap.SCOPE_SUBTREE,
            '(cn=Foo4)',
            ['cn'],
        )
        self.assertEqual(
            result,
            ('cn=Foo4,ou=Container,'+self.server.suffix, {'cn': [b'Foo4']})
        )
        with self.assertRaises(ldap.SIZELIMIT_EXCEEDED):
            # > 2 entries returned
            self._ldap_conn.find_unique_entry(
                self.server.suffix,
                ldap.SCOPE_ONELEVEL,
                '(cn=Foo*)',
                ['*'],
            )
        with self.assertRaises(ldap.NO_UNIQUE_ENTRY):
            # 0 entries returned
            self._ldap_conn.find_unique_entry(
                self.server.suffix,
                ldap.SCOPE_ONELEVEL,
                '(cn=Bar*)',
                ['*'],
            )

    def test_search_subschema(self):
        l = self._ldap_conn
        dn = l.search_subschemasubentry_s()
        self.assertIsInstance(dn, str)
        self.assertEqual(dn, "cn=Subschema")
        subschema = l.read_subschemasubentry_s(dn)
        self.assertIsInstance(subschema, dict)
        self.assertEqual(
            sorted(subschema),
            [
                'attributeTypes',
                'ldapSyntaxes',
                'matchingRuleUse',
                'matchingRules',
                'objectClasses'
            ]
        )

    def test004_enotconn(self):
        l = self.ldap_object_class('ldap://127.0.0.1:42')
        try:
            m = l.simple_bind_s("", "")
            r = l.result4(m, ldap.MSG_ALL, self.timeout)
        except ldap.SERVER_DOWN as ldap_err:
            errno_val = ldap_err.args[0]['errno']
            if errno_val != errno.ENOTCONN:
                self.fail("expected errno=%d, got %d"
                          % (errno.ENOTCONN, errno_val))
            info = ldap_err.args[0]['info']
            expected_info = os.strerror(errno.ENOTCONN)
            if info != expected_info:
                self.fail(f"expected info={expected_info!r}, got {info!r}")
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
    @requires_ldapi()
    def test006_sasl_external_bind_s(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        self.assertEqual(l.whoami_s(), 'dn:'+self.server.root_dn.lower())
        authz_id = 'dn:cn=Foo2,%s' % (self.server.suffix)
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s(authz_id=authz_id)
        self.assertEqual(l.whoami_s(), authz_id.lower())

    @requires_sasl()
    @requires_ldapi()
    def test006_sasl_options(self):
        l = self.ldap_object_class(self.server.ldapi_uri)

        minssf = l.get_option(ldap.OPT_X_SASL_SSF_MIN)
        self.assertGreaterEqual(minssf, 0)
        self.assertLessEqual(minssf, 256)
        maxssf = l.get_option(ldap.OPT_X_SASL_SSF_MAX)
        self.assertGreaterEqual(maxssf, 0)
        # libldap sets SSF_MAX to INT_MAX
        self.assertLessEqual(maxssf, 2**31 - 1)

        l.set_option(ldap.OPT_X_SASL_SSF_MIN, 56)
        l.set_option(ldap.OPT_X_SASL_SSF_MAX, 256)
        self.assertEqual(l.get_option(ldap.OPT_X_SASL_SSF_MIN), 56)
        self.assertEqual(l.get_option(ldap.OPT_X_SASL_SSF_MAX), 256)

        l.sasl_external_bind_s()
        with self.assertRaisesRegex(ValueError, "write-only option"):
            l.get_option(ldap.OPT_X_SASL_SSF_EXTERNAL)
        l.set_option(ldap.OPT_X_SASL_SSF_EXTERNAL, 256)
        self.assertEqual(l.whoami_s(), 'dn:' + self.server.root_dn.lower())

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

    def test_simple_bind_noarg(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        l.simple_bind_s()
        self.assertEqual(l.whoami_s(), '')
        l = self.ldap_object_class(self.server.ldap_uri)
        l.simple_bind_s(None, None)
        self.assertEqual(l.whoami_s(), '')

    def _check_byteswarning(self, warning, expected_message):
        self.assertIs(warning.category, ldap.LDAPBytesWarning)
        self.assertIn(expected_message, str(warning.message))

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

    @requires_tls()
    @unittest.skipUnless(
        hasattr(ldap, "OPT_X_TLS_PEERCERT"),
        reason="Requires OPT_X_TLS_PEERCERT"
    )
    def test_get_tls_peercert(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        peercert = l.get_option(ldap.OPT_X_TLS_PEERCERT)
        self.assertEqual(peercert, None)
        with self.assertRaises(ValueError):
            l.set_option(ldap.OPT_X_TLS_PEERCERT, b"")

        l.set_option(ldap.OPT_X_TLS_CACERTFILE, self.server.cafile)
        l.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        l.start_tls_s()

        peercert = l.get_option(ldap.OPT_X_TLS_PEERCERT)
        self.assertTrue(peercert)
        self.assertIsInstance(peercert, bytes)

        with open(self.server.servercert, "rb") as f:
            server_cert = f.read()
        pem_body = PEM_CERT_RE.search(server_cert).group(1)
        server_der = base64.b64decode(pem_body)

        self.assertEqual(server_der, peercert)

    def test_dse(self):
        dse = self._ldap_conn.read_rootdse_s()
        self.assertIsInstance(dse, dict)
        self.assertEqual(dse['supportedLDAPVersion'], [b'3'])
        keys = set(dse)
        # SASL info may be missing in restricted build environments
        keys.discard('supportedSASLMechanisms')
        self.assertEqual(
            keys,
            {'configContext', 'entryDN', 'namingContexts', 'objectClass',
             'structuralObjectClass', 'subschemaSubentry',
             'supportedControl', 'supportedExtension', 'supportedFeatures',
             'supportedLDAPVersion'}
        )
        self.assertEqual(
            self._ldap_conn.get_naming_contexts(),
            [self.server.suffix.encode('utf-8')]
        )

    def test_compare_s_true(self):
        base = self.server.suffix
        l = self._ldap_conn
        result = l.compare_s('cn=Foo1,%s' % base, 'cn', b'Foo1')
        self.assertIs(result, True)

    def test_compare_s_false(self):
        base = self.server.suffix
        l = self._ldap_conn
        result = l.compare_s('cn=Foo1,%s' % base, 'cn', b'Foo2')
        self.assertIs(result, False)

    def test_compare_s_notfound(self):
        base = self.server.suffix
        l = self._ldap_conn
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            result = l.compare_s('cn=invalid,%s' % base, 'cn', b'Foo2')

    def test_compare_s_invalidattr(self):
        base = self.server.suffix
        l = self._ldap_conn
        with self.assertRaises(ldap.UNDEFINED_TYPE):
            result = l.compare_s('cn=Foo1,%s' % base, 'invalidattr', b'invalid')

    def test_compare_true_exception_contains_message_id(self):
        base = self.server.suffix
        l = self._ldap_conn
        msgid = l.compare('cn=Foo1,%s' % base, 'cn', b'Foo1')
        with self.assertRaises(ldap.COMPARE_TRUE) as cm:
            l.result()
        self.assertEqual(cm.exception.args[0]["msgid"], msgid)

    def test_async_search_no_such_object_exception_contains_message_id(self):
        msgid = self._ldap_conn.search("CN=XXX", ldap.SCOPE_SUBTREE)
        with self.assertRaises(ldap.NO_SUCH_OBJECT) as cm:
            self._ldap_conn.result()
        self.assertEqual(cm.exception.args[0]["msgid"], msgid)

    def test_passwd_s(self):
        l = self._ldap_conn

        # first, create a user to change password on
        dn = "cn=PasswordTest," + self.server.suffix
        result, pmsg, msgid, ctrls = l.add_ext_s(
            dn,
            [
                ('objectClass', b'person'),
                ('sn', b'PasswordTest'),
                ('cn', b'PasswordTest'),
                ('userPassword', b'initial'),
            ]
        )
        self.assertEqual(result, ldap.RES_ADD)
        self.assertIsInstance(msgid, int)
        self.assertEqual(pmsg, [])
        self.assertEqual(ctrls, [])

        # try changing password with a wrong old-pw
        with self.assertRaises(ldap.UNWILLING_TO_PERFORM):
            l.passwd_s(dn, "bogus", "ignored")

        # have the server generate a new random pw
        respoid, respvalue = l.passwd_s(dn, "initial", None, extract_newpw=True)
        self.assertEqual(respoid, None)

        password = respvalue.genPasswd
        self.assertIsInstance(password, bytes)

        # try changing password back
        respoid, respvalue = l.passwd_s(dn, password, "initial")
        self.assertEqual(respoid, None)
        self.assertEqual(respvalue, None)

        l.delete_s(dn)

    def test_slapadd(self):
        with self.assertRaises(ldap.INVALID_DN_SYNTAX):
            self._ldap_conn.add_s("myAttribute=foobar,ou=Container,%s" % self.server.suffix, [
                ("objectClass", b'myClass'),
                ("myAttribute", b'foobar'),
            ])

        self.server.slapadd(SCHEMA_TEMPLATE, ["-n0"])
        self.server.restart()
        self.reset_connection()

        self._ldap_conn.add_s("myAttribute=foobar,ou=Container,%s" % self.server.suffix, [
            ("objectClass", b'myClass'),
            ("myAttribute", b'foobar'),
        ])


class Test01_ReconnectLDAPObject(Test00_SimpleLDAPObject):
    """
    test ReconnectLDAPObject by restarting slapd
    """

    ldap_object_class = ReconnectLDAPObject

    @requires_sasl()
    @requires_ldapi()
    def test101_reconnect_sasl_external(self):
        l = self.ldap_object_class(self.server.ldapi_uri)
        l.sasl_external_bind_s()
        authz_id = l.whoami_s()
        self.assertEqual(authz_id, 'dn:'+self.server.root_dn.lower())
        self.server.restart()
        self.assertEqual(l.whoami_s(), authz_id)

    def test102_reconnect_simple_bind(self):
        l = self.ldap_object_class(self.server.ldap_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)
        self.server.restart()
        self.assertEqual(l.whoami_s(), 'dn:'+bind_dn)

    def test103_reconnect_get_state(self):
        l1 = self.ldap_object_class(self.server.ldap_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l1.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
        self.assertEqual(
            l1.__getstate__(),
            {
                '_last_bind': (
                    'simple_bind_s',
                    (bind_dn, 'user1_pw'),
                    {}
                ),
                '_options': [(17, 3)],
                '_reconnects_done': 0,
                '_retry_delay': 60.0,
                '_retry_max': 1,
                '_start_tls': 0,
                '_trace_level': ldap._trace_level,
                '_trace_stack_limit': 5,
                '_uri': self.server.ldap_uri,
                'timeout': -1,
            },
        )

    def test104_reconnect_restore(self):
        l1 = self.ldap_object_class(self.server.ldap_uri)
        bind_dn = 'cn=user1,'+self.server.suffix
        l1.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
        l1_state = pickle.dumps(l1)
        del l1
        l2 = pickle.loads(l1_state)
        self.assertEqual(l2.whoami_s(), 'dn:'+bind_dn)

    def test105_reconnect_restore(self):
        l1 = self.ldap_object_class(self.server.ldap_uri, retry_max=2, retry_delay=1)
        bind_dn = 'cn=user1,'+self.server.suffix
        l1.simple_bind_s(bind_dn, 'user1_pw')
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)
        self.server._proc.terminate()
        self.server.wait()
        try:
            l1.whoami_s()
        except ldap.SERVER_DOWN:
            pass
        else:
            self.assertEqual(True, False)
        finally:
            self.server._start_slapd()
        self.assertEqual(l1.whoami_s(), 'dn:'+bind_dn)


@requires_init_fd()
class Test03_SimpleLDAPObjectWithFileno(Test00_SimpleLDAPObject):
    def _open_ldap_conn(self, who=None, cred=None, **kwargs):
        if hasattr(self, '_sock'):
            raise RuntimeError("socket already connected")
        self._sock = socket.create_connection(
            (self.server.hostname, self.server.port)
        )
        return super()._open_ldap_conn(
            who=who, cred=cred, fileno=self._sock.fileno(), **kwargs
        )

    def tearDown(self):
        self._sock.close()
        del self._sock
        super().tearDown()

    def reset_connection(self):
        self._sock.close()
        del self._sock
        super(Test03_SimpleLDAPObjectWithFileno, self).reset_connection()


if __name__ == '__main__':
    unittest.main()
