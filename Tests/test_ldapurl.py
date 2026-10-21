"""
Automatic tests for python-ldap's module ldapurl

See https://www.python-ldap.org/ for details.
"""

import os
from urllib.parse import quote

import pytest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import ldapurl
from ldapurl import LDAPUrl


class MyLDAPUrl(LDAPUrl):
    attr2extype = {
        'who': 'bindname',
        'cred': 'X-BINDPW',
        'start_tls': 'startTLS',
        'trace_level': 'trace',
    }


class TestIsLDAPUrl:
    is_ldap_url_tests = {
        # Examples from RFC2255
        'ldap:///o=University%20of%20Michigan,c=US': 1,
        'ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,c=US': 1,
        'ldap://ldap.itd.umich.edu/o=University%20of%20Michigan,': 1,
        'ldap://host.com:6666/o=University%20of%20Michigan,': 1,
        'ldap://ldap.itd.umich.edu/c=GB?objectClass?one': 1,
        'ldap://ldap.question.com/o=Question%3f,c=US?mail': 1,
        'ldap://ldap.netscape.com/o=Babsco,c=US???(int=%5c00%5c00%5c00%5c04)': 1,
        'ldap:///??sub??bindname=cn=Manager%2co=Foo': 1,
        'ldap:///??sub??!bindname=cn=Manager%2co=Foo': 1,
        # More examples from various sources
        'ldap://ldap.nameflow.net:1389/c%3dDE': 1,
        'ldap://root.openldap.org/dc=openldap,dc=org': 1,
        'ldaps://root.openldap.org/dc=openldap,dc=org': 1,
        'ldap://x500.mh.se/o=Mitthogskolan,c=se????1.2.752.58.10.2=T.61': 1,
        'ldp://root.openldap.org/dc=openldap,dc=org': 0,
        'ldap://localhost:1389/ou%3DUnstructured%20testing%20tree%2Cdc%3Dstroeder%2Cdc%3Dcom??one': 1,
        'ldaps://ldap.example.com/c%3dDE': 1,
        'ldapi:///dc=stroeder,dc=de????x-saslmech=EXTERNAL': 1,
        'LDAP://localhost': True,
        'LDAPS://localhost': True,
        'LDAPI://%2Frun%2Fldap.sock': True,
        ' ldap://space.example': False,
        'ldap ://space.example': False,
    }

    def test_isLDAPUrl(self):
        for ldap_url, expected in self.is_ldap_url_tests.items():
            result = ldapurl.isLDAPUrl(ldap_url)
            assert result == expected, (
                'isLDAPUrl("%s") returns %d instead of %d.'
                % (
                    ldap_url,
                    result,
                    expected,
                ),
            )
            if expected:
                LDAPUrl(ldapUrl=ldap_url)
            else:
                with pytest.raises(ValueError):
                    LDAPUrl(ldapUrl=ldap_url)


class TestParseLDAPUrl:
    parse_ldap_url_tests = [
        ('ldap://root.openldap.org/dc=openldap,dc=org', LDAPUrl(hostport='root.openldap.org', dn='dc=openldap,dc=org')),
        (
            'ldap://root.openldap.org/dc%3dboolean%2cdc%3dnet???%28objectClass%3d%2a%29',
            LDAPUrl(hostport='root.openldap.org', dn='dc=boolean,dc=net', filterstr='(objectClass=*)'),
        ),
        (
            'ldap://root.openldap.org/dc=openldap,dc=org??sub?',
            LDAPUrl(hostport='root.openldap.org', dn='dc=openldap,dc=org', scope=ldapurl.LDAP_SCOPE_SUBTREE),
        ),
        (
            'ldap://root.openldap.org/dc=openldap,dc=org??one?',
            LDAPUrl(hostport='root.openldap.org', dn='dc=openldap,dc=org', scope=ldapurl.LDAP_SCOPE_ONELEVEL),
        ),
        (
            'ldap://root.openldap.org/dc=openldap,dc=org??base?',
            LDAPUrl(hostport='root.openldap.org', dn='dc=openldap,dc=org', scope=ldapurl.LDAP_SCOPE_BASE),
        ),
        (
            'ldap://x500.mh.se/o=Mitthogskolan,c=se????1.2.752.58.10.2=T.61',
            LDAPUrl(
                hostport='x500.mh.se',
                dn='o=Mitthogskolan,c=se',
                extensions=ldapurl.LDAPUrlExtensions(
                    {'1.2.752.58.10.2': ldapurl.LDAPUrlExtension(critical=0, extype='1.2.752.58.10.2', exvalue='T.61')}
                ),
            ),
        ),
        (
            'ldap://localhost:12345/dc=stroeder,dc=com????!bindname=cn=Michael%2Cdc=stroeder%2Cdc=com,!X-BINDPW=secretpassword',
            LDAPUrl(
                hostport='localhost:12345',
                dn='dc=stroeder,dc=com',
                extensions=ldapurl.LDAPUrlExtensions(
                    {
                        'bindname': ldapurl.LDAPUrlExtension(
                            critical=1, extype='bindname', exvalue='cn=Michael,dc=stroeder,dc=com'
                        ),
                        'X-BINDPW': ldapurl.LDAPUrlExtension(critical=1, extype='X-BINDPW', exvalue='secretpassword'),
                    }
                ),
            ),
        ),
        (
            'ldap://localhost:54321/dc=stroeder,dc=com????bindname=cn=Michael%2Cdc=stroeder%2Cdc=com,X-BINDPW=secretpassword',
            LDAPUrl(
                hostport='localhost:54321',
                dn='dc=stroeder,dc=com',
                who='cn=Michael,dc=stroeder,dc=com',
                cred='secretpassword',
            ),
        ),
        (
            'ldaps://localhost:12345/dc=stroeder,dc=com',
            LDAPUrl(
                urlscheme='ldaps',
                hostport='localhost:12345',
                dn='dc=stroeder,dc=com',
            ),
        ),
        (
            'LDAPS://localhost:12345/dc=stroeder,dc=com',
            LDAPUrl(
                urlscheme='ldaps',
                hostport='localhost:12345',
                dn='dc=stroeder,dc=com',
            ),
        ),
        (
            'ldaps://localhost:12345/dc=stroeder,dc=com',
            LDAPUrl(
                urlscheme='LDAPS',
                hostport='localhost:12345',
                dn='dc=stroeder,dc=com',
            ),
        ),
        (
            'ldapi://%2ftmp%2fopenldap2-1389/dc=stroeder,dc=com',
            LDAPUrl(
                urlscheme='ldapi',
                hostport='/tmp/openldap2-1389',
                dn='dc=stroeder,dc=com',
            ),
        ),
    ]

    def test_ldapurl(self):
        for ldap_url_str, test_ldap_url_obj in self.parse_ldap_url_tests:
            ldap_url_obj = LDAPUrl(ldapUrl=ldap_url_str)
            assert ldap_url_obj == test_ldap_url_obj, (
                f'Attributes of LDAPUrl({ldap_url_str!r}) are:\n{ldap_url_obj!r}\ninstead of:\n{test_ldap_url_obj!r}'
            )
            unparsed_ldap_url_str = test_ldap_url_obj.unparse()
            unparsed_ldap_url_obj = LDAPUrl(ldapUrl=unparsed_ldap_url_str)
            assert unparsed_ldap_url_obj == test_ldap_url_obj, (
                f'Attributes of LDAPUrl({unparsed_ldap_url_str!r}) are:\n{unparsed_ldap_url_obj!r}\ninstead of:\n{test_ldap_url_obj!r}'
            )


class TestLDAPUrl:
    def test_combo(self):
        u = MyLDAPUrl(
            'ldap://127.0.0.1:1234/dc=example,dc=com'
            + '?attr1,attr2,attr3'
            + '?sub'
            + '?'
            + quote('(objectClass=*)')
            + '?bindname='
            + quote('cn=d,c=au')
            + ',X-BINDPW='
            + quote('???')
            + ',trace=8'
        )
        assert u.urlscheme == 'ldap'
        assert u.hostport == '127.0.0.1:1234'
        assert u.dn == 'dc=example,dc=com'
        assert u.attrs == ['attr1', 'attr2', 'attr3']
        assert u.scope == ldapurl.LDAP_SCOPE_SUBTREE
        assert u.filterstr == '(objectClass=*)'
        assert len(u.extensions) == 3
        assert u.who == 'cn=d,c=au'
        assert u.cred == '???'
        assert u.trace_level == '8'

    def test_parse_default_hostport(self):
        u = LDAPUrl('ldap://')
        assert u.urlscheme == 'ldap'
        assert u.hostport == ''

    def test_parse_empty_dn(self):
        u = LDAPUrl('ldap://')
        assert u.dn == ''
        u = LDAPUrl('ldap:///')
        assert u.dn == ''
        u = LDAPUrl('ldap:///?')
        assert u.dn == ''

    def test_parse_default_attrs(self):
        u = LDAPUrl('ldap://')
        assert u.attrs is None

    def test_parse_default_scope(self):
        u = LDAPUrl('ldap://')
        assert u.scope is None  # RFC4516 s3

    def test_parse_default_filter(self):
        u = LDAPUrl('ldap://')
        assert u.filterstr is None  # RFC4516 s3

    def test_parse_default_extensions(self):
        u = LDAPUrl('ldap://')
        assert len(u.extensions) == 0

    def test_parse_schemes(self):
        u = LDAPUrl('ldap://')
        assert u.urlscheme == 'ldap'
        u = LDAPUrl('ldapi://')
        assert u.urlscheme == 'ldapi'
        u = LDAPUrl('ldaps://')
        assert u.urlscheme == 'ldaps'

    def test_parse_hostport(self):
        u = LDAPUrl('ldap://a')
        assert u.hostport == 'a'
        u = LDAPUrl('ldap://a.b')
        assert u.hostport == 'a.b'
        u = LDAPUrl('ldap://a.')
        assert u.hostport == 'a.'
        u = LDAPUrl('ldap://%61%62:%32/')
        assert u.hostport == 'ab:2'
        u = LDAPUrl('ldap://[::1]/')
        assert u.hostport == '[::1]'
        u = LDAPUrl('ldap://[::1]')
        assert u.hostport == '[::1]'
        u = LDAPUrl('ldap://[::1]:123/')
        assert u.hostport == '[::1]:123'
        u = LDAPUrl('ldap://[::1]:123')
        assert u.hostport == '[::1]:123'

    def test_parse_dn(self):
        u = LDAPUrl('ldap:///')
        assert u.dn == ''
        u = LDAPUrl('ldap:///dn=foo')
        assert u.dn == 'dn=foo'
        u = LDAPUrl('ldap:///dn=foo%2cdc=bar')
        assert u.dn == 'dn=foo,dc=bar'
        u = LDAPUrl('ldap:///dn=foo%20bar')
        assert u.dn == 'dn=foo bar'
        u = LDAPUrl('ldap:///dn=foo%2fbar')
        assert u.dn == 'dn=foo/bar'
        u = LDAPUrl('ldap:///dn=foo%2fbar?')
        assert u.dn == 'dn=foo/bar'
        u = LDAPUrl('ldap:///dn=foo%3f?')
        assert u.dn == 'dn=foo?'
        u = LDAPUrl('ldap:///dn=foo%3f')
        assert u.dn == 'dn=foo?'
        u = LDAPUrl('ldap:///dn=str%c3%b6der.com')
        assert u.dn == 'dn=str\xf6der.com'

    def test_parse_attrs(self):
        u = LDAPUrl('ldap:///?')
        assert u.attrs is None
        u = LDAPUrl('ldap:///??')
        assert u.attrs is None
        u = LDAPUrl('ldap:///?*?')
        assert u.attrs == ['*']
        u = LDAPUrl('ldap:///?*,*?')
        assert u.attrs == ['*', '*']
        u = LDAPUrl('ldap:///?a')
        assert u.attrs == ['a']
        u = LDAPUrl('ldap:///?%61')
        assert u.attrs == ['a']
        u = LDAPUrl('ldap:///?a,b')
        assert u.attrs == ['a', 'b']
        u = LDAPUrl('ldap:///?a%3fb')
        assert u.attrs == ['a?b']

    def test_parse_scope_default(self):
        u = LDAPUrl('ldap:///??')
        assert u.scope is None  # on opposite to RFC4516 s3 for referral chasing
        u = LDAPUrl('ldap:///???')
        assert u.scope is None  # on opposite to RFC4516 s3 for referral chasing

    def test_parse_scope(self):
        u = LDAPUrl('ldap:///??sub')
        assert u.scope == ldapurl.LDAP_SCOPE_SUBTREE
        u = LDAPUrl('ldap:///??sub?')
        assert u.scope == ldapurl.LDAP_SCOPE_SUBTREE
        u = LDAPUrl('ldap:///??base')
        assert u.scope == ldapurl.LDAP_SCOPE_BASE
        u = LDAPUrl('ldap:///??base?')
        assert u.scope == ldapurl.LDAP_SCOPE_BASE
        u = LDAPUrl('ldap:///??one')
        assert u.scope == ldapurl.LDAP_SCOPE_ONELEVEL
        u = LDAPUrl('ldap:///??one?')
        assert u.scope == ldapurl.LDAP_SCOPE_ONELEVEL
        u = LDAPUrl('ldap:///??subordinates')
        assert u.scope == ldapurl.LDAP_SCOPE_SUBORDINATES
        u = LDAPUrl('ldap:///??subordinates?')
        assert u.scope == ldapurl.LDAP_SCOPE_SUBORDINATES

    def test_parse_filter(self):
        u = LDAPUrl('ldap:///???(cn=Bob)')
        assert u.filterstr == '(cn=Bob)'
        u = LDAPUrl('ldap:///???(cn=Bob)?')
        assert u.filterstr == '(cn=Bob)'
        u = LDAPUrl('ldap:///???(cn=Bob%20Smith)?')
        assert u.filterstr == '(cn=Bob Smith)'
        u = LDAPUrl('ldap:///???(cn=Bob/Smith)?')
        assert u.filterstr == '(cn=Bob/Smith)'
        u = LDAPUrl('ldap:///???(cn=Bob:Smith)?')
        assert u.filterstr == '(cn=Bob:Smith)'
        u = LDAPUrl('ldap:///???&(cn=Bob)(objectClass=user)?')
        assert u.filterstr == '&(cn=Bob)(objectClass=user)'
        u = LDAPUrl('ldap:///???|(cn=Bob)(objectClass=user)?')
        assert u.filterstr == '|(cn=Bob)(objectClass=user)'
        u = LDAPUrl('ldap:///???(cn=Q%3f)?')
        assert u.filterstr == '(cn=Q?)'
        u = LDAPUrl('ldap:///???(cn=Q%3f)')
        assert u.filterstr == '(cn=Q?)'
        u = LDAPUrl('ldap:///???(sn=Str%c3%b6der)')  # (possibly bad?)
        assert u.filterstr == '(sn=Str\xf6der)'
        u = LDAPUrl('ldap:///???(sn=Str\\c3\\b6der)')
        assert u.filterstr == '(sn=Str\\c3\\b6der)'  # (recommended)
        u = LDAPUrl('ldap:///???(cn=*\\2a*)')
        assert u.filterstr == '(cn=*\\2a*)'
        u = LDAPUrl('ldap:///???(cn=*%5c2a*)')
        assert u.filterstr == '(cn=*\\2a*)'

    def test_parse_extensions(self):
        u = LDAPUrl('ldap:///????')
        assert u.extensions is None
        assert u.who is None
        u = LDAPUrl('ldap:///????bindname=cn=root')
        assert len(u.extensions) == 1
        assert u.who == 'cn=root'
        u = LDAPUrl('ldap:///????!bindname=cn=root')
        assert len(u.extensions) == 1
        assert u.who == 'cn=root'
        u = LDAPUrl('ldap:///????bindname=%3f,X-BINDPW=%2c')
        assert len(u.extensions) == 2
        assert u.who == '?'
        assert u.cred == ','

    def test_parse_extensions_nulls(self):
        u = LDAPUrl('ldap:///????bindname=%00name')
        assert u.who == '\0name'

    def test_parse_extensions_5questions(self):
        u = LDAPUrl('ldap:///????bindname=?')
        assert len(u.extensions) == 1
        assert u.who == '?'

    def test_parse_extensions_novalue(self):
        u = LDAPUrl('ldap:///????bindname')
        assert len(u.extensions) == 1
        assert u.who is None

    @pytest.mark.xfail
    def test_bad_urls(self):
        for bad in (
            '',
            'ldap:',
            'ldap:/',
            ':///',
            '://',
            '///',
            '//',
            '/',
            'ldap:///?????',  # extension can't start with '?'
            'LDAP://',
            'invalid://',
            'ldap:///??invalid',
            # XXX-- the following should raise exceptions!
            'ldap://:389/',  # [host [COLON port]]
            'ldap://a:/',  # [host [COLON port]]
            r'ldap://%%%/',  # invalid URL encoding
            'ldap:///?,',  # attrdesc *(COMMA attrdesc)
            'ldap:///?a,',  # attrdesc *(COMMA attrdesc)
            'ldap:///?,a',  # attrdesc *(COMMA attrdesc)
            'ldap:///?a,,b',  # attrdesc *(COMMA attrdesc)
            r'ldap://%00/',  # RFC4516 2.1
            r'ldap:///%00',  # RFC4516 2.1
            r'ldap:///?%00',  # RFC4516 2.1
            r'ldap:///??%00',  # RFC4516 2.1
            'ldap:///????0=0',  # extype must start with Alpha
            'ldap:///????a_b=0',  # extype contains only [-a-zA-Z0-9]
            'ldap:///????!!a=0',  # only one exclamation allowed
        ):
            with pytest.raises(ValueError):
                LDAPUrl(bad)

    def test_html_href(self):
        u = ldapurl.LDAPUrl('ldap://root.openldap.org/dc=openldap,dc=org')
        assert u.htmlHREF() == (
            '<a href="ldap://root.openldap.org/dc%3Dopenldap%2Cdc%3Dorg???">ldap://root.openldap.org/dc%3Dopenldap%2Cdc%3Dorg???</a>'
        )

    def test_html_href_escaping(self):
        bad_chars = '<"&\'>'
        u = ldapurl.LDAPUrl(f'ldap://{bad_chars}/dc={bad_chars},dc=org?scope={bad_chars}')
        assert u.htmlHREF() == (
            '<a href="ldap://&lt;&quot;&amp;&#x27;&gt;/dc%3D%3C%22%26%27%3E%2Cdc%3Dorg?scope=&lt;&quot;&amp;&#x27;&gt;??">ldap://&lt;"&amp;\'&gt;/dc%3D%3C%22%26%27%3E%2Cdc%3Dorg?scope=&lt;"&amp;\'&gt;??</a>'
        )
        assert u.htmlHREF(bad_chars, bad_chars, bad_chars) == (
            '<a target="&lt;&quot;&amp;&#x27;&gt;" href="&lt;&quot;&amp;&#x27;&gt;ldap://&lt;&quot;&amp;&#x27;&gt;/dc%3D%3C%22%26%27%3E%2Cdc%3Dorg?scope=&lt;&quot;&amp;&#x27;&gt;??">&lt;"&amp;\'&gt;</a>'
        )
