import ldap
import os
import unittest
import slapd
import socket


CI_DISABLED = set(os.environ.get("CI_DISABLED", "").split(":"))
if "LDAPI" in CI_DISABLED:
    HAVE_LDAPI = False
else:
    HAVE_LDAPI = hasattr(socket, "AF_UNIX")


def identity(test_item):
    """Identity decorator"""
    return test_item


def skip_unless_ci(reason, feature=None):
    """Skip test unless test case is executed on CI like Travis CI"""
    if not os.environ.get("CI", False):
        return unittest.skip(reason)
    elif feature in CI_DISABLED:
        return unittest.skip(reason)
    else:
        # Don't skip on Travis
        return identity


def requires_tls():
    """Decorator for TLS tests

    Tests are not skipped on CI (e.g. Travis CI)
    """
    if not ldap.TLS_AVAIL:
        return skip_unless_ci("test needs ldap.TLS_AVAIL", feature="TLS")
    else:
        return identity


def requires_sasl():
    if not ldap.SASL_AVAIL:
        return skip_unless_ci("test needs ldap.SASL_AVAIL", feature="SASL")
    else:
        return identity


def requires_ldapi():
    if not HAVE_LDAPI:
        return skip_unless_ci("test needs ldapi support (AF_UNIX)", feature="LDAPI")
    else:
        return identity


def requires_init_fd():
    if not ldap.INIT_FD_AVAIL:
        return skip_unless_ci("test needs ldap.INIT_FD", feature="INIT_FD")
    else:
        return identity


class SlapdTestCase(unittest.TestCase):
    """
    test class which also clones or initializes a running slapd
    """

    server_class = slapd.Slapd
    server = None
    ldap_object_class = None

    def _open_ldap_conn(self, who=None, cred=None, **kwargs):
        """
        return a LDAPObject instance after simple bind
        """
        ldap_conn = self.ldap_object_class(self.server.ldap_uri, **kwargs)
        ldap_conn.protocol_version = 3
        # ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        ldap_conn.simple_bind_s(who or self.server.root_dn, cred or self.server.root_pw)
        return ldap_conn

    @classmethod
    def setUpClass(cls):
        cls.server = cls.server_class()
        cls.server.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
