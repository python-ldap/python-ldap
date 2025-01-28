"""
Automatic tests for python-ldap's module ldappool

See https://www.python-ldap.org/ for details.
"""

import os
import sys
import unittest
import time

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ["LDAPNOINIT"] = "1"

import ldappool
from ldappool import Connection, ConnectionPool

import ldap as _ldap
from ldapurl import LDAPUrl
import ldapurl


class ldapmock:
    """Mocking some LDAP methods to avoid having a
    full LDAP Setup for unittestst"""

    def __init__(self, fail=0, down=0):
        self.fail = int(fail)
        self.down = int(down)

    @property
    def __whoami_s(self):
        """if down was set when initializing
        we fail for the count until we return success
        """
        for _ in range(self.down):
            self.down -= 1
            if self.down < 0:
                self.down = 0
            raise _ldap.SERVER_DOWN()
        return "cn=tester,dc=example,dc=com"

    def whoami_s(self):
        """if down was set when initializing
        we fail for the count until we return success
        """
        for _ in range(self.down):
            self.down -= 1
            if self.down < 0:
                self.down = 0
            raise _ldap.SERVER_DOWN()
        return "cn=tester,dc=example,dc=com"

    def initialize(self, uri):
        return self

    def simple_bind_s(self, binddn, bindpw):
        """if fail was set when initializing
        we fail for the count until we return success
        """
        for _ in range(self.fail):
            self.fail -= 1
            if self.fail < 0:
                self.fail = 0
            raise _ldap.INVALID_CREDENTIALS()
        return (97, [])

    def set_option(self, *args, **kwargs):
        return True

    def search_s(self, *args, **kwargs):
        return True

    def authenticate(self, binddn, bindpw):
        """if fail was set when initializing
        we fail for the count until we return success
        """
        for _ in range(self.fail):
            self.fail -= 1
            if self.fail < 0:
                self.fail = 0
            raise _ldap.INVALID_CREDENTIALS()
        return (97, [])

    def unbind_s(self, *args, **kwargs):
        return True

    def __enter__(self):
        return 

class TestConnection(unittest.TestCase):

    def test_Connectionparams(self):
        """test if a Connection handles parameters correctly"""
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        assert connection.params.get("retries") == 3
        assert connection.inUse == False
        assert connection.established == False
        assert connection.binddn == "cn=tester,dc=example,dc=com"
        assert connection.bindpw == "changeme"

    def test_Connectionhandling(self):
        """test if a Connection changes state when in use"""
        ldap = ldapmock(fail=0)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        with connection as ctx:
            assert connection.inUse == True
            assert connection.established == True
            assert connection.whoami == "cn=tester,dc=example,dc=com"

    def test_Connectionhandlingautherror(self):
        """test if a connection raises exception if credentials are wrong"""
        ldap = ldapmock(fail=2)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "allow_tls_fallback": True},
        )
        with self.assertRaises(_ldap.INVALID_CREDENTIALS) as ctx:
            connection.conn()

    def test_Connectionhandlingauthentication(self):
        """test if a connection can authenticate for someone"""
        ldap = ldapmock(fail=0, down=0)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 1, "allow_tls_fallback": True},
        )
        connection._conn = ldap
        with connection as ctx:
            assert ctx.authenticate("test", "test") == (97, [])

    def test_Connectionhandlingserverdown(self):
        """test if aconnection retries until params.retries reached"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        with connection as ctx:
            assert connection.whoami == "cn=tester,dc=example,dc=com"

    def test_ConnectionhandlingserverdownExceed(self):
        """test to ensure we raise ldap.SERVER_DOWN after max retries
        has been reached and we have not succeeded"""
        ldap = ldapmock(down=10)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        with self.assertRaises(_ldap.SERVER_DOWN) as ctx:
            with connection as ctx:
                connection.whoami

        """test to ensure without context ldap.SERVER_DOWN after max retries
            has been reached and we have not succeeded"""
        ldap = ldapmock(down=10)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        with self.assertRaises(_ldap.SERVER_DOWN) as ctx:
            connection.conn.search_s()

    def test_Connectionconfigchange(self):
        """test if a connection updates configuration changes accordingly"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        connection = Connection(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3},
        )
        connection.set_credentials("cn=another,dc=example,dc=com", "changetoo")
        assert connection.binddn == "cn=another,dc=example,dc=com"
        assert connection.bindpw == "changetoo"

    def test_Connectionlocktime(self):
        """test locktime which ensures we do not stress the connections too often"""
        conn = Connection(LDAPUrl("ldap:///"), "", "")
        assert conn._Connection__locktime() == True
        assert conn._Connection__locktime() == False
        time.sleep(15)
        assert conn._Connection__locktime() == True


    def test_Connectionmethods(self):
        """test Connection methods which are there for
        simplifying handling with the class"""

        """check set_uri"""
        conn = Connection(LDAPUrl("ldap://127.0.0.1/"), "", "")
        conn.set_uri(LDAPUrl("ldap://localhost/dc=example,dc=com"))
        assert conn.uri == Connection(LDAPUrl("ldap://localhost/dc=example,dc=com"), "", "").uri

        """check set_binddn"""
        conn = Connection(LDAPUrl("ldap://127.0.0.1/"), "", "")
        conn.set_binddn("cn=Directory Manager")
        assert conn.binddn == "cn=Directory Manager"

        """check set_bindpw"""
        conn = Connection(LDAPUrl("ldap://127.0.0.1/"), "", "")
        conn.set_bindpw("changeme")
        assert conn.bindpw == "changeme"

        """check set_credentials"""
        conn = Connection(LDAPUrl("ldap://127.0.0.1/"), "", "")
        conn.set_credentials("cn=Directory Manager", "changeme")
        assert conn.binddn == "cn=Directory Manager"
        assert conn.bindpw == "changeme"


class TestConnectionPool(unittest.TestCase):

    def test_ConnectionPoolParams(self):
        """test if ConnectionPool handles parameters correctly"""
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "autoBind": True},
            max=3,
        )
        assert pool.params.get("retries") == 3
        assert pool.params.get("autoBind") == True
        assert pool.binddn == "cn=tester,dc=example,dc=com"
        assert pool.bindpw == "changeme"
        assert pool.basedn == "dc=example,dc=com"
        assert pool.scope == _ldap.SCOPE_SUBTREE
        assert pool.filter == "(uid=tester)"
        assert pool.attributes == ["uid", "mail"]

    def test_ConnectionPoolhandling(self):
        """test if ConnectionPool context for Connection
        is handled correctly"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        assert len(pool._pool) == 3
        assert pool.ping
        with pool.get() as conn:
            assert conn.search_s("something") == True
            assert conn.authenticate("test", "test") == (97, [])

    def test_ConnectionPoolCleanup(self):
        """test if ConnectionPool removing Connection
        without deleting it"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True, "autoBind": True},
            max=3,
        )
        assert len(pool._pool) == 3
        assert pool.ping
        conn = pool.get()
        pool.delete(conn)

    def test_ConnectionPoolconfigchange(self):
        """test if ConnectionPool delegates configuration changes
        to Connections in pool during runtime change"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        pool.scale
        assert len(pool) == 3
        pool.set_credentials("cn=another,dc=example,dc=com", "changetoo")
        assert pool.binddn == "cn=another,dc=example,dc=com"
        assert pool.bindpw == "changetoo"
        for conn in pool._pool:
            assert conn.binddn == "cn=another,dc=example,dc=com"
            assert conn.bindpw == "changetoo"

    def test_ConnectionPoolLDAPPoolExhausted(self):
        """test if ConnectionPool raises Exception when
        all connections are in use"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        pool.scale
        assert len(pool) == 3
        with self.assertRaises(ldappool.LDAPPoolExhausted) as ctx:
            for _ in range(pool.max + 1):
                c = pool.get()

    def test_ConnectionPoolLDAPPoolExhausted(self):
        """test if all connections are free'ed when returned
        to the Pool but connection kept established"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        pool.scale
        assert len(pool) == 3

        conn = []
        for _ in range(pool.max - 1):
            conn.append(pool.get())
        for c in conn:
            pool.put(c)
            assert c.inUse == False
            assert c.established == True

    def test_ConnectionPoolLDAPPoolGiveback(self):
        """test if ConnectionPool giveback returns
        connections to the pool"""
        ldap = ldapmock()
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        pool.scale
        assert len(pool) == 3
        conn = pool.get()
        conn.giveback()
        assert conn.inUse == False

        """test if all connections are free'ed when returned
           to the Pool but connection kept established"""
        conn = []
        for _ in range(pool.max - 1):
            conn.append(pool.get())
        for c in conn:
            pool.put(c)
            assert c.inUse == False
            assert c.established == True

    def test_ConnectionPoolLDAPLockTimeout(self):
        """test if ConnectionPool raises Locktimeout accordingly
        when connection has been locked"""
        ldap = ldapmock(down=2)
        ldappool.ldap.initialize = ldap.initialize
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        pool.scale
        assert len(pool) == 1
        with self.assertRaises(ldappool.LDAPLockTimeout) as ctx:
            c = pool.get()
            if not c._lock.acquire(blocking=True, timeout=1):
                raise ldappool.LDAPLockTimeout()
            if not c._lock.acquire(blocking=True, timeout=1):
                raise ldappool.LDAPLockTimeout()
            c.authenticate("test", "test") == (97, [])

        """test if ConnectionPool releases lock when Connection
           is used and returned"""
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        pool.scale
        assert len(pool) == 1
        with pool.get() as ctx:
            pass
        with pool.get() as ctx:
            pass

    def test_ConnectionPoolmethods(self):
        """test ConnectionPool methods which are there for
        simplifying handling with the class"""

        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?sub?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        assert pool.scope == _ldap.SCOPE_SUBTREE
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?base?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        assert pool.scope == _ldap.SCOPE_BASE
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?one?(uid=tester)"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        assert pool.scope == _ldap.SCOPE_ONELEVEL
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?one?(uid=tester)?extensiontest"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=1,
        )
        assert isinstance(pool.extensions, ldapurl.LDAPUrlExtensions)
        pool = ConnectionPool(
            uri=LDAPUrl(
                "ldaps://localhost:636/dc=example,dc=com?uid,mail?one?(uid=tester)?extensiontest"
            ),
            binddn="cn=tester,dc=example,dc=com",
            bindpw="changeme",
            params={"retries": 3, "prewarm": True},
            max=3,
        )
        pool.status

if __name__ == "__main__":
    unittest.main()
