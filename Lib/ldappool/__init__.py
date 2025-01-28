try:
    import dataclasses
except ImportError:
    # we are on python < 3.7 so ignore
    pass
import logging
import sys
import threading
import time
from urllib.parse import urlparse

import ldap
from ldapurl import LDAPUrl

# nano seconds to ensure we know the locked time
ns = 1_000_000_000
ns_locktimeout = 15.0

logging.basicConfig(level=logging.INFO, stream=sys.stdout)


class LDAPPoolExhausted(Exception):
    pass


class LDAPPoolDown(Exception):
    pass


class LDAPLockTimeout(Exception):
    pass


def e2c(entry):
    try:
        cls = dataclasses.make_dataclass(
            "", ["dn"] + list(entry[1].keys()), frozen=True
        )
        return cls(**dict(list([("dn", entry[0])] + list(entry[1].items()))))
    except NameError as dcerror:
        print(f"dataclasses not supported")
        return entry


class Connection(object):
    def __init__(
        self,
        uri: LDAPUrl,
        binddn: str,
        bindpw: str,
        params: dict = {},
    ):
        self.uri = uri
        self.binddn = binddn
        self.bindpw = bindpw
        self.params = params
        self.established = False
        self.inUse = False
        self._whoami = None
        self._conn = False
        self._lock = threading.Lock()
        self._pool = None
        self._health = 0.0
        (f"ConnectionPool new Connection {self}")
        if self.params.get("prewarm", False):
            self.__enter__()

    def __locktime(self):
        if self._health == 0.0:
            self._health = time.perf_counter_ns()
            return True
        if (time.perf_counter_ns() - self._health) / ns < ns_locktimeout:
            return False
        return True

    @property
    def whoami(self):
        return self._whoami

    def __whoami(self):
        # do not stress the connection too often
        if not self.__locktime():
            return
        for r in range(self.params.get("retries", 3)):
            try:
                self._whoami = self._conn.whoami_s()
                return
            except ldap.SERVER_DOWN as ldaperr:
                logging.error(f"__whoami ConnectionPool {ldaperr}")
                self.established = False
                # just catch that error until we finished iterating
                try:
                    self.__enter__()
                except:
                    continue
        raise ldap.SERVER_DOWN(f"max retries {self.params.get('retries', 3)} reached")

    @property
    def conn(self):
        if self._conn == False:
            self.__enter__()
        try:
            if self.established:
                self.__whoami()
        except ldap.SERVER_DOWN as ldaperr:
            self.established = False
            raise LDAPPoolDown(
                f"could not establish connection with {self.uri.initializeUrl()}"
                + f" with max retries of {self.params.get('retries', 3)}"
            )
        return self._conn

    def __lock_acquire(self):
        try:
            if self._lock.acquire(blocking=True, timeout=1):
                return True
            else:
                raise LDAPLockTimeout()
        except Exception as lockerr:
            return False

    def __lock_release(self):
        try:
            self._lock.release()
            return True
        except Exception as lockerr:
            return False

    def authenticate(
        self,
        binddn: str,
        bindpw: str,
    ):

        if not self.__lock_acquire():
            raise LDAPLockTimeout()

        try:
            self.conn.simple_bind_s(
                binddn,
                bindpw,
            )
            if not self.__lock_release():
                raise LDAPLockTimeout()
        except ldap.INVALID_CREDENTIALS as ldaperr:
            # rollback auth anyway
            self.__lock_release()
            self.__authenticate__()
            raise ldap.INVALID_CREDENTIALS
        # rollback auth anyway
        self.__authenticate__()
        return True

    def __authenticate__(self):
        if not self.__lock_acquire():
            raise LDAPLockTimeout()
        try:
            self.conn.simple_bind_s(
                self.binddn,
                self.bindpw,
            )
            logging.debug("__whoami from __authenticate__")
            self.__whoami()
            self.__lock_release()
        except ldap.INVALID_CREDENTIALS as ldaperr:
            self.__lock_release()
            logging.info(ldaperr)
            raise ldap.INVALID_CREDENTIALS

    def __set_connection_parameters__(self):
        try:
            self._conn.set_option(
                ldap.OPT_REFERRALS, self.params.get("referrals", False)
            )
            self._conn.set_option(
                ldap.OPT_NETWORK_TIMEOUT, self.params.get("network_timeout", 10.0)
            )
            self._conn.set_option(ldap.OPT_TIMEOUT, self.params.get("timeout", 10.0))
            self._conn.set_option(
                ldap.OPT_X_KEEPALIVE_IDLE, self.params.get("keepalive_idle", 10)
            )
            self._conn.set_option(
                ldap.OPT_X_KEEPALIVE_INTERVAL, self.params.get("keepalive_interval", 5)
            )
            self._conn.set_option(
                ldap.OPT_X_KEEPALIVE_PROBES, self.params.get("keepalive_probes", 3)
            )
            self._conn.set_option(ldap.OPT_RESTART, ldap.OPT_ON)
            if self.params.get("allow_tls_fallback", False):
                self._conn.set_option(ldap.OPT_X_TLS_TRY, 1)
            self._conn.set_option(ldap.OPT_X_TLS_NEWCTX, ldap.OPT_OFF)
        except Exception as connerr:
            logging.error(f"cannot set LDAP option {connerr}")

    def __enter__(self):
        self.inUse = True
        if not self.established:
            logging.debug(
                f"ConnectionPool {self} initializin LDAP {self.uri.initializeUrl()}"
            )
            try:
                self._conn = ldap.initialize(self.uri.initializeUrl())
                self.__set_connection_parameters__()
                if self.params.get("autoBind", False):
                    (
                        f"ConnectionPool {self} autoBind with {self.binddn} password {'x'*len(self.bindpw)}"
                    )
                self.__authenticate__()
            except Exception as ldaperr:
                (ldaperr)
                raise ldaperr
        self.established = True
        return self.conn

    def giveback(self, force=False):
        try:
            if force:
                try:
                    self._conn.unbind_s()
                except Exception as ldaperr:
                    logging.error(
                        "ConnectionPool unbind connection"
                        + f"{self} exception {ldaperr}"
                    )
                self.inUse = False
                return

            if self.params.get("autoBind", False):
                if not self.params.get("keep", False):
                    logging.debug(f"ConnectionPool unbind connection {self}")
                    try:
                        self._conn.unbind_s()
                    except Exception as ldaperr:
                        logging.error(
                            "ConnectionPool unbind connection"
                            + f"{self} exception {ldaperr}"
                        )
            self.inUse = False
        except AttributeError:
            self.inUse = False

    def __del__(self):
        self.giveback()
        if all([self._pool is not None, not self.params.get("keep", False)]):
            logging.debug(f"ConnectionPool deleteing connection {self} from Pool")
            self._pool.delete(self)

    def __exit__(self, type, value, traceback):
        self.giveback()
        if all([self._pool is not None, not self.params.get("keep", False)]):
            self._pool.delete(self)

    def __cmp__(self, other):
        if isinstance(other, Connection):
            return self.uri.initializeUrl() == other.uri.initializeUrl()
        return False

    def set_uri(self, uri: LDAPUrl):
        self.uri = uri
        return True

    def set_binddn(self, binddn: str):
        self.binddn = binddn
        return True

    def set_bindpw(self, bindpw: str):
        self.bindpw = bindpw
        return True

    def set_credentials(self, binddn: str, bindpw: str):
        self.set_binddn(binddn)
        self.set_bindpw(bindpw)
        return True


class ConnectionPool(object):
    def __init__(
        self,
        uri: LDAPUrl = LDAPUrl("ldap:///"),
        binddn: str = "",
        bindpw: str = "",
        params: dict = {},
        max: int = 10,
    ):
        self.uri = uri
        self.binddn = binddn
        self.bindpw = bindpw
        self.params = params
        self.max = int(max)
        self._lock = threading.Lock()
        self._pool = []
        logging.debug(f"ConnectionPool {self} starting with {self.max} connections")
        if self.params.get("prewarm", False):
            self.scale

    @property
    def basedn(self):
        return self.uri.dn

    @property
    def scope(self):
        return self.uri.scope

    @property
    def filter(self):
        return self.uri.filterstr

    @property
    def attributes(self):
        return self.uri.attrs

    @property
    def extensions(self):
        return self.uri.extensions

    def set_uri(self, uri: LDAPUrl):
        if not isinstance(uri, LDAPUrl):
            uri = LDAPUrl(uri)
        if len(self._pool) > 0:
            list(
                map(
                    lambda c: (c.set_uri(uri), c.giveback(force=True)),
                    filter(lambda cp: cp.uri != uri, self._pool),
                )
            )
        self.uri = uri
        return True

    def set_binddn(self, binddn: str):
        if len(self._pool) > 0:
            list(
                map(
                    lambda c: (c.set_binddn(binddn), c.giveback(force=True)),
                    filter(lambda cp: cp.binddn != binddn, self._pool),
                )
            )
        self.binddn = binddn
        return True

    def set_bindpw(self, bindpw: str):
        if len(self._pool) > 0:
            list(
                map(
                    lambda c: (c.set_bindpw(bindpw), c.giveback(force=True)),
                    filter(lambda cp: cp.bindpw != bindpw, self._pool),
                )
            )
        self.bindpw = bindpw
        return True

    def set_credentials(self, binddn: str, bindpw: str):
        self.set_binddn(binddn)
        self.set_bindpw(bindpw)
        return True

    @property
    def scale(self):
        for _ in range(self.max - len(self._pool)):
            self.put(
                Connection(
                    uri=self.uri,
                    binddn=self.binddn,
                    bindpw=self.bindpw,
                    params=self.params,
                )
            )

    def __enter__(self):
        if len(self._pool) == 0:
            self.scale
        with self.get() as conn:
            yield conn
            self.put(conn)

    @property
    def ping(self):
        with self.get() as conn:
            try:
                return True
            except Exception as ldaperr:
                try:
                    if conn.search_s("cn=config", ldap.SCOPE_ONELEVEL) != []:
                        return True
                    else:
                        # we might have ACI's in place
                        return True
                except Exception as ldaperr:  # collect with parent exception
                    pass
                logging.error(
                    f"LDAP exception pinging server {self.uri.initializeUrl()} {ldaperr}"
                )
                raise ldaperr
        return True

    def get(self, binddn: str = "", bindpw: str = ""):
        if len(self._pool) == 0:
            self.scale
        self._lock.acquire(timeout=1)
        if len(self._pool) == 0:
            self._lock.release()
            logging.warning(
                f"max connections {self.max} reached, consider increasing pool size"
            )
            raise LDAPPoolExhausted(
                f"max connections {self.max} reached, consider increasing pool size"
            )
        try:
            con = list(filter(lambda x: not x.inUse, self._pool))[0]
        except IndexError:
            self._lock.release()
            logging.warning(
                f"all connections {self.max} in use, consider increasing pool size"
            )
            raise LDAPPoolExhausted(
                f"all connections {self.max} in use, consider increasing pool size"
            )
        con.inUse = True
        self._lock.release()
        if all([binddn != "", bindpw != ""]):
            try:
                con.authenticate(binddn, bindpw)
            except ldap.INVALID_CREDENTIALS:
                self.put(con)
                raise ldap.INVALID_CREDENTIALS
        return con

    def put(self, connection):
        self._lock.acquire(timeout=1)
        if connection.inUse:
            connection.giveback()
        if not connection in self._pool:
            self._pool.append(connection)
        connection._pool = self
        self._lock.release()
        return True

    def status(self):
        self._lock.acquire(timeout=1)
        for p in self._pool:
            if p.inUse:
                if sys.getrefcount(p) < 4:
                    p.giveback()
            logging.info(f"Id {p} inUse {p.inUse} {p.established} {p.whoami}")
        self._lock.release()

    def delete(self, connection, force=True):
        self._lock.acquire(timeout=1)
        if connection in self._pool:
            if any([not self.params.get("keep", False), force]):
                self._pool.remove(connection)
                del connection
        self._lock.release()

    def __len__(self):
        return len(self._pool)
