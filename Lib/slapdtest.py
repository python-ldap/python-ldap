"""
slapdtest - module for spawning test instances of OpenLDAP's slapd server

See http://www.python-ldap.org/ for details.

\$Id: slapdtest.py,v 1.2 2017/04/26 20:46:37 stroeder Exp $

Python compability note:
This module only works with Python 2.7.x since
"""

__version__ = '2.4.37'

import os
import socket
import time
import subprocess
import logging
import unittest

# determine log level
try:
    _LOG_LEVEL = os.environ['LOGLEVEL']
    try:
        _LOG_LEVEL = int(_LOG_LEVEL)
    except ValueError:
        pass
except KeyError:
    _LOG_LEVEL = logging.WARN

# initialize the module logger
_LOGGER = logging.getLogger("python-ldap-slapd")
_LOGGER.setLevel(_LOG_LEVEL)

# a template string for generating simple slapd.conf file
SLAPD_CONF_TEMPLATE = """
moduleload back_%(database)s
include "%(schema_include)s"
loglevel %(loglevel)s
allow bind_v2
database %(database)s
directory "%(directory)s"
suffix "%(suffix)s"
rootdn "%(rootdn)s"
rootpw "%(rootpw)s"
"""

LOCALHOST = '127.0.0.1'

def mkdirs(path):
    """
    Creates the directory path unless it already exists
    """
    if not os.access(os.path.join(path, os.path.curdir), os.F_OK):
        _LOGGER.debug("creating temp directory %s", path)
        os.mkdir(path)

def delete_directory_content(path):
    """
    Recursively delete content of directory
    """
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for filename in filenames:
            _LOGGER.info("remove %s", os.path.join(dirpath, filename))
            os.remove(os.path.join(dirpath, filename))
        for dirname in dirnames:
            _LOGGER.info("rmdir %s", os.path.join(dirpath, dirname))
            os.rmdir(os.path.join(dirpath, dirname))

def find_available_tcp_port(host=LOCALHOST):
    """
    find an available port for TCP connection
    """
    sock = socket.socket()
    sock.bind((host, 0))
    port = sock.getsockname()[1]
    sock.close()
    _LOGGER.info("Found available port %d", port)
    return port

class SlapdObject(object):
    """
    Controller class for a slapd instance, OpenLDAP's server.

    This class creates a temporary data store for slapd, runs it
    on a private port, and initialises it with a top-level dc and
    the root user.

    When a reference to an instance of this class is lost, the slapd
    server is shut down.
    """
    slapd_conf_template = SLAPD_CONF_TEMPLATE
    database = 'mdb'
    suffix = 'dc=slapd-test,dc=python-ldap,dc=org'
    root_cn = 'Manager'
    root_dn = 'cn=%s,%s' % (root_cn, suffix)
    root_pw = 'password'
    slapd_loglevel = 'stats stats2'

    TMPDIR = os.environ.get('TMP', os.getcwd())
    SBINDIR = os.environ.get('SBIN', '/usr/sbin')
    BINDIR = os.environ.get('BIN', '/usr/bin')
    SCHEMADIR = os.environ.get('SCHEMA', '/etc/openldap/schema')
    INIT_SCHEMA_FILE = os.environ.get('SCHEMA_FILE', 'core.schema')
    INIT_SCHEMA_PATH = os.environ.get('SCHEMA_PATH', os.path.join(SCHEMADIR, INIT_SCHEMA_FILE))
    PATH_LDAPADD = os.path.join(BINDIR, 'ldapadd')
    PATH_LDAPWHOAMI = os.path.join(BINDIR, 'ldapwhoami')
    PATH_SLAPD = os.path.join(SBINDIR, 'slapd')
    PATH_SLAPTEST = os.path.join(SBINDIR, 'slaptest')

    # time in secs to wait before trying to access slapd via LDAP (again)
    _start_sleep = 1.5

    def __init__(self):
        self._proc = None
        self._port = find_available_tcp_port(LOCALHOST)
        self.ldap_uri = "ldap://%s:%d/" % (LOCALHOST, self._port)
        self._log = _LOGGER
        self.testrundir = os.path.join(self.TMPDIR, 'python-ldap-test')
        self._slapd_conf = os.path.join(self.testrundir, "slapd.conf")
        self._db_directory = os.path.join(self.testrundir, "openldap-data")

    def _gen_config(self):
        """
        generates a slapd.conf and returns it as one string
        """
        config_dict = {
            'schema_include': self.INIT_SCHEMA_PATH,
            'loglevel': self.slapd_loglevel,
            'database': self.database,
            'directory': self._db_directory,
            'suffix': self.suffix,
            'rootdn': self.root_dn,
            'rootpw': self.root_pw,
        }
        return self.slapd_conf_template % config_dict

    def _write_config(self):
        """Writes the slapd.conf file out, and returns the path to it."""
        self._log.debug("writing config to %s", self._slapd_conf)
        config_file = file(self._slapd_conf, "wb")
        config_file.write(self._gen_config())
        config_file.close()

    def start(self):
        """
        Starts the slapd server process running, and waits for it to come up.
        """
        if self._proc is None:
            start_ok = False
            config_path = None
            # init directory structure
            delete_directory_content(self.testrundir)
            mkdirs(self.testrundir)
            mkdirs(self._db_directory)
            try:
                self._write_config()
                self._test_configuration()
                self._start_slapd()
                self._wait_for_slapd()
                start_ok = True
                self._log.debug("slapd ready at %s", self.ldap_uri)
                self.started()
            finally:
                if not start_ok:
                    if config_path:
                        try:
                            os.remove(config_path)
                        except os.error:
                            pass
                    if self._proc:
                        self.stop()

    def _start_slapd(self):
        # Spawns/forks the slapd process
        self._write_config()
        self._log.info("starting slapd")
        self._proc = subprocess.Popen([
            self.PATH_SLAPD,
            "-f", self._slapd_conf,
            "-h", self.ldap_uri,
            "-d", "0",
        ])

    def _wait_for_slapd(self):
        # Waits until the LDAP server socket is open, or slapd crashed
        while 1:
            if self._proc.poll() is not None:
                self._stopped()
                raise RuntimeError("slapd exited before opening port")
            time.sleep(self._start_sleep)
            try:
                self._log.debug("Connecting to %s", self.ldap_uri)
                self.ldapwhoami()
            except RuntimeError:
                pass
            else:
                return

    def stop(self):
        """Stops the slapd server, and waits for it to terminate"""
        if self._proc is not None:
            self._log.debug("stopping slapd")
            if hasattr(self._proc, 'terminate'):
                self._proc.terminate()
            else:
                import posix
                import signal
                posix.kill(self._proc.pid, signal.SIGTERM)
            self.wait()

    def restart(self):
        """
        Restarts the slapd server; ERASING previous content.
        Starts the server even it if isn't already running.
        """
        self.stop()
        self.start()

    def wait(self):
        """Waits for the slapd process to terminate by itself."""
        if self._proc:
            self._proc.wait()
            self._stopped()

    def _stopped(self):
        """Called when the slapd server is known to have terminated"""
        if self._proc is not None:
            self._log.info("slapd terminated")
            self._proc = None
            try:
                os.remove(self._slapd_conf)
            except os.error:
                self._log.debug("could not remove %s", self._slapd_conf)

    def _test_configuration(self):
        self._log.debug("testing configuration")
        popen_list = [
            self.PATH_SLAPTEST,
            "-f", self._slapd_conf,
            '-u',
        ]
        if self._log.isEnabledFor(logging.DEBUG):
            popen_list.append('-v')
            popen_list.extend(['-d', 'config'])
        else:
            popen_list.append('-Q')
        try:
            proc = subprocess.Popen(popen_list)
            if proc.wait() != 0:
                raise RuntimeError("configuration test failed")
            self._log.debug("configuration seems ok")
        finally:
            os.remove(self._slapd_conf)

    def ldapwhoami(self, extra_args=None):
        """Runs ldapwhoami on this slapd instance"""
        extra_args = extra_args or []
        self._log.debug("whoami")
        proc = subprocess.Popen(
            [
                self.PATH_LDAPWHOAMI,
                "-x",
                "-D", self.root_dn,
                "-w", self.root_pw,
                "-H", self.ldap_uri
            ] + extra_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        if proc.wait() != 0:
            raise RuntimeError("ldapwhoami process failed")

    def ldapadd(self, ldif, extra_args=None):
        """Runs ldapadd on this slapd instance, passing it the ldif content"""
        extra_args = extra_args or []
        self._log.debug("adding %s", repr(ldif))
        proc = subprocess.Popen(
            [
                self.PATH_LDAPADD,
                "-x",
                "-D", self.root_dn,
                "-w", self.root_pw,
                "-H", self.ldap_uri
            ] + extra_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        proc.communicate(ldif)
        if proc.wait() != 0:
            raise RuntimeError("ldapadd process failed")

    def started(self):
        """
        This method is called when the LDAP server has started up and is empty.
        By default, this method adds the two initial objects,
        the domain object and the root user object.
        """
        assert self.suffix.startswith("dc=")
        suffix_dc = self.suffix.split(',')[0][3:]
        assert self.root_dn.startswith("cn=")
        assert self.root_dn.endswith("," + self.suffix)
        self._log.debug(
            "adding %s and %s",
            self.suffix,
            self.root_dn,
        )
        self.ldapadd(
            "\n".join([
                'dn: '+self.suffix,
                'objectClass: dcObject',
                'objectClass: organization',
                'dc: '+suffix_dc,
                'o: '+suffix_dc,
                '',
                'dn: '+self.root_dn,
                'objectClass: organizationalRole',
                'cn: '+self.root_cn,
                ''
            ])
        )


class SlapdTestCase(unittest.TestCase):
    """
    test class which also clones or initializes a running slapd
    """

    server_class = SlapdObject
    server = None

    def _open_ldap_conn(self, who=None, cred=None):
        """
        return a LDAPObject instance after simple bind
        """
        import ldap
        ldap_conn = self.ldap_object_class(self.server.ldap_uri)
        ldap_conn.protocol_version = 3
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        ldap_conn.simple_bind_s(who or self.server.root_dn, cred or self.server.root_pw)
        return ldap_conn

    @classmethod
    def setUpClass(cls):
        if cls.server is None:
            cls.server = cls.server_class()
            cls.server.start()
        cls.server = cls.server

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.stop()
        except AttributeError:
            pass
        try:
            delete_directory_content(cls.server.testrundir)
        except AttributeError:
            pass
