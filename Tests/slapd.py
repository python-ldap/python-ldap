
"""
Utilities for starting up a test slapd server
and talking to it with ldapsearch/ldapadd.
"""

import sys
import os
import socket
import time
import subprocess
import logging
import base64

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
include %(path_schema_core)s
loglevel %(loglevel)s
allow bind_v2
database %(database)s
directory %(directory)s
suffix %(suffix)s
rootdn %(rootdn)s
rootpw %(rootpw)s
"""

def quote(s):
    '''Quotes the '"' and '\' characters in a string and surrounds with "..."'''
    return '"%s"' % s.replace('\\', '\\\\').replace('"', '\\"')

def mkdirs(path):
    """Creates the directory path unless it already exists"""
    if not os.access(os.path.join(path, os.path.curdir), os.F_OK):
        _LOGGER.debug("creating temp directory %s", path)
        os.mkdir(path)

def delete_directory_content(path):
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for n in filenames:
            _LOGGER.info("remove %s", os.path.join(dirpath, n))
            os.remove(os.path.join(dirpath, n))
        for n in dirnames:
            _LOGGER.info("rmdir %s", os.path.join(dirpath, n))
            os.rmdir(os.path.join(dirpath, n))

LOCALHOST = '127.0.0.1'

def find_available_tcp_port(host=LOCALHOST):
    s = socket.socket()
    s.bind((host, 0))
    port = s.getsockname()[1]
    s.close()
    _LOGGER.info("Found available port %d", port)
    return port

class SlapdObject:
    """
    Controller class for a slapd instance, OpenLDAP's server.

    This class creates a temporary data store for slapd, runs it
    on a private port, and initialises it with a top-level dc and
    the root user.

    When a reference to an instance of this class is lost, the slapd
    server is shut down.
    """

    database = 'ldif'
    suffix = 'dc=slapd-test,dc=python-ldap,dc=org'
    root_cn = 'Manager'
    root_dn = 'cn=%s,%s' % (root_cn, suffix)
    root_pw = 'password'
    slapd_loglevel = 'stats stats2'
    
    _log = _LOGGER

    # Use /var/tmp to placate apparmour on Ubuntu:
    PATH_TMPDIR = '/var/tmp'
    PATH_SBINDIR = '/usr/sbin'
    PATH_BINDIR = '/usr/bin'
    PATH_SCHEMA_CORE = '/etc/openldap/schema/core.schema'
    PATH_LDAPADD = os.path.join(PATH_BINDIR, 'ldapadd')
    PATH_LDAPSEARCH = os.path.join(PATH_BINDIR, 'ldapsearch')
    PATH_SLAPD = os.path.join(PATH_SBINDIR, 'slapd')
    PATH_SLAPTEST = os.path.join(PATH_SBINDIR, 'slaptest')

    def __init__(self):
        self._proc = None
        self._port = 0
        self._tmpdir = os.path.join(os.environ.get('TMP', self.PATH_TMPDIR), 'python-ldap-test')
        self._slapd_conf = os.path.join(self._tmpdir, "slapd.conf")
        self._db_directory = os.path.join(self._tmpdir, "openldap-data")
        self._config = self._generate_slapd_conf()
        self._log.setLevel(_LOG_LEVEL)

    # getters
    def get_url(self):
        return "ldap://%s:%d/" % self.get_address()

    def get_address(self):
        if self._port == 0:
            self._port = find_available_tcp_port(LOCALHOST)
        return (LOCALHOST, self._port)

    def __del__(self):
        self.stop()

    def _generate_slapd_conf(self):
        """
        returns a string with a complete slapd.conf
        """
        # reinitialize database
        delete_directory_content(self._db_directory)
        # generate slapd.conf lines
        config_dict = {
            'path_schema_core': quote(self.PATH_SCHEMA_CORE),
            'loglevel': self.slapd_loglevel,
            'database': quote(self.database),
            'directory': quote(self._db_directory),
            'suffix': quote(self.suffix),
            'rootdn': quote(self.root_dn),
            'rootpw': quote(self.root_pw),
        }
        return SLAPD_CONF_TEMPLATE % config_dict

    def _write_config(self):
        """Writes the slapd.conf file out, and returns the path to it."""
        mkdirs(self._tmpdir)
        mkdirs(self._db_directory)
        self._log.debug("writing config to %s", self._config)
        config_file = file(self._slapd_conf, "wb")
        config_file.write(self._config)
        config_file.close()

    def start(self):
        """
        Starts the slapd server process running, and waits for it to come up.
        """
        if self._proc is None:
            ok = False
            config_path = None
            try:
                self._test_configuration()
                self._start_slapd()
                self._wait_for_slapd()
                ok = True
                self._log.debug("slapd ready at %s", self.get_url())
                self.started()
            finally:
                if not ok:
                    if config_path:
                        try: os.remove(config_path)
                        except os.error: pass
                    if self._proc:
                        self.stop()

    def _start_slapd(self):
        # Spawns/forks the slapd process
        self._write_config()
        self._log.info("starting slapd")
        self._proc = subprocess.Popen([
            self.PATH_SLAPD,
            "-f", self._slapd_conf,
            "-h", self.get_url(),
            "-d", "0",
        ])

    def _wait_for_slapd(self):
        # Waits until the LDAP server socket is open, or slapd crashed
        s = socket.socket()
        while 1:
            if self._proc.poll() is not None:
                self._stopped()
                raise RuntimeError("slapd exited before opening port")
            try:
                self._log.debug("Connecting to %s", repr(self.get_address()))
                s.connect(self.get_address())
                s.close()
                return
            except socket.error:
                time.sleep(1)

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
        self._write_config()
        self._log.debug("testing configuration")
        popen_list = [
            self.PATH_SLAPTEST,
            "-f", self._slapd_conf,
#            "-u", os.environ['USER'],
        ]
        if self._log.isEnabledFor(logging.DEBUG):
            popen_list.append('-v')
            popen_list.extend(['-d', 'config'])
        else:
            popen_list.append('-Q')
        try:
            p = subprocess.Popen(popen_list)
            if p.wait() != 0:
                raise RuntimeError("configuration test failed")
            self._log.debug("configuration seems ok")
        finally:
            pass
            #os.remove(self._slapd_conf)

    def ldapadd(self, ldif, extra_args=None):
        """Runs ldapadd on this slapd instance, passing it the ldif content"""
        extra_args = extra_args or []
        self._log.debug("adding %s", repr(ldif))
        p = subprocess.Popen(
            [
                self.PATH_LDAPADD,
                "-x",
                "-D", self.root_dn,
                "-w", self.root_pw,
                "-H", self.get_url()
            ] + extra_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        p.communicate(ldif)
        if p.wait() != 0:
            raise RuntimeError("ldapadd process failed")

    def ldapsearch(
            self, base=None, filterstr='(objectClass=*)', attrs=None,
            scope='sub', extra_args=None
        ):
        attrs = attrs or []
        extra_args = extra_args or []
        if base is None:
            base = self.suffix
        self._log.debug("ldapsearch filterstr=%s", repr(filterstr))
        p = subprocess.Popen(
            [
                self.PATH_LDAPSEARCH,
                "-x",
                "-D", self.root_dn,
                "-w", self.root_pw,
                "-H", self.get_url(),
                "-b", base,
                "-s", scope,
                "-LL",
            ]+extra_args+[filterstr]+attrs,
            stdout=subprocess.PIPE,
        )
        output = p.communicate()[0]
        if p.wait() != 0:
            raise RuntimeError("ldapadd process failed")

        # RFC 2849: LDIF format
        # unfold
        lines = []
        for l in output.split('\n'):
            if l.startswith(' '):
                lines[-1] = lines[-1] + l[1:]
            elif l == '' and lines and lines[-1] == '':
                pass # ignore multiple blank lines
            else:
                lines.append(l)
        # Remove comments
        lines = [l for l in lines if not l.startswith("#")]

        # Remove leading version and blank line(s)
        if lines and lines[0] == '':
            del lines[0]
        if not lines or lines[0] != 'version: 1':
            raise RuntimeError("expected 'version: 1', got " + repr(lines[:1]))
        del lines[0]
        if lines and lines[0] == '':
            del lines[0]

        # ensure the ldif ends with a blank line (unless it is just blank)
        if lines and lines[-1] != '':
            lines.append('')

        objects = []
        obj = []
        for line in lines:
            if line == '': # end of an object
                if obj[0][0] != 'dn':
                    raise RuntimeError("first line not dn", repr(obj))
                objects.append((obj[0][1], obj[1:]))
                obj = []
            else:
                attr, value = line.split(':', 2)
                if value.startswith(': '):
                    value = base64.decodestring(value[2:])
                elif value.startswith(' '):
                    value = value[1:]
                else:
                    raise RuntimeError("bad line: " + repr(line))
                obj.append((attr, value))
        assert obj == []
        return objects

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
