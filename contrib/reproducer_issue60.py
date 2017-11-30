#!/usr/bin/python
"""Reproducer for https://github.com/python-ldap/python-ldap/issues/60

Fails in 3rd iteration on Fedora 27 with nss-3.34.0-1.0.fc27.x86_64
and openldap-2.4.45-3.fc27.x86_64

$ sudo dnf builddep python-ldap
$ sudo yum install -y gcc python-devel openldap-devel openldap-servers openldap-clients

$ ./contrib/nssreproducer.py
$ ./contrib/nssreproducer.py --no-cacertfile
"""

from __future__ import print_function

import argparse
import os
import sys
import subprocess


def connect(server, cacertfile):
    import ldap
    from ldap.ldapobject import SimpleLDAPObject

    conn = SimpleLDAPObject(server.ldap_uri)
    conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)
    if cacertfile:
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
        conn.set_option(ldap.OPT_X_TLS_CACERTFILE, server.cafile)
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    else:
        # don't check CA
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
    conn.start_tls_s()
    conn.simple_bind_s(server.root_dn, server.root_pw)
    return conn


def reproducer(server, iterations=10, cacertfile=False):
    print("Testing with cacertfile={}...".format(cacertfile))
    for i in range(1, iterations+1):
        print("  Iteration {}, cacacertfile={}".format(i, cacertfile))
        conn = connect(server, cacertfile=cacertfile)
        print("    ", conn.whoami_s())
        conn.unbind()


def print_info(args):
    import ldap
    print("")
    print("Python:", sys.version_info)
    if args.use_system:
        print("Using system package:")
    else:
        print("Using local package:")
    print("python-ldap:", ldap.__version__, ldap.__file__)
    print("TLS PACKAGE:", ldap.get_option(ldap.OPT_X_TLS_PACKAGE))
    print("API INFO:", ldap.get_option(ldap.OPT_API_INFO))
    print("")


def main():
    parser = argparse.ArgumentParser("reproducer_issue60")
    parser.add_argument(
        "--no-cacertfile",
        action="store_false",
        dest="cacertfile",
        help="Don't set OPT_X_TLS_CACERTFILE"
    )
    parser.add_argument(
        "--system-package",
        action="store_true",
        dest="use_system",
        help="Don't compile python-ldap, use system package"
    )
    args = parser.parse_args()

    if not args.use_system:
        # build extension module in-place
        subprocess.check_call([
            sys.executable, 'setup.py', 'build_ext', '-i'
        ])
        sys.path.insert(0, 'Lib')
    else:
        if not os.path.islink('slapdtest'):
            os.symlink('Lib/slapdtest', 'slapdtest')
        sys.path.insert(0, os.getcwd())

    print_info(args)

    import slapdtest
    server = slapdtest.SlapdObject()
    server.start()
    try:
        reproducer(server, cacertfile=args.cacertfile)
    finally:
        server.stop()
        if os.path.islink('slapdtest'):
            os.unlink('slapdtest')


if __name__ == '__main__':
    main()
