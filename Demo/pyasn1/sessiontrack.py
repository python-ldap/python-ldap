#!/usr/bin/env python3
"""
demo_track_ldap_session.py

Client-side demo implementation of Session Tracking Control

https://tools.ietf.org/html/draft-wahl-ldap-session-03
"""


__version__ = '0.1'

import getpass
import sys

import ldap
import ldapurl
from ldap.controls.sessiontrack import SESSION_TRACKING_FORMAT_OID_USERNAME, SessionTrackingControl


try:
  ldap_url = ldapurl.LDAPUrl(sys.argv[1])
except (IndexError, ValueError):
  print(f'Usage: {sys.argv[0]} <LDAP URL>')
  sys.exit(1)

# Set debugging level
#ldap.set_option(ldap.OPT_DEBUG_LEVEL,255)
ldapmodule_trace_level = 2
ldapmodule_trace_file = sys.stderr

ldap_conn = ldap.ldapobject.LDAPObject(
  ldap_url.initializeUrl(),
  trace_level=ldapmodule_trace_level,
  trace_file=ldapmodule_trace_file
)

if ldap_url.who and ldap_url.cred is None:
  print(f'Password for {ldap_url.who!r}:')
  ldap_url.cred = getpass.getpass()

try:
  ldap_conn.simple_bind_s(ldap_url.who or '',ldap_url.cred or '')

except ldap.INVALID_CREDENTIALS as e:
  print('Simple bind failed:',str(e))
  sys.exit(1)

st_ctrl = SessionTrackingControl(
  '192.0.2.1',
  'app.example.com',
  SESSION_TRACKING_FORMAT_OID_USERNAME,
  'bloggs'
)

ldap_conn.search_ext_s(
  ldap_url.dn or '',
  ldap_url.scope or ldap.SCOPE_SUBTREE,
  ldap_url.filterstr or '(objectClass=*)',
  ldap_url.attrs or ['*'],
  serverctrls=[st_ctrl]
)
