#!/usr/bin/env python
"""
This sample script demonstrates the use of the server-side-sorting control
(see RFC 2891)

Requires module pyasn1 (see http://pyasn1.sourceforge.net/)
"""

import pprint,ldap

from ldap.controls.sss import SSSRequestControl

uri = "ldap://ipa.demo1.freeipa.org"

l = ldap.initialize(uri,trace_level=0)
l.simple_bind_s('uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org','Secret123')

for id_attr in ('uidNumber','gidNumber'):
  sss_control = SSSRequestControl(ordering_rules=['-%s' % (id_attr)])
  ldap_result = l.search_ext_s(
    'dc=demo1,dc=freeipa,dc=org',
    ldap.SCOPE_SUBTREE,
    '(%s=*)' % (id_attr),
    attrlist=[id_attr],
    serverctrls = [sss_control],
  )
  print 'Highest value of %s' % (id_attr)
  if ldap_result:
    dn,entry = ldap_result[0]
    print '->',entry[id_attr]
  else:
    print 'not found'
