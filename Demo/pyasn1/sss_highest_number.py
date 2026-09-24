#!/usr/bin/env python3
"""
This sample script demonstrates the use of the server-side-sorting control
(see RFC 2891)
"""

import ldap
from ldap.controls.sss import SSSRequestControl
from ldap.ldapobject import LDAPObject
from ldap.resiter import ResultProcessor


class MyLDAPObject(LDAPObject, ResultProcessor):
  pass


uri = "ldap://ipa.demo1.freeipa.org"

l = MyLDAPObject(uri, trace_level=0)
l.simple_bind_s('uid=admin,cn=users,cn=accounts,dc=demo1,dc=freeipa,dc=org', 'Secret123')

for id_attr in ('uidNumber', 'gidNumber'):
  # reverse sorting request control
  sss_control = SSSRequestControl(ordering_rules=[f'-{id_attr}'])
  # send search request
  msg_id = l.search_ext(
    'dc=demo1,dc=freeipa,dc=org',
    ldap.SCOPE_SUBTREE,
    f'({id_attr}=*)',
    attrlist=[id_attr],
    sizelimit=1,
    serverctrls=[sss_control],
  )
  # collect result
  ldap_result = []
  try:
    for res_type, res_data, res_msgid, res_controls in l.allresults(msg_id, add_ctrls=0):
      ldap_result.extend(res_data)
  except ldap.SIZELIMIT_EXCEEDED:
    pass
  # print result
  print(f'Highest value of {id_attr}')
  if ldap_result:
    dn, entry = ldap_result[0]
    print('->', entry[id_attr])
  else:
    print('not found')
