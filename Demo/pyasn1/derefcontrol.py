#!/usr/bin/env python
"""
This sample script demonstrates the use of the dereference control
(see https://tools.ietf.org/html/draft-masarati-ldap-deref)

Requires module pyasn1 (see http://pyasn1.sourceforge.net/)
"""

import pprint,ldap,ldap.modlist,ldap.resiter

from ldap.controls.deref import DereferenceControl

uri = "ldap://localhost:2071/"

class MyLDAPObject(ldap.ldapobject.LDAPObject,ldap.resiter.ResultProcessor):
  pass


l = MyLDAPObject(uri,trace_level=0)
l.simple_bind_s('uid=diradm,dc=example,dc=com','testsecret')

dc = DereferenceControl(
  True,
  {
    'member':[
      'uid',
      'description',
#      'cn',
#      'mail',
    ],
  }
)

print 'pyasn1 output of request control:'
print dc._derefSpecs().prettyPrint()

msg_id = l.search_ext(
  'dc=example,dc=com',
  ldap.SCOPE_SUBTREE,
  '(objectClass=groupOfNames)',
  attrlist=['cn','objectClass','member','description'],
  serverctrls = [dc]
)

for res_type,res_data,res_msgid,res_controls in l.allresults(msg_id,add_ctrls=1):
  for dn,entry,deref_control in res_data:
    # process dn and entry
    print dn,entry['objectClass']
    if deref_control:
      pprint.pprint(deref_control[0].derefRes)
