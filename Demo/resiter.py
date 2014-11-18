"""
Demo for using ldap.resiter.ResultProcessor
written by Michael Stroeder <michael@stroeder.com>

See http://www.python-ldap.org for details.

\$Id: resiter.py,v 1.2 2014/11/18 08:27:22 stroeder Exp $

Python compability note:
Requires Python 2.3+
"""

import ldap,ldap.resiter

class LDAPObject(ldap.ldapobject.LDAPObject,ldap.resiter.ResultProcessor):
  pass

l = LDAPObject('ldap://localhost:1390',trace_level=1)
l.protocol_version = 3
msgid = l.search('dc=stroeder,dc=de',ldap.SCOPE_SUBTREE,'(cn=m*)')

result_iter = l.allresults(msgid)
for result_type,result_list,result_msgid,result_serverctrls in result_iter:
  print result_type,result_list,result_msgid,result_serverctrls

l.unbind_s()
