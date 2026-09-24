#!/usr/bin/env python3
import os,ldap,pickle

temp_file_name = os.path.join(os.environ.get('TMP','/tmp'),'pickle_ldap-%d' % (os.getpid()))

l1 = ldap.ldapobject.ReconnectLDAPObject('ldap://localhost:1390',trace_level=1)
l1.protocol_version = 3
l1.search_s('',ldap.SCOPE_BASE,'(objectClass=*)')

with open(temp_file_name, 'wb') as pickle_file:
    pickle.dump(l1, pickle_file)

with open(temp_file_name, 'rb') as pickle_file:
    l2 = pickle.load(pickle_file)
l2.search_s('',ldap.SCOPE_BASE,'(objectClass=*)')
