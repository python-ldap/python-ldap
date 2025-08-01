# LDAP Pooling example

## entries as dict

```python
from ldappool import ConnectionPool
pool = ConnectionPool(
	params={"keep": True, "autoBind": True, "retries": 2}, 
	max=5)
pool.set_uri("ldaps://ldap.example.com:636/dc=example,dc=com?uid,mail?sub?(|(uid=test)(mail=test@example.com))")
pool.set_credentials("binddn", "bindpw")
with pool.get() as conn:
	for entry in conn.search_s(pool.basedn,
                                   pool.scope,
                                   pool.filter,
                                   pool.attributes):
		print(f"{entry[0]}: {entry[1].get('uid')} {entry[1].get('mail')}")
		for member in entry[1].get("memberOf", []):
			print(member)
``` 

## entry to dataclass example
```python
from ldappool import ConnectionPool
from ldappool import e2c
pool = ConnectionPool(
        params={"keep": True, "autoBind": True, "retries": 2},
        max=5)
pool.set_uri("ldaps://ldap.example.com:636/dc=example,dc=com?uid,mail?sub?(|(uid=test)(mail=test@example.com))")
pool.set_credentials("binddn", "bindpw")
with pool.get() as conn:
	for entry in map(e2c, conn.search_s(pool.basedn,
                                            pool.scope,
                                            pool.filter,
                                            pool.attributes)):
		print(f"{entry.dn}: {entry.uid} {entry.mail}")
		for member in entry.memberOf:
			print(member)
```

## changing the connection or credentials for the pool

```python
from ldappool import ConnectionPool
from ldappool import e2c
pool = ConnectionPool(
        params={"keep": True, "autoBind": True, "retries": 2},
        max=5)
pool.set_uri("ldaps://ldap.example.com:636/dc=example,dc=com?uid,mail?sub?(|(uid=test)(mail=test@example.com))")
pool.set_credentials("binddn", "bindpw")
with pool.get() as conn:
        for entry in map(e2c, conn.search_s(pool.basedn,
                                            pool.scope,
                                            pool.filter,
                                            pool.attributes)):
                print(f"{entry.dn}: {entry.uid} {entry.mail}")

pool.set_credentials(entry.dn, "changeme")
with pool.get() as conn:
        for entry in map(e2c, conn.search_s(pool.basedn,
                                            pool.scope,
                                            pool.filter,
                                            pool.attributes)):
                print(f"{entry.dn}: {entry.uid} {entry.mail}")
```
