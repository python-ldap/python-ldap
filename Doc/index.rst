##########################
python-ldap Documentation
##########################

.. topic:: Abstract

   This document describes the package python-ldap with its various modules.

   Depending on what you want to do this manual assumes basic to expert
   knowledge about the Python language and the LDAP standard (LDAPv3).


********
Contents
********

.. toctree::
   :maxdepth: 3

   installing.rst
   ldap.rst
   ldap-async.rst
   ldap-controls.rst
   ldap-dn.rst
   ldap-extop.rst
   ldap-filter.rst
   ldap-modlist.rst
   ldap-resiter.rst
   ldap-schema.rst
   ldap-syncrepl.rst
   ldap-sasl.rst
   ldif.rst
   ldapurl.rst
   slapdtest.rst



*********************
Bytes/text management
*********************

The LDAP protocol states that some fields (distinguised names, relative distinguished names,
attribute names, queries) be encoded in UTF-8; some other (mostly attribute *values*) **MAY**
contain any type of data, and thus be treated as bytes.

In Python 2, ``python-ldap`` used bytes for all fields, including those guaranteed to be text.
In order to support Python 3, this distinction is made explicit. This is done
through the ``bytes_mode`` flag to ``ldap.initialize()``.

When porting from ``python-ldap`` 2.x, users are advised to update their code to set ``bytes_mode=False``
on calls to these methods.
Under Python 2, ``python-pyldap`` aggressively checks the type of provided arguments, and will raise a ``TypeError``
for any invalid parameter.
However, if the ``bytes_mode`` kwarg isn't provided, ``pyldap`` will only
raise warnings.

The typical usage is as follows; note that only the result's *values* are of the bytes type:

.. code-block:: pycon

    >>> import ldap
    >>> con = ldap.initialize('ldap://localhost:389', bytes_mode=False)
    >>> con.simple_bind_s('login', 'secret_password')
    >>> results = con.search_s('ou=people,dc=example,dc=org', ldap.SCOPE_SUBTREE, "(cn=Raphaël)")
    >>> results
    [
        ("cn=Raphaël,ou=people,dc=example,dc=org", {
            'cn': [b'Rapha\xc3\xabl'],
            'sn': [b'Barrois'],
        }),
    ]


******************
Indices and tables
******************

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
