python-ldap
===========


What is python-ldap?
--------------------

python-ldap provides an object-oriented API to access `LDAP`_
directory servers from `Python`_ programs.

For LDAP operations the module wraps `OpenLDAP`_'s
client library, *libldap*.

Additionally, the package contains modules for other LDAP-related stuff:

  * `LDIF`_ parsing and generation
  * LDAP URLs
  * LDAPv3 subschema

.. _LDAP: https://en.wikipedia.org/wiki/Ldap
.. _Python: https://www.python.org/
.. _OpenLDAP: https://www.openldap.org/
.. _LDIF: https://en.wikipedia.org/wiki/LDIF


Get it!
-------

:ref:`Installation instructions <installing>` are available for
several platforms.


Mailing list
------------

Discussion about the use and future of python-ldap occurs in
the ``python-ldap@python.org`` mailing list.

You can `subscribe or unsubscribe`_ to this list or browse the `list archive`_.

.. _subscribe or unsubscribe: https://mail.python.org/mailman/listinfo/python-ldap
.. _list archive: https://mail.python.org/pipermail/python-ldap/


Documentation
-------------

The documentation for python-ldap 3.x is hosted at `Read the Docs`_.

You can switch between versions of the library, or download PDF or HTML
versions for offline use, using the sidebar on the right.

Documentation for some older versions is available for download at the
`GitHub release page`_.

.. _Read the Docs: http://python-ldap.readthedocs.io/en/latest/
.. _GitHub release page: https://github.com/python-ldap/python-ldap/releases


Contents
--------

.. toctree::
   :maxdepth: 2

   installing.rst
   reference/index.rst
   resources.rst
   faq.rst


Bytes/text management
---------------------

The LDAP protocol states that some fields (distinguished names, relative distinguished names,
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


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
