.. _text-bytes:

Bytes/text management
=====================

Python 3 introduces a hard distinction between *text* (``str``) – sequences of
characters (formally, *Unicode codepoints*) – and ``bytes`` – sequences of
8-bit values used to encode *any* kind of data for storage or transmission.

Python 2 has the same distinction between ``str`` (bytes) and
``unicode`` (text).
However, values can be implicitly converted between these types as needed,
e.g. when comparing or writing to disk or the network.
The implicit encoding and decoding can be a source of subtle bugs when not
designed and tested adequately.

In python-ldap 2.x (for Python 2), bytes were used for all fields,
including those guaranteed to be text.

From version 3.0, python-ldap uses text where appropriate.
On Python 2, the :ref:`bytes mode <bytes_mode>` setting influences how text is
handled.


What's text, and what's bytes
-----------------------------

The LDAP protocol states that some fields (distinguished names, relative
distinguished names, attribute names, queries) be encoded in UTF-8.
In python-ldap, these are represented as text (``str`` on Python 3,
``unicode`` on Python 2).

Attribute *values*, on the other hand, **MAY**
contain any type of data, including text.
To know what type of data is represented, python-ldap would need access to the
schema, which is not always available (nor always correct).
Thus, attribute values are *always* treated as ``bytes``.
Encoding/decoding to other formats – text, images, etc. – is left to the caller.


.. _bytes_mode:

The bytes mode
--------------

The behavior of python-ldap 3.0 in Python 2 is influenced by a ``bytes_mode``
argument to :func:`ldap.initialize`.
The argument can take these values:

``bytes_mode=True``: backwards-compatible

    Text values returned from python-ldap are always bytes (``str``).
    Text values supplied to python-ldap may be either bytes or Unicode.
    The encoding for bytes is always assumed to be UTF-8.

    Not available in Python 3.

``bytes_mode=False``: strictly future-compatible

    Text values must be represented as ``unicode``.
    An error is raised if python-ldap receives a text value as bytes (``str``).

Unspecified: relaxed mode with warnings

    Causes a warning on Python 2.

    Text values returned from python-ldap are always ``unicode``.
    Text values supplied to python-ldap should be ``unicode``;
    warnings are emitted when they are not.

    The warnings are of type :class:`~ldap.LDAPBytesWarning`, which
    is a subclass of :class:`BytesWarning` designed to be easily
    :ref:`filtered out <filter-bytes-warning>` if needed.

Backwards-compatible behavior is not scheduled for removal until Python 2
itself reaches end of life.


Porting recommendations
-----------------------

Since end of life of Python 2 is coming in a few years,
projects are strongly urged to make their code compatible with Python 3.
General instructions for this are provided `in Python documentation`_ and in
the `Conservative porting guide`_.

.. _in Python documentation: https://docs.python.org/3/howto/pyporting.html
.. _Conservative porting guide: https://portingguide.readthedocs.io/en/latest/


When porting from python-ldap 2.x, users are advised to update their code
to set ``bytes_mode=False``, and fix any resulting failures.

The typical usage is as follows.
Note that only the result's *values* are of the ``bytes`` type:

.. code-block:: pycon

    >>> import ldap
    >>> con = ldap.initialize('ldap://localhost:389', bytes_mode=False)
    >>> con.simple_bind_s(u'login', u'secret_password')
    >>> results = con.search_s(u'ou=people,dc=example,dc=org', ldap.SCOPE_SUBTREE, u"(cn=Raphaël)")
    >>> results
    [
        ("cn=Raphaël,ou=people,dc=example,dc=org", {
            'cn': [b'Rapha\xc3\xabl'],
            'sn': [b'Barrois'],
        }),
    ]


.. _filter-bytes-warning:

Filtering warnings
------------------

The bytes mode warnings can be filtered out and ignored with a
simple filter.

.. code-block:: python

   import warnings
   import ldap

   if hasattr(ldap, 'LDAPBytesWarning'):
       warnings.simplefilter('ignore', ldap.LDAPBytesWarning)
