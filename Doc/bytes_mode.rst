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
In python-ldap, these are represented as text (``str`` on Python 3).

Attribute *values*, on the other hand, **MAY**
contain any type of data, including text.
To know what type of data is represented, python-ldap would need access to the
schema, which is not always available (nor always correct).
Thus, attribute values are *always* treated as ``bytes``.
Encoding/decoding to other formats – text, images, etc. – is left to the caller.


.. _bytes_mode:

The bytes mode
--------------

In Python 3, text values are represented as ``str``, the Unicode text type.
