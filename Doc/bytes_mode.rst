.. _text-bytes:
.. _bytes_mode:

Bytes/text management
=====================

The LDAP protocol states that some fields (distinguished names, relative
distinguished names, attribute names, queries) be encoded in UTF-8.
In python-ldap, these are represented as text (``str`` on Python 3).

Attribute *values*, on the other hand, **MAY**
contain any type of data, including text.
To know what type of data is represented, python-ldap would need access to the
schema, which is not always available (nor always correct).
Thus, attribute values are *always* treated as ``bytes``.
Encoding/decoding to other formats – text, images, etc. – is left to the caller.


Historical note
---------------

Python 3 introduced a hard distinction between *text* (``str``) – sequences of
characters (formally, *Unicode codepoints*) – and ``bytes`` – sequences of
8-bit values used to encode *any* kind of data for storage or transmission.

Python 2 had the same distinction between ``str`` (bytes) and
``unicode`` (text).
However, values could be implicitly converted between these types as needed,
e.g. when comparing or writing to disk or the network.
The implicit encoding and decoding can be a source of subtle bugs when not
designed and tested adequately.

In python-ldap 2.x (for Python 2), bytes were used for all fields,
including those guaranteed to be text.

From version 3.0 to 3.3, python-ldap uses text where appropriate.
On Python 2, special ``bytes_mode`` and ``bytes_strictness`` settings
influenced how text was handled.

From version 3.3 on, only Python 3 is supported. The “bytes mode” settings
are deprecated and do nothing.
