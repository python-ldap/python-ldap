Released 3.5.0 (unreleased)
---------------------------

Breaking:

* :attr:`~ldap.schema.models.SchemaElement.token_defaults` class attribute had to
  go, we could not find a safe way to keep it working with subclasses and are
  unaware of any users either

API changes:

* The deprecated :data:`ldap.OPT_X_TLS` option has been removed, as announced in the
  3.4.3 release notes. The ``OPT_X_TLS_*`` option constants (such as
  :data:`ldap.OPT_X_TLS_NEWCTX` and :data:`ldap.OPT_X_TLS_REQUIRE_CERT`) are unaffected.

* :class:`ldap.DummyLock` has been removed as it has been useless since Python 3.7
* :data:`ldap.controls.KNOWN_RESPONSE_CONTROLS` now only contains :class:`~ldap.controls.ResponseControl` types

* Iterating :class:`ldap.schema.Entry` now correctly iterates over the visible keys,
  not internal representation

* code better aligns with documentation:

  * :class:`~ldap.controls.simple.AuthorizationIdentityResponseControl` now decodes
    returned identity as documented
  * :class:`~ldap.ldapobject.LDAPObject`'s ``*_s`` functions actually return ``None`` as advertised
  * :class:`ldif.LDIFParser` now correctly ignores unknown URL schemes rather than
    attaching ``None`` as value
  * People overriding :meth:`~ldap.syncrepl.SyncreplConsumer.syncrepl_present` will no longer see
    :attr:`~ldap.controls.syncrepl.SyncDoneControl.refreshDeletes` have a value of ``None``

* If using the search MixIn classes (including :class:`~ldap.syncrepl.SyncreplConsumer`) and replacing
  the relevant controls in :data:`ldap.controls.KNOWN_RESPONSE_CONTROLS` at the same time, make
  sure you subclass the original implementations

* Calling :meth:`~ldap.schema.subentry.SubSchema.get_structural_oc` with incompatible
  ``STRUCTURAL`` object classes has produced undefined behaviour in the past and it
  does again. This and :meth:`ldap.schema.subentry.SubSchema.attribute_types` and :meth:`ldap.schema.models.Entry.attribute_types` with
  DIT content rules enforced will raise an error in future versions

Fixes:

* :class:`~ldap.controls.pwdpolicy.PasswordExpiredControl` finally returns reported
  status

* corrected :mod:`ldap.functions` export list to remove long gone items


Deprecations:

* See above note for :meth:`~ldap.schema.subentry.SubSchema.get_structural_oc` and its users
* :func:`~ldap.schema.tokenizer.extract_tokens` has been replaced with
  :func:`~ldap.schema.tokenizer.parse_tokens` and will go away eventually

* :mod:`_ldap` module is now a stub forwarding to :mod:`ldap._ldap`, :mod:`_ldap` will
  go away eventually

Infrastructure:

* Building from source now requires setuptools >= 77, needed for the
  PEP 639 license metadata in ``pyproject.toml``

* Removed the ``[install]`` byte-compile options from :file:`setup.cfg`, so
  locally built wheels no longer contain ``__pycache__`` directories

Released 3.4.8 (2026-09-16)
---------------------------

Fixes:

* Plugged memory and reference leaks at error-handling time (#40, #617, #619,
  #620, #621, #622, #632)

* VLV control now honors ``contextID`` passed in (#618)
* :mod:`ldapurl` now correctly escapes when emitting an HTML anchor (#628)
* :func:`_ldap.str2dn` now handles empty string correctly (#549)
* Handle server-sent invalid UTF-8 correctly (by throwing an error) (#624)
* corrected :mod:`ldap.functions` export list to remove long gone items


Doc:

* file descriptor ownership has now been clarified - if providing a file descriptor to set up a new
  :class:`~ldap.ldapobject.LDAPObject`, it is now owned and managed by the module, do not close it
  yourself (#575)

* clarifications on handling EINTR -> use :data:`ldap.OPT_RESTART` (#242)
* clarified build dependencies (#569)
* clarified :data:`ldap.OPT_CLIENT_CONTROLS`/:data:`ldap.OPT_SERVER_CONTROLS` (#639)


Infrastructure:

* Build requirement pinned to ``setuptools>=61``: older setuptools ignores
  the PEP 621 ``[project]`` table and produces an ``sdist`` with broken metadata
  (``Name: unknown``), which made pip silently fall back to ancient releases
  when building 3.4.5 from source (#616). Old environments now fail with a
  clear resolver error instead.

* Removed the ``[install]`` section (``compile``/``optimize``) from
  :file:`setup.cfg`; it caused ``bdist_wheel`` to embed ``__pycache__``
  byte-code files in published wheels (#615).

Released 3.4.7 2026-05-19
-------------------------

No code changes, correcting for the fact that the previous release artifacts
uploaded to PyPI contained unintended files.

Released 3.4.6 2026-05-14
-------------------------

Fixes:

* ``attrlist`` parameter is now properly checked before use, avoiding memory
  errors due to type mismatches

* Fixed errors with ``requestName``/``requestValue`` in ``extop.dds``
* :mod:`ldif` and :mod:`ldap.schema` modules now actively close sockets as they're
  finished with them

Infrastructure:

* Package no longer requires ``setuptools-scm``


Released 3.4.5 2025-10-10
-------------------------

Security fixes:

* CVE-2025-61911 (GHSA-r7r6-cc7p-4v5m): Enforce :class:`str` input in
  :func:`ldap.filter.escape_filter_chars` with ``escape_mode=1``; ensure proper
  escaping. (thanks to ``lukas-eu``)

* CVE-2025-61912 (GHSA-p34h-wq7j-h5v6): Correct NUL escaping in
  :func:`ldap.dn.escape_dn_chars` to ``\00`` per RFC 4514. (thanks to ``aradona91``)

Fixes:

* :class:`~ldap.ldapobject.ReconnectLDAPObject` now properly reconnects on :exc:`ldap.UNAVAILABLE`, :exc:`ldap.CONNECT_ERROR`
  and :exc:`ldap.TIMEOUT` exceptions (previously only :exc:`ldap.SERVER_DOWN`), fixing reconnection
  issues especially during server restarts

* Fixed :file:`syncrepl.py` to use named constants instead of raw decimal values
  for result types

* Fixed error handling in :class:`~ldap.controls.openldap.SearchNoOpMixIn` to prevent an undefined variable error


Tests:

* Added comprehensive reconnection test cases including concurrent operation
  handling and server restart scenarios

Doc/

* Updated installation docs and fixed various documentation typos
* Added ReadTheDocs configuration file


Infrastructure:

* Add testing and document support for Python 3.13


Released 3.4.4 2022-11-17
-------------------------

Fixes:

* Reconnect race condition in :class:`~ldap.ldapobject.ReconnectLDAPObject` is now fixed
* Socket ownership is now claimed once we have passed it to libldap
* ``LDAP_set_option`` string formats are now compatible with Python 3.12


Doc/

* Security Policy was created
* Broken article links are fixed now
* Bring Conscious Language improvements


Infrastructure:

* Add testing and document support for Python 3.10, 3.11, and 3.12



Released 3.4.3 2022-09-15
-------------------------

This is a minor release to bring back the removed :data:`ldap.OPT_X_TLS` option.
Please note, it's still a deprecated option and it will be removed in 3.5.0.

The following deprecated option has been brought back:

- :data:`ldap.OPT_X_TLS`


Fixes:

* Sphinx documentation is now successfully built
* PyPy 3 test stability was improved
* :file:`setup.py` deprecation warning is now resolved



Released 3.4.2 2022-07-06
-------------------------

This is a minor release to provide out-of-the-box compatibility with the merge
of libldap and ``libldap_r`` that happened with OpenLDAP's 2.5 release.

The following undocumented functions are deprecated and scheduled for removal:

- :func:`ldap.cidict.strlist_intersection`
- :func:`ldap.cidict.strlist_minus`
- :func:`ldap.cidict.strlist_union`


The following deprecated option has been removed:

- :data:`ldap.OPT_X_TLS`


Doc/

* SASL option usage has been clarified


Lib/

* ``ppolicy`` control definition has been updated to match Behera draft 11


Modules/

* By default, compile against libldap, checking whether it provides a
  thread-safe implementation at runtime

* When decoding controls, the module can now distinguish between no value
  (now exposed as ``None``) and an empty value (exposed as ``b''``)

* Several new OpenLDAP options are now supported:
  * :data:`ldap.OPT_SOCKET_BIND_ADDRESSES`
  * :data:`ldap.OPT_TCP_USER_TIMEOUT`
  * :data:`ldap.OPT_X_SASL_MAXBUFSIZE`
  * :data:`ldap.OPT_X_SASL_SECPROPS`
  * :data:`ldap.OPT_X_TLS_ECNAME`
  * :data:`ldap.OPT_X_TLS_PEERCERT`
  * :data:`ldap.OPT_X_TLS_PROTOCOL`-related options and constants


Fixes:

* Encoding/decoding of boolean controls has been corrected
* :class:`ldap.schema.models.Entry` is now usable
* ``method`` keyword to :meth:`~ldap.ldapobject.ReconnectLDAPObject.bind_s` is now usable



Released 3.4.0 2021-11-26
-------------------------

This release requires Python 3.6 or above,
and is tested with Python 3.6 to 3.10.
Python 2 is no longer supported.

New code in the python-ldap project is available under the MIT license
(available in :file:`LICENCE.MIT` in the source). Several contributors have agreed
to apply this license to their previous contributions as well.
See the :file:`README` for details.

The following undocumented functions are deprecated and scheduled for removal:

- :func:`ldap.cidict.strlist_intersection`
- :func:`ldap.cidict.strlist_minus`
- :func:`ldap.cidict.strlist_union`


Security fixes:

* Fix inefficient regular expression which allows denial-of-service attacks
  when parsing specially-crafted LDAP schema.
  (GHSL-2021-117)

Changes:

* On MacOS, remove option to make LDAP connections from a file descriptor
  when built with the system libldap (which lacks the underlying function,
  ``ldap_init_fd``)

* Attribute values of the post read control are now :class:`bytes`
  instead of ISO8859-1 decoded :class:`str`

* :class:`ldapurl.LDAPUrl` now treats :attr:`ldapurl.LDAPUrl.urlscheme` as case-insensitive
* Several OpenLDAP options are now supported:
  * :data:`ldap.OPT_X_TLS_REQUIRE_SAN`
  * :data:`ldap.OPT_X_SASL_SSF_EXTERNAL`
  * :data:`ldap.OPT_X_TLS_PEERCERT`


Fixes:

* The :meth:`ldap.cidict.cidict.copy` method of :class:`ldap.cidict.cidict` was added back. It was unintentionally
  removed in 3.3.0

* Fixed getting/setting ``SASL`` options on ``big-endian`` platforms
* Unknown LDAP result codes are now converted to :exc:`ldap.LDAPError`,
  rather than raising a :exc:`SystemError`.

:mod:`slapdtest`:

* Show stderr of ``slapd -Ttest``
* :class:`slapdtest.SlapdObject` uses directory-based configuration of ``slapd``
* :class:`slapdtest.SlapdObject` startup is now faster


Infrastructure:

* CI now runs on GitHub Actions rather than Travis CI.



Released 3.3.0 2020-06-18
-------------------------

Highlights:

* :exc:`ldap.LDAPError` now contains additional fields, such as ``ctrls``, ``result``, ``msgid``
* :meth:`~ldap.ldapobject.LDAPObject.passwd_s` can now extract the newly generated password
* LDAP connections can now be made from a file descriptor


This release is tested on Python 3.8, and the beta of Python 3.9.

The following undocumented functions are deprecated and scheduled for removal:

- :func:`ldap.cidict.strlist_intersection`
- :func:`ldap.cidict.strlist_minus`
- :func:`ldap.cidict.strlist_union`


Modules/

* Ensure :class:`~ldap.ldapobject.ReconnectLDAPObject` is not left in an inconsistent state after
  a reconnection timeout

* Syncrepl now correctly parses :obj:`SyncInfoMessage` when the message is a ``syncIdSet``
* Release GIL around global get/set option call
* Do not leak serverctrls in result functions
* Don't over-allocate memory in ``attrs_from_List()``
* Fix thread support check for Python 3
* With OpenLDAP 2.4.48, use the new header ``openldap.h``


Lib/

* Fix some edge cases regarding quoting in the schema tokenizer
* Fix escaping a single space in :func:`ldap.dn.escape_dn_chars`
* Fix string formatting in :func:`ldap.compare_ext_s`
* Prefer iterating :class:`dict` instead of calling :meth:`dict.keys`


Doc/

* Clarify the relationship between :func:`ldap.initialize` and :class:`~ldap.ldapobject.LDAPObject`
* Improve documentation of TLS options
* Update FAQ to include Samba AD-DC error message
  "Operation unavailable without authentication"

* Fix several incorrect examples and demos
  (but note that these are not yet tested)

* Update Debian installation instructions for Debian Buster
* Typo fixes in documentation and doc strings


Test/

* Test and document error cases in :func:`ldap.compare_s`
* Test if reconnection is done after connection loss
* Make test certificates valid for the far future
* Use ``slapd -Tt`` instead of ``slaptest``


Infrastructure:

* Mark the :file:`LICENCE` file as a license for setuptools
* Use ``unittest discover`` rather than ``setup.py test`` to run tests



Released 3.2.0 2019-03-13
-------------------------

Lib/

* Add support for X-ORIGIN in :mod:`ldap.schema`'s :class:`~ldap.schema.models.ObjectClass`
* Make :func:`ldap.initialize` pass extra keyword arguments to :class:`~ldap.ldapobject.LDAPObject`
* :mod:`ldap.controls.sss`: use :class:`str` instead of ``basestring`` on Python 3
* Provide ``ldap._trace_*`` attributes in non-debug mode


Doc/

* Fix ReST syntax for links to :meth:`~ldap.ldapobject.LDAPObject.set_option` and :meth:`~ldap.ldapobject.LDAPObject.get_option`


Tests/

* Use ``intersphinx`` to link to Python documentation
* Correct type of some attribute values to :class:`bytes`
* Use system-specific ENOTCONN value


Infrastructure:

* Add testing and document support for Python 3.7
* Add Python 3.8-dev to Tox and CI configuration
* Add ``Doc/requirements.txt`` for building on Read the Docs



Released 3.1.0 2018-05-25
-------------------------

This release brings two minor API changes:

- Long-deprecated functions :func:`ldap.open` and :func:`ldap.init` are removed
- :meth:`~ldap.ldapobject.LDAPObject.compare_s` and :meth:`~ldap.ldapobject.LDAPObject.compare_ext_s` return :class:`bool` instead of 0 or 1


All changes since 3.0.0:

Lib/

* Remove long deprecated functions :func:`ldap.open` and :func:`ldap.init`
* :meth:`~ldap.ldapobject.LDAPObject.compare_s` and :meth:`~ldap.ldapobject.LDAPObject.compare_ext_s` now return a :class:`bool`
  instead of 1 or 0.

* Make iteration over :class:`ldap.cidict.cidict` yield same values as :meth:`dict.keys`
* Fail if :mod:`pyasn1` is not installed
* Fix parsing of :obj:`ldap.controls.ppolicy.PPolicyControl` ASN.1 structure
* Use :meth:`dict.items` when appropriate in :class:`dict` iteration
* Add support for tracing LDAP calls. Tracing can now be enabled with
  the environment variable ``PYTHON_LDAP_TRACE_LEVEL`` and redirected to a file with
  ``PYTHON_LDAP_TRACE_FILE``.
  (This is mainly intended for debugging and internal testing; the
  configuration or output may change in future versions.)

Modules/

* Fix ref counting bug in ``LDAPmessage_to_python``


Doc/

* Remove warning about unreleased version
* Doc: Replace Mac OS X -> macOS


Tests/

* Add tests and coverage for tracing
* Disable warnings-as-errors for Python 3.4
* Fix ``assertTrue`` to ``assertEqual``
* Mark several test values as :class:`bytes`


``Lib/slapdtest/``

* Fix error message for missing commands
* Make :class:`slapdtest.SlapdObject` a context manager
* Disable SASL external when missing SASL support
* Make :attr:`~slapdtest.SlapdObject.root_dn` a property
* In :class:`slapdtest.SlapdObject`, build include directives dynamically
* Move import statements to top level


Code style:

* Add ``Makefile`` rules for automatic formatting of C and Python code
* Reformat and indent all C files
* Trim whitespace throughout the project


Infrastructure:

* Add ``py3-trace`` tox environment to Travis CI configuration
* Add new pytest cache directory to ``.gitignore``


General:

* Update all ``pypi.python.org`` URLs to ``pypi.org``



Released 3.0.0 2018-03-12
-------------------------

Notable changes since 2.4.45 (please see detailed logs below):

* Python 3 support and ``bytes_mode``
  see: https://python-ldap.readthedocs.io/en/latest/bytes_mode.html

* The module :mod:`ldap.async` is renamed to :mod:`ldap.asyncsearch`
* New dependencies: :mod:`pyasn1`, :mod:`pyasn1_modules`
* Dropped support for Python 2.6 and 3.3



Changes since 3.0.0b4:

Lib/

* Add ``bytes_strictness`` to allow configuring behavior on bytes/text mismatch


Modules/

* Add argument name to bytes mode :exc:`TypeError`
* Use correct integer types for BER encode/decode (fix for ``big-endian`` machines)


Test/

* Set $LDAPNOINIT in all tests
* Add test for secure TLS default
* Ignore SASL methods in DSE test (fix for restricted environments)
* Remove filterstr workaround from syncrepl test
* Explicitly set :data:`ldap.OPT_X_TLS_REQUIRE_CERT` option to :data:`ldap.OPT_X_TLS_HARD` in ``test_tls_ext_noca``


Doc/

* Link to bytes mode from text-string arguments in the :mod:`ldap` module


Infrastructure:

* Include ``lber`` in list of libraries in :file:`setup.cfg`


Released 3.0.0b4 2018-01-10
---------------------------

Changes since 3.0.0b3:

Removed support for Python 3.3, which reached its end-of-life 2017-09-29.

Lib/

* Make default argument values work under ``bytes_mode``
* Update use of :func:`map` to use :class:`list`/:class:`set` comprehensions instead


Test/

* Refactor syncrepl tests to run with ``bytes_mode``


Doc/

* Document :attr:`~ldif.LDIFRecordList.all_records` attribute of :class:`ldif.LDIFRecordList`



Released 3.0.0b3 2017-12-20
---------------------------

Changes since 3.0.0b2:

The functions :func:`ldap.open`, :func:`ldap.init`, :func:`ldif.CreateLDIF`
and :func:`ldif.ParseLDIF`, which were deprecated for over a decade,
are scheduled for removal in python-ldap 3.1.

Infrastructure:

* Require setuptools to build
* Start running automatic tests on PyPy


Lib/

* When raising :exc:`ldap.LDAPBytesWarning`, give helpful code locations
* Use modern Python idioms in several places
* Avoid re-implementing :meth:`collections.UserDict.get` in :class:`ldap.cidict.cidict` and :class:`ldap.schema.models.Entry`


Doc/

* Use HTTPS links


Test/

* Add reproducer for OpenLDAP's NSS shutdown/restart issue
* Make testing on non-Linux platforms easier



Released 3.0.0b2 2017-12-11
---------------------------

Changes since 3.0.0b1:

The module :mod:`ldap.async` is renamed to :mod:`ldap.asyncsearch`, due to
`async` becoming a keyword in Python 3.7.
The old module name is deprecated, but will be available as long
as Python 3.6 is supported.

Lib/

* Use custom :class:`ldap.LDAPBytesWarning` class
* Rename :mod:`ldap.async` to :mod:`ldap.asyncsearch`


Modules/

* Support ``None`` for :meth:`~ldap.ldapobject.LDAPObject.set_option` (:data:`ldap.OPT_TIMEOUT`) and :data:`ldap.OPT_NETWORK_TIMEOUT`
* Fix error reporting of :meth:`~ldap.ldapobject.LDAPObject.set_option`
* Change memory handling in ``attrs_from_List()``


Test/

* Remove workaround for OpenLDAP NSS issue


Demo/

* Use uniform shebang in all demos


Doc/

* Provide build dependencies for Alpine and CentOS
* Move sample workflow out of the main Contributing guide


Infrastructure:

* Add ``valgrind`` target to check for memory leaks
* Minimal configuration for pytest



Released 3.0.0b1 2017-12-04
---------------------------

Changes since 2.4.45:
(this list includes changes from 2.5.x)

New dependencies (automatically installed when using pip):

* :mod:`pyasn1` 0.3.7+
* :mod:`pyasn1_modules` 0.1.5+


Python 3 support and ``bytes_mode``:

* merged from the pyldap fork (https://github.com/pyldap)
* please see documentation on ``bytes_mode`` and text/bytes handling:
    https://python-ldap.readthedocs.io/en/latest/bytes_mode.html

Removed support for Python 2.6.

Infrastructure:

* Move to Git
* Don't define search path for includes and libs in the default :file:`setup.cfg`
* Include sasl/sasl.h from the standard path
* Re-format :file:`README` to ReStructured Text
* Setup for automatic testing using Travis CI
* Add coverage reporting for Python and C
* Add install requires into :file:`setup.py`
* Remove ``distclean.sh`` in favor of ``make clean``
* Use ``package``, ``depends``, ``install_requires`` in :file:`setup.py`
* Add make target for scan-build (static analysis using clang)
* Add make target and suppression file for Valgrind (memory checker)


Modules/

* Remove unused ``LDAPberval`` helper functions
* Fix type conversion in page control
* Fix multiple ref leaks in error-handling code
* Fix reference leak in result4
* Fix several compiler warnings
* Fix memory leak in ``whoami``
* Fix internal error handling of ``LDAPControl_to_List()``
* Fix two memory leaks and release GIL in ``encode_assertion_control``
* Allow :meth:`~ldap.ldapobject.LDAPObject.set_option` to set timeouts to infinity

and, thanks to Michael Ströder:

* removed unused code schema.c
* moved code from version.c to ``ldapmodule.c``
* removed obsolete backward compatibility constants from ``common.h``
* build checks whether ``LDAP_API_VERSION`` is OpenLDAP 2.4.x
* :data:`_ldap.__author__` and :data:`_ldap.__license__` also set from :mod:`ldap.pkginfo`
* assume C extension API for Python 2.7+


Lib/

* Avoid :func:`eval` for getting module-level variables to fix running under pytest
* Compatibility changes for :mod:`pyasn1` 0.3 or newer

and, thanks to Michael Ströder:

* :data:`ldap.__version__`, :data:`ldap.__author__` and :data:`ldap.__license__` now
  imported from new sub-module :mod:`ldap.pkginfo` also to :file:`setup.py`

* Added safety assertion when importing :mod:`_ldap`:
  :data:`ldap.pkginfo.__version__` must match :data:`_ldap.__version__`

* removed standalone module :mod:`dsml`
* :meth:`~slapdtest.SlapdObject.restart` just restarts slapd
  without cleaning any data

* The methods :meth:`~ldap.controls.sss.SSSResponseControl.decodeControlValue` and
  :meth:`~ldap.controls.vlv.VLVResponseControl.decodeControlValue` now follow the coding
  convention to use camel-cased ASN.1 name as class attribute name.
  The old class names are still set for backward compatibility
  but should not be used in new code because they might be removed
  in a later release.

* removed :class:`ldap.controls.sss.SSSRequestControl` from :data:`ldap.controls.KNOWN_RESPONSE_CONTROLS`
* removed all dependencies on modules string and types
* removed use of ``.has_key()``
* removed class :class:`ldap.ldapobject.NonblockingLDAPObject`
* new global constant :data:`ldap.LIBLDAP_API_INFO`
* right after importing :mod:`_ldap` there is a call into libldap to initialize it
* methods :meth:`~ldap.controls.sss.SSSResponseControl.decodeControlValue` and :meth:`~ldap.controls.vlv.VLVResponseControl.decodeControlValue`
  does not set class attribute ``result_code`` anymore

* always use :class:`bytes` for :class:`uuid.UUID` constructor in :mod:`ldap.syncrepl`
* module :mod:`ldif` now uses functions :func:`base64.b64encode` and :func:`base64.b64decode`
* fixed pickling and restoring of :class:`~ldap.ldapobject.ReconnectLDAPObject`


``Lib/slapdtest``

* Automatically try some common locations for ``SCHEMADIR``
* Ensure server is stopped when the process exits
* Check for LDAP schema and slapd binaries
* :mod:`slapdtest` is now a package and includes testing certificates


Tests/

* Expand cidict membership test
* Add test suite for binds
* Add test suite for edits
* Add a smoke-check for :meth:`~ldap.schema.subentry.SubSchema.listall` and :meth:`~ldap.schema.subentry.SubSchema.attribute_types`
* Add test case for SASL EXTERNAL auth
* Add tests for ``start_tls``
* In CI, treat compiler warnings as fatal errors
* Added tests for :mod:`ldap.syncrepl`

and, thanks to Michael Ströder:

* added explicit reconnect tests for :class:`~ldap.ldapobject.ReconnectLDAPObject`
* scripts do not directly call :meth:`~slapdtest.SlapdTestCase.setUpClass` anymore
* added LDIF test with folded, base64-encoded attribute
* added more tests for sub-module :mod:`ldap.dn`


Doc/

* Build documentation without the compiled C extension
* Merge contents from python-ldap.org
* Move reference documentation in its own section
* Document return value of ``{modify,add,delete}_ext_s()`` as a :class:`tuple`
* Add tests for documentation (build & spelling)
* Link to documentation of old versions
* Add a contributing guide


Released 2.4.45 2017-10-09
--------------------------

Changes since 2.4.44:

Lib/

* Fixed re-raising of the wrong exception in :meth:`~ldap.ldapobject.SimpleLDAPObject._ldap_call`
  (thanks to Aigars Grins)

Tests/

* removed work-around in :file:`t_cext.py`


Released 2.4.44 2017-09-08
--------------------------

Changes since 2.4.43:

Modules/

* more fine-grained GIL releasing in function ``l_ldap_result4()``


Released 2.4.43 2017-09-06
--------------------------

Changes since 2.4.42:

Lib/

* fixed passing all arguments from :meth:`~ldap.ldapobject.LDAPObject.sasl_non_interactive_bind_s`
  to :meth:`~ldap.ldapobject.LDAPObject.sasl_interactive_bind_s`

Tests/

* added test for :meth:`~ldap.ldapobject.LDAPObject.sasl_external_bind_s`


Doc/

* added docs for SASL bind methods
* more references
* better sorting of :class:`~ldap.ldapobject.LDAPObject` methods


Released 2.4.42 2017-09-04
--------------------------

Changes since 2.4.41:

Lib/

* added new :class:`slapdtest.SlapdObject` methods
  :meth:`~slapdtest.SlapdObject._ln_schema_files` and
  :meth:`~slapdtest.SlapdObject._create_sub_dirs`

* :class:`slapdtest.SlapdObject` methods :meth:`~slapdtest.SlapdObject.setup_rundir`
  and :meth:`~slapdtest.SlapdObject.gen_config`
  are now "public" methods

* removed pseudo test script from module :mod:`ldap.cidict`


Tests/

* added sub-module for testing class :class:`ldap.cidict.cidict`
* avoid deprecated method alias :meth:`unittest.TestCase.assertEquals`


Released 2.4.41 2017-07-12
--------------------------

Changes since 2.4.40:

Lib/

* Added support for increment: lines in LDIF changes records


Released 2.4.40 2017-06-27
--------------------------

Changes since 2.4.39:

Modules/

* fixed memory leaks when using extended controls
  (thanks to Erik Cumps)

Released 2.4.39 2017-05-31
--------------------------

Changes since 2.4.38:

Lib/

* fixed ``errno``-related :exc:`ldap.TIMEOUT` regression


:file:`Lib/slapdtest.py`

* Removed obsolete assert statements


Released 2.4.38 2017-04-28
--------------------------

Changes since 2.4.37:

:file:`Lib/slapdtest.py`

* :class:`slapdtest.SlapdObject` now evaluates environment variable ``SLAPD`` for optionally pointing
  to OpenLDAP's slapd executable (e.g. with OpenLDAP LTB builds)

* added LDAPI support in :class:`slapdtest.SlapdObject`, which is internally used
  in methods :meth:`~slapdtest.SlapdObject.ldapadd` and :meth:`~slapdtest.SlapdObject.ldapwhoami`

* added method :meth:`~slapdtest.SlapdObject.ldapmodify`
* fixed enabling logger in ``slaptest``
* directory name now contains port to be able to run several :class:`slapdtest.SlapdObject`
  instances side-by-side (e.g. with replication)

* added ``authz-regexp`` mapping to ``rootdn`` for user running the test
* internally use SASL/EXTERNAL via LDAPI to bind
* :attr:`~slapdtest.SlapdObject.server_id` used as ``serverID`` in ``slapd.conf`` for MMR
* Removed method :meth:`~slapdtest.SlapdObject.started` because :meth:`~slapdtest.SlapdTestCase.setUpClass`
  will be used to add initial entries

Tests/

* :class:`~ldap.ldapobject.ReconnectLDAPObject` is also tested by sub-classing test class


Released 2.4.37 2017-04-27
--------------------------

Changes since 2.4.36:

Lib/

* fixed ``errno``-related regression introduced in 2.4.35


Tests/

* added more checks to :file:`t_cext.py`
* renamed :file:`t_search.py` to :file:`t_ldapobject.py` and code-cleaning
* added test for ``errno``-related regression to :file:`t_ldapobject.py`


Released 2.4.36 2017-04-26
--------------------------

Changes since 2.4.35:

Lib/

* gracefully handle :exc:`KeyError` in :meth:`~ldap.ldapobject.SimpleLDAPObject._ldap_call` when
  using ``errno``

* added new standalone module :mod:`slapdtest` (formerly :file:`Tests/slapd.py`)
  for general use (still experimental)

Tests/

* refactored :file:`t_cext.py` and :file:`t_search.py`
* set environment variable ``LDAPNOINIT=1`` in :file:`t_cext.py` and :file:`t_search.py` to avoid
  interference with locally installed ``.ldaprc`` or ``ldap.conf``

* by default ``back-mdb`` is now used for slapd-based tests
  which requires fairly recent OpenLDAP builds but implements
  full feature set

* environment variables can be set for :file:`slapd.py` to tweak path names
  of executable, temporary, and schema data to be used

* new class :class:`slapdtest.SlapdTestCase`


Released 2.4.35 2017-04-25
--------------------------

Changes since 2.4.33:
(2.4.34 is missing because of foolish PyPI version madness)

Modules/

* use ``errno`` in a safer way
* set ``errno`` as LDAPError class item
* do not use :func:`strerror` which is not thread-safe and platform-specific


Lib/

* :meth:`~ldap.ldapobject.SimpleLDAPObject._ldap_call` sets LDAPError info to value returned
  by platform-neutral :func:`os.strerror`

Released 2.4.33 2017-04-25
--------------------------

Changes since 2.4.32:

Lib/

* faster implementation of :func:`ldap.schema.tokenizer.split_tokens`
  (thanks to Christian Heimes)

* removed unused second argument of :func:`ldap.schema.tokenizer.split_tokens`
* fixed method calls in :class:`~ldap.ldapobject.ReconnectLDAPObject` (thanks to Philipp Hahn)


Modules/

* an empty info message is replaced with ``strerror(errno)`` if ``errno`` is non-zero
  which gives more information e.g. in case of :exc:`ldap.SERVER_DOWN`
  (thanks to Markus Klein)

* removed superfluous ``ldap_memfree(error)`` from ``LDAPerror()``
  (thanks to Markus Klein)

Tests/

* refactored :file:`t_ldap_schema_tokenizer.py`


Released 2.4.32 2017-02-14
--------------------------

Changes since 2.4.31:

Running tests made easier:

- python :file:`setup.py` test
- added ``tox.ini``


Released 2.4.31 2017-02-14
--------------------------

Changes since 2.4.30:

Tests/

* new test scripts :file:`t_ldap_schema_tokenizer.py` and :file:`t_ldap_modlist.py`
  on former raw scripts (thanks to Petr Viktorin)

* new test cases in :file:`t_ldapurl.py` based on former raw scripts
  (thanks to Petr Viktorin)

* new test-cases in :file:`t_ldap_dn.py`
* moved a script to Demo/


Released 2.4.30 2017-02-08
--------------------------

Changes since 2.4.29:

Lib/

* compatibility fix in :mod:`ldap.controls.deref` to be compatible with
  recent :mod:`pyasn1` 0.2.x (thanks to Ilya Etingof)

Released 2.4.29 2017-01-25
--------------------------

Changes since 2.4.28:

Modules/

* Fixed checking for empty server error message
  (thanks to Bradley Baetz)

* Fixed releasing GIL when calling ``ldap_start_tls_s()``
  (thanks to Lars Munch)

Released 2.4.28 2016-11-17
--------------------------

Changes since 2.4.27:

Lib/

* :meth:`~ldap.ldapobject.LDAPObject.unbind_ext_s` invokes :meth:`~ldap.ldapobject.LDAPObject._trace_file.flush`
  only if :attr:`~ldap.ldapobject.LDAPObject._trace_level` is non-zero and Python is running
  in debug mode

* :meth:`~ldap.ldapobject.LDAPObject.unbind_ext_s` now ignores :exc:`AttributeError`
  in case :attr:`~ldap.ldapobject.LDAPObject._trace_file` has no ``flush()`` method

* added dummy method :meth:`ldap.logger.logging_file_class.flush` because
  :meth:`~ldap.ldapobject.LDAPObject.unbind_ext_s` invokes it

Released 2.4.27 2016-08-01
--------------------------

Changes since 2.4.26:

Lib/

* added ``strf_secs`` and ``strp_secs`` to :data:`ldap.functions.__all__`
* fixed regression introduced with 2.4.26:
  :class:`ldif.LDIFParser` did not fully parse LDIF records without trailing empty
  separator line

Released 2.4.26 2016-07-24
--------------------------

Changes since 2.4.25:

Installation:

* added :mod:`ldap.controls.sss` to ``py_modules`` in :file:`setup.py`


Lib/

* :meth:`~ldap.ldapobject.LDAPObject.unbind_ext` now removes class attribute
  :attr:`~ldap.ldapobject.LDAPObject._l` to completely invalidate C wrapper object

* :meth:`~ldap.ldapobject.LDAPObject.unbind_ext` now flushes trace file
* :class:`ldap.ldapobject.SimpleLDAPObject`:
  added convenience methods :meth:`~ldap.ldapobject.SimpleLDAPObject.read_rootdse_s` and :meth:`~ldap.ldapobject.SimpleLDAPObject.get_naming_contexts`

* added functions :func:`ldap.strf_secs` and :func:`ldap.strp_secs`
* added function :func:`ldap.filter.time_span_filter`
* Refactored :class:`ldif.LDIFParser`
  * :attr:`ldif.LDIFParser.version` is now an integer
  * ignore multiple empty lines between records

* Fixed :func:`ldap.dn.is_dn`


Modules/

* Fixed #69 segmentation fault on ``whoami_s`` after unbind
  (thanks to Christian Heimes and Petr Viktorin)

Tests/

* Fixed :meth:`~ldap.ldapobject.LDAPObject.result3` being used instead of correct :meth:`~ldap.ldapobject.LDAPObject.result4`
  (see #66, thanks to David D. Riddle)

* :file:`Tests/slapd.py` honors environment variable ``$TMP`` instead of just using
  hard-coded ``/var/tmp``

* :file:`Tests/slapd.py` now expects schema to be in ``/etc/openldap/``
* :file:`Tests/t_ldapurl.py` now independent of module :mod:`ldap`
* :file:`Tests/t_ldif.py` now has more test-cases including change records
* added some more test scripts for sub-modules :mod:`ldap.dn`, :mod:`ldap.filter` and
  :mod:`ldap.functions` (not complete yet)

Released 2.4.25 2016-01-18
--------------------------

Changes since 2.4.23:
(2.4.24 is missing because of foolish PyPI version madness)

Lib/

* Fix for ``attrlist=None`` regression introduced in 2.4.23
  by ref count patch

Released 2.4.23 2016-01-17
--------------------------

Changes since 2.4.22:

Modules/

* Ref count issue in ``attrs_from_List()`` was fixed
  (thanks to Elmir Jagudin)

Released 2.4.22 2015-10-25
--------------------------

Changes since 2.4.21:

Lib/

* :class:`ldif.LDIFParser` now also accepts value-spec without a space
  after the colon.

* Added keyword argument ``authz_id`` to :class:`~ldap.ldapobject.LDAPObject` methods
  :meth:`~ldap.ldapobject.LDAPObject.sasl_non_interactive_bind_s`,
  :meth:`~ldap.ldapobject.LDAPObject.sasl_external_bind_s`, and
  :meth:`~ldap.ldapobject.LDAPObject.sasl_gssapi_bind_s`

* Added missing ``self`` to :meth:`~ldap.ldapobject.LDAPObject.fileno`.
* :meth:`~ldap.ldapobject.ReconnectLDAPObject.sasl_bind_s` now correctly uses
  generic wrapper arguments ``*args,**kwargs``

* Correct method name :meth:`ldif.LDIFParser.handle_modify`
* Corrected ``__all__`` in :mod:`ldap.controls.pwdpolicy` and
  :mod:`ldap.controls.openldap`

Doc/

* Started missing docs for sub-module :mod:`ldap.sasl`.


Released 2.4.21 2015-09-25
--------------------------

Changes since 2.4.20:

Lib/

* :meth:`~ldap.ldapobject.LDAPObject.read_s` now returns ``None`` instead of raising
  :exc:`ldap.NO_SUCH_OBJECT` in case the search operation returned empty result.

* :meth:`ldap.resiter.ResultProcessor.allresults` now takes new keyword
  argument ``add_ctrls`` which is internally passed to :meth:`~ldap.ldapobject.LDAPObject.result4`
  and lets the method also return response control along with the search
  results.

* Added :mod:`ldap.controls.deref` implementing support for dereference control


Tests/

* Unit tests for module :mod:`ldif` (thanks to Petr Viktorin)


Released 2.4.20 2015-07-07
--------------------------

Changes since 2.4.19:

* New wrapping of OpenLDAP's function ``ldap_sasl_bind_s()`` allows
  to intercept the SASL handshake (thanks to René Kijewski)

Modules/

* Added exceptions :exc:`ldap.VLV_ERROR`, :exc:`ldap.X_PROXY_AUTHZ_FAILURE` and
  :exc:`ldap.AUTH_METHOD_NOT_SUPPORTED`

Lib/

* Abandoned old syntax when raising :exc:`ValueError` in modules :mod:`ldif` and
  :mod:`ldapurl`, more information in some exceptions.

* :mod:`ldap.ldapobject` :class:`~ldap.ldapobject.LDAPObject`:
  New convenience methods for SASL GSSAPI or EXTERNAL binds

* Refactored parts in :class:`ldif.LDIFParser`:

  - New class attributes :attr:`~ldif.LDIFParser.line_counter` and :attr:`~ldif.LDIFParser.byte_counter` contain
    amount of LDIF data read so far
  - Renamed some internally used methods
  - Added support for parsing change records currently limited to
    ``changetype: modify``
  - New separate methods :meth:`~ldif.LDIFParser.parse_entry_records` (also called by :meth:`~ldif.LDIFParser.parse`)
    and :meth:`~ldif.LDIFParser.parse_change_records`
  - Stricter order checking of ``dn:``, ``changetype:``, etc.
  - Removed non-existent ``AttrTypeandValueLDIF`` from :data:`ldif.__all__`

* New mix-in :class:`ldap.controls.openldap.SearchNoOpMixIn`
  adds convenience method ``noop_search_st`` to :class:`~ldap.ldapobject.LDAPObject` class

* Added new modules which implement the control classes
  for Virtual List View (see ``draft-ietf-ldapext-ldapv3-vlv``) and
  Server-side Sorting (see RFC 2891) (thanks to Benjamin Dauvergne)
  Note: This is still experimental! Even the API can change later.

Released 2.4.19 2015-01-10
--------------------------

Changes since 2.4.18:

Lib/

* Fixed missing :attr:`~ldap.ldapobject.ReconnectLDAPObject._reconnect_lock` when pickling
  (see SF#64, thanks to Dan O'Reilly)

* Added :mod:`ldap.controls.pagedresults` which is pure Python implementation of
  Simple Paged Results Control (see RFC 2696) and delivers the correct
  result size

Released 2.4.18 2014-10-09
--------------------------

Changes since 2.4.17:

Lib/

* Fixed raising exception in :meth:`~ldap.ldapobject.LDAPObject.read_s` when reading
  an entry returns empty search result

Released 2.4.17 2014-09-27
--------------------------

Changes since 2.4.16:

Lib/

* New hook :meth:`~ldap.syncrepl.SyncReplConsumer.syncrepl_refreshdone` in :class:`ldap.syncrepl.SyncReplConsumer`
  (thanks to Petr Spacek and Chris Mikkelson)

Modules/

* Added support for getting file descriptor of connection
  with :data:`ldap.OPT_DESC`

Released 2.4.16 2014-09-10
--------------------------

Changes since 2.4.15:

Lib/

* New convenience function :func:`ldap.dn.is_dn`
* New convenience function :func:`ldap.escape_str`
* New convenience methods :meth:`~ldap.ldapobject.LDAPObject.read_s` and
  :meth:`~ldap.ldapobject.LDAPObject.find_unique_entry`

* Fixed invoking :meth:`~ldap.ldapobject.LDAPObject.start_tls_s` in :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect`
  (thanks to Philipp Hahn)

Released 2.4.15 2014-03-24
--------------------------

Changes since 2.4.14:

Lib/

* Added missing modules :mod:`ldap.controls.openldap` and
  :mod:`ldap.controls.pwdpolicy` to :file:`setup.py`

* Added missing imports to :mod:`ldap.controls.pwdpolicy`
* Fixed :obj:`ldap.controls.pwdpolicy.decodeControlValue` to decode
  string of digits

* Support for X-SUBST in schema element class LDAPSyntax
* Support for X-ORDERED and X-ORIGIN in schema element class :class:`~ldap.schema.models.AttributeType`
* :mod:`ldapurl`: New scope 'subordinates' defined in
  ``draft-sermersheim-ldap-subordinate-scope``

Modules/

* New constant :data:`ldap.SCOPE_SUBORDINATE` derived from :file:`ldap.h` for
  ``draft-sermersheim-ldap-subordinate-scope``

* Fixed constant :data:`ldap.sasl.CB_GETREALM` (thanks to Martin Pfeifer)


Released 2.4.14 2014-01-31
--------------------------

Changes since 2.4.13:

Lib/

* Added :class:`ldap.controls.openldap.SearchNoOpControl`
* New method :meth:`ldap.async.AsyncSearchHandler.afterFirstResult`
  for doing something right after successfully receiving but before
  processing first result

* Better log data written when invoking :meth:`~ldap.LDAPLock.acquire` and
  :meth:`~ldap.LDAPLock.release`

* :class:`~ldap.ldapobject.LDAPObject` and friends now pass ``desc`` to :class:`ldap.LDAPLock` which
  results in better logging

* :class:`~ldap.ldapobject.ReconnectLDAPObject` now uses internal class-wide
  lock for serializing reconnects

* Method signature of :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect` changed to be able
  to call it with separate ``retry_max`` and ``retry_delay`` values

Modules/

* Added support for retrieving negotiated TLS version/cipher
  with :meth:`~ldap.ldapobject.LDAPObject.get_option` with the help of upcoming OpenLDAP libs

Released 2.4.13 2013-06-27
--------------------------

Changes since 2.4.12:

Lib/

* :meth:`~ldap.ldapobject.ReconnectLDAPObject._apply_last_bind` now sends
  anonymous simple bind request even if the calling application
  did not to provoke :exc:`ldap.SERVER_DOWN` in method :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect`

* :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect` now also catches
  :exc:`ldap.TIMEOUT` exception after reconnection attempt

* Several other fixes for :class:`~ldap.ldapobject.ReconnectLDAPObject`
  (thanks to Jonathan Giannuzzi)

Released 2.4.12 2013-06-01
--------------------------

Changes since 2.4.11:

Lib/

* Truly optional import of :exc:`pyasn1.error.PyAsn1Error` exception which should
  not fail anymore if :mod:`pyasn1` is not installed

Released 2.4.11 2013-05-27
--------------------------

Changes since 2.4.10:

Lib/

* :func:`ldap.controls.DecodeControlTuples` now simply ignores
  :exc:`pyasn1.error.PyAsn1Error` exception raised during decoding malformed
  response control values in case of non-critical controls.

* :meth:`ldif.LDIFWriter.unparse` does not simply skip empty
  records anymore.

Released 2.4.10 2012-06-07
--------------------------

Changes since 2.4.9:

Lib/

* :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect` now preserves
  order of options set with :meth:`~ldap.ldapobject.LDAPObject.set_option` before.
  This is needed e.g. for setting connection-specific TLS options.

Demo/

* Better version of :file:`Demo/pyasn1/syncrepl.py`
  (thanks to Ben Cooksley)

Released 2.4.9 2012-03-14
-------------------------

Changes since 2.4.8:

Lib/

* :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect` now does kind of
  an internal locking to pause other threads while reconnecting
  is pending.

* Changes to bind- and StartTLS-related operation methods of
  class :class:`~ldap.ldapobject.ReconnectLDAPObject` for more robustness

* New constant :data:`ldap.OPT_NAMES_DICT` contains mapping from
  integer to variable name for all option-related constants.

Released 2.4.8 2012-02-21
-------------------------

Changes since 2.4.7:

Lib/

* Fixed overzealous check for non-unique NAMEs in
  :meth:`~ldap.schema.subentry.SubSchema.__init__`

* Fixed typos in control decoding method
  :meth:`~ldap.controls.simple.OctetStringInteger.decodeControlValue`

* Added experimental support for ``draft-vchu-ldap-pwd-policy``


Released 2.4.7 2012-12-19
-------------------------

Changes since 2.4.6:

Lib/

* Separate classes for request/response controls for RFC 3829
* Fixed :meth:`~ldap.schema.subentry.SubSchema.attribute_types` to
  also eliminate double attribute types in MAY clause of
  DIT content rule

Modules/

* Fixed memory leak (thanks to David Malcolm)


Released 2.4.6 2011-11-27
-------------------------

Changes since 2.4.5:

Lib/

* :mod:`ldap.controls.ppolicy`:
  Another fix for decoding the password policy response control

Released 2.4.5 2011-11-25
-------------------------

Changes since 2.4.4:

Installation:

* defines for SASL and SSL in :file:`setup.cfg` to be more friendly to
  Python setup tools (``easy_install``)

Lib/

* Fixed typo in :func:`ldap.functions._ldap_function_call` which
  always released :data:`ldap._ldap_module_lock` instead of local lock

* :mod:`ldap.controls.ppolicy`:
  Fixed decoding the password policy response control

Demo/

* Demo script for :mod:`ldap.controls.ppolicy`


Released 2.4.4 2011-10-26
-------------------------

Changes since 2.4.3:

Modules/

* Format intermediate messages as three-element :class:`tuple` s instead of
  4-tuples to match the format of other response messages.
  (thanks to Chris Mikkelson)

* Fixes for memory leaks (thanks to Chris Mikkelson)


Lib/

* New experimental(!) sub-module :mod:`ldap.syncrepl` implementing syncrepl
  consumer (see RFC 4533, thanks to Chris Mikkelson)

Doc/

* Cleaned up RST files
* Added missing classes


Released 2.4.3 2011-07-23
-------------------------

Changes since 2.4.2:

Lib/

* Mostly corrected/updated ``__doc__`` strings


Doc/

* Corrected RST files
* Added missing modules, functions, classes, methods, parameters etc.
  at least as auto-generated doc

Released 2.4.2 2011-07-21
-------------------------

Changes since 2.4.1:

Lib/

Logging:

* :func:`pprint.pformat` is now used when writing method/function
  arguments to the trace log

:mod:`ldap.schema.subentry`:

* :meth:`~ldap.schema.subentry.SubSchema.__init__` now has new keyword argument ``check_uniqueness``
  which enables checking whether OIDs are unique in the subschema subentry

* Code-cleaning: consistent use of :meth:`~ldap.schema.subentry.SubSchema.getoid` instead of
  accessing :attr:`~ldap.schema.subentry.SubSchema.name2oid` directly.

* :meth:`~ldap.schema.subentry.SubSchema.getoid` now has keyword argument
  ``raise_keyerror=0`` and raises :exc:`KeyError` with an appropriate description.

Released 2.4.1 2011-07-05
-------------------------

Changes since 2.4.0:

Modules:

* New LDAP option :data:`ldap.OPT_X_TLS_PACKAGE` available in OpenLDAP 2.4.26+
  to determine the name of the SSL/TLS package OpenLDAP was
  built with

Lib/

* :func:`ldap.modlist.modifyModlist`: New keyword argument
  ``case_ignore_attr_types`` used to define attribute types for which
  comparison of old and new values should be case-insensitive

* Minor changes to which data is sent to debug output for various
  trace levels

* Now tag [1] is used in :class:`ldap.extop.dds.RefreshResponse` in
  compliance with RFC 2589 (fix available for OpenLDAP ITS#6886)

* New sub-module :mod:`ldap.controls.sessiontrack` implements request control
  as described in ``draft-wahl-ldap-session`` (needs ``pyasn1_modules``)

Released 2.4.0 2011-06-02
-------------------------

Changes since 2.3.13:

* OpenLDAP 2.4.11+ required to build
* Support for extracting LDAPv3 extended controls in
  ``LDAP_RES_SEARCH_ENTRY`` responses
  (see SF#2829057, thanks to Rich)

* Generic support for LDAPv3 extended operations (thanks to Rich)


Lib/

* new class API in :mod:`ldap.controls`, not backwards-compatible!
* new sub-modules for :mod:`ldap.controls`, some require :mod:`pyasn1` and :mod:`pyasn1_modules`
* New methods :meth:`~ldap.ldapobject.LDAPObject.result4` and :meth:`~ldap.ldapobject.LDAPObject.extop_result`
* New (optional) :class:`ldap.controls.AssertionControl`
* New helper module :mod:`ldap.logger` contains file-like object which
  sends trace messages to :func:`logging.log`

* Removed non-functional method :meth:`~ldap.ldapobject.LDAPObject.set_cache_options`
* Removed unused dictionary :data:`ldap.controls.knownLDAPControls`


Modules/

* ``ldapcontrol.c``: Fixed ``encode_assertion_control()`` and function is no longer
  hidden behind an ``#ifdef`` statement

Released 2.3.13 2011-02-19
--------------------------

Changes since 2.3.12:

Modules/

* Correct ``#ifdef`` statement for ``LDAP_OPT_X_TLS_CRLFILE`` in
  :file:`constants.c` fixes build with older OpenLDAP libs

* Support for ``LDAP_OPT_DEFBASE`` (see SF#3072016, thanks to Johannes)


Released 2.3.12 2010-08-05
--------------------------

Changes since 2.3.11:

Lib/

* Removed tabs from various modules to make things work with ``python -tt``.
* Quick fix to :func:`ldif.is_dn` to let multi-valued RDNs pass as valid.
  Is too liberal in some corner cases though...

* Fix to :func:`ldif.is_dn` to allow dashes in attribute type (see SF#3020292)
* :func:`ldap.open` now outputs a deprecation warning
* module-wide locking is now limited to calling :func:`_ldap.initialize`.
  Still :func:`ldap.functions._ldap_function_call` is used to wrap all
  calls for writing debug log.

Modules/

* New LDAP options available in OpenLDAP 2.4.18+ supported in
  :meth:`~ldap.ldapobject.LDAPObject.get_option`/:meth:`~ldap.ldapobject.LDAPObject.set_option`:
  :data:`ldap.OPT_X_KEEPALIVE_IDLE`, :data:`ldap.OPT_X_KEEPALIVE_PROBES`,
  :data:`ldap.OPT_X_KEEPALIVE_INTERVAL`,
  :data:`ldap.OPT_X_TLS_CRLCHECK`, :data:`ldap.OPT_X_TLS_CRLFILE`

Doc/

* Various small updates/improvements


Released 2.3.11 2010-02-26
--------------------------

Changes since 2.3.10:

Lib/

* Fixed LDAP URL parsing with four ? but no real extensions
* :meth:`~ldap.ldapobject.LDAPObject.rename_s` now also accepts arguments
  serverctrls and clientctrls

* Removed untested and undocumented class :class:`ldap.ldapobject.SmartLDAPObject`
* Removed broken method :meth:`~ldap.ldapobject.LDAPObject.manage_dsa_it`


Modules/

* Make use of ``LDAP_OPT_X_TLS_NEWCTX`` only if available in
  OpenLDAP libs used for the build

* Fixed ``#ifdef`` statements for :data:`ldap.OPT_X_TLS_PROTOCOL_MIN`


Doc/

* Some updates and corrections regarding description of use of
  LDAPv3 controls

* Some more descriptions for constants
* Removed comments related to old LaTeX-based documentation system


Released 2.3.10 2009-10-30
--------------------------

Changes since 2.3.9:

Lib/

* The ``diagnosticMessage`` returned by a server is written to the trace
  output also for successful operations.

* Fixed handling of LDAP URL extensions with implicit value ``None`` which are
  mapped to class attributes of :class:`ldapurl.LDAPUrl`.

* Fixed handling of LDAP URLs with ? being part of extensions.
* Fixed exceptions raised by :meth:`~ldap.ldapobject.LDAPObject.get_option`/:meth:`~ldap.ldapobject.LDAPObject.set_option` (SF#1964993)
* :mod:`ldap.functions`: Fixed import trace-related variables from base module :mod:`ldap`
* Fixed :mod:`ldap.resiter` missing in RPMs built with ``python :file:`setup.py` bdist_rpm``
* Fix in :class:`ldap.schema.models.SchemaElement`:
  :func:`repr` was liberally used in methods :meth:`~ldap.schema.models.SchemaElement.key_attr` and :meth:`~ldap.schema.models.SchemaElement.key_list` to enclose
  values in quotes.

Modules/

* Changed internal API ``List_to_LDAPControls()`` to ``LDAPControls_from_object()``
* Supported was added for retrieving the SASL username during SASL bind with
  ``ldap_get_option(LDAP_OPT_X_SASL_USERNAME)`` if available in libldap.

* New LDAP option constant :data:`ldap.OPT_X_TLS_NEWCTX` supported
  in :meth:`~ldap.ldapobject.LDAPObject.set_option`

* New LDAP option constants supported in :meth:`~ldap.ldapobject.LDAPObject.get_option`/:meth:`~ldap.ldapobject.LDAPObject.set_option`:
  :data:`ldap.OPT_X_TLS_PROTOCOL_MIN`, :data:`ldap.OPT_CONNECT_ASYNC`, :data:`ldap.OPT_X_TLS_DHFILE`

* Fixed setting :data:`_ldap.OPT_ON` and :data:`_ldap.OPT_OFF`
* ``l_ldap_result3()``: controls are now parsed for all response types (SF#2829057)


Doc/

* Added example for :mod:`ldap.resiter`


Released 2.3.9 2009-07-26
-------------------------

Changes since 2.3.8:

Lib/

* All modules (:mod:`ldap`, :mod:`ldif`, :mod:`dsml` and :mod:`ldapurl`) have common version number now
* Non-exported function :func:`ldif.needs_base64` was abandoned and is now
  implemented as method :meth:`~ldif.LDIFWriter._needs_base64_encoding`.
  This allows sub-classes of :class:`ldif.LDIFWriter` to implement determining whether
  attribute values have to be base64-encoded in a different manner and is
  the same approach like in class :class:`dsml.DSMLWriter`.

* :meth:`~ldapurl.LDAPUrlExtension._parse` now gracefully handles LDAP URL extensions
  without explicit exvalue as being set with implicit value ``None``.

Modules/

* New LDAP option constant :data:`ldap.OPT_X_SASL_NOCANON` supported
  in :meth:`~ldap.ldapobject.LDAPObject.get_option`/:meth:`~ldap.ldapobject.LDAPObject.set_option`

Released 2.3.8 2009-04-30
-------------------------

Changes since 2.3.7:

Lib/

* :mod:`ldap.schema.models`: More fault-tolerant parsing of SYNTAX in
  ``AttributeTypeDescription``

* :func:`ldap.schema.tokenizer.split_tokens`:
  More tolerant parsing of items separated only with a DOLLAR without
  surrounding white-spaces (because WSP is declared as zero or more spaces
  in RFC 4512)

Released 2.3.7 2009-04-09
-------------------------

Changes since 2.3.6:

Lib/

* :func:`urllib.quote` is now used in :meth:`~ldapurl.LDAPUrlExtension.unparse` to quote
  all special URL characters in extension values

Modules/

* Fixed ``ldapcontrol.c`` not to raise :exc:`ldap.ENCODING_ERROR` in
  function ``encode_rfc2696()`` on 64-bit systems

* Fixed segmentation fault if an error code in an LDAP response was outside
  the known error codes and could not be mapped to a specific
  exception class (thanks to Sean)

* :file:`errors.c`: ``LDAP_ERROR_MAX`` set to ``LDAP_PROXIED_AUTHORIZATION_DENIED``
  if available in OpenLDAP header

* new exception class :exc:`ldap.PROXIED_AUTHORIZATION_DENIED`
  if available in OpenLDAP header

* Fixed :file:`functions.c` not to raise :exc:`ldap.ENCODING_ERROR` in
  function ``l_ldap_str2dn()`` on 64-bit systems (see SF#2725356)

Released 2.3.6 2009-02-22
-------------------------

Changes since 2.3.5:

Lib/

* Importing :func:`ldap.str2dn` which directly imported :func:`_ldap.str2dn`
  is prohibited now (see SF#2181141)

Modules/

* :meth:`~ldap.ldapobject.LDAPObject.get_option`: Added support for reading more SASL options.
  (:data:`ldap.OPT_X_SASL_MECH`, :data:`ldap.OPT_X_SASL_REALM`, :data:`ldap.OPT_X_SASL_AUTHCID` and
  :data:`ldap.OPT_X_SASL_AUTHZID`)

* Added some explicit type casts to fix issues while building
  with SunStudio

* Fixed compiling issue with GCC 4.4
  (see SF#2555793, thanks to Matej and Martin)

Doc/

* Clarified not to use ``ldap_get_dn()`` directly
* Fixed description of :data:`ldap.SASL_AVAIL` and :data:`ldap.TLS_AVAIL`
  (see SF#2555804, thanks to Matej and Martin)

Released 2.3.5 2008-07-06
-------------------------

Changes since 2.3.4:

Lib/

* Fixed methods :meth:`ldap.cidict.cidict.__contains__` and
  :meth:`~ldap.schema.models.Entry.__contains__`

* FWIW method :meth:`~ldap.ldapobject.LDAPObject.cancel_s` returns a result now
* Fixed :class:`ldap.schema.models.NameForm`: Class attribute :attr:`~ldap.schema.models.NameForm.oc` is now
  of type :class:`str`, not :class:`tuple` to be compliant with RFC 4512

Released 2.3.4 2008-03-29
-------------------------

Changes since 2.3.3:

Modules/

* Fixed segmentation fault when calling :meth:`~ldap.ldapobject.LDAPObject.get_option`
  (see SF#1926507, thanks to Matej)

Released 2.3.3 2008-03-26
-------------------------

Changes since 2.3.2:

Fixed backward compatibility when building with OpenLDAP 2.3.x libs.

Released 2.3.2 2008-03-26
-------------------------

Changes since 2.3.1:

Lib/

* :func:`ldap.dn.escape_dn_chars` now really adheres to
  RFC 4514 section 2.4 by escaping null characters and a
  space occurring at the beginning of the string

* New method :meth:`ldap.cidict.cidict.__contains__`
* :func:`ldap.dn.explode_dn` and :func:`ldap.dn.explode_rdn`
  have a new optional keyword argument flags which is
  passed to :func:`ldap.dn.str2dn`.

Modules/

* Removed unused ``OPT_PRIVATE_EXTENSION_BASE`` from :file:`constants.c`


Doc/

* Various additions, updates, polishing (thanks to James).


Released 2.3.1 2007-07-25
-------------------------

Changes since 2.3.0:

* Support for setuptools (building .egg, thanks to Torsten)
* Support for matched values control (RFC 3876, thanks to Andreas)


Lib/

* Fixed :mod:`ldif` (see SF#1709111, thanks to Dmitry)
* :mod:`ldap.schema.models`:
  SUP now separated by ``$`` (the :meth:`~ldap.schema.models.AttributeType.__str__`,
  :meth:`~ldap.schema.models.ObjectClass.__str__`, and
  :meth:`~ldap.schema.models.DITStructureRule.__str__` methods; thanks to Stefan)

Modules/

* Added constant :data:`ldap.MOD_INCREMENT` to support
  modify+increment extension (see RFC 4525, thanks to Andreas)

Released 2.3.0 2007-03-27
-------------------------

Changes since 2.2.1:

* OpenLDAP 2.3+ required now to build.
* Added support for Cancel operation ext. op. if supported

in OpenLDAP API of the libs used for the build.

Modules/

* Removed deprecated code for setting options by name
* Added ``l_ldap_cancel()``
* Some modifications related to PEP 353 for
  Python 2.5 on 64-bit platforms (see SF#1467529, thanks to Matej)

* Added new function ``l_ldap_str2dn()``, removed functions
  ``l_ldap_explode_dn()`` and ``l_ldap_explode_rdn()``
  (see SF#1657848, thanks to David)

Lib/

* Added method :meth:`~ldap.ldapobject.LDAPObject.cancel`
* :func:`ldap.schema.subentry.urlfetch` now can do non-anonymous
  simple bind if the LDAP URL provided contains extensions
  'bindname' and 'X-BINDPW'. (see SF#1589206)

* :func:`ldap.filter.escape_filter_chars` has a new keyword argument
  ``escape_mode`` now which defines which chars to be escaped
  (see SF#1193271).

* Various important fixes to :class:`~ldap.ldapobject.ReconnectLDAPObject`
* Moved all DN-related functions to sub-module :mod:`ldap.dn`,
  import them in :mod:`ldap.functions` for backward compatibility

* :func:`ldap.dn.explode_dn` and :func:`ldap.dn.explode_rdn` use the new
  wrapper function :func:`ldap.dn.str2dn` (related to SF#1657848)

* ``changetype`` issue partially fixed (see SF#1683746)


Released 2.2.1 2006-11-15
-------------------------

Changes since 2.2.0:

Modules/

* Fix for Python 2.5 ``free()``: invalid pointer (see SF#1575329)
* :meth:`~ldap.ldapobject.LDAPObject.passwd` accepts ``None`` for arguments ``user``, ``oldpw``, ``newpw``
  (see SF#1440151)

Lib/

* :meth:`ldif.LDIFWriter.unparse` now accepts instances of
  derived :class:`dict` and :class:`list` classes (see SF#1489898)

Released 2.2.0 2006-04-10
-------------------------

Changes since 2.0.11:

* OpenLDAP 2.2+ required now to build.


Modules/

* Dropped all occurrences of '#ifdef #``LDAP_VENDOR_VERSION``'.
* Fixed wrong :class:`tuple` size in ``l_ldap_result3()`` (see SF#1368108)
* Fixed :meth:`~ldap.ldapobject.LDAPObject.get_option`(:data:`ldap.OPT_API_INFO`) (see SF#1440165)
* Fixed memory leak in ``l_ldap_result3()`` when all=0
  (see SF#1457325)

* Fixed memory leak in ``l_ldap_result3()`` in error cases
  (see SF#1464085)

Lib/

* Fixed :meth:`~ldap.schema.models.DITStructureRule.__str__` to
  separate SUP rule-ids with a single space instead of ' $ '

* Fixed :class:`ldap.async.Dict`
* Added :class:`ldap.async.IndexedDict`
* :meth:`~ldap.schema.subentry.SubSchema.attribute_types` has new
  keyword argument ``ignore_dit_content_rule``

Released 2.0.11 2005-11-07
--------------------------

Changes since 2.0.10:

Lib/

* :class:`ldap.ldapobject.LDAPObject`:
  Each method returns a result now

* :class:`ldap.ldapobject.ReconnectLDAPObject`:
  Some methods called the wrong methods of :class:`~ldap.ldapobject.LDAPObject`. Fixed.

* Added new class :class:`ldap.async.Dict`
* Slightly cleaned up :meth:`ldap.schema.subentry.SubSchema.attribute_types`
* New sub-module :mod:`ldap.resiter`, which simply provides a mix-in
  class for :class:`~ldap.ldapobject.LDAPObject` with a generator method
  :meth:`~ldap.resiter.ResultProcessor.allresults`.
  Obviously this only works with Python 2.3+. And
  it's still experimental.

Released 2.0.10 2005-09-23
--------------------------

Changes since 2.0.9:

Lib/

* Switched back to old implementation of
  :func:`ldap.schema.tokenizer.split_tokens` since the new one
  had a bug which deletes the spaces from DESC

* :exc:`ldap.INSUFFICIENT_ACCESS` is now ignored in
  :meth:`~ldap.ldapobject.LDAPObject.search_subschemasubentry_s`

Released 2.0.9 2005-07-28
-------------------------

Changes since 2.0.8:

Modules/

* Removed ``__doc__`` strings from ``ldapcontrol.c`` to "fix"
  build problems with Python versions 2.2 and earlier.

Released 2.0.8 2005-06-22 at Linuxtag 2005, Karlsruhe, Germany
--------------------------------------------------------------

Changes since 2.0.7:

* Preliminary support for receiving LDAP controls added.
  Contributor:
  - Andreas Ames


Lib/

- Added classes in module :mod:`ldif` to :data:`ldif.__all__` to fix
  from :mod:`ldif` import *

- Removed ``BitString`` syntax from
  :data:`ldap.schema.models.NOT_HUMAN_READABLE_LDAP_SYNTAXES`
  since the LDAP encoding is in fact human-readable

- :mod:`ldapurl` :meth:`~ldapurl.LDAPUrlExtension.unparse` outputs empty string
  if :attr:`~ldapurl.LDAPUrlExtension.exvalue` is ``None``

- Added :class:`ldap.controls.SimplePagedResultsControl`


Released 2.0.7 2005-04-29
-------------------------

Changes since 2.0.6:

* Added preliminary support for sending LDAP controls
  with a request.
  Contributors:
  - Deepak Giridharagopal
  - Ingo Steuwer
  (Receiving controls in LDAP results still not supported.)

Modules:

* :file:`LDAPObject.c`: removed :func:`l_ldap_manage_dsa_it`
* :file:`LDAPObject.c`: Added missing ``#ifdef`` around ``l_ldap_passwd()``
  for compatibility with older OpenLDAP libs.

Lib/

* New algorithm in :func:`ldap.schema.tokenizer.split_tokens`
  contributed by Wido Depping which is more robust
  when parsing very broken schema elements
  (e.g. Oracle's OID).

* Fixed argument list (position of timeout) when calling
  :meth:`~ldap.ldapobject.LDAPObject.search_ext_s` from :meth:`~ldap.ldapobject.LDAPObject.search_st` and :meth:`~ldap.ldapobject.LDAPObject.search_s`.

* :meth:`~ldap.ldapobject.LDAPObject.search_ext_s` correctly calls :meth:`~ldap.ldapobject.LDAPObject.search_ext_s` now.
* Re-implemented :meth:`~ldap.ldapobject.LDAPObject.manage_dsa_it` without calling :mod:`_ldap`.


Released 2.0.6 2004-12-03
-------------------------

Changes since 2.0.5:

Lib/

* Added sub-module :mod:`ldap.dn`
* Added function :func:`ldap.dn.escape_dn_chars`
* Special check when implicitly setting SUP 'top' to
  structural object classes without SUP defined to avoid
  a loop in the super class chain.

Released 2.0.5 2004-11-11
-------------------------

Changes since 2.0.4:

Some small improvements for SASL:
The noisy output during SASL bind is avoided now. Interaction
with output on stderr can be enabled by the calling application
by explicitly defining SASL flags.

Removed obsolete directory Win32/.

Lib/

* Make sure that :attr:`ldap.sasl.sasl.cb_value_dict` is a dictionary
  even when the caller passes in ``None`` to argument ``cb_value_dict``

* Added new keyword argument ``sasl_flags`` to method
  :meth:`~ldap.ldapobject.LDAPObject.sasl_interactive_bind_s`

Modules/

* ``l_ldap_sasl_interactive_bind_s()``:
  New keyword argument ``sasl_flags`` passed to
  ``ldap_sasl_interactive_bind_s()``

Released 2.0.4 2004-10-27
-------------------------

Changes since 2.0.3:

Modules/

* Applied some fixes for 64-bit platforms to :file:`LDAPObject.c`
* Constants :data:`ldap.TLS_AVAIL` and :data:`ldap.SASL_AVAIL` will indicate
  whether python-ldap was built with support for SSL/TLS
  and/or SASL

:file:`setup.py` and Modules/

* Applied some fixes for building under Win32


Released 2.0.3 2004-10-06
-------------------------

Changes since 2.0.2:

* Added support for LDAP Password Modify Extended Operation
  (see RFC 3062)

Demo/:

* Added ``passwd_ext_op.py``


Modules/

* Added ``l_ldap_passwd()`` in :file:`LDAPObject.c`


Lib/

* Added methods :meth:`~ldap.ldapobject.LDAPObject.passwd` and :meth:`~ldap.ldapobject.LDAPObject.passwd_s` to
  :class:`ldap.ldapobject.LDAPObject`

Released 2.0.2 2004-07-29
-------------------------

Changes since 2.0.1:

Modules/

* Fixed detecting appropriate OpenLDAP libs version for
  determining whether ``ldap_whoami_s()`` is available or not.
  This fixes build problems with OpenLDAP libs 2.1.0 up
  to 2.1.12.

Released 2.0.1 2004-06-29
-------------------------

Changes since 2.0.0:

:mod:`dsml`:

* Fixed wrong exception message format string


:mod:`ldap.schema.models`:

* Fixed :meth:`~ldap.schema.models.Entry.__delitem__` to delete really everything
  when deleting an attribute dictionary item.

Released 2.0.0 2004-05-18
-------------------------

Changes since 2.0.0pre21:

:mod:`ldif`:

* Empty records are simply ignored in :meth:`ldif.LDIFWriter.unparse`


Modules/

* New method :meth:`~ldap.ldapobject.LDAPObject.result2` returns a three-element :class:`tuple` containing the ``msgid``
  of the outstanding operation.

:mod:`ldap.ldapobject`:

* New :mod:`_ldap` wrapper method :meth:`~ldap.ldapobject.LDAPObject.result2` (see above)
  which is now used by :meth:`~ldap.ldapobject.LDAPObject.result`.

Released 2.0.0pre21 2004-03-29
------------------------------

Changes since 2.0.0pre20:

:file:`setup.py`:

* ``runtime_library_dirs`` is set


Modules/

* (Hopefully) fixed building with OpenLDAP 2.2 libs in :file:`errors.c`
* Removed meaningless :func:`repr` function from :file:`LDAPObject.c`
* Removed setting ``LDAP_OPT_PROTOCOL_VERSION`` in ``l_ldap_sasl_bind_s()``
* Modified string handling via ``berval`` instead of ``*char``
  in ``l_ldap_compare_ext()`` makes it possible to compare attribute
  values with null chars.

* Wrapped ``ldap_sasl_bind()`` for simple binds instead of ``ldap_bind()``
  since 1. the latter is marked deprecated and 2. ``ldap_sasl_bind()``
  allows password credentials with null chars.

* Removed unused sources ``linkedlist.c`` and ``linkedlist.h``
* Function ``l_ldap_whoami_s()`` only added if built against
  OpenLDAP 2.1.x+ libs (should preserve compatibility with 2.0 libs)

:mod:`ldap.ldapobject`:

* :meth:`~ldap.ldapobject.LDAPObject.bind` only allows simple binds since Kerberos V4
  binds of LDAPv2 are not supported anymore. An assert statement
  was added to make the coder aware of that.

* Renamed former :meth:`~ldap.ldapobject.LDAPObject.sasl_bind_s` to
  :meth:`~ldap.ldapobject.LDAPObject.sasl_interactive_bind_s` since it wraps OpenLDAP's
  ``ldap_sasl_interactive_bind_s()``

Released 2.0.0pre20 2004-03-19
------------------------------

Changes since 2.0.0pre19:

Modules/

* Removed doc strings from :file:`functions.c`
* Removed probably unused wrapper function ``l_ldap_dn2ufn()`` since
  ``ldap_dn2ufn()`` is deprecated in OpenLDAP 2.1+

* Removed wrapper function ``l_ldap_is_ldap_url()``.
* Removed macro ``add_int_r()`` from :file:`constants.c` since it caused
  incompatibility issues with OpenLDAP 2.2 libs
  (Warning: all result types are Integers now! Use the constants!)

* New wrapper function ``l_ldap_whoami_s()``


:mod:`ldap.ldapobject`:

* New wrapper method :meth:`~ldap.ldapobject.LDAPObject.whoami_s`


:mod:`ldap.functions`:

* Removed :func:`ldapurl.isLDAPUrl`. The more general function
  :func:`ldapurl.isLDAPUrl` should be used instead.

:mod:`ldap.sasl`:

* Added class :class:`ldap.sasl.cram_md5` (for SASL mech ``CRAM-MD5``)


:mod:`ldap.async`:

* Use constants for search result types (see note about
  ``add_int_r()`` above).

Released 2.0.0pre19 2004-01-22
------------------------------

Changes since 2.0.0pre18:

Modules/

* :file:`LDAPObject.c`:
  Most deprecated functions of OpenLDAP C API are not used anymore.

* :file:`functions.c`:
  Removed unused ``default_ldap_port()``.

* :file:`constants.c`:
  Removed unused or silly constants
  ``AUTH_KRBV4``, ``AUTH_KRBV41``, ``AUTH_KRBV42``, ``URL_ERR_BADSCOPE``, ``URL_ERR_MEM``

* :file:`errors.c`:
  Fixed building with OpenLDAP 2.2.x
  (errors caused by negative error constants in :file:`ldap.h`)

:mod:`ldap.ldapobject`.:class:`~ldap.ldapobject.LDAPObject`:

* Removed unused wrapper methods :meth:`_ldap.LDAPObject.uncache_entry`, :meth:`_ldap.LDAPObject.uncache_request`,
  :meth:`_ldap.LDAPObject.url_search`, :meth:`_ldap.LDAPObject.url_search_st` and :meth:`_ldap.LDAPObject.url_search_s`

* New wrapper methods for all the ``_ext()`` methods in :class:`_ldap.LDAPObject`.


:mod:`ldap.modlist`:

* Some performance optimizations and simplifications
  in function :func:`ldap.modlist.modifyModlist`

Released 2.0.0pre18 2003-12-09
------------------------------

Changes since 2.0.0pre17:

:mod:`ldap.ldapobject`:

* Fixed missing :obj:`ldap._ldap_function_call` in
  :meth:`~ldap.ldapobject.ReconnectLDAPObject.reconnect`

Released 2.0.0pre17 2003-12-03
------------------------------

Changes since 2.0.0pre16:

:mod:`ldap.functions`:

* Fixed :exc:`ImportError` when running python -O


Released 2.0.0pre16 2003-12-02
------------------------------

Changes since 2.0.0pre15:

Modules/

* Removed definition of unused constant ``RES_EXTENDED_PARTIAL`` since
  the corresponding symbol ``LDAP_RES_EXTENDED_PARTIAL`` seems to not
  be available in OpenLDAP-HEAD (pre 2.2) anymore.

All in Lib/

* Fixed some subtle bugs/oddities reported by ``pychecker``.


:mod:`dsml`:

* Renamed :attr:`~dsml.DSMLWriter._f` to :attr:`~dsml.DSMLWriter._output_file`
* Added wrapper method :meth:`~dsml.DSMLWriter.unparse`, which simply
  calls :meth:`~dsml.DSMLWriter.writeRecord`

:mod:`ldap.ldapobject`:

* Simplified :meth:`~ldap.ldapobject.LDAPObject.search_subschemasubentry_s`


:mod:`ldap.functions`:

* Moved :obj:`ldap._ldap_function_call` into :mod:`ldap.functions`.
* ``apply()`` is not used anymore since it seems deprecated


:mod:`ldap.async`:

* Added class :class:`dsml.DSMLWriter`


:mod:`ldap.schema`:

* Removed unused keyword argument strict from
  :meth:`~ldap.schema.subentry.SubSchema.attribute_types`

* Fixed backward compatibility issue (for Python prior to 2.2) in
  :meth:`~ldap.schema.subentry.SubSchema.listall`

Released 2.0.0pre15 2003-11-11
------------------------------

Changes since 2.0.0pre14:

Modules/
Follow rule "Always include Python.h first"

:mod:`ldap.schema.subentry`:

* Added new method :meth:`~ldap.schema.subentry.SubSchema.get_structural_oc`
* Added new method :meth:`~ldap.schema.subentry.SubSchema.get_applicable_aux_classes`
* Methods :meth:`~ldap.schema.subentry.SubSchema.listall` and :meth:`~ldap.schema.subentry.SubSchema.tree` have
  new keyword argument ``schema_element_filters``

* Support for DIT content rules in :meth:`~ldap.schema.subentry.SubSchema.attribute_types`


Released 2.0.0pre14 2003-10-03
------------------------------

Changes since 2.0.0pre13:

:file:`setup.py`:

* Some modifications to ease building for Win32
* Added directory Build/ mainly intended for platform-specific
  examples of :file:`setup.cfg`

* Fixed installing :mod:`ldap.filter`


:mod:`ldap.ldapobject`:

* Added class attribute :attr:`~ldap.ldapobject.LDAPObject.network_timeout` mapped to
  :meth:`~ldap.ldapobject.LDAPObject.set_option`(:data:`ldap.OPT_NETWORK_TIMEOUT`, ...)

* :meth:`~ldap.ldapobject.LDAPObject.search_ext`: Pass arguments serverctrls,clientctrls
  to :obj:`_ldap.search_ext`

:mod:`ldap.sasl`:

* Added class :class:`ldap.sasl.external` for handling
  the SASL mechanism EXTERNAL

* Dictionary :data:`ldap.sasl.saslmech_handler_class` built during import
  for all the known SASL mechanisms derived from class definitions

:mod:`ldap.schema`:

* More graceful handling of :exc:`KeyError` in :meth:`~ldap.schema.subentry.SubSchema.attribute_types`
* New method :meth:`~ldap.schema.subentry.SubSchema.get_inheritedattr` for retrieving inherited
  class attributes

* New method :meth:`~ldap.schema.subentry.SubSchema.get_inheritedobj` for retrieving a
  schema element instance including all inherited class attributes

Released 2.0.0pre13 2003-06-02
------------------------------

Changes since 2.0.0pre12:

:mod:`ldap.async`:

* Checking type of argument ``writer_obj`` relaxed in
  :meth:`~ldif.LDIFWriter.__init__` since file-like objects are
  not necessarily an instance of file.

:mod:`ldap.schema`:

* :meth:`~ldap.schema.subentry.SubSchema.attribute_types` now correctly
  handles attribute types without NAME set

* If SUP is not defined for a structural object class 'top' is
  assumed to be the only super-class by default

* '_' is now the abstract top node in :meth:`~ldap.schema.subentry.SubSchema.tree` for all
  schema element classes since ABSTRACT and AUXILIARY object
  classes are not derived from 'top' by default

Released 2.0.0pre12 2003-05-27
------------------------------

Changes since 2.0.0pre11:

New sub-module :mod:`ldap.filter`:

* Added functions :func:`ldap.filter.escape_filter_chars` and :func:`ldap.filter.filter_format`


:mod:`ldap.ldapobject`:

* Trace log writes LDAP URI of connection instead of module name
* :meth:`~ldap.ldapobject.LDAPObject.search_s` passes self.timeout as argument timeout when
  calling :meth:`~ldap.ldapobject.LDAPObject.search_ext_s`

* Keyword arguments for :meth:`~ldap.ldapobject.LDAPObject.simple_bind` and :meth:`~ldap.ldapobject.LDAPObject.simple_bind_s`
  with defaults for anonymous bind.

* :attr:`~ldap.ldapobject.LDAPObject.protocol_version` is set to LDAPv3 as default
  (this might make code changes necessary in a real LDAPv2
  environment)

* Default for keyword argument ``trace_stack_limit`` passed to
  :meth:`~ldap.ldapobject.LDAPObject.__init__` is 5

* Updated ``__doc__`` strings
* Aligned and tested :class:`~ldap.ldapobject.ReconnectLDAPObject` and Smart:class:`~ldap.ldapobject.LDAPObject`


:mod:`ldap.async`:

* :class:`ldif.LDIFWriter` uses :mod:`ldif` :class:`ldif.LDIFWriter` instead of calling
  function :func:`ldif.CreateLDIF`

* :class:`ldif.LDIFWriter` accepts either file-like object or :mod:`ldif` :class:`ldif.LDIFWriter`
  instance as argument for specifying the output

:mod:`ldif`:

* Abandoned argument ``all_records`` of :meth:`~ldif.LDIFRecordList.__init__`


:mod:`ldapurl`:

* :func:`urllib.unquote` used instead of :func:`urllib.unquote_plus`


Released 2.0.0pre11 2003-05-02
------------------------------

Changes since 2.0.0pre10:

:mod:`ldap.ldapobject`:

* Cosmetic change: Named argument list for :meth:`~ldap.ldapobject.LDAPObject.compare`
  instead of ``*args,**kwargs``.

* Fixed bug in :meth:`~ldap.ldapobject.ReconnectLDAPObject._apply_method_s` affecting
  compatibility with Python 2.0. The bug was introduced with
  2.0.0pre09 by dropping use of ``apply()``.

:mod:`ldap.modlist`:

* :func:`ldap.modlist.modifyModlist`: Only ``None`` is filtered from attribute value lists,
  '' is preserved as valid attribute value. But filtering applies
  to ``old_value`` and ``new_value`` now.

:mod:`ldap.schema`:

* Zero-length attribute values for schema elements are ignored
  (needed on e.g. Active Directory)

:mod:`dsml`:
Added support for parsing and generating DSMLv1.
Still experimental though.


Released 2.0.0pre10 2003-04-19
------------------------------

Changes since 2.0.0pre09:

:mod:`ldap.schema`:

* Emulate ``BooleanType`` for compatibility with Python2.3 in assert
  statements

Released 2.0.0pre09 2003-04-19
------------------------------

Changes since 2.0.0pre08:

Modified :file:`setup.py` to support Cyrus-SASL 2.x.

:mod:`ldap.ldapobject`:

* ``apply()`` is not used anymore since it seems deprecated
* Fixed :meth:`~ldap.ldapobject.ReconnectLDAPObject.__setstate__` and :meth:`~ldap.ldapobject.ReconnectLDAPObject.__getstate__` of :class:`~ldap.ldapobject.ReconnectLDAPObject`


:mod:`ldap.schema`:

* Completed classes for ``nameForms``, ``dITStructureRules``, and
  ``dITContentRules``

Released 2.0.0pre08 2003-04-11
------------------------------

Changes since 2.0.0pre07:

:mod:`ldap.schema`:

* For backward compatibility with Python versions prior to 2.2
  :file:`Lib/ldap/schema/tokenizer.py` and :file:`Lib/ldap/schema/models.py` use
  ``(())`` instead of :class:`tuple` for creating empty tuples.

Released 2.0.0pre07 2003-04-03
------------------------------

Changes since 2.0.0pre06:

:file:`LDAPObject.c`:
  * Wrapped OpenLDAP's ``ldap_search_ext()``
  * Removed empty ``__doc__`` strings
  * Removed :meth:`~ldap.ldapobject.LDAPObject.fileno`
  * Removed all stuff related to caching in OpenLDAP libs


:mod:`ldap.ldapobject`:
  * Fixed SASL rebind in :class:`~ldap.ldapobject.ReconnectLDAPObject`
  * use :meth:`~ldap.ldapobject.LDAPObject.search_ext` instead ``ldap_search()``
  * new class attribute timeout for setting a global time-out
    value for all synchronous operations

:mod:`ldap.schema`:

* Fixed two typos in :mod:`ldap.schema.models`
* Some attempts to improve performance of parser/tokenizer
* Completely reworked to have separate OID dictionaries for
  the different schema element classes

* Fixed the Demo/schema*.py to reflect changes to :mod:`ldap.schema`


Documentation updates and various ``__doc__`` string modifications.

:mod:`ldapurl`:
  * Removed all Unicode stuff from module :mod:`ldapurl`
  * Consistent URL encoding in module :mod:`ldapurl`


:mod:`ldif`:
  * Removed :class:`ldif.FileWriter`
  * Proper handling of FILL (see RFC 2849)


Released 2.0.0pre06 2002-09-23
------------------------------

Changes since 2.0.0pre05:

- Fine-grained locking when linking against ``libldap_r``
- New wrapper class :class:`~ldap.ldapobject.ReconnectLDAPObject`
- Security fix to module :mod:`ldapurl`
- Other fixes and improvements to whole package
- LDAPv3 schema support
  (still somewhat premature and undocumented)

Released 2.0.0pre05 2002-07-20
------------------------------

Released 2.0.0pre04 2002-02-09
------------------------------

Released 2.0.0pre02 2002-02-01
------------------------------

Released 1.10alpha3 2000-09-19
------------------------------
