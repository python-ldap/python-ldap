.. _Download information:

Installing python-ldap
######################

Installing from PyPI
====================

The preferred point for downloading the “official” source distribution
is now the `PyPI repository`_ which supports installing via `pip`_.
For example::

    python -m pip install python-ldap

.. _PyPI repository: https://pypi.python.org/pypi/python-ldap/
.. _pip: https://pip.pypa.io/en/stable/

For installing from PyPI, you will need the :ref:`build prerequisites`
as when installing from source.

We do not currently provide pre-built packages (wheels).


Furthermore, python-ldap requires the modules `pyasn1`_ and `pyasn1-modules`_.
``pip`` will install these automatically.

.. _pyasn1: https://pypi.python.org/pypi/pyasn1
.. _pyasn1-modules: https://pypi.python.org/pypi/pyasn1-modules


Pre-built Binaries
==================

Because distributions seem to be all over the place, this page
tries to list all the current ones we know of.

Note that the python-ldap team is not responsible for the binary packages
except the sources you can grab from the PyPI page. Also note that binary
packages are most times not up to date. If you experience troubles
with a binary package, it would be nice if you try to build a recent version
of python-ldap before submitting a bug report to make sure you did not
hit a problem already fixed in recent releases.

`openSUSE Linux <https://www.opensuse.org/>`_
---------------------------------------------

ships with python-ldap and there's an additional
`download repository <http://download.opensuse.org/repositories/devel:/languages:/python/>`_
which contains builds of latest releases
(see also `OBS package <https://build.opensuse.org/package/show/devel:languages:python/python-ldap>`_

`Debian Linux <https://www.debian.org>`_
----------------------------------------

Have a look into the
`Debian Package Tracker <https://tracker.debian.org/pkg/python-ldap>`_
to get up to date information which versions are available.


Windows
-------

Unofficial packages for Windows are available on
`Christoph Gohlke's page <https://www.lfd.uci.edu/~gohlke/pythonlibs/>`_.


`FreeBSD <https://www.freebsd.org/`_
------------------------------------

The CVS repository of FreeBSD contains the package
`py-ldap <https://svnweb.freebsd.org/ports/head/net/py-ldap/>`_

Mac OS X
--------

You can install directly with pip::

    xcode-select --install
    pip install python-ldap \
        --global-option=build_ext \
        --global-option="-I$(xcrun --show-sdk-path)/usr/include/sasl"


Installing from Source
======================


python-ldap is built and installed using the Python setuptools.
From a source repository::

    python -m pip install setuptools
    python setup.py install

If you have more than one Python interpreter installed locally, you should
use the same one you plan to use python-ldap with.

See further instructions can be found in `Setuptools documentation`_.


.. _Setuptools documentation: https://docs.python.org/3/distributing/index.html


.. _build prerequisites:

Build prerequisites
===================

The following software packages are required to be installed
on the local system when building python-ldap:

- `Python`_ version 2.7, or 3.3 or later including its development files
- `OpenLDAP`_ client libs version 2.4.11 or later
  It is not possible and not supported to build with prior versions.
- `OpenSSL`_ (optional)
- `cyrus-sasl`_ (optional)
- Kerberos libraries, MIT or heimdal (optional)

.. _Python: https://www.python.org/
.. _OpenLDAP: https://www.openldap.org/
.. _OpenSSL: https://www.openssl.org/
.. _cyrus-sasl: https://www.cyrusimap.org/sasl/


setup.cfg
=========

The file setup.cfg allows to set some build and installation
parameters for reflecting the local installation of required
software packages. Only section [_ldap] is described here.
More information about other sections can be found in the
documentation of Python's DistUtils.

.. data:: library_dirs

   Specifies in which directories to search for required libraries.

.. data:: include_dirs

   Specifies in which directories to search for include files of required libraries.

.. data:: libs

   A space-separated list of library names to link to (see :ref:`libs-used-label`).

.. data:: extra_compile_args

   Compiler options.

.. data:: extra_objects

.. _libs-used-label:


Libraries used
---------------

.. data:: ldap
   :noindex:
.. data:: ldap_r
   :noindex:

   The LDAP protocol library of OpenLDAP. ldap_r is the reentrant version
   and should be preferred.

.. data:: lber
   :noindex:

   The BER encoder/decoder library of OpenLDAP.

.. data:: sasl2
   :noindex:

   The Cyrus-SASL library if needed and present during build

.. data:: ssl
   :noindex:

   The SSL/TLS library of OpenSSL if needed and present during build

.. data:: crypto
   :noindex:

   The basic cryptographic library of OpenSSL if needed and present during build

Example
-------

The following example is for a full-featured build (including SSL and SASL support)
of python-ldap with OpenLDAP installed in a different prefix directory
(here /opt/openldap-2.4) and SASL header files found in /usr/include/sasl.
Debugging symbols are preserved with compile option -g.

::

  [_ldap]
  library_dirs = /opt/openldap-2.4/lib
  include_dirs = /opt/openldap-2.4/include /usr/include/sasl

  extra_compile_args = -g
  extra_objects =

  libs = ldap_r lber sasl2 ssl crypto

