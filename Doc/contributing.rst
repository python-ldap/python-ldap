.. highlight:: console

Contributing to python-ldap
***************************

Thank you for your interest in python-ldap!
If you'd like to contribute (be it code, documentation, maintenance effort,
or anything else), this guide is for you.


Communication
=============

Always keep in mind that python-ldap is developed and maintained by volunteers.
We're happy to share our work, and to work with you to make the library better,
but (until you pay someone), there's obligation to provide assistance.

So, keep it friendly, respectful, and supportive!


Mailing list
------------

Discussion about the use and future of python-ldap occurs in
the ``python-ldap@python.org`` mailing list.

It's also the channel to use if documentation (including this guide) is not
clear to you.
Do try searching around before you ask on the list, though!

You can `subscribe or unsubscribe`_ to this list or browse the `list archive`_.

.. _subscribe or unsubscribe: https://mail.python.org/mailman/listinfo/python-ldap
.. _list archive: https://mail.python.org/pipermail/python-ldap/


Issues
------

Please report bugs, missing features and other issues to `the bug tracker`_
at GitHub. You will need a GitHub account for that.

If you prefer not to open a GitHub account, you're always welcome to use the
mailing list.


Security Contact
----------------

If you found a security issue that should not be discussed publicly,
please e-mail the maintainer at ``pviktori@redhat.com``.
If required, write to coordinate a more secure channel.

All other communication should be public.


Process for Code contributions
==============================

If you're used to open-source Python development with Git, here's the gist:

* ``git clone https://github.com/python-ldap/python-ldap``
* Use GitHub for `the bug tracker`_ and pull requests.
* Run tests with `tox`_; ignore Python interpreters you don't have locally.

.. _the bug tracker: https://github.com/python-ldap/python-ldap/issues
.. _tox: https://tox.readthedocs.io/en/latest/

Or, if you prefer to avoid closed-source services:

* ``git clone https://pagure.io/python-ldap``
* Send bug reports and patches to the mailing list.
* Run tests with `tox`_; ignore Python interpreters you don't have locally.
* Read the documentation directly at `Read the Docs`_.

.. _Read the Docs: http://python-ldap.readthedocs.io/

If you're new to some aspect of the project, you're welcome to use (or adapt)
the workflow below.


Sample workflow
---------------

We assume that, as a user of python-ldap you're not new to software
development in general, so these instructions are terse.
If you need additional detail, please do ask on the mailing list.

.. note::

    The following instructions are for Linux.
    If you can translate them to another system, please contribute your
    translation!


Install `Git`_ and `tox`_.

Clone the repository::

    $ git clone https://github.com/python-ldap/python-ldap
    $ cd python-ldap

Create a `virtual environment`_ to ensure you in-development python-ldap won't
affect the rest of your system::

    $ python3 -m venv __venv__

(For Python 2, install `virtualenv`_ and use it instead of ``python3 -m venv``.)

.. _git: https://git-scm.com/
.. _virtual environment: https://docs.python.org/3/library/venv.html
.. _virtualenv: https://virtualenv.pypa.io/en/stable/

Activate the virtual environment::

    $ source __venv__/bin/activate

Install python-ldap to it in `editable mode`_::

    (__venv__)$ python -m pip install -e .

This way, importing a Python module from python-ldap will directly
use the code from your source tree.
If you change C code, you will still need to recompile
(using the ``pip install`` command again).

.. _editable mode: https://pip.pypa.io/en/stable/reference/pip_install/#editable-installs

Change the code as desired.


To run tests, install and run `tox`_::

    (__venv__)$ python -m pip install tox
    (__venv__)$ tox --skip-missing-interpreters

This will run tests on all supported versions of Python that you have
installed, skipping the ones you don't.
To run a subset of test environments, run for example::

    (__venv__)$ tox -e py27,py36

In addition to ``pyXY`` environments, we have extra environments
for checking things independent of the Python version:

* ``doc`` checks syntax and spelling of the documentation
* ``coverage-report`` generates a test coverage report for Python code.
  It must be used last, e.g. ``tox -e py27,py36,coverage-report``.
* ``py2-nosasltls`` and ``py3-nosasltls`` check functionality without
  SASL and TLS bindings compiled in.


When your change is ready, commit to Git, and submit a pull request on GitHub.
You can take a look at the `committer instructions`_ to see what we are looking
for in a pull request.

If you don't want to open a GitHub account, please send patches as attachments
to the python-ldap mailing list.


.. _additional tests:

Additional tests and scripts
============================

We use several specialized tools for debugging and maintenance.

Make targets
------------

``make lcov-open``
    Generate and view test coverage for C code.
    Requires ``make`` and ``lcov``.

``make scan-build``
    Run static analysis. Requires ``clang``.


Reference leak tests
--------------------

Reference leak tests require a *pydebug* build of CPython and `pytest`_ with
`pytest-leaks`_ plugin. A *pydebug* build has a global reference counter, which
keeps track of all reference increments and decrements. The leak plugin runs
each test multiple times and checks if the reference count increases.

.. _pytest: https://docs.pytest.org/en/latest/
.. _pytest-leaks: https://pypi.python.org/pypi/pytest-leaks

Download and compile the *pydebug* build::

    $ curl -O https://www.python.org/ftp/python/3.6.3/Python-3.6.3.tar.xz
    $ tar xJf Python-3.6.3.tar.xz
    $ cd Python-3.6.3
    $ ./configure --with-pydebug
    $ make

Create a virtual environment with the *pydebug* build::

    $ ./python -m venv /tmp/refleak
    $ /tmp/refleak/bin/pip install pytest pytest-leaks

Run reference leak tests::

    $ cd path/to/python-ldap
    $ /tmp/refleak/bin/pip install --upgrade .
    $ /tmp/refleak/bin/pytest -v -R: Tests/t_*.py

Run ``/tmp/refleak/bin/pip install --upgrade .`` every time a file outside
of ``Tests/`` is modified.


.. _committer instructions:

Instructions for core committers
================================

If you have the authority (and responsibility) of merging changes from others,
remember:

* All code changes need to be reviewed by someone other than the author.

* Tests must always pass. New features without tests shall *not* pass review.

* Make sure commit messages don't use GitHub-specific link syntax.
  Use the full URL, e.g. ``https://github.com/python-ldap/python-ldap/issues/50``
  instead of ``#20``.

  * Exception: it's fine to use the short form in the summary line of a merge
    commit, if the full URL appears later.
  * It's OK to use shortcuts in GitHub *discussions*, where they are not
    hashed into immutable history.

* Make a merge commit if the contribution contains several well-isolated
  separate commits with good descriptions. Use *squash-and-merge* (or
  *fast-forward* from a command line) for all other cases.

* It's OK to push small changes into a pull request. If you do this, document
  what you have done (so the contributor can learn for the future), and get
  their :abbr:`ACK (confirmation)` before merging.

* When squashing, do edit commit messages to add references to the pull request
  and relevant discussions/issues, and to conform to Git best practices.

  * Consider making the summary line suitable for the CHANGES document,
    and starting it with a prefix like ``Lib:`` or ``Tests:``.

* Push to Pagure as well.

If you have good reason to break the “rules”, go ahead and break them,
but mention why.


Instructions for release managers
=================================

If you are tasked with releasing python-ldap, remember to:

* Bump all instances of the version number.
* Go through all changes since last version, and add them to ``CHANGES``.
* Run :ref:`additional tests` as appropriate, fix any regressions.
* Merge all that (using pull requests).
* Run ``python setup.py sdist``, and smoke-test the resulting package
  (install in a clean virtual environment, import ``ldap``).
* Create Git tag ``python-ldap-{version}``, and push it to GitHub and Pagure.
* Release the ``sdist`` on PyPI.
* Announce the release on the mailing list.
  Mention the Git hash.
