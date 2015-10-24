.. % $Id: ldap-sasl.rst,v 1.1 2015/10/24 12:49:41 stroeder Exp $


********************************************
:py:mod:`ldap.sasl` Handling LDAPv3 schema
********************************************

.. py:module:: ldap.sasl

This module implements various authentication methods for SASL bind.

.. seealso::

   :rfc:`4422` - Simple Authentication and Security Layer (SASL)


:py:mod:`ldap.sasl` SASL bind requests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. py:module:: ldap.sasl


.. py:data:: CB_USER

.. py:data:: CB_AUTHNAME

.. py:data:: CB_LANGUAGE

.. py:data:: CB_PASS

.. py:data:: CB_ECHOPROMPT

.. py:data:: CB_NOECHOPROMPT

.. py:data:: CB_GETREALM


Functions
=========

.. autofunction:: ldap.sasl.subentry.urlfetch

Classes
=======

.. autoclass:: ldap.sasl.sasl
   :members:

.. autoclass:: ldap.sasl.cram_md5
   :members:

.. autoclass:: ldap.sasl.digest_md5
   :members:

.. autoclass:: ldap.sasl.gssapi
   :members:

.. autoclass:: ldap.sasl.external
   :members:


.. _ldap.sasl-example:

Examples for ldap.sasl
^^^^^^^^^^^^^^^^^^^^^^^^

::

   import ldap.sasl
