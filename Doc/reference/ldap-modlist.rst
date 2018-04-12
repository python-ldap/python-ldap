:py:mod:`ldap.modlist` Generate modify lists
==============================================

.. py:module:: ldap.modlist


The :mod:`ldap.modlist` module defines the following functions:


.. function:: addModlist(entry [, ignore_attr_types=[]]) -> list

   This function builds a list suitable for passing it directly as argument
   *modlist* to method :py:meth:`ldap.ldapobject.LDAPObject.add` or
   its synchronous counterpart :py:meth:`ldap.ldapobject.LDAPObject.add_s`.

   *entry* is a dictionary like returned when receiving search results.

   *ignore_attr_types* is a list of attribute type
   names which shall be ignored completely. Attributes of these types will not appear
   in the result at all.

   The value parts of the *entry* dictionary must be any of a list of
   :py:class:`bytes` objects, a :py:class:`bytes` object, or :py:const:`None` (in Python 3).
   The :py:class:`bytes` object is treated as a list which contains
   single :py:class:`bytes` object.
   These :py:class:`bytes` data are passed to the C interface without
   any conversion.
   :py:const:`None` means :c:data:`NULL` in C (no values).



.. function:: modifyModlist( old_entry, new_entry [, ignore_attr_types=[] [, ignore_oldexistent=0 [, case_ignore_attr_types=None]]]) -> list

   This function builds a list suitable for passing it directly as argument
   *modlist* to method :py:meth:`ldap.ldapobject.LDAPObject.modify` or
   its synchronous counterpart :py:meth:`ldap.ldapobject.LDAPObject.modify_s`.

   Roughly when applying the resulting modify list to an entry
   holding  the data *old_entry* it will be modified in such a way that the entry
   holds *new_entry* after the modify operation. It is handy in situations when it
   is impossible to track user changes to an entry's data or for synchronizing
   operations.

   *old_entry* and *new_entry* are dictionaries like returned when
   receiving search results.

   *ignore_attr_types* is a list of attribute type
   names which shall be ignored completely. These attribute types will not appear
   in the result at all.

   If *ignore_oldexistent* is non-zero attribute type names which
   are in *old_entry* but are not found in *new_entry* at all are not deleted.
   This is handy for situations where your application sets attribute value to
   an empty string for deleting an attribute. In most cases leave zero.

   If *case_ignore_attr_types* is a list of attribute type names for which
   the comparison will be conducted case-insensitive. It is useful in
   situations where a LDAP server normalizes values and one wants to avoid
   unnecessary changes (e.g. case of attribute type names in DNs).

   .. note::
      Replacing attribute values is always done with a
      :py:const:`ldap.MOD_DELETE`/:py:const:`ldap.MOD_ADD` pair instead of
      :py:const:`ldap.MOD_REPLACE` to work-around potential issues with
      attributes for which no EQUALITY matching rule are defined in the
      server's subschema.  This works correctly in most situations but
      rarely fails with some LDAP servers implementing (schema) checks on
      transient state entry during processing the modify operation.
