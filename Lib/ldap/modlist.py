"""
ldap.modlist - create add/modify modlist's

See https://www.python-ldap.org/ for details.
"""

from ldap import __version__

import ldap


def addModlist(entry, ignore_attr_types=None):
    """Build modify list for call of method LDAPObject.add()"""
    ignore_attr_types = set(map(str.lower, ignore_attr_types or []))
    modlist = []
    for attrtype in entry.keys():
        if attrtype.lower() in ignore_attr_types:
            # This attribute type is ignored
            continue
        # Eliminate empty attr value strings in list
        attrvaluelist = [
            val
            for val in entry[attrtype]
            if val is not None
        ]
        if attrvaluelist:
            modlist.append((attrtype, entry[attrtype]))
    return modlist # addModlist()


def modifyModlist(
        old_entry,
        new_entry,
        ignore_attr_types=None,
        ignore_oldexistent=0,
        case_ignore_attr_types=None
    ):
    """
    Build differential modify list for calling LDAPObject.modify()/modify_s()

    old_entry
        Dictionary holding the old entry
    new_entry
        Dictionary holding what the new entry should be
    ignore_attr_types
        List of attribute type names to be ignored completely
    ignore_oldexistent
        If non-zero attribute type names which are in old_entry
        but are not found in new_entry at all are not deleted.
        This is handy for situations where your application
        sets attribute value to '' for deleting an attribute.
        In most cases leave zero.
    case_ignore_attr_types
        List of attribute type names for which comparison will be made
        case-insensitive
    """
    ignore_attr_types = set(map(str.lower, ignore_attr_types or []))
    case_ignore_attr_types = set(map(str.lower, case_ignore_attr_types or []))
    modlist = []
    attrtype_lower_map = {}
    for a in old_entry.keys():
        attrtype_lower_map[str.lower(a)] = a
    for attrtype in new_entry.keys():
        attrtype_lower = str.lower(attrtype)
        if attrtype_lower in ignore_attr_types:
            # This attribute type is ignored
            continue
        # Filter away null-strings
        new_value = [
            val
            for val in new_entry[attrtype]
            if val is not None
        ]
        if attrtype_lower in attrtype_lower_map:
            old_value = [
                val
                for val in old_entry.get(attrtype_lower_map[attrtype_lower], [])
                if val is not None
            ]
            del attrtype_lower_map[attrtype_lower]
        else:
            old_value = []
        if not old_value and new_value:
            # Add a new attribute to entry
            modlist.append((ldap.MOD_ADD, attrtype, new_value))
        elif old_value and new_value:
            # Replace existing attribute
            replace_attr_value = len(old_value) != len(new_value)
            if not replace_attr_value:
                if attrtype_lower in case_ignore_attr_types:
                    old_value_set = set(map(str.lower, old_value))
                    new_value_set = set(map(str.lower, new_value))
                else:
                    old_value_set = set(old_value)
                    new_value_set = set(new_value)
                replace_attr_value = new_value_set != old_value_set
            if replace_attr_value:
                modlist.append((ldap.MOD_DELETE, attrtype, None))
                modlist.append((ldap.MOD_ADD, attrtype, new_value))
        elif old_value and not new_value:
            # Completely delete an existing attribute
            modlist.append((ldap.MOD_DELETE, attrtype, None))
    if not ignore_oldexistent:
        # Remove all attributes of old_entry which are not present
        # in new_entry at all
        for a in attrtype_lower_map.keys():
            if a in ignore_attr_types:
                # This attribute type is ignored
                continue
            attrtype = attrtype_lower_map[a]
            modlist.append((ldap.MOD_DELETE, attrtype, None))
    return modlist # modifyModlist()
