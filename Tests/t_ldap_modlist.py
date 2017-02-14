"""
Tests for module ldap.modlist
"""
import unittest

import ldap

from ldap.modlist import addModlist,modifyModlist

class TestModlist(unittest.TestCase):

    addModlist_tests = [
        (
            {
                'objectClass':['person','pilotPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'dummy1':[],
                'dummy2':['2'],
                'dummy3':[''],
            },
            [
                ('objectClass',['person','pilotPerson']),
                ('cn',['Michael Str\303\266der','Michael Stroeder']),
                ('sn',['Str\303\266der']),
                ('dummy2',['2']),
                ('dummy3',['']),
            ]
        ),
    ]

    def test_addModlist(self):
        for entry,test_modlist in self.addModlist_tests:
            test_modlist.sort()
            result_modlist = addModlist(entry)
            result_modlist.sort()
            self.assertEqual(
                test_modlist, result_modlist,
                'addModlist(%s) returns\n%s\ninstead of\n%s.' % (
                    repr(entry),repr(result_modlist),repr(test_modlist)
                )
            )

    modifyModlist_tests = [
        (
            {
                'objectClass':['person','pilotPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'enum':['a','b','c'],
                'c':['DE'],
            },
            {
                'objectClass':['person','inetOrgPerson'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':[],
                'enum':['a','b','d'],
                'mail':['michael@stroeder.com'],
            },
            [],
            [
                (ldap.MOD_DELETE,'objectClass',None),
                (ldap.MOD_ADD,'objectClass',['person','inetOrgPerson']),
                (ldap.MOD_DELETE,'c',None),
                (ldap.MOD_DELETE,'sn',None),
                (ldap.MOD_ADD,'mail',['michael@stroeder.com']),
                (ldap.MOD_DELETE,'enum',None),
                (ldap.MOD_ADD,'enum',['a','b','d']),
            ]
        ),

        (
            {
                'c':['DE'],
            },
            {
                'c':['FR'],
            },
            [],
            [
                (ldap.MOD_DELETE,'c',None),
                (ldap.MOD_ADD,'c',['FR']),
            ]
        ),

        # Now a weird test-case for catching all possibilities
        # of removing an attribute with MOD_DELETE,attr_type,None
        (
            {
                'objectClass':['person'],
                'cn':[None],
                'sn':[''],
                'c':['DE'],
            },
            {
                'objectClass':[],
                'cn':[],
                'sn':[None],
            },
            [],
            [
                (ldap.MOD_DELETE,'c',None),
                (ldap.MOD_DELETE,'objectClass',None),
                (ldap.MOD_DELETE,'sn',None),
            ]
        ),

        (
            {
                'objectClass':['person'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':['Str\303\266der'],
                'enum':['a','b','C'],
            },
            {
                'objectClass':['Person'],
                'cn':['Michael Str\303\266der','Michael Stroeder'],
                'sn':[],
                'enum':['a','b','c'],
            },
            ['objectClass'],
            [
                (ldap.MOD_DELETE,'sn',None),
                (ldap.MOD_DELETE,'enum',None),
                (ldap.MOD_ADD,'enum',['a','b','c']),
            ]
        ),

    ]

    def test_modifyModlist(self):
        for old_entry, new_entry, case_ignore_attr_types, test_modlist in self.modifyModlist_tests:
            test_modlist.sort()
            result_modlist = modifyModlist(
                old_entry, new_entry,
                case_ignore_attr_types=case_ignore_attr_types)
            result_modlist.sort()

            self.assertEqual(
                test_modlist, result_modlist,
                'modifyModlist(%s,%s) returns\n%s\ninstead of\n%s.' % (
                    repr(old_entry),
                    repr(new_entry),
                    repr(result_modlist),
                    repr(test_modlist),
                )
            )


if __name__ == '__main__':
    unittest.main()
