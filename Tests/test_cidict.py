"""
Automatic tests for python-ldap's module ldap.cidict

See https://www.python-ldap.org/ for details.
"""

import os
import warnings


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'
import ldap
import ldap.cidict


class TestCidict:
    """
    test ldap.cidict.cidict
    """

    def test_cidict(self):
        """
        test function is_dn()
        """
        assert not ldap.dn.is_dn('foobar,ou=ae-dir')
        data = {
            'AbCDeF': 123,
        }
        cix = ldap.cidict.cidict(data)
        assert cix['ABCDEF'] == 123
        assert cix.get('ABCDEF', None) == 123
        assert cix.get('not existent', None) is None
        cix['xYZ'] = 987
        assert cix['XyZ'] == 987
        assert cix.get('xyz', None) == 987
        cix_keys = sorted(cix.keys())
        assert cix_keys == ['AbCDeF', 'xYZ']
        cix_keys = sorted(cix)
        assert cix_keys == ['AbCDeF', 'xYZ']
        cix_items = sorted(cix.items())
        assert cix_items == [('AbCDeF', 123), ('xYZ', 987)]
        del cix['abcdEF']
        assert 'abcdef' not in cix._keys
        assert 'AbCDef' not in cix._keys
        assert 'abcdef' not in cix
        assert 'AbCDef' not in cix
        assert not cix.has_key('abcdef')
        assert not cix.has_key('AbCDef')

    def test_strlist_deprecated(self):
        strlist_funcs = [ldap.cidict.strlist_intersection, ldap.cidict.strlist_minus, ldap.cidict.strlist_union]
        for strlist_func in strlist_funcs:
            with warnings.catch_warnings(record=True) as w:
                warnings.resetwarnings()
                warnings.simplefilter('always', DeprecationWarning)
                strlist_func(['a'], ['b'])
            assert len(w) == 1

    def test_cidict_data(self):
        """test the deprecated data atrtribute"""
        d = ldap.cidict.cidict({'A': 1, 'B': 2})
        with warnings.catch_warnings(record=True) as w:
            warnings.resetwarnings()
            warnings.simplefilter('always', DeprecationWarning)
            data = d.data
        assert data == {'a': 1, 'b': 2}
        assert len(w) == 1

    def test_copy(self):
        cix1 = ldap.cidict.cidict({'a': 1, 'B': 2})
        cix2 = cix1.copy()
        assert cix1 == cix2
        cix1['c'] = 3
        assert 'c' not in cix2
        cix2['C'] = 4
        assert cix1 != cix2
        assert list(cix1.keys()) == ['a', 'B', 'c']
        assert list(cix2.keys()) == ['a', 'B', 'C']
