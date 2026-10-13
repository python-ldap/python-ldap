"""
Automatic tests for python-ldap's module ldap.filter

See https://www.python-ldap.org/ for details.
"""

import os

import pytest


# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

from ldap.filter import escape_filter_chars, filter_format, is_filter


class TestFilter:
    """
    test ldap.functions
    """

    def test_is_filter(self):
        """
        test function is_filter()
        """
        assert is_filter('')
        assert is_filter('foo=')
        assert is_filter('foo=bar')
        assert is_filter('foo=*')
        assert is_filter(filter_format('foo=%s', ['*']))
        assert is_filter('(foo=bar)')
        assert is_filter('(&(foo=bar))')
        assert is_filter('(|(foo=bar))')
        assert is_filter(filter_format('foo=%s', ['\x00']))
        assert is_filter('foo>=')
        assert is_filter('(foo>=)')
        assert is_filter('foo==bar')
        assert not is_filter('foobar')
        assert not is_filter('(foo=')
        assert not is_filter('foo=)')
        assert not is_filter('=bar')
        with pytest.raises(ValueError):
            is_filter('foo=\x00')
        with pytest.raises(TypeError):
            is_filter(object())

    def test_escape_filter_chars_mode0(self):
        """
        test function escape_filter_chars() with escape_mode=0
        """
        assert escape_filter_chars(r'foobar') == 'foobar'
        assert escape_filter_chars(r'foo\bar') == r'foo\5cbar'
        assert escape_filter_chars(r'foo\bar', escape_mode=0) == r'foo\5cbar'

    def test_escape_filter_chars_mode1(self):
        """
        test function escape_filter_chars() with escape_mode=1
        """
        assert (
            escape_filter_chars('\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x84\xc3\x96\xc3\x9c\xc3\x9f', escape_mode=1)
            == r'\c3\a4\c3\b6\c3\bc\c3\84\c3\96\c3\9c\c3\9f'
        )
        with pytest.raises(TypeError):
            escape_filter_chars(['abc@*()/xyz'], escape_mode=1)
        with pytest.raises(TypeError):
            escape_filter_chars({'abc@*()/xyz': 1}, escape_mode=1)

    def test_escape_filter_chars_mode2(self):
        """
        test function escape_filter_chars() with escape_mode=2
        """
        assert escape_filter_chars('foobar', escape_mode=2) == r'\66\6f\6f\62\61\72'
