"""Compatibility wrappers for Py2/Py3."""

import sys

if sys.version_info[0] < 3:
    from UserDict import UserDict, IterableUserDict
    from urllib import quote
    from urllib import quote_plus
    from urllib import unquote as urllib_unquote
    from urllib import urlopen
    from urlparse import urlparse

    def unquote(uri):
        """Specialized unquote that uses UTF-8 for parsing."""
        uri = uri.encode('ascii')
        unquoted = urllib_unquote(uri)
        return unquoted.decode('utf-8')

    # Old-style of re-raising an exception is SyntaxError in Python 3,
    # so hide behind exec() so the Python 3 parser doesn't see it
    exec('''def reraise(exc_type, exc_value, exc_traceback):
        """Re-raise an exception given information from sys.exc_info()

        Note that unlike six.reraise, this does not support replacing the
        traceback. All arguments must come from a single sys.exc_info() call.
        """
        raise exc_type, exc_value, exc_traceback
    ''')

else:
    from collections import UserDict
    IterableUserDict = UserDict
    from urllib.parse import quote, quote_plus, unquote, urlparse
    from urllib.request import urlopen

    def reraise(exc_type, exc_value, exc_traceback):
        """Re-raise an exception given information from sys.exc_info()

        Note that unlike six.reraise, this does not support replacing the
        traceback. All arguments must come from a single sys.exc_info() call.
        """
        # In Python 3, all exception info is contained in one object.
        raise exc_value
