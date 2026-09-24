"""
ldap - base module

See https://www.python-ldap.org/ for details.
"""

# This is also the overall release version number

from __future__ import annotations

import os
import sys
import threading
from typing import Any

from ldap._types import *
from ldap.pkginfo import __author__, __license__, __version__  # noqa: F401


if __debug__:
  # Tracing is only supported in debugging mode
  import atexit
  import traceback  # noqa: F401
  _trace_level = int(os.environ.get("PYTHON_LDAP_TRACE_LEVEL", "0"))
  _trace_file_path = os.environ.get("PYTHON_LDAP_TRACE_FILE")
  if _trace_file_path is None:
    _trace_file = sys.stderr
  else:
    _trace_file = open(_trace_file_path, 'a')  # noqa: SIM115
    atexit.register(_trace_file.close)
  _trace_stack_limit = None
else:
  # Any use of the _trace attributes should be guarded by `if __debug__`,
  # so they should not be needed here.
  # But, providing different API for debug mode is unnecessarily fragile.
  _trace_level = 0
  _trace_file = sys.stderr
  _trace_stack_limit = None

from ldap import _ldap


assert _ldap.__version__ == __version__, \
       ImportError(f'ldap {__version__} and _ldap {_ldap.__version__} version mismatch!')
from ldap._ldap import *  # noqa: E402


# call into libldap to initialize it right now
LIBLDAP_API_INFO = _ldap.get_option(_ldap.OPT_API_INFO)

OPT_NAMES_DICT = {}
for k, v in vars(_ldap).items():
  if k.startswith('OPT_'):
    OPT_NAMES_DICT[v] = k

LDAPLockBaseClass = threading.Lock


class LDAPLock:
  """
  Mainly a wrapper class to log all locking events.
  Note that this cumbersome approach with _lock attribute was taken
  since threading.Lock is not suitable for sub-classing.
  """
  _min_trace_level = 3

  def __init__(
    self,
    lock_class: type[Any] | None = None,
    desc: str = ''
  ) -> None:
    """
    lock_class
        Class compatible to threading.Lock
    desc
        Description shown in debug log messages
    """
    self._desc = desc
    self._lock = (lock_class or LDAPLockBaseClass)()

  def acquire(self) -> bool:
    if __debug__ and _trace_level >= self._min_trace_level:
      _trace_file.write(f'***{self.__class__.__name__}.acquire() {self!r} {self._desc}\n')
    return self._lock.acquire()

  def release(self) -> None:
    if __debug__ and _trace_level >= self._min_trace_level:
      _trace_file.write(f'***{self.__class__.__name__}.release() {self!r} {self._desc}\n')
    self._lock.release()


# Create module-wide lock for serializing all calls into underlying LDAP lib
_ldap_module_lock = LDAPLock(desc='Module wide')

from ldap.functions import escape_str, get_option, initialize, set_option, strf_secs, strp_secs  # noqa: E402, F401, I001
from ldap.dn import explode_dn, explode_rdn  # noqa: E402, F401
from ldap.ldapobject import NO_UNIQUE_ENTRY, LDAPBytesWarning  # noqa: E402, F401


# For compatibility of 2.3 and 2.4 OpenLDAP API
OPT_DIAGNOSTIC_MESSAGE = OPT_ERROR_STRING
