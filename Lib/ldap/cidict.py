"""
This is a convenience wrapper for dictionaries
returned from LDAP servers containing attribute
names of variable case.

See https://www.python-ldap.org/ for details.
"""
import warnings

from collections.abc import MutableMapping
from ldap.pkginfo import __version__

from typing import (
    Any,
    Dict,
    Iterator,
    List,
    Mapping,
    MutableMapping as MutableMappingType,
    TypeVar,
    Optional,
)

T = TypeVar('T', bound=Any)

from typing_extensions import Self


class cidict(MutableMappingType[str, T]):
    """
    Case-insensitive but case-respecting dictionary.
    """
    __slots__ = ('_keys', '_data')

    def __init__(self, default: Optional[Mapping[str, T]] = None) -> None:
        self._keys: Dict[str, str] = {}
        self._data: Dict[str, T] = {}
        if default:
            self.update(default)

    # MutableMapping abstract methods

    def __getitem__(self, key: str) -> T:
        return self._data[key.lower()]

    def __setitem__(self, key: str, value: T) -> None:
        lower_key = key.lower()
        self._keys[lower_key] = key
        self._data[lower_key] = value

    def __delitem__(self, key: str) -> None:
        lower_key = key.lower()
        del self._keys[lower_key]
        del self._data[lower_key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys.values())

    def __len__(self) -> int:
        return len(self._keys)

    # Specializations for performance

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        return key.lower() in self._keys

    def clear(self) -> None:
        self._keys.clear()
        self._data.clear()

    def copy(self) -> Self:
        inst = self.__class__.__new__(self.__class__)
        inst._data = self._data.copy()
        inst._keys = self._keys.copy()
        return inst

    __copy__ = copy

    # Backwards compatibility

    def has_key(self, key: str) -> bool:
        """Compatibility with python-ldap 2.x"""
        return key in self

    @property
    def data(self) -> Dict[str, T]:
        """Compatibility with older IterableUserDict-based implementation"""
        warnings.warn(
            'ldap.cidict.cidict.data is an internal attribute; it may be ' +
            'removed at any time',
            category=DeprecationWarning,
            stacklevel=2,
        )
        return self._data


def strlist_minus(a: List[str], b: List[str]) -> List[str]:
  """
  Return list of all items in a which are not in b (a - b).
  a,b are supposed to be lists of case-insensitive strings.
  """
  warnings.warn(
    "strlist functions are deprecated and will be removed in 3.5",
    category=DeprecationWarning,
    stacklevel=2,
  )
  temp: cidict[str] = cidict()
  for elt in b:
    temp[elt] = elt
  result = [
    elt
    for elt in a
    if elt not in temp
  ]
  return result


def strlist_intersection(a: List[str], b: List[str]) -> List[str]:
  """
  Return intersection of two lists of case-insensitive strings a,b.
  """
  warnings.warn(
    "strlist functions are deprecated and will be removed in 3.5",
    category=DeprecationWarning,
    stacklevel=2,
  )
  temp: cidict[str] = cidict()
  for elt in a:
    temp[elt] = elt
  result = [
    temp[elt]
    for elt in b
    if elt in temp
  ]
  return result


def strlist_union(a: List[str], b: List[str]) -> List[str]:
  """
  Return union of two lists of case-insensitive strings a,b.
  """
  warnings.warn(
    "strlist functions are deprecated and will be removed in 3.5",
    category=DeprecationWarning,
    stacklevel=2,
  )
  temp: cidict[str] = cidict()
  for elt in a:
    temp[elt] = elt
  for elt in b:
    temp[elt] = elt
  return [x for x in temp.values()]
