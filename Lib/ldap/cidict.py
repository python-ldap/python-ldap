"""
This is a convenience wrapper for dictionaries
returned from LDAP servers containing attribute
names of variable case.

See https://www.python-ldap.org/ for details.
"""

__version__ = """$Revision: 1.15 $"""

from UserDict import UserDict
from string import lower

class cidict(UserDict):
  """
  Case-insensitive but case-respecting dictionary.
  """

  def __init__(self,default=None):
    self._keys = {}
    UserDict.__init__(self,{})
    self.update(default or {})

  def __getitem__(self,key):
    return self.data[lower(key)]

  def __setitem__(self,key,value):
    lower_key = lower(key)
    self._keys[lower_key] = key
    self.data[lower_key] = value

  def __delitem__(self,key):
    lower_key = lower(key)
    del self._keys[lower_key]
    del self.data[lower_key]

  def update(self,dict):
    for key in dict.keys():
      self[key] = dict[key]

  def has_key(self,key):
    return UserDict.has_key(self,lower(key))

  def __contains__(self,key):
    return self.has_key(key)

  def get(self,key,failobj=None):
    try:
      return self[key]
    except KeyError:
      return failobj

  def keys(self):
    return self._keys.values()

  def items(self):
    result = []
    for k in self._keys.values():
      result.append((k,self[k]))
    return result


def strlist_minus(a,b):
  """
  Return list of all items in a which are not in b (a - b).
  a,b are supposed to be lists of case-insensitive strings.
  """
  temp = cidict()
  for elt in b:
    temp[elt] = elt
  result = [
    elt
    for elt in a
    if not temp.has_key(elt)
  ]
  return result


def strlist_intersection(a,b):
  """
  Return intersection of two lists of case-insensitive strings a,b.
  """
  temp = cidict()
  for elt in a:
    temp[elt] = elt
  result = [
    temp[elt]
    for elt in b
    if temp.has_key(elt)
  ]
  return result


def strlist_union(a,b):
  """
  Return union of two lists of case-insensitive strings a,b.
  """
  temp = cidict()
  for elt in a:
    temp[elt] = elt
  for elt in b:
    temp[elt] = elt
  return temp.values()
