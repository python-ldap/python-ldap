"""
ldapurl - handling of LDAP URLs as described in RFC 4516

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

from collections.abc import MutableMapping
from urllib.parse import quote, unquote

from typing import Dict, Iterator, List, TYPE_CHECKING
if TYPE_CHECKING:
  from typing_extensions import Self

__version__ = '3.4.3'

__all__ = [
  # constants
  'SEARCH_SCOPE','SEARCH_SCOPE_STR',
  'LDAP_SCOPE_BASE','LDAP_SCOPE_ONELEVEL','LDAP_SCOPE_SUBTREE',
  # functions
  'isLDAPUrl',
  # classes
  'LDAPUrlExtension','LDAPUrlExtensions','LDAPUrl'
]

LDAP_SCOPE_BASE = 0
LDAP_SCOPE_ONELEVEL = 1
LDAP_SCOPE_SUBTREE = 2
LDAP_SCOPE_SUBORDINATES = 3

SEARCH_SCOPE_STR = {
  None:'',
  LDAP_SCOPE_BASE:'base',
  LDAP_SCOPE_ONELEVEL:'one',
  LDAP_SCOPE_SUBTREE:'sub',
  LDAP_SCOPE_SUBORDINATES:'subordinates',
}

SEARCH_SCOPE = {
  '':None,
  # the search scope strings defined in RFC 4516
  'base':LDAP_SCOPE_BASE,
  'one':LDAP_SCOPE_ONELEVEL,
  'sub':LDAP_SCOPE_SUBTREE,
  # from draft-sermersheim-ldap-subordinate-scope
  'subordinates':LDAP_SCOPE_SUBORDINATES,
}


def isLDAPUrl(s: str) -> bool:
  """Returns True if s is a LDAP URL, else False
  """
  return s.lower().startswith(('ldap://', 'ldaps://', 'ldapi://'))


def ldapUrlEscape(s: str) -> str:
  """Returns URL encoding of string s"""
  return quote(s).replace(',','%2C').replace('/','%2F')


class LDAPUrlExtension:
  """
  Class for parsing and unparsing LDAP URL extensions
  as described in RFC 4516.

  Usable class attributes:
    critical
          Boolean integer marking the extension as critical
    extype
          Type of extension
    exvalue
          Value of extension
  """

  def __init__(
    self,
    extensionStr: str | None = None,
    critical: int = 0,
    extype: str | None = None,
    exvalue: str | None = None
  ) -> None:
    self.critical = critical
    self.extype = extype
    self.exvalue = exvalue
    if extensionStr:
      self._parse(extensionStr)

  def _parse(self, extension: str) -> None:
    extension = extension.strip()
    if not extension:
      # Don't parse empty strings
      self.extype,self.exvalue = None,None
      return
    self.critical = extension[0]=='!'
    if extension[0]=='!':
      extension = extension[1:].strip()
    try:
      self.extype,self.exvalue = extension.split('=',1)
    except ValueError:
      # No value, just the extype
      self.extype,self.exvalue = extension,None
    else:
      self.exvalue = unquote(self.exvalue.strip())
    self.extype = self.extype.strip()

  def unparse(self) -> str:
    if self.exvalue is None:
      return '{}{}'.format('!'*(self.critical>0),self.extype)
    else:
      return '{}{}={}'.format(
        '!'*(self.critical>0),
        self.extype,quote(self.exvalue or '')
      )

  def __str__(self) -> str:
    return self.unparse()

  def __repr__(self) -> str:
    return '<{}.{} instance at {}: {}>'.format(
      self.__class__.__module__,
      self.__class__.__name__,
      hex(id(self)),
      self.__dict__
    )

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, LDAPUrlExtension):
      return False
    elif self.critical != other.critical:
      return False
    elif self.extype != other.extype:
      return False
    elif self.exvalue != other.exvalue:
      return False
    else:
      return True

  def __ne__(self, other: object) -> bool:
    return not self.__eq__(other)


class LDAPUrlExtensions(MutableMapping[str, LDAPUrlExtension]):
    """
    Models a collection of LDAP URL extensions as
    a mapping type
    """
    __slots__ = ('_data', )

    def __init__(self, default: Dict[str, LDAPUrlExtension] | None = None) -> None:
        self._data: Dict[str, LDAPUrlExtension] = {}
        if default is not None:
            self.update(default)

    def __setitem__(self, name: str, value: LDAPUrlExtension) -> None:
        """Store an extension

        name
            string
        value
            LDAPUrlExtension instance, whose extype nust match `name`
        """
        if not isinstance(value, LDAPUrlExtension):
            raise TypeError("value must be LDAPUrlExtension, not "
                            + type(value).__name__)
        if name != value.extype:
            raise ValueError(
                "key {!r} does not match extension type {!r}".format(
                    name, value.extype))
        self._data[name] = value

    def __getitem__(self, name: str) -> LDAPUrlExtension:
        return self._data[name]

    def __delitem__(self, name: str) -> None:
        del self._data[name]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __str__(self) -> str:
        return ','.join(str(v) for v in self.values())

    def __repr__(self) -> str:
        return '<{}.{} instance at {}: {}>'.format(
            self.__class__.__module__,
            self.__class__.__name__,
            hex(id(self)),
            self._data
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self._data == other._data

    def parse(self, extListStr: str) -> None:
        for extension_str in extListStr.strip().split(','):
            if extension_str:
                e = LDAPUrlExtension(extension_str)
                if e.extype is not None:
                  self[e.extype] = e

    def unparse(self) -> str:
        return ','.join(v.unparse() for v in self.values())


class LDAPUrl:
  """
  Class for parsing and unparsing LDAP URLs
  as described in RFC 4516.

  Usable class attributes:
    urlscheme
        URL scheme (either ldap, ldaps or ldapi)
    hostport
        LDAP host (default '')
    dn
        String holding distinguished name (default '')
    attrs
        list of attribute types (default None)
    scope
        integer search scope for ldap-module
    filterstr
        String representation of LDAP Search Filters
        (see RFC 4515)
    extensions
        Dictionary used as extensions store
    who
        Maps automagically to bindname LDAP URL extension
    cred
        Maps automagically to X-BINDPW LDAP URL extension
  """

  attr2extype = {'who':'bindname','cred':'X-BINDPW'}

  def __init__(
    self,
    ldapUrl: str | None = None,
    urlscheme: str = 'ldap',
    hostport: str = '',
    dn: str = '',
    attrs: List[str] | None = None,
    scope: int | None = None,
    filterstr: str | None = None,
    extensions: LDAPUrlExtensions = LDAPUrlExtensions(),
    who: str | None = None,
    cred: str | None = None
  ) -> None:
    self.urlscheme=urlscheme.lower()
    self.hostport=hostport
    self.dn=dn
    self.attrs=attrs
    self.scope=scope
    self.filterstr=filterstr
    self.extensions=extensions

    if ldapUrl is not None:
      self._parse(ldapUrl)
    if who!=None:
      self.who = who
    if cred!=None:
      self.cred = cred

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, LDAPUrl):
      return False
    elif self.urlscheme != other.urlscheme:
      return False
    elif self.urlscheme != other.urlscheme:
      return False
    elif self.hostport != other.hostport:
      return False
    elif self.dn != other.dn:
      return False
    elif self.attrs != other.attrs:
      return False
    elif self.scope != other.scope:
      return False
    elif self.filterstr != other.filterstr:
      return False
    elif self.extensions != other.extensions:
      return False
    else:
      return True

  def __ne__(self, other: object) -> bool:
    return not self.__eq__(other)

  def _parse(self, ldap_url: str) -> None:
    """
    parse a LDAP URL and set the class attributes
    urlscheme,host,dn,attrs,scope,filterstr,extensions
    """
    if not isLDAPUrl(ldap_url):
      raise ValueError('Value %s for ldap_url does not seem to be a LDAP URL.' % (repr(ldap_url)))
    scheme,rest = ldap_url.split('://',1)
    self.urlscheme = scheme.lower()
    slash_pos = rest.find('/')
    qemark_pos = rest.find('?')
    if (slash_pos==-1) and (qemark_pos==-1):
      # No / and ? found at all
      self.hostport = unquote(rest)
      self.dn = ''
      return
    else:
      if slash_pos!=-1 and (qemark_pos==-1 or (slash_pos<qemark_pos)):
        # Slash separates DN from hostport
        self.hostport = unquote(rest[:slash_pos])
        # Eat the slash from rest
        rest = rest[slash_pos+1:]
      elif qemark_pos!=1 and (slash_pos==-1 or (slash_pos>qemark_pos)):
        # Question mark separates hostport from rest, DN is assumed to be empty
        self.hostport = unquote(rest[:qemark_pos])
        # Do not eat question mark
        rest = rest[qemark_pos:]
      else:
        raise ValueError('Something completely weird happened!')
    paramlist=rest.split('?',4)
    paramlist_len = len(paramlist)
    if paramlist_len>=1:
      self.dn = unquote(paramlist[0]).strip()
    if (paramlist_len>=2) and (paramlist[1]):
      self.attrs = unquote(paramlist[1].strip()).split(',')
    if paramlist_len>=3:
      scope = paramlist[2].strip()
      try:
        self.scope = SEARCH_SCOPE[scope]
      except KeyError:
        raise ValueError('Invalid search scope %s' % (repr(scope)))
    if paramlist_len>=4:
      filterstr = paramlist[3].strip()
      if not filterstr:
        self.filterstr = None
      else:
        self.filterstr = unquote(filterstr)
    if paramlist_len>=5:
      self.extensions = LDAPUrlExtensions()
      if paramlist[4]:
        self.extensions.parse(paramlist[4])
    return

  def applyDefaults(self, defaults: Dict[str, str]) -> None:
    """
    Apply defaults to all class attributes which are None.

    defaults
        Dictionary containing a mapping from class attributes
        to default values
    """
    for k, value in defaults.items():
      if getattr(self,k) is None:
        setattr(self, k, value)

  def initializeUrl(self) -> str:
    """
    Returns LDAP URL suitable to be passed to ldap.initialize()
    """
    if self.urlscheme=='ldapi':
      # hostport part might contain slashes when ldapi:// is used
      hostport = ldapUrlEscape(self.hostport)
    else:
      hostport = self.hostport
    return f'{self.urlscheme}://{hostport}'

  def unparse(self) -> str:
    """
    Returns LDAP URL depending on class attributes set.
    """
    if self.attrs is None:
      attrs_str = ''
    else:
      attrs_str = ','.join(self.attrs)
    scope_str = SEARCH_SCOPE_STR[self.scope]
    if self.filterstr is None:
      filterstr = ''
    else:
      filterstr = ldapUrlEscape(self.filterstr)
    dn = ldapUrlEscape(self.dn)
    if self.urlscheme=='ldapi':
      # hostport part might contain slashes when ldapi:// is used
      hostport = ldapUrlEscape(self.hostport)
    else:
      hostport = self.hostport
    ldap_url = '{}://{}/{}?{}?{}?{}'.format(
      self.urlscheme,
      hostport,dn,attrs_str,scope_str,filterstr
    )
    ldap_url = ldap_url+'?'+self.extensions.unparse()
    return ldap_url

  def htmlHREF(
    self,
    urlPrefix: str = '',
    hrefText: str | None = None,
    hrefTarget: str | None = None
  ) -> str:
    """
    Returns a string with HTML link for this LDAP URL.

    urlPrefix
        Prefix before LDAP URL (e.g. for addressing another web-based client)
    hrefText
        link text/description
    hrefTarget
        string added as link target attribute
    """
    if not isinstance(urlPrefix, str):
        raise TypeError("urlPrefix must be str, not "
                        + type(urlPrefix).__name__)
    if hrefText is None:
        hrefText = self.unparse()
    if not isinstance(hrefText, str):
        raise TypeError("hrefText must be str, not "
                        + type(hrefText).__name__)
    if hrefTarget is None:
        target = ''
    else:
        if not isinstance(hrefTarget, str):
            raise TypeError("hrefTarget must be str, not "
                            + type(hrefTarget).__name__)
        target = ' target="%s"' % hrefTarget
    return '<a{} href="{}{}">{}</a>'.format(
        target, urlPrefix, self.unparse(), hrefText
    )

  def __str__(self) -> str:
    return self.unparse()

  def __repr__(self) -> str:
    return '<{}.{} instance at {}: {}>'.format(
      self.__class__.__module__,
      self.__class__.__name__,
      hex(id(self)),
      self.__dict__
    )

  def __getattr__(self, name: str) -> str | None:
    if name in self.attr2extype:
      extype = self.attr2extype[name]
      if extype not in self.extensions:
        return None
      elif self.extensions[extype].exvalue is None:
        return None
      else:
        value = self.extensions[extype].exvalue
        if value is None:
            return None
        else:
            return unquote(value)
    else:
      raise AttributeError('{} has no attribute {}'.format(
        self.__class__.__name__,name
      ))

  def __setattr__(self, name: str, value: str) -> None:
    if name in self.attr2extype:
      extype = self.attr2extype[name]
      if value is None:
        # A value of None means that extension is deleted
        delattr(self,name)
      else:
        # Add appropriate extension
        self.extensions[extype] = LDAPUrlExtension(
          extype=extype,exvalue=unquote(value)
        )
    else:
      self.__dict__[name] = value

  def __delattr__(self, name: str) -> None:
    if name in self.attr2extype:
      extype = self.attr2extype[name]
      if self.extensions:
        try:
          del self.extensions[extype]
        except KeyError:
          pass
    else:
      del self.__dict__[name]
