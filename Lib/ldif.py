"""
ldif - generate and parse LDIF data (see RFC 2849)

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

import re
from base64 import b64encode, b64decode
from io import StringIO
import warnings

from urllib.parse import urlparse
from urllib.request import urlopen

from typing import TYPE_CHECKING, BinaryIO, Dict, List, TextIO, Tuple, Sequence, cast
if TYPE_CHECKING:
  from typing_extensions import TypeAlias

__version__ = '3.4.3'

__all__ = [
  # constants
  'ldif_pattern',
  # functions
  'CreateLDIF',
  'ParseLDIF',
  # classes
  'LDIFWriter',
  'LDIFParser',
  'LDIFRecordList',
  'LDIFCopy',
]

LDAPModListAddition: TypeAlias = "Tuple[str, List[bytes]]"
"""The type of an addition entry in a modlist."""

LDAPModListModify: TypeAlias = "Tuple[int, str, List[bytes] | None]"
"""The type of a modification entry in a modlist."""

LDAPModListEntry: TypeAlias = "LDAPModListAddition | LDAPModListModify"
"""The type of a single entry in a modlist."""

LDAPModList: TypeAlias = "Sequence[LDAPModListEntry]"
"""The type of a modlist."""

LDAPEntryDict: TypeAlias = "Dict[str, List[bytes]]"
"""The type used to store attribute-value mappings for a given LDAP entry (attribute name, list of binary values)."""

LDAPControl: TypeAlias = "Tuple[str, str, str | None]"
"""The type used to store controls (type, criticality, value)."""

LDAPControls: TypeAlias = "List[LDAPControl]"
"""The type used to store control lists."""

attrtype_pattern = r'[\w;.-]+(;[\w_-]+)*'
attrvalue_pattern = r'(([^,]|\\,)+|".*?")'
attrtypeandvalue_pattern = attrtype_pattern + r'[ ]*=[ ]*' + attrvalue_pattern
rdn_pattern   = attrtypeandvalue_pattern + r'([ ]*\+[ ]*' + attrtypeandvalue_pattern + r')*[ ]*'
dn_pattern   = rdn_pattern + r'([ ]*,[ ]*' + rdn_pattern + r')*[ ]*'
dn_regex   = re.compile('^%s$' % dn_pattern)

ldif_pattern = '^((dn(:|::) %(dn_pattern)s)|(%(attrtype_pattern)s(:|::) .*)$)+' % vars()

MOD_OP_INTEGER = {
  'add':0, # ldap.MOD_ADD
  'delete':1, # ldap.MOD_DELETE
  'replace':2, # ldap.MOD_REPLACE
  'increment':3, # ldap.MOD_INCREMENT
}

MOD_OP_STR = {
  0:'add',1:'delete',2:'replace',3:'increment'
}

CHANGE_TYPES = ['add','delete','modify','modrdn']
valid_changetype_set = set(CHANGE_TYPES)


def is_dn(s: str) -> int:
  """
  returns 1 if s is a LDAP DN
  """
  if s=='':
    return 1
  rm = dn_regex.match(s)
  if rm is None:
    return 0
  elif rm.group(0)!=s:
    return 0
  else:
    return 1


SAFE_STRING_PATTERN = b'(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)'
safe_string_re = re.compile(SAFE_STRING_PATTERN)

def list_dict(l: List[str]) -> Dict[str, None]:
  """
  return a dictionary with all items of l being the keys of the dictionary
  """
  return {i: None for i in l}


class LDIFWriter:
  """
  Write LDIF entry or change records to file object
  Copy LDIF input to a file output object containing all data retrieved
  via URLs
  """

  def __init__(
    self,
    output_file: TextIO,
    base64_attrs: List[str] | None = [],
    cols: int = 76,
    line_sep: str = '\n'
  ) -> None:
    """
    output_file
        file object for output; should be opened in *text* mode
    base64_attrs
        list of attribute types to be base64-encoded in any case
    cols
        Specifies how many columns a line may have before it's
        folded into many lines.
    line_sep
        String used as line separator
    """
    self._output_file = output_file
    self._base64_attrs = list_dict([a.lower() for a in (base64_attrs or [])])
    self._cols = cols
    self._last_line_sep = line_sep
    self.records_written = 0

  def _unfold_lines(self, line: str) -> None:
    """
    Write string line as one or more folded lines
    """
    # Check maximum line length
    line_len = len(line)
    if line_len<=self._cols:
      self._output_file.write(line)
      self._output_file.write(self._last_line_sep)
    else:
      # Fold line
      pos = self._cols
      self._output_file.write(line[0:min(line_len,self._cols)])
      self._output_file.write(self._last_line_sep)
      while pos<line_len:
        self._output_file.write(' ')
        self._output_file.write(line[pos:min(line_len,pos+self._cols-1)])
        self._output_file.write(self._last_line_sep)
        pos = pos+self._cols-1

  def _needs_base64_encoding(self, attr_type: str, attr_value: bytes) -> int:
    """
    returns 1 if attr_value has to be base-64 encoded because
    of special chars or because attr_type is in self._base64_attrs
    """
    return attr_type.lower() in self._base64_attrs or \
           not safe_string_re.search(attr_value) is None

  def _unparseAttrTypeandValue(self, attr_type: str, attr_value: bytes) -> None:
    """
    Write a single attribute type/value pair

    attr_type
          attribute type (text)
    attr_value
          attribute value (bytes)
    """
    if self._needs_base64_encoding(attr_type,attr_value):
      # Encode with base64
      encoded = b64encode(attr_value).decode('ascii')
      encoded = encoded.replace('\n','')
      self._unfold_lines(':: '.join([attr_type, encoded]))
    else:
      self._unfold_lines(': '.join([attr_type, attr_value.decode('ascii')]))

  def _unparseEntryRecord(self, entry: LDAPEntryDict) -> None:
    """
    entry
        dictionary holding an entry
    """
    for attr_type, values in sorted(entry.items()):
      for attr_value in values:
        self._unparseAttrTypeandValue(attr_type,attr_value)

  def _unparseChangeRecord(self, modlist: LDAPModList) -> None:
    """
    modlist
        list of additions (2-tuple) or modifications (3-tuple)
    """
    mod_len = len(modlist[0])
    if mod_len==2:
      changetype = 'add'
    elif mod_len==3:
      changetype = 'modify'
    else:
      raise ValueError("modlist item of wrong length: %d" % (mod_len))
    self._unparseAttrTypeandValue('changetype',changetype.encode('ascii'))
    for mod in modlist:
      # Note: the following order will give mod_vals the right type
      if mod_len==3:
        mod = cast(LDAPModListModify, mod)
        mod_op,mod_type,mod_vals = mod
        self._unparseAttrTypeandValue(MOD_OP_STR[mod_op],
                                      mod_type.encode('ascii'))
      elif mod_len==2:
        mod = cast(LDAPModListAddition, mod)
        mod_type,mod_vals = mod
      else:
        raise ValueError("Subsequent modlist item of wrong length")
      if mod_vals:
        for mod_val in mod_vals:
          self._unparseAttrTypeandValue(mod_type,mod_val)
      if mod_len==3:
        self._output_file.write('-'+self._last_line_sep)

  def unparse(self, dn: str, record: LDAPEntryDict | LDAPModList) -> None:
    """
    dn
          string-representation of distinguished name
    record
          Either a dictionary holding the LDAP entry {attrtype:record}
          or a list with a modify list like for LDAPObject.modify().
    """
    # Start with line containing the distinguished name
    self._unparseAttrTypeandValue('dn', dn.encode('utf-8'))
    # Dispatch to record type specific writers
    if isinstance(record,dict):
      self._unparseEntryRecord(record)
    elif isinstance(record,list):
      self._unparseChangeRecord(record)
    else:
      raise ValueError('Argument record must be dictionary or list instead of %s' % (repr(record)))
    # Write empty line separating the records
    self._output_file.write(self._last_line_sep)
    # Count records written
    self.records_written = self.records_written+1


def CreateLDIF(
    dn: str,
    record: LDAPEntryDict | LDAPModList,
    base64_attrs: List[str],
    cols: int = 76,
  ) -> str:
  """
  Create LDIF single formatted record including trailing empty line.
  This is a compatibility function.

  dn
        string-representation of distinguished name
  record
        Either a dictionary holding the LDAP entry {attrtype:record}
        or a list with a modify list like for LDAPObject.modify().
  base64_attrs
        list of attribute types to be base64-encoded in any case
  cols
        Specifies how many columns a line may have before it's
        folded into many lines.
  """
  warnings.warn(
    'ldif.CreateLDIF() is deprecated. Use LDIFWriter.unparse() instead. It '
    'will be removed in python-ldap 3.1',
    category=DeprecationWarning,
    stacklevel=2,
  )
  f = StringIO()
  ldif_writer = LDIFWriter(f,base64_attrs,cols,'\n')
  ldif_writer.unparse(dn,record)
  s = f.getvalue()
  f.close()
  return s


class LDIFParser:
  """
  Base class for a LDIF parser. Applications should sub-class this
  class and override method handle() to implement something meaningful.

  Public class attributes:

  records_read
        Counter for records processed so far
  """

  def __init__(
    self,
    input_file: TextIO | BinaryIO,
    ignored_attr_types: List[str] | None = [],
    max_entries: int = 0,
    process_url_schemes: List[str] | None = [],
    line_sep: str = '\n',
  ) -> None:
    """
    Parameters:
    input_file
        File-object to read the LDIF input from
    ignored_attr_types
        Attributes with these attribute type names will be ignored.
    max_entries
        If non-zero specifies the maximum number of entries to be
        read from f.
    process_url_schemes
        List containing strings with URLs schemes to process with urllib.
        An empty list turns off all URL processing and the attribute
        is ignored completely.
    line_sep
        String used as line separator
    """
    # Detect whether the file is open in text or bytes mode.
    if isinstance(input_file.read(0), bytes):
      self._binary_input_file: BinaryIO | None = cast(BinaryIO, input_file)
      self._text_input_file: TextIO | None = None
    else:
      self._binary_input_file = None
      self._text_input_file = cast(TextIO, input_file)

    self._max_entries = max_entries
    self._process_url_schemes = list_dict([s.lower() for s in (process_url_schemes or [])])
    self._ignored_attr_types = list_dict([a.lower() for a in (ignored_attr_types or [])])
    self._last_line_sep = line_sep
    self.version: int | None = None
    # Initialize counters
    self.line_counter = 0
    self.byte_counter = 0
    self.records_read = 0
    self.changetype_counter = {}.fromkeys(CHANGE_TYPES,0)
    # Store some symbols for better performance
    self._b64decode = b64decode
    # Read very first line
    try:
      self._last_line = self._readline()
    except EOFError:
      self._last_line = ''

  def handle(self, dn: str, entry: LDAPEntryDict) -> str | None:
    """
    Process a single content LDIF record. This method should be
    implemented by applications using LDIFParser.
    """
    pass

  def _readline(self) -> str | None:
    if self._text_input_file is not None:
      s = self._text_input_file.readline()
    elif self._binary_input_file is not None:
      # The RFC does not allow UTF-8 values; we support it as a
      # non-official, backwards compatibility layer
      s = self._binary_input_file.readline().decode('utf-8')
    else:
      return None

    self.line_counter = self.line_counter + 1
    self.byte_counter = self.byte_counter + len(s)
    if not s:
      return None
    elif s[-2:]=='\r\n':
      return s[:-2]
    elif s[-1:]=='\n':
      return s[:-1]
    else:
      return s

  def _unfold_lines(self) -> str:
    """
    Unfold several folded lines with trailing space into one line
    """
    if self._last_line is None:
      raise EOFError('EOF reached after %d lines (%d bytes)' % (
        self.line_counter,
        self.byte_counter,
      ))
    unfolded_lines = [ self._last_line ]
    next_line = self._readline()
    while next_line and next_line[0]==' ':
      unfolded_lines.append(next_line[1:])
      next_line = self._readline()
    self._last_line = next_line
    return ''.join(unfolded_lines)

  def _next_key_and_value(self) -> Tuple[str | None, bytes | None]:
    """
    Parse a single attribute type and value pair from one or
    more lines of LDIF data

    Returns attr_type (text) and attr_value (bytes)
    """
    # Reading new attribute line
    unfolded_line = self._unfold_lines()
    # Ignore comments which can also be folded
    while unfolded_line and unfolded_line[0]=='#':
      unfolded_line = self._unfold_lines()
    if not unfolded_line:
      return None,None
    if unfolded_line=='-':
      return '-',None
    try:
      colon_pos = unfolded_line.index(':')
    except ValueError as e:
      raise ValueError('no value-spec in %s' % (repr(unfolded_line)))
    attr_type = unfolded_line[0:colon_pos]
    # if needed attribute value is BASE64 decoded
    value_spec = unfolded_line[colon_pos:colon_pos+2]
    if value_spec==': ':
      # All values should be valid ascii; we support UTF-8 as a
      # non-official, backwards compatibility layer.
      attr_value_str = unfolded_line[colon_pos+2:].lstrip()
      attr_value = attr_value_str.encode('utf-8')
    elif value_spec=='::':
      # attribute value needs base64-decoding
      # base64 makes sense only for ascii
      attr_value_str = unfolded_line[colon_pos+2:]
      attr_value = self._b64decode(attr_value_str.encode('ascii'))
    elif value_spec==':<':
      # fetch attribute value from URL
      url = unfolded_line[colon_pos+2:].strip()
      attr_value = None
      if self._process_url_schemes:
        u = urlparse(url)
        if u[0] in self._process_url_schemes:
          attr_value = urlopen(url).read()
    else:
      # All values should be valid ascii; we support UTF-8 as a
      # non-official, backwards compatibility layer.
      attr_value = unfolded_line[colon_pos+1:].encode('utf-8')
    return attr_type,attr_value

  def _consume_empty_lines(self) -> Tuple[str | None, bytes | None]:
    """
    Consume empty lines until first non-empty line.
    Must only be used between full records!

    Returns non-empty key-value-tuple.
    """
    # Local symbol for better performance
    next_key_and_value = self._next_key_and_value
    # Consume empty lines
    try:
      k,v = next_key_and_value()
      while k is None and v is None:
        k,v = next_key_and_value()
    except EOFError:
      k,v = None,None
    return k,v

  def parse_entry_records(self) -> None:
    """
    Continuously read and parse LDIF entry records
    """
    # Local symbol for better performance
    next_key_and_value = self._next_key_and_value

    try:
      # Consume empty lines
      k,v = self._consume_empty_lines()
      # Consume 'version' line
      if k=='version':
        if v is not None:
          self.version = int(v.decode('ascii'))
        k,v = self._consume_empty_lines()
    except EOFError:
      return

    # Loop for processing whole records
    while k!=None and \
          (not self._max_entries or self.records_read<self._max_entries):
      # Consume first line which must start with "dn: "
      if k!='dn':
        raise ValueError('Line %d: First line of record does not start with "dn:": %s' % (self.line_counter,repr(k)))
      # Value of a 'dn' field *has* to be valid UTF-8
      # k is text, v is bytes.
      if v is None:
        raise ValueError('Line %d: DN has None value.' % (self.line_counter))
      dn = v.decode('utf-8')
      if not is_dn(dn):
        raise ValueError('Line %d: Not a valid string-representation for dn: %s.' % (self.line_counter,repr(v)))

      entry: LDAPEntryDict = {}

      # Loop for reading the attributes
      while True:
        try:
          k,v = next_key_and_value()
        except EOFError:
          break

        if k is None:
          break
        elif v is None:
          continue

        # Add the attribute to the entry if not ignored attribute
        if not k.lower() in self._ignored_attr_types:
          try:
            entry[k].append(v)
          except KeyError:
            entry[k]=[v]

      # handle record
      self.handle(dn,entry)
      self.records_read = self.records_read + 1
      # Consume empty separator line(s)
      k,v = self._consume_empty_lines()

  def parse(self) -> None:
    """
    Invokes LDIFParser.parse_entry_records() for backward compatibility
    """
    self.parse_entry_records()

  def handle_modify(
    self,
    dn: str,
    modops: LDAPModList,
    controls: LDAPControls | None = None,
  ) -> None:
    """
    Process a single LDIF record representing a single modify operation.
    This method should be implemented by applications using LDIFParser.
    """
    controls = [] or None
    pass

  def parse_change_records(self) -> None:
    # Local symbol for better performance
    next_key_and_value = self._next_key_and_value
    # Consume empty lines
    k,v = self._consume_empty_lines()
    # Consume 'version' line
    if k=='version':
      if v is not None:
        self.version = int(v.decode('ascii'))
      k,v = self._consume_empty_lines()

    # Loop for processing whole records
    while k!=None and \
          (not self._max_entries or self.records_read<self._max_entries):
      # Consume first line which must start with "dn: "
      if k!='dn':
        raise ValueError('Line %d: First line of record does not start with "dn:": %s' % (self.line_counter,repr(k)))
      # Value of a 'dn' field *has* to be valid UTF-8
      # k is text, v is bytes.
      if v is None:
        raise ValueError('Line %d: DN has None value.' % (self.line_counter))
      dn = v.decode('utf-8')
      if not is_dn(dn):
        raise ValueError('Line %d: Not a valid string-representation for dn: %s.' % (self.line_counter,repr(v)))

      # Consume second line of record
      k,v = next_key_and_value()
      # Read "control:" lines
      controls = []
      while k!=None and k=='control':
        if v is None:
          raise ValueError('Line %d: control has None value.' % (self.line_counter))
        # v is still bytes, spec says it should be valid utf-8; decode it.
        control = v.decode('utf-8')
        try:
          control_type,criticality,control_value = control.split(' ',2)
        except ValueError:
          control_value = None
          control_type,criticality = control.split(' ',1)
        controls.append((control_type,criticality,control_value))
        k,v = next_key_and_value()

      # Determine changetype first
      changetype = ''
      # Consume changetype line of record
      if k=='changetype':
        if v is None:
          raise ValueError('Line %d: changetype has None value.' % (self.line_counter))
        # v is still bytes, spec says it should be valid utf-8; decode it.
        changetype = v.decode('utf-8')
        if not changetype in valid_changetype_set:
          raise ValueError('Invalid changetype: %s' % repr(v))
        k,v = next_key_and_value()

      if changetype=='modify':
        # From here we assume a change record is read with changetype: modify
        modops = []

        try:
          # Loop for reading the list of modifications
          while True:
            if k is None:
              break

            # Extract attribute mod-operation (add, delete, replace)
            try:
              modop = MOD_OP_INTEGER[k]
            except KeyError:
              raise ValueError('Line %d: Invalid mod-op string: %s' % (self.line_counter,repr(k)))

            if v is None:
              raise ValueError('Line %d: mod-op has None value.' % (self.line_counter))

            # we now have the attribute name to be modified
            # v is still bytes, spec says it should be valid utf-8; decode it.
            modattr = v.decode('utf-8')
            modvalues = []
            try:
              k,v = next_key_and_value()
            except EOFError:
              k,v = None,None
            while k==modattr:
              if v is not None:
                modvalues.append(v)
              try:
                k,v = next_key_and_value()
              except EOFError:
                k,v = None,None
            modops.append((modop,modattr,modvalues or None))
            k,v = next_key_and_value()
            if k=='-':
              # Consume next line
              k,v = next_key_and_value()
        except EOFError:
          k,v = None,None

        if modops:
          # append entry to result list
          self.handle_modify(dn,modops,controls)

      else:

        # Consume the unhandled change record
        while k!=None:
          k,v = next_key_and_value()

      # Consume empty separator line(s)
      k,v = self._consume_empty_lines()

      # Increment record counters
      try:
        self.changetype_counter[changetype] = self.changetype_counter[changetype] + 1
      except KeyError:
        self.changetype_counter[changetype] = 1
      self.records_read = self.records_read + 1


class LDIFRecordList(LDIFParser):
  """
  Collect all records of a LDIF file. It can be a memory hog!

  Records are stored in :attr:`.all_records` as a single list
  of 2-tuples (dn, entry), after calling :meth:`.parse`.
  """

  def __init__(
    self,
    input_file: TextIO | BinaryIO,
    ignored_attr_types: List[str] | None = [],
    max_entries: int = 0,
    process_url_schemes: List[str] | None = [],
  ) -> None:
    LDIFParser.__init__(self,input_file,ignored_attr_types,max_entries,process_url_schemes)

    #: List storing parsed records.
    self.all_records: List[Tuple[str, LDAPEntryDict]] = []
    self.all_modify_changes: List[Tuple[str, LDAPModList, LDAPControls | None]] = []

  def handle(self, dn: str, entry: LDAPEntryDict) -> None:
    """
    Append a single record to the list of all records (:attr:`.all_records`).
    """
    self.all_records.append((dn,entry))

  def handle_modify(
    self,
    dn: str,
    modops: LDAPModList,
    controls: LDAPControls | None = None,
  ) -> None:
    """
    Process a single LDIF record representing a single modify operation.
    This method should be implemented by applications using LDIFParser.
    """
    controls = [] or None
    self.all_modify_changes.append((dn,modops,controls))


class LDIFCopy(LDIFParser):
  """
  Copy LDIF input to LDIF output containing all data retrieved
  via URLs
  """

  def __init__(
    self,
    input_file: TextIO | BinaryIO,
    output_file: TextIO,
    ignored_attr_types: List[str] | None = [],
    max_entries: int = 0,
    process_url_schemes: List[str] | None = [],
    base64_attrs: List[str] = [],
    cols: int = 76,
    line_sep: str = '\n'
  ) -> None:
    """
    See LDIFParser.__init__() and LDIFWriter.__init__()
    """
    LDIFParser.__init__(self,input_file,ignored_attr_types,max_entries,process_url_schemes)
    self._output_ldif = LDIFWriter(output_file,base64_attrs,cols,line_sep)

  def handle(self, dn: str, entry: LDAPEntryDict) -> None:
    """
    Write single LDIF record to output file.
    """
    self._output_ldif.unparse(dn,entry)


def ParseLDIF(
    f: TextIO | BinaryIO,
    ignore_attrs: List[str] | None = [],
    maxentries: int = 0
  ) -> List[Tuple[str, LDAPEntryDict]]:
  """
  Parse LDIF records read from file.
  This is a compatibility function.
  """
  warnings.warn(
    'ldif.ParseLDIF() is deprecated. Use LDIFRecordList.parse() instead. It '
    'will be removed in python-ldap 3.1',
    category=DeprecationWarning,
    stacklevel=2,
  )
  ldif_parser = LDIFRecordList(
    f,ignored_attr_types=ignore_attrs,max_entries=maxentries
  )
  ldif_parser.parse()
  return ldif_parser.all_records
