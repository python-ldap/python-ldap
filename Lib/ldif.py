"""
ldif - generate and parse LDIF data (see RFC 2849)

See https://www.python-ldap.org/ for details.
"""

import urlparse
import urllib
import re
from base64 import b64encode, b64decode

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

__version__ = '2.5.3'

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

attrtype_pattern = r'[\w;.-]+(;[\w_-]+)*'
attrvalue_pattern = r'(([^,]|\\,)+|".*?")'
attrtypeandvalue_pattern = attrtype_pattern + r'[ ]*=[ ]*' + attrvalue_pattern
rdn_pattern = attrtypeandvalue_pattern + r'([ ]*\+[ ]*' + attrtypeandvalue_pattern + r')*[ ]*'
dn_pattern = rdn_pattern + r'([ ]*,[ ]*' + rdn_pattern + r')*[ ]*'
dn_regex = re.compile('^%s$' % dn_pattern)

ldif_pattern = '^((dn(:|::) %(dn_pattern)s)|(%(attrtype_pattern)s(:|::) .*)$)+' % vars()

MOD_OP_INTEGER = {
    'add': 0,       # ldap.MOD_ADD
    'delete': 1,    # ldap.MOD_DELETE
    'replace': 2,   # ldap.MOD_REPLACE
    'increment': 3, # ldap.MOD_INCREMENT
}

MOD_OP_STR = {
    0: 'add',
    1: 'delete',
    2: 'replace',
    3: 'increment',
}

CHANGE_TYPES = ['add', 'delete', 'modify', 'modrdn']
VALID_CHANGETYPES = set(CHANGE_TYPES)


def is_dn(name):
    """
    returns True if s is a LDAP DN
    """
    if name == '':
        return True
    return dn_regex.match(name) != None


SAFE_STRING_PATTERN = '(^(\000|\n|\r| |:|<)|[\000\n\r\200-\377]+|[ ]+$)'
safe_string_re = re.compile(SAFE_STRING_PATTERN)


class LDIFWriter(object):
    """
    Write LDIF entry or change records to file object
    Copy LDIF input to a file output object containing all data retrieved
    via URLs
    """

    def __init__(self, output_file, base64_attrs=None, cols=76, line_sep='\n'):
        """
        output_file
            file object for output
        base64_attrs
            list of attribute types to be base64-encoded in any case
        cols
            Specifies how many columns a line may have before it's
            folded into many lines.
        line_sep
            String used as line separator
        """
        self._output_file = output_file
        base64_attrs = base64_attrs or []
        self._base64_attrs = set([a.lower() for a in base64_attrs])
        self._cols = cols
        self._last_line_sep = line_sep
        self.records_written = 0

    def _unfold_lines(self, line):
        """
        Write string line as one or more folded lines
        """
        # Check maximum line length
        line_len = len(line)
        if line_len <= self._cols:
            self._output_file.write(line)
            self._output_file.write(self._last_line_sep)
        else:
            # Fold line
            pos = self._cols
            self._output_file.write(line[0:min(line_len, self._cols)])
            self._output_file.write(self._last_line_sep)
            while pos < line_len:
                self._output_file.write(' ')
                self._output_file.write(line[pos:min(line_len, pos+self._cols-1)])
                self._output_file.write(self._last_line_sep)
                pos = pos+self._cols-1
        return # _unfold_lines()

    def _needs_base64_encoding(self, attr_type, attr_value):
        """
        returns True if attr_value has to be base-64 encoded because
        of special chars or because attr_type is in self._base64_attrs
        """
        return attr_type.lower() in self._base64_attrs or \
               safe_string_re.search(attr_value) is not None

    def _unparse_attr_type_and_value(self, attr_type, attr_value):
        """
        Write a single attribute type/value pair

        attr_type
              attribute type
        attr_value
              attribute value
        """
        if self._needs_base64_encoding(attr_type, attr_value):
            # Encode with base64
            aval = b64encode(attr_value)
            sep = ':: '
        else:
            aval = attr_value
            sep = ': '
        self._unfold_lines(sep.join((attr_type, aval)))
        return # _unparseAttrTypeandValue()

    def _unparse_entry_record(self, entry):
        """
        entry
            dictionary holding an entry
        """
        for attr_type in sorted(entry.keys()):
            for attr_value in entry[attr_type]:
                self._unparse_attr_type_and_value(attr_type, attr_value)

    def _unparse_change_record(self, modlist):
        """
        modlist
            list of additions (2-tuple) or modifications (3-tuple)
        """
        mod_len = len(modlist[0])
        if mod_len == 2:
            changetype = 'add'
        elif mod_len == 3:
            changetype = 'modify'
        else:
            raise ValueError("modlist item of wrong length: %d" % (mod_len))
        self._unparse_attr_type_and_value('changetype', changetype)
        for mod in modlist:
            if mod_len == 2:
                mod_type, mod_vals = mod
            elif mod_len == 3:
                mod_op, mod_type, mod_vals = mod
                self._unparse_attr_type_and_value(MOD_OP_STR[mod_op], mod_type)
            else:
                raise ValueError("Subsequent modlist item of wrong length")
            if mod_vals:
                for mod_val in mod_vals:
                    self._unparse_attr_type_and_value(mod_type, mod_val)
            if mod_len == 3:
                self._output_file.write('-'+self._last_line_sep)

    def unparse(self, dn, record):
        """
        dn
              string-representation of distinguished name
        record
              Either a dictionary holding the LDAP entry {attrtype:record}
              or a list with a modify list like for LDAPObject.modify().
        """
        # Start with line containing the distinguished name
        self._unparse_attr_type_and_value('dn', dn)
        # Dispatch to record type specific writers
        if isinstance(record, dict):
            self._unparse_entry_record(record)
        elif isinstance(record, list):
            self._unparse_change_record(record)
        else:
            raise ValueError('Argument record must be dictionary or list, was %r' % (record))
        # Write empty line separating the records
        self._output_file.write(self._last_line_sep)
        # Count records written
        self.records_written = self.records_written+1
        return # unparse()


def CreateLDIF(dn, record, base64_attrs=None, cols=76):
    """
    Create LDIF single formatted record including trailing empty line.
    This is a compability function. Use is deprecated!

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
    fileobj = StringIO()
    ldif_writer = LDIFWriter(fileobj, base64_attrs, cols, '\n')
    ldif_writer.unparse(dn, record)
    res = fileobj.getvalue()
    fileobj.close()
    return res


class LDIFParser(object):
    """
    Base class for a LDIF parser. Applications should sub-class this
    class and override method handle() to implement something meaningful.

    Public class attributes:

    records_read
          Counter for records processed so far
    """

    def __init__(
            self,
            input_file,
            ignored_attr_types=None,
            max_entries=0,
            process_url_schemes=None,
            line_sep='\n'
        ):
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
        self._input_file = input_file
        self._max_entries = max_entries
        self._process_url_schemes = set([s.lower() for s in (process_url_schemes or [])])
        self._ignored_attr_types = set([a.lower() for a in (ignored_attr_types or [])])
        self._last_line_sep = line_sep
        self.version = None
        # Initialize counters
        self.line_counter = 0
        self.byte_counter = 0
        self.records_read = 0
        self.changetype_counter = {}.fromkeys(CHANGE_TYPES, 0)
        # Store some symbols for better performance
        self._b64decode = b64decode
        # Read very first line
        try:
            self._last_line = self._readline()
        except EOFError:
            self._last_line = ''

    def handle(self, dn, entry):
        """
        Process a single content LDIF record. This method should be
        implemented by applications using LDIFParser.
        """
        pass

    def _readline(self):
        line = self._input_file.readline()
        self.line_counter = self.line_counter + 1
        self.byte_counter = self.byte_counter + len(line)
        if not line:
            return None
        elif line[-2:] == '\r\n':
            return line[:-2]
        elif line[-1:] == '\n':
            return line[:-1]
        return line

    def _unfold_lines(self):
        """
        Unfold several folded lines with trailing space into one line
        """
        if self._last_line is None:
            raise EOFError('EOF reached after %d lines (%d bytes)' % (
                self.line_counter,
                self.byte_counter,
            ))
        unfolded_lines = [self._last_line]
        next_line = self._readline()
        while next_line and next_line[0] == ' ':
            unfolded_lines.append(next_line[1:])
            next_line = self._readline()
        self._last_line = next_line
        return ''.join(unfolded_lines)

    def _next_key_and_value(self):
        """
        Parse a single attribute type and value pair from one or
        more lines of LDIF data
        """
        # Reading new attribute line
        unfolded_line = self._unfold_lines()
        # Ignore comments which can also be folded
        while unfolded_line and unfolded_line[0] == '#':
            unfolded_line = self._unfold_lines()
        if not unfolded_line:
            return None, None
        if unfolded_line == '-':
            return '-', None
        try:
            colon_pos = unfolded_line.index(':')
        except ValueError:
            raise ValueError('no value-spec in %r' % (unfolded_line))
        attr_type = unfolded_line[0:colon_pos]
        # if needed attribute value is BASE64 decoded
        value_spec = unfolded_line[colon_pos:colon_pos+2]
        if value_spec == ': ':
            attr_value = unfolded_line[colon_pos+2:].lstrip()
        elif value_spec == '::':
            # attribute value needs base64-decoding
            attr_value = self._b64decode(unfolded_line[colon_pos+2:])
        elif value_spec == ':<':
            # fetch attribute value from URL
            url = unfolded_line[colon_pos+2:].strip()
            attr_value = None
            if self._process_url_schemes:
                if urlparse.urlparse(url)[0] in self._process_url_schemes:
                    attr_value = urllib.urlopen(url).read()
        else:
            attr_value = unfolded_line[colon_pos+1:]
        return attr_type, attr_value

    def _consume_empty_lines(self):
        """
        Consume empty lines until first non-empty line.
        Must only be used between full records!

        Returns non-empty key-value-tuple.
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        # Consume empty lines
        try:
            key, val = next_key_and_value()
            while key == val == None:
                key, val = next_key_and_value()
        except EOFError:
            key, val = None, None
        return key, val

    def parse_entry_records(self):
        """
        Continously read and parse LDIF entry records
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value

        try:
            # Consume empty lines
            key, val = self._consume_empty_lines()
            # Consume 'version' line
            if key == 'version':
                self.version = int(val)
                key, val = self._consume_empty_lines()
        except EOFError:
            return

        # Loop for processing whole records
        while key != None and \
              (not self._max_entries or self.records_read < self._max_entries):
            # Consume first line which must start with "dn: "
            if key != 'dn':
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %r' % (
                        self.line_counter,
                        key,
                    )
                )
            if not is_dn(val):
                raise ValueError(
                    'Line %d: Not a valid string-representation for dn: %r' % (
                        self.line_counter,
                        val,
                    )
                )
            dn = val
            entry = {}
            # Consume second line of record
            key, val = next_key_and_value()

            # Loop for reading the attributes
            while key != None:
                # Add the attribute to the entry if not ignored attribute
                if not key.lower() in self._ignored_attr_types:
                    try:
                        entry[key].append(val)
                    except KeyError:
                        entry[key] = [val]
                # Read the next line within the record
                try:
                    key, val = next_key_and_value()
                except EOFError:
                    key, val = None, None

            # handle record
            self.handle(dn, entry)
            self.records_read = self.records_read + 1
            # Consume empty separator line(s)
            key, val = self._consume_empty_lines()
        return # parse_entry_records()

    def parse(self):
        """
        Invokes LDIFParser.parse_entry_records() for backward compability
        """
        return self.parse_entry_records()

    def handle_modify(self, dn, modops, controls=None):
        """
        Process a single LDIF record representing a single modify operation.
        This method should be implemented by applications using LDIFParser.
        """
        pass

    def parse_change_records(self):
        """
        parse LDIF change records
        """
        # Local symbol for better performance
        next_key_and_value = self._next_key_and_value
        # Consume empty lines
        key, val = self._consume_empty_lines()
        # Consume 'version' line
        if key == 'version':
            self.version = int(val)
            key, val = self._consume_empty_lines()

        # Loop for processing whole records
        while key != None and \
              (not self._max_entries or self.records_read < self._max_entries):
            # Consume first line which must start with "dn: "
            if key != 'dn':
                raise ValueError(
                    'Line %d: First line of record does not start with "dn:": %r' % (
                        self.line_counter,
                        key,
                    )
                )
            if not is_dn(val):
                raise ValueError(
                    'Line %d: Not a valid string-representation for dn: %r' % (
                        self.line_counter,
                        val,
                    )
                )
            dn = val
            # Consume second line of record
            key, val = next_key_and_value()
            # Read "control:" lines
            controls = []
            while key != None and key == 'control':
                try:
                    control_type, criticality, control_value = val.split(' ', 2)
                except ValueError:
                    control_value = None
                    control_type, criticality = val.split(' ', 1)
                controls.append((control_type, criticality, control_value))
                key, val = next_key_and_value()

            # Determine changetype first
            changetype = None
            # Consume changetype line of record
            if key == 'changetype':
                if val not in VALID_CHANGETYPES:
                    raise ValueError('Invalid changetype: %r' % val)
                changetype = val
                key, val = next_key_and_value()

            if changetype == 'modify':
                # From here we assume a change record is read with changetype: modify
                modops = []
                try:
                    # Loop for reading the list of modifications
                    while key != None:
                        # Extract attribute mod-operation (add, delete, replace)
                        try:
                            modop = MOD_OP_INTEGER[key]
                        except KeyError:
                            raise ValueError(
                                'Line %d: Invalid mod-op string: %r' % (self.line_counter, key)
                            )
                        # we now have the attribute name to be modified
                        modattr = val
                        modvalues = []
                        try:
                            key, val = next_key_and_value()
                        except EOFError:
                            key, val = None, None
                        while key == modattr:
                            modvalues.append(val)
                            try:
                                key, val = next_key_and_value()
                            except EOFError:
                                key, val = None, None
                        modops.append((modop, modattr, modvalues or None))
                        key, val = next_key_and_value()
                        if key == '-':
                            # Consume next line
                            key, val = next_key_and_value()
                except EOFError:
                    key, val = None, None
                if modops:
                    # append entry to result list
                    self.handle_modify(dn, modops, controls)
            else:
                # Consume the unhandled change record
                while key != None:
                    key, val = next_key_and_value()

            # Consume empty separator line(s)
            key, val = self._consume_empty_lines()

            # Increment record counters
            try:
                self.changetype_counter[changetype] = self.changetype_counter[changetype] + 1
            except KeyError:
                self.changetype_counter[changetype] = 1
            self.records_read = self.records_read + 1

        return # parse_change_records()


class LDIFRecordList(LDIFParser):
    """
    Collect all records of LDIF input into a single list.
    of 2-tuples (dn,entry). It can be a memory hog!
    """

    def __init__(
            self,
            input_file,
            ignored_attr_types=None,
            max_entries=0,
            process_url_schemes=None,
        ):
        """
        See LDIFParser.__init__()

        Additional Parameters:
        all_records
            List instance for storing parsed records
        """
        LDIFParser.__init__(
            self,
            input_file,
            ignored_attr_types,
            max_entries,
            process_url_schemes,
        )
        self.all_records = []
        self.all_modify_changes = []

    def handle(self, dn, entry):
        """
        Append single record to dictionary of all records.
        """
        self.all_records.append((dn, entry))

    def handle_modify(self, dn, modops, controls=None):
        """
        Process a single LDIF record representing a single modify operation.
        This method should be implemented by applications using LDIFParser.
        """
        controls = [] or None
        self.all_modify_changes.append((dn, modops, controls))


class LDIFCopy(LDIFParser):
    """
    Copy LDIF input to LDIF output containing all data retrieved
    via URLs
    """

    def __init__(
            self,
            input_file,
            output_file,
            ignored_attr_types=None,
            max_entries=0,
            process_url_schemes=None,
            base64_attrs=None,
            cols=76,
            line_sep='\n',
        ):
        """
        See LDIFParser.__init__() and LDIFWriter.__init__()
        """
        LDIFParser.__init__(
            self,
            input_file,
            ignored_attr_types,
            max_entries,
            process_url_schemes,
        )
        self._output_ldif = LDIFWriter(output_file, base64_attrs, cols, line_sep)

    def handle(self, dn, entry):
        """
        Write single LDIF record to output file.
        """
        self._output_ldif.unparse(dn, entry)


def ParseLDIF(fileobj, ignore_attrs=None, maxentries=0):
    """
    Parse LDIF records read from file.
    This is a compability function. Use is deprecated!
    """
    ldif_parser = LDIFRecordList(
        fileobj,
        ignored_attr_types=ignore_attrs,
        max_entries=maxentries,
        process_url_schemes=0,
    )
    ldif_parser.parse()
    return ldif_parser.all_records
