"""
ldap.asyncsearch - handle async LDAP search operations

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

import ldap

from ldap.pkginfo import __version__
from ldap.controls import RequestControl
from typing import Any, Dict, Iterable, List, Sequence, TextIO, Tuple
from ldap_types import *

import ldif

SEARCH_RESULT_TYPES = {
  ldap.RES_SEARCH_ENTRY,
  ldap.RES_SEARCH_RESULT,
  ldap.RES_SEARCH_REFERENCE,
}

ENTRY_RESULT_TYPES = {
  ldap.RES_SEARCH_ENTRY,
  ldap.RES_SEARCH_RESULT,
}


class WrongResultType(Exception):

  def __init__(
    self,
    receivedResultType: int,
    expectedResultTypes: Iterable[int],
  ) -> None:
    self.receivedResultType = receivedResultType
    self.expectedResultTypes = expectedResultTypes
    Exception.__init__(self)

  def __str__(self) -> str:
    return 'Received wrong result type {} (expected one of {}).'.format(
      self.receivedResultType,
      ', '.join([str(x) for x in self.expectedResultTypes]),
    )


class AsyncSearchHandler:
  """
  Class for stream-processing LDAP search results

  Arguments:

  l
    LDAPObject instance
  """

  def __init__(self, l: ldap.ldapobject.LDAPObject) -> None:
    self._l = l
    self._msgId: int | None = None
    self._afterFirstResult = 1

  def startSearch(
    self,
    searchRoot: str,
    searchScope: int,
    filterStr: str,
    attrList: List[str] | None = None,
    attrsOnly: int = 0,
    timeout: int = -1,
    sizelimit: int = 0,
    serverctrls: List[RequestControl] | None = None,
    clientctrls: List[RequestControl] | None = None,
  ) -> None:
    """
    searchRoot
        See parameter base of method LDAPObject.search()
    searchScope
        See parameter scope of method LDAPObject.search()
    filterStr
        See parameter filter of method LDAPObject.search()
    attrList=None
        See parameter attrlist of method LDAPObject.search()
    attrsOnly
        See parameter attrsonly of method LDAPObject.search()
    timeout
        Maximum time the server shall use for search operation
    sizelimit
        Maximum number of entries a server should return
        (request client-side limit)
    serverctrls
        list of server-side LDAP controls
    clientctrls
        list of client-side LDAP controls
    """
    self._msgId = self._l.search_ext(
      searchRoot,searchScope,filterStr,
      attrList,attrsOnly,serverctrls,clientctrls,timeout,sizelimit
    )
    self._afterFirstResult = 1

  def preProcessing(self) -> Any:
    """
    Do anything you want after starting search but
    before receiving and processing results
    """

  def afterFirstResult(self) -> Any:
    """
    Do anything you want right after successfully receiving but before
    processing first result
    """

  def postProcessing(self) -> Any:
    """
    Do anything you want after receiving and processing all results
    """

  def processResults(
    self,
    ignoreResultsNumber: int = 0,
    processResultsCount: int = 0,
    timeout: int = -1,
  ) -> int:
    """
    ignoreResultsNumber
        Don't process the first ignoreResultsNumber results.
    processResultsCount
        If non-zero this parameters indicates the number of results
        processed is limited to processResultsCount.
    timeout
        See parameter timeout of ldap.LDAPObject.result()
    """
    if self._msgId is None:
        raise RuntimeError('processResults() called without calling startSearch() first')

    self.preProcessing()
    result_counter = 0
    end_result_counter = ignoreResultsNumber+processResultsCount
    go_ahead = 1
    partial = 0
    self.beginResultsDropped = 0
    self.endResultBreak = result_counter
    try:
      result_type,result_list = None,None
      while go_ahead:
        while result_type is None and not result_list:
          result_type,result_list,result_msgid,result_serverctrls = self._l.result3(self._msgId,0,timeout)
          if self._afterFirstResult:
            self.afterFirstResult()
            self._afterFirstResult = 0
        if not result_list:
          break
        if result_type not in SEARCH_RESULT_TYPES:
          raise WrongResultType(result_type,SEARCH_RESULT_TYPES)
        # Loop over list of search results
        for result_item in result_list:
          if result_counter<ignoreResultsNumber:
            self.beginResultsDropped = self.beginResultsDropped+1
          elif processResultsCount==0 or result_counter<end_result_counter:
            self._processSingleResult(result_type,result_item)
          else:
            go_ahead = 0 # break-out from while go_ahead
            partial = 1
            break # break-out from this for-loop
          result_counter = result_counter+1
        result_type,result_list = None,None
        self.endResultBreak = result_counter
    finally:
      if partial and self._msgId!=None:
        self._l.abandon(self._msgId)
    self.postProcessing()
    return partial # processResults()

  def _processSingleResult(
    self,
    resultType: int,
    resultItem: LDAPSearchResult,
  ) -> Any:
    """
    Process single entry

    resultType
        result type
    resultItem
        Single item of a result list
    """
    pass


class AsyncList(AsyncSearchHandler):
  """
  Class for collecting all search results.

  This does not seem to make sense in the first place but think
  of retrieving exactly a certain portion of the available search
  results.
  """

  def __init__(self, l: ldap.ldapobject.LDAPObject) -> None:
    AsyncSearchHandler.__init__(self,l)
    self.allResults: List[Tuple[int, LDAPSearchResult]] = []

  def _processSingleResult(
    self,
    resultType: int,
    resultItem: LDAPSearchResult,
  ) -> None:
    self.allResults.append((resultType,resultItem))


class AsyncDict(AsyncSearchHandler):
  """
  Class for collecting all search results into a dictionary {dn:entry}
  """

  def __init__(self, l: ldap.ldapobject.LDAPObject) -> None:
    AsyncSearchHandler.__init__(self,l)
    self.allEntries: Dict[str, LDAPEntryDict] = {}

  def _processSingleResult(
    self,
    resultType: int,
    resultItem: LDAPSearchResult,
  ) -> None:
    if resultType in ENTRY_RESULT_TYPES:
      # Search continuations are ignored
      dn,entry = resultItem
      self.allEntries[dn] = entry


class AsyncIndexedDict(AsyncDict):
  """
  Class for collecting all search results into a dictionary {dn:entry}
  and maintain case-sensitive equality indexes to entries
  """

  def __init__(
    self,
    l: ldap.ldapobject.LDAPObject,
    indexed_attrs: Sequence[str] | None = None,
  ) -> None:
    AsyncDict.__init__(self,l)
    self.indexed_attrs = indexed_attrs or ()
    self.index: Dict[str, Dict[bytes, List[str]]] = {}.fromkeys(self.indexed_attrs,{})

  def _processSingleResult(
    self,
    resultType: int,
    resultItem: LDAPSearchResult,
  ) -> None:
    if resultType in ENTRY_RESULT_TYPES:
      # Search continuations are ignored
      dn,entry = resultItem
      self.allEntries[dn] = entry
      for a in self.indexed_attrs:
        if a in entry:
          for v in entry[a]:
            try:
              self.index[a][v].append(dn)
            except KeyError:
              self.index[a][v] = [ dn ]


class FileWriter(AsyncSearchHandler):
  """
  Class for writing a stream of LDAP search results to a file object

  Arguments:
  l
    LDAPObject instance
  f
    File object instance where the LDIF data is written to
  """

  def __init__(
    self,
    l: ldap.ldapobject.LDAPObject,
    f: TextIO,
    headerStr: str = '',
    footerStr: str = '',
  ) -> None:
    AsyncSearchHandler.__init__(self,l)
    self._f = f
    self.headerStr = headerStr
    self.footerStr = footerStr

  def preProcessing(self) -> None:
    """
    The headerStr is written to output after starting search but
    before receiving and processing results.
    """
    self._f.write(self.headerStr)

  def postProcessing(self) -> None:
    """
    The footerStr is written to output after receiving and
    processing results.
    """
    self._f.write(self.footerStr)


class LDIFWriter(FileWriter):
  """
  Class for writing a stream LDAP search results to a LDIF file

  Arguments:

  l
    LDAPObject instance
  writer_obj
    Either a file-like object or a ldif.LDIFWriter instance used for output
  """

  def __init__(
    self,
    l: ldap.ldapobject.LDAPObject,
    writer_obj: TextIO | ldif.LDIFWriter,
    headerStr: str = '',
    footerStr: str = '',
  ) -> None:
    if isinstance(writer_obj,ldif.LDIFWriter):
      self._ldif_writer = writer_obj
    else:
      self._ldif_writer = ldif.LDIFWriter(writer_obj)
    FileWriter.__init__(self,l,self._ldif_writer._output_file,headerStr,footerStr)

  def _processSingleResult(
    self,
    resultType: int,
    resultItem: LDAPSearchResult,
  ) -> None:
    if resultType in ENTRY_RESULT_TYPES:
      # Search continuations are ignored
      dn,entry = resultItem
      self._ldif_writer.unparse(dn,entry)
