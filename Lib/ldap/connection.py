"""
connection.py - wraps class _ldap.LDAPObject

See https://www.python-ldap.org/ for details.
"""

from ldap.pkginfo import __version__, __author__, __license__

__all__ = [
    'Connection',
]


from numbers import Real
from typing import AnyStr, Optional, Union

import ldap
from ldap.controls import DecodeControlTuples, RequestControl
from ldap.extop import ExtendedRequest
from ldap.extop.passwd import PasswordModifyResponse
from ldap.ldapobject import SimpleLDAPObject, NO_UNIQUE_ENTRY
from ldap.response import (
    Response,
    SearchEntry, SearchReference,
    IntermediateResponse, ExtendedResult,
)

from ldapurl import LDAPUrl

RequestControls = Optional[list[RequestControl]]


# TODO: remove _ext and _s functions as we rework request API
class Connection(SimpleLDAPObject):
    resp_ctrl_classes = None

    def __init__(self, uri: Union[LDAPUrl, str, None], **kwargs):
        if isinstance(uri, LDAPUrl):
            uri = uri.unparse()
        super().__init__(uri, **kwargs)

    def result(self, msgid: int = ldap.RES_ANY, *, all: int = 1,
               timeout: Optional[float] = None,
               defaultIntermediateClass:
                   Optional[type[IntermediateResponse]] = None,
               defaultExtendedClass: Optional[type[ExtendedResult]] = None
               ) -> Optional[list[Response]]:
        """
        result([msgid: int = RES_ANY [, all: int = 1 [,
                    timeout: Optional[float] = None]]])
            -> Optional[list[Response]]

        This method is used to wait for and return the result of an
        operation previously initiated by one of the LDAP asynchronous
        operation routines (e.g. search(), modify(), etc.) They all
        return an invocation identifier (a message id) upon successful
        initiation of their operation. This id is guaranteed to be
        unique across an LDAP session, and can be used to request the
        result of a specific operation via the msgid parameter of the
        result() method.

        If the result of a specific operation is required, msgid should
        be set to the invocation message id returned when the operation
        was initiated; otherwise RES_ANY should be supplied.

        The all parameter is used to wait until a final response for
        a given operation is received, this is useful with operations
        (like search) that generate multiple responses and is used
        to select whether a single item should be returned or to wait
        for all the responses before returning.

        Using search as an example: A search response is made up of
        zero or more search entries followed by a search result. If all
        is 0, search entries will be returned one at a time as they
        come in, via separate calls to result(). If all is 1, the
        search response will be returned in its entirety, i.e. after
        all entries and the final search result have been received. If
        all is 2, all search entries that have been received so far
        will be returned.

        The method returns a list of messages or None if polling and no
        messages arrived yet.

        The result() method will block for timeout seconds, or
        indefinitely if timeout is negative.  A timeout of 0 will
        effect a poll. The timeout can be expressed as a floating-point
        value. If timeout is None the default in self.timeout is used.

        If a timeout occurs, a TIMEOUT exception is raised, unless
        polling (timeout = 0), in which case None is returned.
        """

        if timeout is None:
            timeout = self.timeout

        messages = self._ldap_call(self._l.result, msgid, all, timeout)

        if messages is None:
            return None

        results = []
        for msgid, msgtype, controls, data in messages:
            if controls is not None:
                controls = DecodeControlTuples(controls, self.resp_ctrl_classes)

            if msgtype == ldap.RES_INTERMEDIATE:
                data['defaultClass'] = defaultIntermediateClass
            if msgtype == ldap.RES_EXTENDED:
                data['defaultClass'] = defaultExtendedClass
            m = Response(msgid, msgtype, controls, **data)
            results.append(m)

        return results

    def add_s(self, dn: str,
              modlist: list[tuple[str, Union[bytes, list[bytes]]]], *,
              ctrls: RequestControls = None) -> ldap.response.AddResult:
        msgid = self.add_ext(dn, modlist, serverctrls=ctrls)
        responses = self.result(msgid)
        result, = responses
        return result

    def bind_s(self, dn: Optional[str] = None,
               cred: Optional[AnyStr] = None, *,
               method: int = ldap.AUTH_SIMPLE,
               ctrls: RequestControls = None) -> ldap.response.BindResult:
        msgid = self.bind(dn, cred, method)
        responses = self.result(msgid)
        result, = responses
        return result

    def compare_s(self, dn: str, attr: str, value: bytes, *,
                  ctrls: RequestControls = None
                  ) -> ldap.response.CompareResult:
        "TODO: remove _s functions introducing a better request API"
        msgid = self.compare_ext(dn, attr, value, serverctrls=ctrls)
        responses = self.result(msgid)
        result, = responses
        return bool(result)

    def delete_s(self, dn: str, *,
                 ctrls: RequestControls = None) -> ldap.response.DeleteResult:
        msgid = self.delete_ext(dn, serverctrls=ctrls)
        responses = self.result(msgid)
        result, = responses
        return result

    def extop_s(self, name: Optional[str] = None,
                value: Optional[bytes] = None, *,
                request: Optional[ExtendedRequest] = None,
                ctrls: RequestControls = None,
                defaultIntermediateClass: Optional[type[IntermediateResponse]] = None,
                defaultExtendedClass: Optional[type[ExtendedResult]] = None
                ) -> list[Union[IntermediateResponse, ExtendedResult]]:
        if request is not None:
            name = request.requestName
            value = request.encodedRequestValue()

        msgid = self.extop(name, value, serverctrls=ctrls)
        return self.result(msgid,
                           defaultIntermediateClass=defaultIntermediateClass,
                           defaultExtendedClass=defaultExtendedClass)

    def modify_s(self, dn: str,
                 modlist: list[tuple[str, Union[bytes, list[bytes]]]], *,
                 ctrls: RequestControls = None) -> ldap.response.ModifyResult:
        msgid = self.modify_ext(dn, modlist, serverctrls=ctrls)
        responses = self.result(msgid)
        result, = responses
        return result

    def passwd_s(self, user: Optional[str] = None,
                 oldpw: Optional[bytes] = None, newpw: Optional[bytes] = None,
                 ctrls: RequestControls = None) -> PasswordModifyResponse:
        msgid = self.passwd(user, oldpw, newpw, serverctrls=ctrls)
        res, = self.result(msgid, defaultExtendedClass=PasswordModifyResponse)
        return res

    def search_s(self, base: Optional[str] = None,
                 scope: int = ldap.SCOPE_SUBTREE,
                 filter: str = "(objectClass=*)",
                 attrlist: Optional[list[str]] = None, *,
                 attrsonly: bool = False,
                 ctrls: RequestControls = None,
                 sizelimit: int = 0, timelimit: int = -1,
                 timeout: Optional[Real] = None
                 ) -> list[Union[SearchEntry, SearchReference]]:
        if timeout is None:
            timeout = timelimit

        msgid = self.search_ext(base, scope, filter, attrlist=attrlist,
                                attrsonly=attrsonly, serverctrls=ctrls,
                                sizelimit=sizelimit, timeout=timelimit)
        result = self.result(msgid, timeout=timeout)
        # FIXME: we want a better way of returning a result with multiple
        # messages, always useful in searches but other operations can also
        # elicit those (by way of an IntermediateResponse)
        result[-1].raise_for_result()
        return result

    def search_subschemasubentry_s(
            self, dn: Optional[str] = None) -> Optional[str]:
        """
        Returns the distinguished name of the sub schema sub entry
        for a part of a DIT specified by dn.

        None as result indicates that the DN of the sub schema sub entry could
        not be determined.
        """
        empty_dn = ''
        attrname = 'subschemaSubentry'
        if dn is None:
            dn = empty_dn
        try:
            r = self.search_s(dn, ldap.SCOPE_BASE, None, [attrname])
        except (ldap.NO_SUCH_OBJECT, ldap.NO_SUCH_ATTRIBUTE,
                ldap.INSUFFICIENT_ACCESS):
            r = []
        except ldap.UNDEFINED_TYPE:
            return None

        attr = r and ldap.cidict.cidict(r[0].attrs).get(attrname)
        if attr:
            return attr[0].decode('utf-8')
        elif dn:
            # Try to find sub schema sub entry in root DSE
            return self.search_subschemasubentry_s(dn=empty_dn)
        else:
            # If dn was already rootDSE we can return here
            return None

    def read_s(self, dn: str, filterstr: Optional[str] = None,
               attrlist: Optional[list[str]] = None,
               ctrls: RequestControls = None,
               timeout: int = -1) -> dict[str, bytes]:
        """
        Reads and returns a single entry specified by `dn'.

        Other attributes just like those passed to `search_s()'
        """
        r = self.search_s(dn, ldap.SCOPE_BASE, filterstr,
                          attrlist=attrlist, ctrls=ctrls, timeout=timeout)
        if r:
            return r[0].attrs
        else:
            return None

    def find_unique_entry(self, base: Optional[str] = None,
                          scope: int = ldap.SCOPE_SUBTREE,
                          filter: str = "(objectClass=*)",
                          attrlist: Optional[list[str]] = None, *,
                          attrsonly: bool = False,
                          ctrls: RequestControls = None,
                          timelimit: int = -1,
                          timeout: Optional[Real] = None
                          ) -> list[Union[SearchEntry, SearchReference]]:
        """
        Returns a unique entry, raises exception if not unique
        """
        r = self.search_s(base, scope, filter, attrlist=attrlist,
                          attrsonly=attrsonly, ctrls=ctrls, timeout=timeout,
                          sizelimit=2)
        if len(r) != 2:
            raise NO_UNIQUE_ENTRY(f'No or non-unique search result for {filter}')
        return r[0]
