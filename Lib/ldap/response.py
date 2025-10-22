"""
response.py - classes for LDAP responses

See https://www.python-ldap.org/ for details.
"""

from ldap.pkginfo import __version__, __author__, __license__

__all__ = [
    'Response',
    'Result',

    'SearchEntry',
    'SearchReference',
    'SearchResult',

    'IntermediateResponse',
    'ExtendedResult',

    'BindResult',
    'ModifyResult',
    'AddResult',
    'DeleteResult',
    'ModRDNResult',
    'CompareResult',
]

from typing import Optional

import ldap
from ldap.controls import ResponseControl


_SUCCESS_CODES = [
    ldap.SUCCESS.errnum,
    ldap.COMPARE_TRUE.errnum,
    ldap.COMPARE_FALSE.errnum,
    ldap.SASL_BIND_IN_PROGRESS.errnum,
]


class Response:
    msgid: int
    msgtype: int
    controls: Optional[list[ResponseControl]]

    __subclasses: dict[int, type] = {}

    def __init_subclass__(cls):
        if not hasattr(cls, 'msgtype'):
            return
        c = __class__.__subclasses.setdefault(cls.msgtype, cls)
        if not issubclass(cls, c):
            msgtype = cls.msgtype
            raise TypeError(f"Attempt to register a default for {msgtype=} "
                            f"that's incompatible with the existing default: "
                            f"{c.__module__}.{c.__qualname__}")

    def __new__(cls, msgid, msgtype, controls=None, **kwargs):
        if cls is not __class__:
            instance = super().__new__(cls)
            instance.msgid = msgid
            instance.msgtype = msgtype
            instance.controls = controls
            return instance

        c = __class__.__subclasses.get(msgtype)
        if c:
            return c.__new__(c, msgid, msgtype, controls, **kwargs)

        instance = super().__new__(cls, **kwargs)
        instance.msgid = msgid
        instance.msgtype = msgtype
        instance.controls = controls
        return instance

    def __repr__(self):
        optional = ""
        if self.controls is not None:
            optional += f", controls={self.controls}"
        return (f"{self.__class__.__name__}(msgid={self.msgid}, "
                f"msgtype={self.msgtype}{optional})")


class Result(Response):
    result: int
    matcheddn: str
    message: str
    referrals: Optional[list[str]]

    def __new__(cls, msgid, msgtype, controls=None, *,
                result, matcheddn, message, referrals, **kwargs):
        instance = super().__new__(cls, msgid, msgtype, controls, **kwargs)

        instance.result = result
        instance.matcheddn = matcheddn
        instance.message = message
        instance.referrals = referrals

        return instance

    def raise_for_result(self) -> 'Result':
        if self.result in _SUCCESS_CODES:
            return self
        raise ldap._exceptions.get(self.result, ldap.LDAPError)(self)

    def __repr__(self):
        optional = ""
        if self.controls is not None:
            optional = f", controls={self.controls}"
        if self.message:
            optional = f", message={self.message!r}"
        return (f"{self.__class__.__name__}"
                f"(msgid={self.msgid}, result={self.result}{optional})")


class SearchEntry(Response):
    msgtype = ldap.RES_SEARCH_ENTRY

    dn: str
    attrs: dict[str, Optional[list[bytes]]]

    def __new__(cls, msgid, msgtype, controls=None, *,
                dn: str, attrs: dict[str, Optional[list[bytes]]], **kwargs):
        instance = super().__new__(cls, msgid, msgtype, controls, **kwargs)

        instance.dn = dn
        instance.attrs = attrs

        return instance


class SearchReference(Response):
    msgtype = ldap.RES_SEARCH_REFERENCE

    referrals: list[str]

    def __new__(cls, msgid, msgtype, controls=None, *,
                referrals, **kwargs):
        instance = super().__new__(cls, msgid, msgtype, controls, **kwargs)

        instance.referrals = referrals

        return instance


class SearchResult(Result):
    msgtype = ldap.RES_SEARCH_RESULT


class IntermediateResponse(Response):
    msgtype = ldap.RES_INTERMEDIATE

    name: Optional[str]
    value: Optional[bytes]

    def __new__(cls, msgid, msgtype, controls=None, *,
                name=None, value=None,
                defaultClass: Optional[type['IntermediateResponse']] = None,
                **kwargs):
        if cls is not __class__:
            instance = super().__new__(cls, msgid, msgtype, controls, **kwargs)
            instance.name = name
            instance.value = value
            return instance

        c = ldap.KNOWN_INTERMEDIATE_RESPONSES.get(name, defaultClass)
        if c:
            instance = c.__new__(c, msgid, msgtype, controls,
                                 name=name, value=value, **kwargs)
            if hasattr(instance, 'decode'):
                instance.decode(value)
            return instance

        instance = super().__new__(cls, msgid, msgtype, controls, **kwargs)
        instance.name = name
        instance.value = value
        return instance

    def __repr__(self):
        optional = ""
        if self.name is not None:
            optional += f", name={self.name!r}"
        if self.value is not None:
            optional += f", value={self.value!r}"
        if self.controls is not None:
            optional += f", controls={self.controls}"
        return (f"{self.__class__.__name__}"
                f"(msgid={self.msgid}{optional})")


class BindResult(Result):
    msgtype = ldap.RES_BIND

    servercreds: Optional[bytes]


class ModifyResult(Result):
    msgtype = ldap.RES_MODIFY


class AddResult(Result):
    msgtype = ldap.RES_ADD


class DeleteResult(Result):
    msgtype = ldap.RES_DELETE


class ModRDNResult(Result):
    msgtype = ldap.RES_MODRDN


class CompareResult(Result):
    msgtype = ldap.RES_COMPARE

    def __bool__(self) -> bool:
        if self.result == ldap.COMPARE_FALSE.errnum:
            return False
        if self.result == ldap.COMPARE_TRUE.errnum:
            return True
        raise ldap._exceptions.get(self.result, ldap.LDAPError)(self)


class ExtendedResult(Result):
    msgtype = ldap.RES_EXTENDED

    responseName: Optional[str]
    value: Optional[bytes]

    def __new__(cls, msgid, msgtype, controls=None, *,
                result, matcheddn, message, referrals,
                name=None, value=None,
                defaultClass: Optional[type['ExtendedResult']] = None,
                **kwargs):
        if cls is not __class__:
            instance = super().__new__(cls, msgid, msgtype, controls,
                                       result=result, matcheddn=matcheddn,
                                       message=message, referrals=referrals)
            instance.name = name
            instance.value = value
            return instance

        c = ldap.KNOWN_EXTENDED_RESPONSES.get(name, defaultClass)
        if not c and msgid == ldap.RES_UNSOLICITED:
            c = UnsolicitedNotification

        if c:
            return c.__new__(c, msgid, msgtype, controls,
                             result=result, matcheddn=matcheddn,
                             message=message, referrals=referrals,
                             name=name, value=value, **kwargs)

        instance = super().__new__(cls, msgid, msgtype, controls,
                                   result=result, matcheddn=matcheddn,
                                   message=message, referrals=referrals)
        instance.name = name
        instance.value = value
        return instance

    def __repr__(self):
        optional = ""
        if self.name is not None:
            optional += f", name={self.name}"
        if self.value is not None:
            optional += f", value={self.value}"
        if self.message:
            optional = f", message={self.message!r}"
        if self.controls is not None:
            optional += f", controls={self.controls}"
        return (f"{self.__class__.__name__}"
                f"(msgid={self.msgid}, result={self.result}{optional})")


class UnsolicitedNotification(ExtendedResult):
    msgid = ldap.RES_UNSOLICITED
