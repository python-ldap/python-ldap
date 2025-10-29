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

    def __init__(self, msgid, msgtype, controls=None):
        self.msgid = msgid
        self.msgtype = msgtype
        self.controls = controls

    @classmethod
    def from_message(cls, msgid, msgtype, controls=None, **kwargs):
        c = cls.__subclasses.get(msgtype)
        if c and c is not cls:
            return c.from_message(msgid, msgtype, controls, **kwargs)

        return cls(msgid, msgtype, controls, **kwargs)

    def __repr__(self):
        optional = ""
        if self.controls is not None:
            optional += f", controls={self.controls}"
        return (f"{self.__class__.__name__}(msgid={self.msgid}, "
                f"msgtype={self.msgtype}{optional})")

    def __rich_repr__(self):
        yield "msgid", self.msgid
        yield "controls", self.controls, None


class Result(Response):
    result: int
    matcheddn: str
    message: str
    referrals: Optional[list[str]]

    def __init__(self, msgid, msgtype, controls=None, *,
                 result: int, matcheddn: str, message: str,
                 referrals: Optional[list[str]]):
        super().__init__(msgid, msgtype, controls)

        self.result = result
        self.matcheddn = matcheddn
        self.message = message
        self.referrals = referrals

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

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "result", self.result
        yield "matcheddn", self.matcheddn, ""
        yield "message", self.message, ""
        yield "referrals", self.referrals, None


class SearchEntry(Response):
    msgtype = ldap.RES_SEARCH_ENTRY

    dn: str
    attrs: dict[str, Optional[list[bytes]]]

    def __init__(self, msgid, msgtype, controls=None, *,
                 dn: str, attrs: dict[str, Optional[list[bytes]]]):
        super().__init__(msgid, msgtype, controls)

        self.dn = dn
        self.attrs = attrs

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "dn", self.dn
        yield "attrs", self.attrs


class SearchReference(Response):
    msgtype = ldap.RES_SEARCH_REFERENCE

    referrals: list[str]

    def __init__(self, msgid, msgtype, controls=None, *, referrals):
        super().__init__(msgid, msgtype, controls)

        self.referrals = referrals

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "referrals", self.referrals


class SearchResult(Result):
    msgtype = ldap.RES_SEARCH_RESULT


class IntermediateResponse(Response):
    msgtype = ldap.RES_INTERMEDIATE

    name: Optional[str]
    value: Optional[bytes]

    def __init__(self, msgid: int, msgtype: int,
                 controls: ResponseControl = None, *,
                 name: Optional[str] = None, value: Optional[bytes] = None):
        super().__init__(msgid, msgtype, controls)
        self.name = name
        self.value = value

        if hasattr(self, 'decode'):
            self.decode(value)

    @classmethod
    def from_message(cls, msgid, msgtype, controls=None, *,
                     name=None, value=None, defaultClass:
                        Optional[type['IntermediateResponse']] = None,
                     **kwargs):
        c = ldap.KNOWN_INTERMEDIATE_RESPONSES.get(name, defaultClass)
        if c and c is not cls:
            return c.from_message(msgid, msgtype, controls,
                                  name=name, value=value, **kwargs)

        return cls(msgid, msgtype, controls, name=name, value=value, **kwargs)

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

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "name", self.name, None
        yield "value", self.value, None


class BindResult(Result):
    msgtype = ldap.RES_BIND

    credentials: Optional[bytes]

    def __init__(self, msgid: int, msgtype: int,
                 controls: ResponseControl = None, *,
                 result, matcheddn, message, referrals,
                 credentials: Optional[bytes] = None):
        super().__init__(msgid, msgtype, controls, result=result,
                         matcheddn=matcheddn, message=message,
                         referrals=referrals)
        self.credentials = credentials

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "credentials", self.credentials, None


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

    name: Optional[str]
    value: Optional[bytes]

    def __init__(self, msgid: int, msgtype: int,
                 controls: ResponseControl = None, *,
                 result: int, matcheddn: str, message: str,
                 referrals: Optional[list[str]],
                 name: Optional[str] = None, value: Optional[bytes] = None):
        super().__init__(msgid, msgtype, controls, result=result,
                         matcheddn=matcheddn, message=message,
                         referrals=referrals)
        self.name = name
        self.value = value

        if hasattr(self, 'decode'):
            self.decode(value)

    @classmethod
    def from_message(cls, msgid, msgtype, controls=None, *,
                     name=None, value=None, defaultClass:
                        Optional[type['ExtendedResult']] = None,
                     **kwargs):
        c = ldap.KNOWN_EXTENDED_RESPONSES.get(name, defaultClass)
        if c and c is not cls:
            return c.from_message(msgid, msgtype, controls,
                                  name=name, value=value, **kwargs)

        return cls(msgid, msgtype, controls, name=name, value=value, **kwargs)

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

    def __rich_repr__(self):
        yield from super().__rich_repr__()
        yield "name", self.name, None
        yield "value", self.value, None


class UnsolicitedNotification(ExtendedResult):
    msgid = ldap.RES_UNSOLICITED
