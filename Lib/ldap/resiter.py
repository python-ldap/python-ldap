"""
ldap.resiter - processing LDAP results with iterators

See https://www.python-ldap.org/ for details.
"""
from __future__ import annotations

from ldap.pkginfo import __version__, __author__, __license__

from ldap.controls import ResponseControl
from ldap.ldapobject import LDAPObject

from typing import Any, Iterator, TYPE_CHECKING

if TYPE_CHECKING:
    _Base = LDAPObject
else:
    _Base = object


class ResultProcessor(_Base):
    """
    Mix-in class used with ldap.ldapopbject.LDAPObject or derived classes.
    """

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        if not isinstance(self, LDAPObject):
            raise TypeError(f"Expecting to be a subclass of {LDAPObject}")
        super().__init__(*args, **kwargs)

    def allresults(
        self,
        msgid: int,
        timeout: int = -1,
        add_ctrls: int = 0,
    ) -> Iterator[tuple[int | None, Any | None, int | None, list[ResponseControl] | None]]:
        """
        Generator function which returns an iterator for processing all LDAP operation
        results of the given msgid like retrieved with LDAPObject.result3() -> 4-tuple
        """
        result_type, result_list, result_msgid, result_serverctrls, _, _ = \
            self.result4(
                msgid,
                0,
                timeout,
                add_ctrls=add_ctrls
            )
        while result_type and result_list:
            yield (
                result_type,
                result_list,
                result_msgid,
                result_serverctrls
            )
            result_type, result_list, result_msgid, result_serverctrls, _, _ = \
                self.result4(
                    msgid,
                    0,
                    timeout,
                    add_ctrls=add_ctrls
                )
        return # allresults()
