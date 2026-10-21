"""
Classes for "Who am I?" extended operation (see RFC 4532)

See https://www.python-ldap.org/ for details.
"""

from __future__ import annotations

from . import ExtendedRequest, ExtendedResponse


class WhoAmIRequest(ExtendedRequest):
    """
    Who Am I? extended request
    """

    requestName: str = '1.3.6.1.4.1.4203.1.11.3'


class WhoAmIResponse(ExtendedResponse):
    """
    Who Am I? extended response
    """

    responseName = None

    def decodeResponseValue(self, value: bytes | None) -> str | None:
        self.dn = None
        raw = value.decode('UTF-8') if value is not None else None
        if raw and raw.startswith('dn:'):
            self.dn = raw[3:]
        return raw
