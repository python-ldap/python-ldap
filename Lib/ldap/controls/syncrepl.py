"""
ldap.controls.syncrepl - classes for the Content Synchronization Operation
(a.k.a. syncrepl) controls (see RFC 4533)

See https://www.python-ldap.org/ for project details.
"""

__all__ = [
  'SyncRequestControl',
  'SyncStateControl', 'SyncDoneControl',
]

from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder
from uuid import UUID

import ldap.controls
from ldap.controls import RequestControl, ResponseControl


class SyncUUID(univ.OctetString):
    """
    syncUUID ::= OCTET STRING (SIZE(16))
    """
    subtypeSpec = constraint.ValueSizeConstraint(16, 16)


class SyncCookie(univ.OctetString):
    """
    syncCookie ::= OCTET STRING
    """


class SyncRequestMode(univ.Enumerated):
    """
           mode ENUMERATED {
               -- 0 unused
               refreshOnly       (1),
               -- 2 reserved
               refreshAndPersist (3)
           },
    """
    namedValues = namedval.NamedValues(
        ('refreshOnly', 1),
        ('refreshAndPersist', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
            constraint.SingleValueConstraint(1, 3)


class SyncRequestValue(univ.Sequence):
    """
       syncRequestValue ::= SEQUENCE {
           mode ENUMERATED {
               -- 0 unused
               refreshOnly       (1),
               -- 2 reserved
               refreshAndPersist (3)
           },
           cookie     syncCookie OPTIONAL,
           reloadHint BOOLEAN DEFAULT FALSE
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mode', SyncRequestMode()),
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('reloadHint', univ.Boolean(False))
    )


class SyncRequestControl(RequestControl):
    """
    The Sync Request Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.1 and the
    controlValue, an OCTET STRING, contains a BER-encoded
    syncRequestValue.  The criticality field is either TRUE or FALSE.
    [..]
    The Sync Request Control is only applicable to the SearchRequest
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.1'

    def __init__(self, criticality=1, cookie=None, mode='refreshOnly',
                 reloadHint=False):
        self.criticality = criticality
        self.cookie = cookie
        self.mode = mode
        self.reloadHint = reloadHint

    def encodeControlValue(self):
        rcv = SyncRequestValue()
        rcv.setComponentByName('mode', SyncRequestMode(self.mode))
        if self.cookie is not None:
            rcv.setComponentByName('cookie', SyncCookie(self.cookie))
        if self.reloadHint is not None:
            rcv.setComponentByName('reloadHint', univ.Boolean(self.reloadHint))
        return encoder.encode(rcv)

    def __repr__(self):
        return '{}(cookie={!r}, mode={!r}, reloadHint={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.mode,
            self.reloadHint
        )

    def __rich_repr__(self):
        yield 'criticality', self.criticality, 1
        yield 'cookie', self.cookie, None
        yield 'mode', self.mode
        yield 'reloadHint', self.reloadHint, False


class SyncStateOp(univ.Enumerated):
    """
           state ENUMERATED {
               present (0),
               add (1),
               modify (2),
               delete (3)
           },
    """
    namedValues = namedval.NamedValues(
        ('present', 0),
        ('add', 1),
        ('modify', 2),
        ('delete', 3)
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
            constraint.SingleValueConstraint(0, 1, 2, 3)


class SyncStateValue(univ.Sequence):
    """
       syncStateValue ::= SEQUENCE {
           state ENUMERATED {
               present (0),
               add (1),
               modify (2),
               delete (3)
           },
           entryUUID syncUUID,
           cookie    syncCookie OPTIONAL
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('state', SyncStateOp()),
        namedtype.NamedType('entryUUID', SyncUUID()),
        namedtype.OptionalNamedType('cookie', SyncCookie())
    )


class SyncStateControl(ResponseControl):
    """
    The Sync State Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.2 and the
    controlValue, an OCTET STRING, contains a BER-encoded SyncStateValue.
    The criticality is FALSE.
    [..]
    The Sync State Control is only applicable to SearchResultEntry and
    SearchResultReference Messages.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.2'

    def decodeControlValue(self, encodedControlValue):
        d = decoder.decode(encodedControlValue, asn1Spec=SyncStateValue())
        state = d[0].getComponentByName('state')
        uuid = UUID(bytes=bytes(d[0].getComponentByName('entryUUID')))
        cookie = d[0].getComponentByName('cookie')
        if cookie is not None and cookie.hasValue():
            self.cookie = bytes(cookie)
        else:
            self.cookie = None
        self.state = state.prettyPrint()
        self.entryUUID = str(uuid)

    def __repr__(self):
        optional = ''
        if self.cookie is not None:
            optional += ', cookie={!r}'.format(self.cookie)
        return '{}(state={!r}, entryUUID={!r}{})'.format(
            self.__class__.__name__,
            self.state,
            self.entryUUID,
            optional,
        )

    def __rich_repr__(self):
        yield 'state', self.state
        yield 'entryUUID', self.entryUUID
        yield 'cookie', self.cookie, None


class SyncDoneValue(univ.Sequence):
    """
       syncDoneValue ::= SEQUENCE {
           cookie          syncCookie OPTIONAL,
           refreshDeletes  BOOLEAN DEFAULT FALSE
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False))
    )


class SyncDoneControl(ResponseControl):
    """
    The Sync Done Control is an LDAP Control [RFC4511] where the
    controlType is the object identifier 1.3.6.1.4.1.4203.1.9.1.3 and the
    controlValue contains a BER-encoded syncDoneValue.  The criticality
    is FALSE (and hence absent).
    [..]
    The Sync Done Control is only applicable to the SearchResultDone
    Message.
    """
    controlType = '1.3.6.1.4.1.4203.1.9.1.3'

    def decodeControlValue(self, encodedControlValue):
        d = decoder.decode(encodedControlValue, asn1Spec=SyncDoneValue())
        cookie = d[0].getComponentByName('cookie')
        if cookie.hasValue():
            self.cookie = bytes(cookie)
        else:
            self.cookie = None
        refresh_deletes = d[0].getComponentByName('refreshDeletes')
        if refresh_deletes.hasValue():
            self.refreshDeletes = bool(refresh_deletes)
        else:
            self.refreshDeletes = None

    def __repr__(self):
        optional = []
        if self.refreshDeletes is not None:
            optional.append('refreshDeletes={!r}'.format(self.refreshDeletes))
        if self.cookie is not None:
            optional.append('cookie={!r}'.format(self.cookie))
        return '{}({})'.format(
            self.__class__.__name__,
            ', '.join(optional)
        )

    def __rich_repr__(self):
        yield 'refreshDeletes', self.refreshDeletes, None
        yield 'cookie', self.cookie, None
