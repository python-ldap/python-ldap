"""
ldap.extop.syncrepl - classes for the Content Synchronization Operation
(a.k.a. syncrepl) Intermediate responses (see RFC 4533)

See https://www.python-ldap.org/ for project details.
"""

from typing import Optional, Sequence

from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder
from uuid import UUID

from ldap.extop import ExtendedRequest, ExtendedResponse, IntermediateResponse
from ldap.controls.syncrepl import (
    SyncCookie, SyncUUID,
)


class RefreshDelete(univ.Sequence):
    """
           refreshDelete  [1] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class RefreshPresent(univ.Sequence):
    """
           refreshPresent [2] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDone', univ.Boolean(True))
    )


class SyncUUIDs(univ.SetOf):
    """
    syncUUIDs      SET OF syncUUID
    """
    componentType = SyncUUID()


class SyncIdSet(univ.Sequence):
    """
     syncIdSet      [3] SEQUENCE {
         cookie         syncCookie OPTIONAL,
         refreshDeletes BOOLEAN DEFAULT FALSE,
         syncUUIDs      SET OF syncUUID
     }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('cookie', SyncCookie()),
        namedtype.DefaultedNamedType('refreshDeletes', univ.Boolean(False)),
        namedtype.NamedType('syncUUIDs', SyncUUIDs())
    )


class SyncInfoValue(univ.Choice):
    """
       syncInfoValue ::= CHOICE {
           newcookie      [0] syncCookie,
           refreshDelete  [1] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
           refreshPresent [2] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDone    BOOLEAN DEFAULT TRUE
           },
           syncIdSet      [3] SEQUENCE {
               cookie         syncCookie OPTIONAL,
               refreshDeletes BOOLEAN DEFAULT FALSE,
               syncUUIDs      SET OF syncUUID
           }
       }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            'newcookie',
            SyncCookie().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
            )
        ),
        namedtype.NamedType(
            'refreshDelete',
            RefreshDelete().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            )
        ),
        namedtype.NamedType(
            'refreshPresent',
            RefreshPresent().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
            )
        ),
        namedtype.NamedType(
            'syncIdSet',
            SyncIdSet().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)
            )
        )
    )


class SyncInfoMessage(IntermediateResponse):
    """
    The Sync Info Message is an LDAP Intermediate Response Message
    [RFC4511] where responseName is the object identifier
    1.3.6.1.4.1.4203.1.9.1.4 and responseValue contains a BER-encoded
    syncInfoValue.  The criticality is FALSE (and hence absent).
    """
    responseName = '1.3.6.1.4.1.4203.1.9.1.4'

    def __new__(cls, msgid, msgtype, controls=None, *,
                name=None, value=None,
                **kwargs):
        if cls is not __class__:
            return super().__new__(cls, msgid, msgtype, controls,
                                   name=name, value=value)
        syncinfo, _ = decoder.decode(value, asn1Spec=SyncInfoValue())
        choice = syncinfo.getName()
        if choice == 'newcookie':
            child = SyncInfoNewCookie
        elif choice == 'refreshDelete':
            child = SyncInfoRefreshDelete
        elif choice == 'refreshPresent':
            child = SyncInfoRefreshPresent
        elif choice == 'syncIdSet':
            child = SyncInfoIDSet
        else:
            raise ValueError
        return child.__new__(child, msgid, msgtype, controls,
                             name=name, value=value)

    def decode(self, value: bytes):
        self.syncinfo, _ = decoder.decode(
            value,
            asn1Spec=SyncInfoValue(),
        )


class SyncInfoNewCookie(SyncInfoMessage):
    cookie: bytes

    def decode(self, value: bytes):
        super().decode(value)
        self.cookie = bytes(self.syncinfo.getComponent())

    def __repr__(self):
        return '{}(cookie={!r})'.format(
            self.__class__.__name__,
            self.cookie,
        )

    def __rich_repr__(self):
        yield "cookie", self.cookie


class SyncInfoRefreshDelete(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDone: bool

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDone = bool(component['refreshDone'])

    def __repr__(self):
        return '{}(cookie={!r}, refreshDone={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDone,
        )

    def __rich_repr__(self):
        yield "cookie", self.cookie, None
        yield "refreshDone", self.refreshDone


class SyncInfoRefreshPresent(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDone: bool

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDone = bool(component['refreshDone'])

    def __repr__(self):
        return '{}(cookie={!r}, refreshDone={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDone,
        )

    def __rich_repr__(self):
        yield "cookie", self.cookie, None
        yield "refreshDone", self.refreshDone


class SyncInfoIDSet(SyncInfoMessage):
    cookie: Optional[bytes]
    refreshDeletes: bool
    syncUUIDs: Sequence[str]

    def decode(self, value: bytes):
        super().decode(value)
        component = self.syncinfo.getComponent()
        self.cookie = None
        cookie = component['cookie']
        if cookie.isValue:
            self.cookie = bytes(cookie)
        self.refreshDeletes = bool(component['refreshDeletes'])

        uuids = []
        for syncuuid in component['syncUUIDs']:
            uuid = UUID(bytes=bytes(syncuuid))
            uuids.append(str(uuid))
        self.syncUUIDs = uuids

    def __repr__(self):
        return '{}(cookie={!r}, refreshDeletes={!r}, syncUUIDs={!r})'.format(
            self.__class__.__name__,
            self.cookie,
            self.refreshDeletes,
            self.syncUUIDs,
        )

    def __rich_repr__(self):
        yield "cookie", self.cookie, None
        yield "refreshDeletes", self.refreshDeletes
        yield "syncUUIDs", self.syncUUIDs
