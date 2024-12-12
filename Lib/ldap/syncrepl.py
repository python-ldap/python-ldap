"""
ldap.syncrepl - for implementing syncrepl consumer (see RFC 4533)

See https://www.python-ldap.org/ for project details.
"""

from ldap.pkginfo import __version__, __author__, __license__
from ldap import RES_SEARCH_RESULT, RES_SEARCH_ENTRY, RES_INTERMEDIATE
from ldap.controls.syncrepl import (
    SyncRequestControl, SyncStateControl, SyncDoneControl,
)
from ldap.response import Response
from ldap.extop.syncrepl import (
    SyncInfoMessage,
    SyncInfoNewCookie, SyncInfoRefreshPresent, SyncInfoRefreshDelete,
    SyncInfoIDSet,
)

__all__ = [
    'SyncreplConsumer',
]


class SyncreplConsumer:
    """
    SyncreplConsumer - LDAP syncrepl consumer object.
    """

    def syncrepl_search(self, base, scope, mode='refreshOnly', cookie=None, **search_args):
        """
        Starts syncrepl search operation.

        base, scope, and search_args are passed along to
        self.search_ext unmodified (aside from adding a Sync
        Request control to any serverctrls provided).

        mode provides syncrepl mode. Can be 'refreshOnly'
        to finish after synchronization, or
        'refreshAndPersist' to persist (continue to
        receive updates) after synchronization.

        cookie: an opaque value representing the replication
        state of the client.  Subclasses should override
        the syncrepl_set_cookie() and syncrepl_get_cookie()
        methods to store the cookie appropriately, rather than
        passing it.

        Only a single syncrepl search may be active on a SyncreplConsumer
        object.  Multiple concurrent syncrepl searches require multiple
        separate SyncreplConsumer objects and thus multiple connections
        (LDAPObject instances).
        """
        if cookie is None:
            cookie = self.syncrepl_get_cookie()

        syncreq = SyncRequestControl(cookie=cookie, mode=mode)

        if 'serverctrls' in search_args:
            search_args['serverctrls'] += [syncreq]
        else:
            search_args['serverctrls'] = [syncreq]

        self.__refreshDone = False
        return self.search_ext(base, scope, **search_args)

    def syncrepl_poll(self, msgid=-1, timeout=None, all=0):
        """
        polls for and processes responses to the syncrepl_search() operation.
        Returns False when operation finishes, True if it is in progress, or
        raises an exception on error.

        If timeout is specified, raises ldap.TIMEOUT in the event of a timeout.

        If all is set to a nonzero value, poll() will return only when finished
        or when an exception is raised.

        """
        while True:
            type, msg, mid, ctrls, n, v = self.result4(
                msgid=msgid,
                timeout=timeout,
                add_intermediates=1,
                add_ctrls=1,
                all=0,
            )

            if type == RES_SEARCH_RESULT:
                # search result. This marks the end of a refreshOnly session.
                # look for a SyncDone control, save the cookie, and if necessary
                # delete non-present entries.
                for c in ctrls:
                    if c.__class__.__name__ != 'SyncDoneControl':
                        continue
                    self.syncrepl_present(None, refreshDeletes=c.refreshDeletes)
                    if c.cookie is not None:
                        self.syncrepl_set_cookie(c.cookie)

                return False

            elif type == RES_SEARCH_ENTRY:
                # search entry with associated SyncState control
                for m in msg:
                    dn, attrs, ctrls = m
                    for c in ctrls:
                        if not isinstance(c, SyncStateControl):
                            continue

                        if c.state == 'present':
                            self.syncrepl_present([c.entryUUID])
                        elif c.state == 'delete':
                            self.syncrepl_delete([c.entryUUID])
                        else:
                            self.syncrepl_entry(dn, attrs, c.entryUUID)
                            if self.__refreshDone is False:
                                self.syncrepl_present([c.entryUUID])

                        if c.cookie is not None:
                            self.syncrepl_set_cookie(c.cookie)
                        break

            elif type == RES_INTERMEDIATE:
                # Intermediate message, process any that are SyncInfoMessage
                for m in msg:
                    name, value, controls = m
                    m = Response(mid, type, name=name, value=value,
                                 controls=controls)
                    if isinstance(m, SyncInfoNewCookie):
                        self.syncrepl_set_cookie(m.cookie)
                    elif isinstance(m, (SyncInfoRefreshPresent, SyncInfoRefreshDelete)):
                        refreshDeletes = isinstance(m, SyncInfoRefreshDelete)
                        self.syncrepl_present(None, refreshDeletes=refreshDeletes)
                        if m.cookie is not None:
                            self.syncrepl_set_cookie(m.cookie)
                        if m.refreshDone:
                            self.__refreshDone = True
                            self.syncrepl_refreshdone()
                    elif isinstance(m, SyncInfoIDSet):
                        if m.refreshDeletes:
                            self.syncrepl_delete(m.syncUUIDs)
                        else:
                            self.syncrepl_present(m.syncUUIDs)
                        if m.cookie is not None:
                            self.syncrepl_set_cookie(m.cookie)

            if all == 0:
                return True


    # virtual methods -- subclass must override these to do useful work

    def syncrepl_set_cookie(self, cookie):
        """
        Called by syncrepl_poll() to store a new cookie provided by the server.
        """
        pass

    def syncrepl_get_cookie(self):
        """
        Called by syncrepl_search() to retrieve the cookie stored by syncrepl_set_cookie()
        """
        pass

    def syncrepl_present(self, uuids, refreshDeletes=False):
        """
        Called by syncrepl_poll() whenever entry UUIDs are presented to the client.
        syncrepl_present() is given a list of entry UUIDs (uuids) and a flag
        (refreshDeletes) which indicates whether the server explicitly deleted
        non-present entries during the refresh operation.

        If called with a list of uuids, the syncrepl_present() implementation
        should record those uuids as present in the directory.

        If called with uuids set to None and refreshDeletes set to False,
        syncrepl_present() should delete all non-present entries from the local
        mirror, and reset the list of recorded uuids.

        If called with uuids set to None and refreshDeletes set to True,
        syncrepl_present() should reset the list of recorded uuids, without
        deleting any entries.
        """
        pass

    def syncrepl_delete(self, uuids):
        """
        Called by syncrepl_poll() to delete entries. A list
        of UUIDs of the entries to be deleted is given in the
        uuids parameter.
        """
        pass

    def syncrepl_entry(self, dn, attrs, uuid):
        """
        Called by syncrepl_poll() for any added or modified entries.

        The provided uuid is used to identify the provided entry in
        any future modification (including dn modification), deletion,
        and presentation operations.
        """
        pass

    def syncrepl_refreshdone(self):
        """
        Called by syncrepl_poll() between refresh and persist phase.

        It indicates that initial synchronization is done and persist phase
        follows.
        """
        pass
