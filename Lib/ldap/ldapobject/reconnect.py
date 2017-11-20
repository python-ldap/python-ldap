"""
ldap.ldapobject.reconnect - wraps class ldap.ldapobject.SimpleLDAPObject
to implement automatic reconnects for synchronous operations

See https://www.python-ldap.org/ for details.
"""

import sys
import time

import _ldap
from ldap.pkginfo import __version__, __author__, __license__
import ldap
from ldap.ldapobject.simple import SimpleLDAPObject


__all__ = [
    'ReconnectLDAPObject',
]


class ReconnectLDAPObject(SimpleLDAPObject):
    """
    In case of server failure (ldap.SERVER_DOWN) the implementations
    of all synchronous operation methods (search_s() etc.) are doing
    an automatic reconnect and rebind and will retry the very same
    operation.

    This is very handy for broken LDAP server implementations
    (e.g. in Lotus Domino) which drop connections very often making
    it impossible to have a long-lasting control flow in the
    application.
    """

    __transient_attrs__ = set([
        '_l',
        '_ldap_object_lock',
        '_trace_file',
        '_reconnect_lock',
        '_last_bind',
    ])

    def __init__(
            self,
            uri,
            trace_level=0, trace_file=None, trace_stack_limit=5,
            retry_max=1, retry_delay=60.0
        ):
        """
        Parameters like SimpleLDAPObject.__init__() with these
        additional arguments:

        retry_max
            Maximum count of reconnect trials
        retry_delay
            Time span to wait between two reconnect trials
        """
        self._uri = uri
        self._options = []
        self._last_bind = None
        SimpleLDAPObject.__init__(self, uri, trace_level, trace_file, trace_stack_limit)
        self._reconnect_lock = ldap.LDAPLock(desc='reconnect lock within %r' % self)
        self._retry_max = retry_max
        self._retry_delay = retry_delay
        self._start_tls = 0
        self._reconnects_done = 0L

    def __getstate__(self):
        """
        return data representation for pickled object
        """
        state = dict([
            (key, val)
            for key, val in self.__dict__.items()
            if key not in self.__transient_attrs__
        ])
        state['_last_bind'] = (
            self._last_bind[0].__name__,
            self._last_bind[1],
            self._last_bind[2],
        )
        return state

    def __setstate__(self, data):
        """
        set up the object from pickled data
        """
        self.__dict__.update(data)
        self._last_bind = (
            getattr(SimpleLDAPObject, self._last_bind[0]),
            self._last_bind[1],
            self._last_bind[2],
        )
        self._ldap_object_lock = self._ldap_lock()
        self._reconnect_lock = ldap.LDAPLock(desc='reconnect lock within %r' % (self))
        self._trace_file = sys.stdout
        self.reconnect(self._uri)

    def _store_last_bind(self, method, *args, **kwargs):
        self._last_bind = (method, args, kwargs)

    def _apply_last_bind(self):
        if self._last_bind != None:
            func, args, kwargs = self._last_bind
            func(self, *args, **kwargs)
        else:
            # Send explicit anon simple bind request to provoke
            # ldap.SERVER_DOWN in method reconnect()
            SimpleLDAPObject.simple_bind_s(self, '', '')

    def _restore_options(self):
        """
        Restore all recorded options
        """
        for key, val in self._options:
            SimpleLDAPObject.set_option(self, key, val)

    def passwd_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.passwd_s, *args, **kwargs)

    def reconnect(self, uri, retry_max=1, retry_delay=60.0):
        """
        Drop and clean up old connection completely and reconnect
        """
        self._reconnect_lock.acquire()
        try:
            reconnect_counter = retry_max
            while reconnect_counter:
                counter_text = '%d. (of %d)' % (retry_max-reconnect_counter+1, retry_max)
                if __debug__ and self._trace_level >= 1:
                    self._trace_file.write('*** Trying %s reconnect to %s...\n' % (
                        counter_text, uri
                    ))
                try:
                    # Do the connect
                    self._l = ldap.functions._ldap_function_call(
                        ldap._ldap_module_lock,
                        _ldap.initialize,
                        uri
                    )
                    self._restore_options()
                    # StartTLS extended operation in case this was called before
                    if self._start_tls:
                        SimpleLDAPObject.start_tls_s(self)
                    # Repeat last simple or SASL bind
                    self._apply_last_bind()
                except (ldap.SERVER_DOWN, ldap.TIMEOUT) as ldap_error:
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write('*** %s reconnect to %s failed\n' % (
                            counter_text, uri
                        ))
                    reconnect_counter = reconnect_counter-1
                    if not reconnect_counter:
                        raise ldap_error
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write('=> delay %s...\n' % (retry_delay))
                    time.sleep(retry_delay)
                    SimpleLDAPObject.unbind_s(self)
                else:
                    if __debug__ and self._trace_level >= 1:
                        self._trace_file.write(
                            '*** %s reconnect to %s successful => repeat last operation\n' % (
                                counter_text,
                                uri,
                            )
                        )
                    self._reconnects_done = self._reconnects_done + 1L
                    break
        finally:
            self._reconnect_lock.release()
        return # reconnect()

    def _apply_method_s(self, func, *args, **kwargs):
        if not hasattr(self, '_l'):
            self.reconnect(self._uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
        try:
            return func(self, *args, **kwargs)
        except ldap.SERVER_DOWN:
            SimpleLDAPObject.unbind_s(self)
            # Try to reconnect
            self.reconnect(self._uri, retry_max=self._retry_max, retry_delay=self._retry_delay)
            # Re-try last operation
            return func(self, *args, **kwargs)

    def set_option(self, option, invalue):
        self._options.append((option, invalue))
        return SimpleLDAPObject.set_option(self, option, invalue)

    def bind_s(self, *args, **kwargs):
        res = self._apply_method_s(SimpleLDAPObject.bind_s, *args, **kwargs)
        self._store_last_bind(SimpleLDAPObject.bind_s, *args, **kwargs)
        return res

    def simple_bind_s(self, *args, **kwargs):
        res = self._apply_method_s(SimpleLDAPObject.simple_bind_s, *args, **kwargs)
        self._store_last_bind(SimpleLDAPObject.simple_bind_s, *args, **kwargs)
        return res

    def start_tls_s(self, *args, **kwargs):
        res = self._apply_method_s(SimpleLDAPObject.start_tls_s, *args, **kwargs)
        self._start_tls = 1
        return res

    def sasl_interactive_bind_s(self, *args, **kwargs):
        """
        sasl_interactive_bind_s(who, auth) -> None
        """
        res = self._apply_method_s(SimpleLDAPObject.sasl_interactive_bind_s, *args, **kwargs)
        self._store_last_bind(SimpleLDAPObject.sasl_interactive_bind_s, *args, **kwargs)
        return res

    def sasl_bind_s(self, *args, **kwargs):
        res = self._apply_method_s(SimpleLDAPObject.sasl_bind_s, *args, **kwargs)
        self._store_last_bind(SimpleLDAPObject.sasl_bind_s, *args, **kwargs)
        return res

    def add_ext_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.add_ext_s, *args, **kwargs)

    def cancel_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.cancel_s, *args, **kwargs)

    def compare_ext_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.compare_ext_s, *args, **kwargs)

    def delete_ext_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.delete_ext_s, *args, **kwargs)

    def extop_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.extop_s, *args, **kwargs)

    def modify_ext_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.modify_ext_s, *args, **kwargs)

    def rename_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.rename_s, *args, **kwargs)

    def search_ext_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.search_ext_s, *args, **kwargs)

    def whoami_s(self, *args, **kwargs):
        return self._apply_method_s(SimpleLDAPObject.whoami_s, *args, **kwargs)
