import concurrent.futures
import gc
import os
import sys
import threading

import pytest


def gil_enabled():
    is_enabled = getattr(sys, '_is_gil_enabled', None)
    if is_enabled is None:
        return True
    return is_enabled()


# Record GIL status before we import _ldap
GIL_STARTS_ENABLED = gil_enabled()

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _ldap  # noqa: E402


# loop and thread counts
THREAD_COUNT = int(os.environ.get('PYTHON_LDAP_THREAD_COUNT', '16'))
ITERATIONS = int(os.environ.get('PYTHON_LDAP_THREAD_ITERATIONS', '200'))


class TestFreeThreadingDeclaration:
    def test_gil_stays_disabled(self):
        """Importing _ldap must not re-enable the GIL."""
        assert GIL_STARTS_ENABLED == gil_enabled(), f'importing _ldap changed the GIL state to {gil_enabled()}'


class ThreadedMixin:
    def run_in_threads(self, routine, count=THREAD_COUNT):
        barrier = threading.Barrier(count)
        errors = []

        def worker(index, count):
            try:
                barrier.wait()
                routine(index, count)
            except Exception as exc:  # noqa: BLE001 - the worker must report every thread failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i, count)) for i in range(count)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        if errors:
            raise errors[0]
        gc.collect()


@pytest.mark.skipif(
    not hasattr(concurrent.futures, 'ThreadPoolExecutor'), reason='threaded subinterpreters are not supported'
)
class SubinterpreterMixin:
    def run_in_threads(self, routine, count=THREAD_COUNT):
        # TODO: Might use concurrent.interpreters and its create_queue instead
        # to get tighter concurrency?
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            futures = [executor.submit(routine, i, count) for i in range(count)]
            done, not_done = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_EXCEPTION)
            for future in done:
                # Flush out any exceptions
                future.result()
            # not_done should only have futures in if there was an exception,
            # but result() above didn't raise?
            assert not not_done
        gc.collect()


class Template:
    def test_exceptions_raising(self):
        def keep_raising(index, count):
            import _ldap

            for i in range(ITERATIONS):
                try:
                    raise _ldap.LDAPError
                except _ldap.LDAPError:
                    pass

        self.run_in_threads(keep_raising)

    def test_concurrent_error_objects(self):
        def raise_through_module(index, count):
            import _ldap

            for _ in range(ITERATIONS):
                l = _ldap.initialize('ldap://:0')
                with pytest.raises(_ldap.LDAPError):
                    l.search_ext('cn=test', _ldap.SCOPE_SUBTREE, '(bad=filter')
                    # l.result4(msgid, _ldap.MSG_ALL, 0)
                del l

        self.run_in_threads(raise_through_module)

    def test_ldapobject_creation(self):
        def create_objects(index, count):
            import _ldap

            for i in range(ITERATIONS):
                # A pure initialize() does not touch the network
                _ldap.initialize('ldap://')

        self.run_in_threads(create_objects)


@pytest.mark.skipif(not _ldap.LIBLDAP_R, reason='libldap is not built thread-safe')
@pytest.mark.skipif(GIL_STARTS_ENABLED, reason='free threading not enabled')
class TestFreeThreading(Template, ThreadedMixin):
    pass


@pytest.mark.skipif(not _ldap.LIBLDAP_R, reason='libldap is not built thread-safe')
class TestSubinterpreters(Template, SubinterpreterMixin):
    pass
