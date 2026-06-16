import concurrent.futures
import gc
import os
import sys
import threading
import unittest


def gil_enabled():
    is_enabled = getattr(sys, '_is_gil_enabled', None)
    if is_enabled is None:
        return True
    return is_enabled()


# Record GIL status before we import _ldap
GIL_STARTS_ENABLED = gil_enabled()

# Switch off processing .ldaprc or ldap.conf before importing _ldap
os.environ['LDAPNOINIT'] = '1'

import _ldap  # noqa: E402 - GIL_STARTS_ENABLED above

# loop and thread counts
THREAD_COUNT = int(os.environ.get('PYTHON_LDAP_THREAD_COUNT', '16'))
ITERATIONS = int(os.environ.get('PYTHON_LDAP_THREAD_ITERATIONS', '200'))


class TestFreeThreadingDeclaration(unittest.TestCase):
    def test_gil_stays_disabled(self):
        """Importing _ldap must not re-enable the GIL."""
        self.assertEqual(
            GIL_STARTS_ENABLED,
            gil_enabled(),
            f"importing _ldap changed the GIL state to {gil_enabled()}"
        )


class ThreadedMixin:
    def run_in_threads(self, routine, count=THREAD_COUNT):
        barrier = threading.Barrier(count)
        errors = []

        def worker(index, count):
            try:
                barrier.wait()
                routine(index, count)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i, count))
                   for i in range(count)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        if errors:
            raise errors[0]
        gc.collect()


@unittest.skipUnless(
    hasattr(concurrent.futures, 'ThreadPoolExecutor'),
    "threaded subinterpreters are not supported"
)
class SubinterpreterMixin:
    def run_in_threads(self, routine, count=THREAD_COUNT):
        # TODO: Might use concurrent.interpreters and its create_queue instead
        # to get tighter concurrency?
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) \
                as executor:
            futures = [executor.submit(routine, i, count)
                       for i in range(count)]
            done, not_done = concurrent.futures.wait(
                    futures, return_when=concurrent.futures.FIRST_EXCEPTION)
            for future in done:
                # Flush out any exceptions
                future.result()
            # not_done should only have futures in if there was an exception,
            # but result() above didn't raise?
            self.assertFalse(not_done)
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

    def test_ldapobject_creation(self):
        def create_objects(index, count):
            import _ldap
            for i in range(ITERATIONS):
                # A pure initialize() does not touch the network
                _ldap.initialize("ldap://")

        self.run_in_threads(create_objects)


@unittest.skipUnless(
    _ldap.LIBLDAP_R,
    "libldap is not built thread-safe"
)
@unittest.skipIf(
    GIL_STARTS_ENABLED,
    "free threading not enabled"
)
class TestFreeThreading(Template, ThreadedMixin, unittest.TestCase):
    pass


@unittest.skipUnless(
    _ldap.LIBLDAP_R,
    "libldap is not built thread-safe"
)
class TestSubinterpreters(Template, SubinterpreterMixin, unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()
