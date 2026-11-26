"""Bounded replay-store, TTL, cap, and concurrency tests."""

import sys
import threading
import unittest

from pyhookverify import HookVerifyError, MemoryReplayStore, NullReplayStore


class MemoryReplayStoreTests(unittest.TestCase):
    def test_first_seen_accepted(self):
        store = MemoryReplayStore(clock=lambda: 100.0)
        store.check_and_store("key", 100.0)
        self.assertEqual(len(store), 1)

    def test_replay_rejected(self):
        store = MemoryReplayStore(clock=lambda: 100.0)
        store.check_and_store("key", 100.0)
        with self.assertRaises(HookVerifyError) as cm:
            store.check_and_store("key", 101.0)
        self.assertEqual(cm.exception.code, "replay")

    def test_distinct_keys(self):
        store = MemoryReplayStore(clock=lambda: 100.0)
        store.check_and_store("a", 100.0)
        store.check_and_store("b", 100.0)
        self.assertEqual(len(store), 2)

    def test_ttl_expiry(self):
        store = MemoryReplayStore(ttl_seconds=10, clock=lambda: 100.0)
        store.check_and_store("key", 100.0)
        self.assertEqual(len(store), 1)
        # At exactly the TTL boundary the entry expires; a fresh entry can be stored.
        store.check_and_store("key", 110.0)
        self.assertEqual(len(store), 1)

    def test_purge_expired(self):
        store = MemoryReplayStore(ttl_seconds=10, clock=lambda: 100.0)
        store.check_and_store("key", 100.0)
        store.purge_expired(111.0)
        self.assertEqual(len(store), 0)

    def test_cap_evicts_oldest(self):
        store = MemoryReplayStore(ttl_seconds=1000, max_entries=2, clock=lambda: 100.0)
        store.check_and_store("a", 100.0)
        store.check_and_store("b", 101.0)
        store.check_and_store("c", 102.0)
        self.assertEqual(len(store), 2)
        self.assertNotIn("a", store)
        self.assertIn("b", store)
        self.assertIn("c", store)

    def test_evicted_oldest_can_be_replayed(self):
        store = MemoryReplayStore(ttl_seconds=1000, max_entries=1, clock=lambda: 100.0)
        store.check_and_store("a", 100.0)
        store.check_and_store("b", 101.0)
        store.check_and_store("a", 102.0)

    def test_zero_ttl_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            MemoryReplayStore(ttl_seconds=0)
        self.assertEqual(cm.exception.code, "invalid_config")

    def test_negative_ttl_rejected(self):
        with self.assertRaises(HookVerifyError):
            MemoryReplayStore(ttl_seconds=-1)

    def test_zero_cap_rejected(self):
        with self.assertRaises(HookVerifyError):
            MemoryReplayStore(max_entries=0)

    def test_bool_cap_rejected(self):
        with self.assertRaises(HookVerifyError):
            MemoryReplayStore(max_entries=True)

    def test_bad_clock_rejected(self):
        with self.assertRaises(HookVerifyError):
            MemoryReplayStore(clock=123)

    def test_empty_key_rejected(self):
        store = MemoryReplayStore()
        with self.assertRaises(HookVerifyError):
            store.check_and_store("", 100.0)

    def test_non_string_key_rejected(self):
        store = MemoryReplayStore()
        with self.assertRaises(HookVerifyError):
            store.check_and_store(1, 100.0)

    def test_default_clock_works(self):
        store = MemoryReplayStore(ttl_seconds=1000)
        store.check_and_store("key")
        self.assertEqual(len(store), 1)

    def test_expired_entry_is_not_contained(self):
        now = [100.0]
        store = MemoryReplayStore(ttl_seconds=10, clock=lambda: now[0])
        store.check_and_store("key", 100.0)
        self.assertIn("key", store)
        now[0] = 111.0
        self.assertNotIn("key", store)


class MemoryReplayStoreConcurrencyTests(unittest.TestCase):
    def test_concurrent_purge_and_store_keeps_the_store_consistent(self):
        # Without a lock, purge_expired iterates the entry dict while another
        # thread resizes it, which raises RuntimeError and aborts the request.
        previous_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)
        try:
            store = MemoryReplayStore(ttl_seconds=10.0, max_entries=5000)
            for index in range(400):
                store.check_and_store("seed-%d" % index, 0.0)
            barrier = threading.Barrier(6)
            errors = []
            errors_lock = threading.Lock()

            def record(error):
                with errors_lock:
                    errors.append(error)

            def writer(worker):
                try:
                    barrier.wait()
                    for index in range(400):
                        store.check_and_store("w%d-%d" % (worker, index), 0.0)
                except BaseException as exc:  # noqa: BLE001 - surfaced below
                    record(exc)

            def purger():
                try:
                    barrier.wait()
                    for _ in range(400):
                        store.purge_expired(0.0)
                except BaseException as exc:  # noqa: BLE001 - surfaced below
                    record(exc)

            threads = [threading.Thread(target=writer, args=(worker,)) for worker in range(3)]
            threads += [threading.Thread(target=purger) for _ in range(3)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(errors, [])
            self.assertLessEqual(len(store), store.max_entries)
        finally:
            sys.setswitchinterval(previous_interval)

    def test_concurrent_duplicate_keys_are_consumed_once(self):
        store = MemoryReplayStore(ttl_seconds=600.0, max_entries=1024)
        barrier = threading.Barrier(8)
        outcomes = []
        outcomes_lock = threading.Lock()

        def worker():
            barrier.wait()
            try:
                store.check_and_store("shared-key", 1000.0)
                outcome = "stored"
            except HookVerifyError as exc:
                outcome = exc.code
            with outcomes_lock:
                outcomes.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(outcomes.count("stored"), 1)
        self.assertEqual(outcomes.count("replay"), 7)


class NullReplayStoreTests(unittest.TestCase):
    def test_records_without_rejecting(self):
        store = NullReplayStore()
        store.check_and_store("a", 1.0)
        store.check_and_store("a", 2.0)
        self.assertEqual(store.keys, ["a", "a"])

    def test_len(self):
        store = NullReplayStore()
        store.check_and_store("a")
        self.assertEqual(len(store), 1)


if __name__ == "__main__":
    unittest.main()
