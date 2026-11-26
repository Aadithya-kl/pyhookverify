"""Bounded replay-store, TTL, and cap tests."""

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
