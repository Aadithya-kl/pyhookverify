"""Bounded in-memory replay protection with TTL and a hard entry cap."""

import collections
from typing import Callable, Deque, Dict, Optional

from .errors import HookVerifyError, ReplayStore

__all__ = ["MemoryReplayStore", "NullReplayStore"]


class MemoryReplayStore(ReplayStore):
    """LRU-ish bounded replay store.

    Keys are stored only after cryptographic verification succeeds. Expired
    entries are purged on every check; when ``max_entries`` is reached the
    oldest entry is evicted. An attacker who can forge valid signatures would
    already have broken the HMAC, so eviction cannot be used to launder a
    signature without first possessing it.
    """

    def __init__(
        self,
        ttl_seconds: float = 600.0,
        max_entries: int = 4096,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool):
            raise HookVerifyError("invalid_config", "ttl_seconds must be numeric")
        if ttl_seconds <= 0:
            raise HookVerifyError("invalid_config", "ttl_seconds must be positive")
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
            raise HookVerifyError("invalid_config", "max_entries must be a positive integer")
        if clock is not None and not callable(clock):
            raise HookVerifyError("invalid_config", "clock must be callable")
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = max_entries
        self._clock = clock
        self._entries: Dict[str, float] = {}
        self._order: Deque[str] = collections.deque()

    def _now(self, now: Optional[float]) -> float:
        if now is not None:
            return float(now)
        return float(self._clock()) if self._clock is not None else __import__("time").time()

    def purge_expired(self, now: Optional[float] = None) -> None:
        """Drop entries whose TTL elapsed at ``now`` (defaults to clock)."""
        current = self._now(now)
        expired = [key for key, expires in self._entries.items() if expires <= current]
        for key in expired:
            self._entries.pop(key, None)
        if expired:
            self._order = collections.deque(k for k in self._order if k in self._entries)

    def check_and_store(self, key: str, now: Optional[float] = None) -> None:
        """Raise ``HookVerifyError('replay')`` if ``key`` was recently seen."""
        if not isinstance(key, str) or not key:
            raise HookVerifyError("invalid_config", "replay key must be a non-empty string")
        current = self._now(now)
        self.purge_expired(current)
        if key in self._entries:
            raise HookVerifyError("replay", "webhook signature was already consumed")
        if len(self._entries) >= self.max_entries:
            oldest = self._order.popleft()
            self._entries.pop(oldest, None)
        self._entries[key] = current + self.ttl_seconds
        self._order.append(key)

    def __contains__(self, key: object) -> bool:
        return key in self._entries

    def __len__(self) -> int:
        return len(self._entries)


class NullReplayStore(ReplayStore):
    """Test-only store that records keys but never rejects them."""

    def __init__(self) -> None:
        self.keys = []

    def check_and_store(self, key: str, now: Optional[float] = None) -> None:
        self.keys.append(key)

    def purge_expired(self, now: Optional[float] = None) -> None:
        return None

    def __len__(self) -> int:
        return len(self.keys)
