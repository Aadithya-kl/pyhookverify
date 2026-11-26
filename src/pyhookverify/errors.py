"""Core value types and errors for pyhookverify.

This module deliberately depends only on the Python standard library.
"""

from dataclasses import dataclass
from typing import Mapping, Optional, Sequence, Union

HeaderValue = Union[str, Sequence[str]]
Headers = Mapping[str, HeaderValue]

__all__ = [
    "HookVerifyError",
    "VerificationResult",
    "ReplayStore",
    "HeaderValue",
    "Headers",
]


class HookVerifyError(Exception):
    """Raised for every malformed input, bad signature, or replayed request.

    ``code`` is a stable machine-readable value so framework adapters can map
    failures to HTTP status codes without parsing exception text.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return "%s: %s" % (self.code, self.message)

    def __repr__(self) -> str:
        return "HookVerifyError(code=%r, message=%r)" % (self.code, self.message)


@dataclass(frozen=True)
class VerificationResult:
    """Successful verification result.

    ``provider`` is the registered provider name, ``secret_index`` identifies
    which rotation secret matched, and ``timestamp`` is the parsed event
    timestamp when the provider supplies one.
    """

    provider: str
    secret_index: int
    timestamp: Optional[int] = None
    signature: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "provider": self.provider,
            "secret_index": self.secret_index,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }


class ReplayStore:
    """Interface for replay stores passed to :class:`WebhookVerifier`."""

    def check_and_store(self, key: str, now: float) -> None:
        """Raise ``HookVerifyError('replay')`` when ``key`` was already seen."""
        raise NotImplementedError

    def purge_expired(self, now: float) -> None:
        """Remove expired entries (optional for custom stores)."""
        return None

    def __len__(self) -> int:
        raise NotImplementedError

