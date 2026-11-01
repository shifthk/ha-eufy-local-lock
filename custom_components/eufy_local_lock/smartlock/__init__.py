"""The eufy smart-lock protocol, independent of Home Assistant (unit-testable alone)."""

from .client import (
    LockCommandError,
    LockIdentity,
    LockSession,
    LockState,
    LockTimeoutError,
    SmartLockClient,
)
from .protocol import LockStatus, is_smart_lock_t8520p

__all__ = [
    "LockCommandError",
    "LockIdentity",
    "LockSession",
    "LockState",
    "LockStatus",
    "LockTimeoutError",
    "SmartLockClient",
    "is_smart_lock_t8520p",
]
