"""Talk to one smart lock over an open P2P station session.

The session (``eufy_home_security.p2p.session.StationSession``) does discovery, the
handshake and the encrypted command channel; this module only knows the lock's own
command protocol on top of it (see :mod:`.protocol`).

How a command goes:

1. :meth:`SmartLockClient.async_set_locked` builds a 1350 frame (see
   :func:`.protocol.build_command`) with the next lock sequence number.
2. The station acknowledges the frame; the lock then answers with a 1351 notify whose
   BLE command code names the command, carrying a return code (0 = done).
3. A lock that disagrees about the sequence number sends a 1916 notify with its own;
   the command is then rebuilt with the corrected number and sent once more.

The lock also pushes NOTIFY frames by itself (keypad, fingerprint, thumb turn,
auto-lock), which update :attr:`SmartLockClient.state` and call the listener.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

from .protocol import (
    CMD_DOORLOCK_P2P_SEQ,
    CMD_SET_PAYLOAD,
    CMD_TRANSFER_PAYLOAD,
    BLE_FOR_COMMAND,
    BleCommand,
    LockReply,
    LockStatus,
    ProtocolError,
    SmartLockCommand,
    build_command,
    decode_reply,
    encode_lock,
    encode_status_query,
)

_LOGGER = logging.getLogger(__name__)

#: How long the lock has to answer one command (it may first have to wake its radio).
REPLY_TIMEOUT = 20.0
#: How long the lock may take to report the new bolt position after a lock command.
SETTLE_TIMEOUT = 15.0
#: How long to wait for the station's receipt of a 1350 frame. Many stations send
#: none; the session then reports the frame delivered once this runs out.
RECEIPT_TIMEOUT = 3.0


class LockSession(Protocol):
    """The part of ``StationSession`` the client uses."""

    async def async_connect(self) -> None: ...

    async def async_close(self) -> None: ...

    async def async_send_json_frame(
        self, command: int, body: Callable[[str], bytes], *, timeout: float | None = None
    ) -> bool: ...

    def add_notify_listener(
        self, callback: Callable[[Mapping[str, Any], Any], None]
    ) -> Callable[[], None]: ...


@dataclass(frozen=True, slots=True)
class LockIdentity:
    """Who the lock is and whom commands are sent as (all from the eufy cloud, once).

    ``admin_user_id`` is the station owner's user id (``member.admin_user_id``);
    ``user_name`` and ``short_user_id`` are this account's nickname and short id at
    the lock (``member.nick_name`` / ``member.short_user_id``), which the lock logs.
    """

    serial: str
    admin_user_id: str
    user_name: str
    short_user_id: str
    channel: int = 0


@dataclass(frozen=True, slots=True)
class LockState:
    status: int | None = None
    battery: int | None = None
    updated_at: float | None = None
    """``time.time()`` of the last status the lock reported."""

    @property
    def is_locked(self) -> bool | None:
        if self.status is None:
            return None
        return self.status == LockStatus.LOCKED

    @property
    def is_jammed(self) -> bool:
        return self.status == LockStatus.JAMMED


class LockCommandError(Exception):
    """The lock answered a command with a non-zero return code."""

    def __init__(self, command: SmartLockCommand, return_code: int) -> None:
        self.command = command
        self.return_code = return_code
        super().__init__(f"lock refused {command.name} (return code {return_code})")


class LockTimeoutError(TimeoutError):
    """The lock did not answer a command in time."""


class _SequenceError(Exception):
    def __init__(self, sequence: int) -> None:
        self.sequence = sequence
        super().__init__(f"lock expects sequence {sequence}")


@dataclass(slots=True)
class _Pending:
    command: BleCommand
    future: asyncio.Future[LockReply] = field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )


class SmartLockClient:
    """One T8520P-family lock behind ``session``."""

    def __init__(
        self,
        session: LockSession,
        identity: LockIdentity,
        *,
        reply_timeout: float = REPLY_TIMEOUT,
    ) -> None:
        self._session = session
        self.identity = identity
        self._reply_timeout = reply_timeout
        self.state = LockState()
        # generateLockSequence: smart locks start from the current time in seconds.
        self._sequence = int(time.time())
        self._pending: _Pending | None = None
        self._command_lock = asyncio.Lock()
        self._listeners: list[Callable[[LockState], None]] = []
        self._unsubscribe: Callable[[], None] | None = None

    # -- lifecycle -----------------------------------------------------------------

    def start(self) -> None:
        """Start listening to the session's notifies (no I/O)."""
        if self._unsubscribe is None:
            self._unsubscribe = self._session.add_notify_listener(self._on_notify)

    async def async_stop(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if self._pending is not None and not self._pending.future.done():
            self._pending.future.cancel()

    def add_listener(self, callback: Callable[[LockState], None]) -> Callable[[], None]:
        """Call ``callback(state)`` whenever the lock reports its status."""
        self._listeners.append(callback)

        def remove() -> None:
            with contextlib.suppress(ValueError):
                self._listeners.remove(callback)

        return remove

    # -- commands ------------------------------------------------------------------

    async def async_refresh(self) -> LockState:
        """Ask the lock for its bolt position and battery."""
        ident = self.identity
        await self._async_command(
            SmartLockCommand.QUERY_STATUS_IN_LOCK,
            lambda: encode_status_query(ident.admin_user_id),
        )
        return self.state

    async def async_set_locked(self, locked: bool) -> LockState:
        """Lock or unlock, then wait (up to :data:`SETTLE_TIMEOUT`) for the new status.

        Raises :class:`LockCommandError` when the lock refuses and
        :class:`LockTimeoutError` when it does not answer. A lock that accepted the
        command but reports no new status in time is asked once more.
        """
        ident = self.identity
        want = LockStatus.LOCKED if locked else LockStatus.UNLOCKED
        settled = asyncio.Event()

        def watch(state: LockState) -> None:
            if state.status in (want, LockStatus.JAMMED):
                settled.set()

        remove = self.add_listener(watch)
        try:
            await self._async_command(
                SmartLockCommand.ON_OFF_LOCK,
                lambda: encode_lock(
                    ident.admin_user_id, locked, ident.user_name, ident.short_user_id
                ),
            )
            try:
                await asyncio.wait_for(settled.wait(), SETTLE_TIMEOUT)
            except TimeoutError:
                await self.async_refresh()
        finally:
            remove()
        return self.state

    async def _async_command(
        self, command: SmartLockCommand, body: Callable[[], bytes]
    ) -> LockReply:
        """Send one command and return the lock's reply (serialised: the lock's
        replies name the command but carry no request id)."""
        async with self._command_lock:
            for attempt in range(2):
                try:
                    reply = await self._async_send_once(command, body())
                except _SequenceError as err:
                    if attempt:
                        raise LockCommandError(command, -1) from err
                    _LOGGER.debug("lock asked for sequence %d; resending", err.sequence)
                    continue
                if reply.return_code != 0:
                    raise LockCommandError(command, reply.return_code)
                return reply
        raise AssertionError("unreachable")

    async def _async_send_once(self, command: SmartLockCommand, data: bytes) -> LockReply:
        ident = self.identity
        self._sequence += 1
        frame = build_command(
            serial=ident.serial,
            admin_user_id=ident.admin_user_id,
            command=command,
            data=data,
            sequence=self._sequence,
            channel=ident.channel,
        )
        pending = _Pending(BLE_FOR_COMMAND[command])
        self._pending = pending
        try:
            _LOGGER.debug("lock: send %s seq %d", command.name, self._sequence)
            # The station's receipt (or lack of one) says nothing about the lock: the
            # answer that counts is the lock's own notify, which may arrive while the
            # session is still waiting for the receipt. Only a frame the station never
            # acknowledged at all raises here.
            send = asyncio.create_task(
                self._session.async_send_json_frame(
                    CMD_SET_PAYLOAD,
                    lambda _account: frame,
                    timeout=min(RECEIPT_TIMEOUT, self._reply_timeout),
                )
            )
            # A send left running after the answer came must not log "never retrieved".
            send.add_done_callback(lambda task: task.cancelled() or task.exception())
            started = time.monotonic()
            done, _ = await asyncio.wait(
                {pending.future, send},
                timeout=self._reply_timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if send in done and pending.future not in done:
                send.result()  # raises when the station never acknowledged the frame
                left = max(self._reply_timeout - (time.monotonic() - started), 0.1)
                done, _ = await asyncio.wait({pending.future}, timeout=left)
            if pending.future not in done:
                raise LockTimeoutError(f"lock did not answer {command.name}")
            return pending.future.result()
        finally:
            if self._pending is pending:
                self._pending = None

    # -- inbound -------------------------------------------------------------------

    def _on_notify(self, obj: Mapping[str, Any], _cipher: Any) -> None:
        cmd = obj.get("cmd")
        payload = obj.get("payload")
        if not isinstance(payload, Mapping):
            return
        if cmd == CMD_DOORLOCK_P2P_SEQ:
            self._on_sequence(payload)
        elif cmd == CMD_TRANSFER_PAYLOAD:
            self._on_transfer(payload)

    def _on_sequence(self, payload: Mapping[str, Any]) -> None:
        seq = payload.get("seq_num")
        if not isinstance(seq, int):
            return
        self._sequence = seq  # the next send adds one, as eufy does (seq_num + 1)
        lock_cmd = payload.get("lock_cmd")
        pending = self._pending
        if isinstance(lock_cmd, int) and lock_cmd > 0 and pending is not None:
            if not pending.future.done():
                pending.future.set_exception(_SequenceError(seq + 1))

    def _on_transfer(self, payload: Mapping[str, Any]) -> None:
        ident = self.identity
        dev_sn = payload.get("dev_sn")
        if isinstance(dev_sn, str) and dev_sn and dev_sn != ident.serial:
            return
        try:
            reply = decode_reply(dict(payload), ident.admin_user_id, ident.serial)
        except ProtocolError as err:
            _LOGGER.debug("lock: undecodable notify: %s", err)
            return
        if reply is None:
            _LOGGER.debug("lock: partial frame ignored")
            return
        _LOGGER.debug(
            "lock: reply %s code %d", reply.command or reply.command_code, reply.return_code
        )
        # A status answer counts only when it succeeded; a pushed NOTIFY always does
        # (eufy-security-client applies both unconditionally).
        if reply.status is not None and (
            reply.return_code == 0 or reply.command is BleCommand.NOTIFY
        ):
            self._update(status=reply.status, battery=reply.battery)
        pending = self._pending
        if (
            pending is not None
            and not pending.future.done()
            and reply.command == pending.command
        ):
            pending.future.set_result(reply)

    def _update(self, *, status: int, battery: int | None) -> None:
        self.state = replace(
            self.state,
            status=status,
            battery=battery if battery else self.state.battery,
            updated_at=time.time(),
        )
        for callback in list(self._listeners):
            try:
                callback(self.state)
            except Exception:
                _LOGGER.exception("lock state listener failed")


__all__ = [
    "LockCommandError",
    "LockIdentity",
    "LockSession",
    "LockState",
    "LockTimeoutError",
    "SmartLockClient",
]
