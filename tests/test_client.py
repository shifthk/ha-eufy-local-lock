"""The client against a fake station session that plays the lock."""

import asyncio
import json

import pytest

from smartlock.client import (
    LockCommandError,
    LockIdentity,
    LockTimeoutError,
    SmartLockClient,
)
from smartlock.protocol import (
    CMD_DOORLOCK_P2P_SEQ,
    CMD_SET_PAYLOAD,
    CMD_TRANSFER_PAYLOAD,
    BleCommand,
    LockStatus,
    ParsePayload,
    aes_key,
    decrypt,
    lock_iv,
    parse_ble_frame,
)
from test_protocol import SERIAL, USER, lock_notify

IDENTITY = LockIdentity(serial=SERIAL, admin_user_id=USER, user_name="Alex", short_user_id="0003")


class FakeLock:
    """A ``LockSession`` whose station forwards to a scripted lock."""

    def __init__(self) -> None:
        self.listeners = []
        self.sent: list[dict] = []
        self.status = LockStatus.LOCKED
        self.battery = 67
        self.script: list = []  # per-send overrides: callables(body) -> notifies
        self.connects = 0

    async def async_connect(self) -> None:
        self.connects += 1

    async def async_close(self) -> None:
        pass

    def add_notify_listener(self, callback):
        self.listeners.append(callback)
        return lambda: self.listeners.remove(callback)

    def push(self, obj: dict) -> None:
        for listener in list(self.listeners):
            listener(obj, None)

    async def async_send_json_frame(self, command, body, *, timeout=None):
        assert command == CMD_SET_PAYLOAD
        obj = json.loads(body(USER))
        self.sent.append(obj)
        if self.script:
            notifies = self.script.pop(0)(obj)
        else:
            notifies = self.answer(obj)
        loop = asyncio.get_running_loop()
        for delay, notify in notifies:
            loop.call_later(delay, self.push, notify)
        return True

    def answer(self, obj: dict) -> list:
        frame = parse_ble_frame(bytes.fromhex(obj["payload"]["lock_payload"]))
        data = ParsePayload(
            decrypt(frame.data, aes_key(USER, obj["payload"]["time"]), lock_iv(SERIAL))
        )
        if frame.command_code == BleCommand.QUERY_STATUS_IN_LOCK:
            return [(0.01, self.status_notify(BleCommand.QUERY_STATUS_IN_LOCK))]
        if frame.command_code == BleCommand.ON_OFF_LOCK:
            self.status = LockStatus.LOCKED if data.read_data(-93) == b"\x00" else LockStatus.UNLOCKED
            return [
                (0.01, transfer(lock_notify(BleCommand.ON_OFF_LOCK, 0))),
                (0.05, self.status_notify(BleCommand.NOTIFY)),
            ]
        raise AssertionError(f"unexpected command {frame.command_code}")

    def status_notify(self, command: BleCommand) -> dict:
        return transfer(lock_notify(command, 0, bytes([self.battery]), bytes([self.status])))


def transfer(payload: dict) -> dict:
    return {"cmd": CMD_TRANSFER_PAYLOAD, "payload": payload}


@pytest.fixture
def lock():
    return FakeLock()


@pytest.fixture
def client(lock):
    client = SmartLockClient(lock, IDENTITY, reply_timeout=0.5)
    client.start()
    return client


async def test_refresh_reads_status_and_battery(client, lock):
    state = await client.async_refresh()
    assert state.is_locked is True
    assert state.battery == 67
    assert lock.sent[0]["payload"]["apiCommand"] == 6012


async def test_unlock_then_lock(client, lock):
    seen = []
    client.add_listener(lambda state: seen.append(state.status))
    state = await client.async_set_locked(False)
    assert state.is_locked is False
    state = await client.async_set_locked(True)
    assert state.is_locked is True
    assert seen == [LockStatus.UNLOCKED, LockStatus.LOCKED]
    seqs = [obj["payload"]["seq_num"] for obj in lock.sent]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


async def test_unsolicited_notify_updates_state(client, lock):
    seen = []
    client.add_listener(lambda state: seen.append(state))
    lock.status = LockStatus.UNLOCKED
    lock.push(lock.status_notify(BleCommand.NOTIFY))
    assert client.state.is_locked is False
    assert seen and seen[-1].battery == 67


async def test_notify_for_another_lock_is_ignored(client, lock):
    notify = lock.status_notify(BleCommand.NOTIFY)
    notify["payload"]["dev_sn"] = "T8520K9999999999"
    lock.push(notify)
    assert client.state.status is None


async def test_refused_command_raises(client, lock):
    lock.script.append(lambda obj: [(0.01, transfer(lock_notify(BleCommand.ON_OFF_LOCK, 2)))])
    with pytest.raises(LockCommandError) as err:
        await client.async_set_locked(False)
    assert err.value.return_code == 2


async def test_silent_lock_times_out(client, lock):
    lock.script.append(lambda obj: [])
    with pytest.raises(LockTimeoutError):
        await client.async_refresh()


async def test_sequence_error_resends_with_the_locks_number(client, lock):
    def wrong_sequence(obj):
        return [(0.01, {"cmd": CMD_DOORLOCK_P2P_SEQ, "payload": {"seq_num": 5000, "lock_cmd": 34}})]

    lock.script.append(wrong_sequence)
    state = await client.async_refresh()
    assert state.is_locked is True
    assert [obj["payload"]["seq_num"] for obj in lock.sent][1] == 5001


async def test_garbage_notifies_do_not_break_anything(client, lock):
    lock.push({"cmd": CMD_TRANSFER_PAYLOAD, "payload": {"lock_payload": "zz"}})
    lock.push({"cmd": CMD_TRANSFER_PAYLOAD, "payload": "nope"})
    lock.push({"cmd": 9999, "payload": {}})
    assert (await client.async_refresh()).is_locked is True


async def test_reply_during_a_receipt_wait_is_not_lost(lock):
    """A station that sends no receipt makes the session wait its timeout; the lock's
    answer, arriving meanwhile, must still complete the command."""

    class SlowReceipt(FakeLock):
        async def async_send_json_frame(self, command, body, *, timeout=None):
            await super().async_send_json_frame(command, body, timeout=timeout)
            await asyncio.sleep(timeout)  # no receipt: wait it out, then "delivered"
            return False

    slow = SlowReceipt()
    client = SmartLockClient(slow, IDENTITY, reply_timeout=0.5)
    client.start()
    loop = asyncio.get_running_loop()
    started = loop.time()
    assert (await client.async_refresh()).is_locked is True
    assert loop.time() - started < 0.3


async def test_unacknowledged_frame_raises_the_sessions_error(lock):
    class NoAck(FakeLock):
        async def async_send_json_frame(self, command, body, *, timeout=None):
            raise ConnectionError("station did not acknowledge")

    client = SmartLockClient(NoAck(), IDENTITY, reply_timeout=0.5)
    client.start()
    with pytest.raises(ConnectionError):
        await client.async_refresh()


async def test_a_lock_that_reports_late_is_asked_again(client, lock, monkeypatch):
    import smartlock.client as module

    monkeypatch.setattr(module, "SETTLE_TIMEOUT", 0.05)

    def accepted_but_quiet(obj):
        lock.status = LockStatus.UNLOCKED
        return [(0.01, transfer(lock_notify(BleCommand.ON_OFF_LOCK, 0)))]

    lock.script.append(accepted_but_quiet)
    state = await client.async_set_locked(False)
    assert state.is_locked is False
    assert [obj["payload"]["apiCommand"] for obj in lock.sent] == [6018, 6012]
