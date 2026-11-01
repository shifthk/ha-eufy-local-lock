"""Wire format of the eufy "smart lock" family (T8520P and relatives) over P2P.

A port of the T8520P path of bropat/eufy-security-client (MIT):
``getSmartLockP2PCommand`` and ``generateSmartLockAESKey`` in ``src/p2p/utils.ts``,
``BleCommandFactory`` in ``src/p2p/ble.ts``, ``WritePayload``/``ParsePayload`` in
``src/http/utils.ts`` and the ``Lock.encodeCmdSmartLock*`` encoders in
``src/http/device.ts``.

The lock speaks a BLE-style command protocol tunnelled through the station's P2P
command channel:

* The app sends a 1350 (``CMD_SET_PAYLOAD``) JSON frame whose ``cmd`` is 1940
  (``CMD_TRANSFER_PAYLOAD``) and whose ``payload.lock_payload`` is a hex BLE frame.
* The BLE frame's data is AES-128-CBC encrypted. The key is the last 12 characters of
  the station owner's user id followed by a 4-byte big-endian "time" that travels in
  the clear next to it; the IV is the lock's serial, zero-padded to 16 bytes.
* The lock answers, and reports changes (keypad, fingerprint, thumb turn), with 1351
  notifies of the same shape.

Nothing here does I/O; it is all pure functions over bytes.
"""

from __future__ import annotations

import json
import random
import struct
import time
from dataclasses import dataclass
from enum import IntEnum

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#: P2P frame type of an app->station JSON command.
CMD_SET_PAYLOAD = 1350
#: P2P frame type of a station->app JSON notify.
CMD_NOTIFY_PAYLOAD = 1351
#: The nested ``cmd`` that carries a smart-lock BLE frame, both ways.
CMD_TRANSFER_PAYLOAD = 1940
#: The nested ``cmd`` of the lock's "your sequence number is wrong" notify.
CMD_DOORLOCK_P2P_SEQ = 1916

#: ``Lock.VERSION_CODE_SMART_LOCK``.
VERSION_CODE_SMART_LOCK = 3

BLE_HEADER = b"\xff\x09"


class FunctionType(IntEnum):
    """``SmartLockFunctionType``: which BLE command table a frame's code is from."""

    TYPE_1 = 1
    TYPE_2 = 2


class SmartLockCommand(IntEnum):
    """``SmartLockCommand``: the app-level command id (``payload.apiCommand``)."""

    CALIBRATE_LOCK = 6017
    QUERY_STATUS_IN_LOCK = 6012
    ON_OFF_LOCK = 6018
    SET_LOCK_PARAM = 6015
    GET_LOCK_PARAM = 6016
    NOTIFY = 142


class BleCommand(IntEnum):
    """``SmartLockBleCommandFunctionType2``: the code inside a type-2 BLE frame."""

    CALIBRATE_LOCK = 33
    QUERY_STATUS_IN_LOCK = 34
    ON_OFF_LOCK = 35
    SET_LOCK_PARAM = 52
    GET_LOCK_PARAM = 53
    NOTIFY = 74


BLE_FOR_COMMAND: dict[SmartLockCommand, BleCommand] = {
    command: BleCommand[command.name] for command in SmartLockCommand
}


class LockStatus(IntEnum):
    """``CMD_SMARTLOCK_QUERY_STATUS`` values (eufy names only these three)."""

    UNLOCKED = 3
    LOCKED = 4
    JAMMED = 5
    """eufy's "Mechanical anomaly": the bolt did not reach either end."""


#: ``BleParameterIndex``: the tag of each field in a TLV payload, as signed bytes.
PARAM_ONE = -95
PARAM_TWO = -94


class ProtocolError(ValueError):
    """A frame or payload that does not decode."""


# -- model -------------------------------------------------------------------------


def is_smart_lock_t8520p(serial: str) -> bool:
    """``Device.isLockWifiT8520P`` by serial: a T8520 whose seventh character is 9.

    (eufy also checks ``device_type == LOCK_WIFI``; the serial alone is what tells the
    newer "P" hardware, which speaks this protocol, from the original T8520.)
    """
    return serial.startswith("T8520") and len(serial) > 6 and serial[6] == "9"


# -- crypto ------------------------------------------------------------------------


def smart_lock_time(now: float | None = None) -> int:
    """``getSmartLockCurrentTimeInSeconds``: seconds OR a random 0..99 (as 32 bits).

    The value only salts the key, so the OR's "jitter" is faithful, not meaningful.
    """
    seconds = int(time.time() if now is None else now)
    return (seconds | random.randrange(100)) & 0xFFFFFFFF


def aes_key(admin_user_id: str, lock_time: int) -> bytes:
    """``generateSmartLockAESKey``: user id's last 12 chars + big-endian u32 time."""
    key = admin_user_id[-12:].encode() + struct.pack(">I", lock_time & 0xFFFFFFFF)
    if len(key) != 16:
        raise ProtocolError("the owner's user id must be at least 12 characters")
    return key


def lock_iv(serial: str) -> bytes:
    """``getLockVectorBytes``: the serial's bytes, zero-padded to 16."""
    raw = serial.encode()
    iv = raw if len(raw) >= 16 else raw.ljust(16, b"\x00")
    if len(iv) != 16:
        raise ProtocolError("a lock serial longer than 16 bytes cannot be an IV")
    return iv


def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC with PKCS#7 (Node's ``createCipheriv`` default)."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padded) + enc.finalize()


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Inverse of :func:`encrypt`; :class:`ProtocolError` on a bad length or padding."""
    if not data or len(data) % 16:
        raise ProtocolError("ciphertext is not a whole number of AES blocks")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as err:
        raise ProtocolError("bad padding: wrong key or not for this lock") from err


# -- TLV payloads (WritePayload / ParsePayload) -------------------------------------


def write_payload(*fields: bytes) -> bytes:
    """``WritePayload``: each field as ``tag | len & 255 | bytes``, tags from 0xA1 up."""
    out = bytearray()
    for index, value in enumerate(fields):
        out += bytes([(0xA1 + index) & 0xFF, len(value) & 0xFF]) + value
    return bytes(out)


def _s8(value: int) -> int:
    return value - 256 if value > 127 else value


class ParsePayload:
    """``ParsePayload``, kept byte-for-byte with the Node original (signed tags and
    lengths included) so that what it reads matches what eufy-security-client reads."""

    def __init__(self, data: bytes) -> None:
        self.data = data

    def _next_step(self, index_value: int, position: int) -> int:
        data = self.data
        new_position = position + 1 + data[position]
        if new_position >= len(data) or _s8(data[new_position]) == index_value + 1:
            return 1
        return 2

    def _position(self, index_value: int) -> int:
        data = self.data
        position = 0
        while position < len(data):
            value = _s8(data[position])
            if value == index_value:
                return position
            position += 1
            if position >= len(data):
                break
            step = self._next_step(value, position)
            if position + step >= len(data):
                break
            if step == 1:
                position = _s8(data[position]) + position + step
            else:
                position = int.from_bytes(data[position : position + 2], "little") + position + step
            if position < 0:
                break
        return -1

    def read_data(self, index_value: int) -> bytes:
        data = self.data
        position = self._position(index_value)
        if position == -1:
            return b""
        position += 1
        if position >= len(data):
            return b""
        step = self._next_step(index_value, position)
        if step == 1:
            length = _s8(data[position])
        else:
            if position + 2 > len(data):
                return b""
            length = int.from_bytes(data[position : position + 2], "little")
        if length < 0 or position + step + length > len(data):
            return b""
        return data[position + step : position + step + length]

    def read_int8(self, index_value: int) -> int:
        position = self._position(index_value)
        if position == -1:
            return 0
        position += 2
        if position >= len(self.data):
            return 0
        return _s8(self.data[position])


# -- payload encoders (Lock.encodeCmdSmartLock*) ------------------------------------


def _time_field(now: float | None = None) -> bytes:
    return struct.pack("<I", int(time.time() if now is None else now) & 0xFFFFFFFF)


def encode_status_query(admin_user_id: str, *, now: float | None = None) -> bytes:
    """``encodeCmdSmartLockStatus`` (also the GET_LOCK_PARAM body)."""
    return write_payload(_time_field(now), admin_user_id.encode())


def encode_lock(
    admin_user_id: str,
    lock: bool,
    user_name: str,
    short_user_id: str,
    *,
    now: float | None = None,
) -> bytes:
    """``encodeCmdSmartLockUnlock``: 0 locks, 1 unlocks."""
    try:
        short_id = bytes.fromhex(short_user_id)
    except ValueError as err:
        raise ProtocolError("short_user_id must be hex") from err
    return write_payload(
        _time_field(now),
        admin_user_id.encode(),
        bytes([0 if lock else 1]),
        user_name.encode(),
        short_id,
    )


# -- BLE frames (BleCommandFactory) -------------------------------------------------


def _xor(data: bytes) -> int:
    result = 0
    for value in data:
        result ^= value
    return result


def build_ble_frame(
    command: BleCommand,
    data: bytes,
    *,
    function_type: FunctionType = FunctionType.TYPE_2,
    encrypted: bool = True,
) -> bytes:
    """``getSmartLockCommand``: header, LE size, version, 0, type, BE flags+code, data, xor."""
    code = (int(encrypted) << 14) + int(command)
    size = len(BLE_HEADER) + 2 + 1 + 1 + 1 + 2 + len(data) + 1
    body = (
        BLE_HEADER
        + struct.pack("<h", size)
        + bytes([VERSION_CODE_SMART_LOCK, 0, int(function_type)])
        + struct.pack(">H", code)
        + data
    )
    return body + bytes([_xor(body)])


@dataclass(frozen=True, slots=True)
class BleFrame:
    """One parsed smart-lock BLE frame (``BleCommandFactory.parseSmartLock``)."""

    version: int
    function_type: int
    command_code: int
    partial: bool
    encrypted: bool
    data: bytes


def parse_ble_frame(frame: bytes) -> BleFrame:
    """``parseSmartLock``; :class:`ProtocolError` for a short, foreign or corrupt frame."""
    if len(frame) < 9 or (frame[0] != BLE_HEADER[0] and frame[1] != BLE_HEADER[1]):
        raise ProtocolError("not a smart-lock BLE frame")
    if _xor(frame[:-1]) != frame[-1]:
        raise ProtocolError("BLE frame checksum mismatch")
    flags = struct.unpack(">H", frame[7:9])[0]
    return BleFrame(
        version=frame[4],
        function_type=frame[6],
        command_code=flags & 0x07FF,
        partial=flags >> 15 == 1,
        encrypted=(flags << 1) >> 15 == 1,
        data=frame[9:-1],
    )


# -- P2P JSON envelope --------------------------------------------------------------


def build_command(
    *,
    serial: str,
    admin_user_id: str,
    command: SmartLockCommand,
    data: bytes,
    sequence: int,
    channel: int = 0,
    lock_time: int | None = None,
) -> bytes:
    """``getSmartLockP2PCommand``: the 1350 frame's JSON body, as the app sends it."""
    lock_time = smart_lock_time() if lock_time is None else lock_time
    ciphertext = encrypt(data, aes_key(admin_user_id, lock_time), lock_iv(serial))
    frame = build_ble_frame(BLE_FOR_COMMAND[command], ciphertext)
    body = {
        "account_id": admin_user_id,
        "cmd": CMD_TRANSFER_PAYLOAD,
        "mChannel": channel,
        "mValue3": 0,
        "payload": {
            "apiCommand": int(command),
            "lock_payload": frame.hex(),
            "seq_num": sequence,
            "time": lock_time,
        },
    }
    return json.dumps(body, separators=(",", ":")).encode()


@dataclass(frozen=True, slots=True)
class LockReply:
    """A decoded 1940 notify: which command it answers and what it carries."""

    command_code: int
    function_type: int
    return_code: int
    fields: ParsePayload

    @property
    def command(self) -> BleCommand | None:
        if self.function_type != FunctionType.TYPE_2:
            return None
        try:
            return BleCommand(self.command_code)
        except ValueError:
            return None

    @property
    def battery(self) -> int | None:
        """Battery % of a status reply or notify (``BleParameterIndex.ONE``)."""
        if self.command not in (BleCommand.QUERY_STATUS_IN_LOCK, BleCommand.NOTIFY):
            return None
        return self.fields.read_int8(PARAM_ONE)

    @property
    def status(self) -> int | None:
        """Lock status of a status reply or notify (``BleParameterIndex.TWO``)."""
        if self.command not in (BleCommand.QUERY_STATUS_IN_LOCK, BleCommand.NOTIFY):
            return None
        return self.fields.read_int8(PARAM_TWO)


def decode_reply(payload: dict, admin_user_id: str, serial: str) -> LockReply | None:
    """Decode a 1940 notify's ``payload``; None for a partial frame (not reassembled
    by eufy-security-client either). :class:`ProtocolError` when it does not decode."""
    hex_frame = payload.get("lock_payload")
    if not isinstance(hex_frame, str):
        raise ProtocolError("notify has no lock_payload")
    try:
        frame = parse_ble_frame(bytes.fromhex(hex_frame))
    except ValueError as err:
        raise ProtocolError(str(err)) from err
    if frame.partial:
        return None
    data = frame.data
    if frame.encrypted:
        raw_time = payload.get("time")
        try:
            lock_time = int(str(raw_time), 16)
        except ValueError as err:
            raise ProtocolError("notify time is not hex") from err
        device_sn = payload.get("dev_sn") or serial
        data = decrypt(data, aes_key(admin_user_id, lock_time), lock_iv(str(device_sn)))
    if not data:
        raise ProtocolError("empty lock reply")
    return LockReply(
        command_code=frame.command_code,
        function_type=frame.function_type,
        return_code=_s8(data[0]),
        fields=ParsePayload(data[1:]),
    )
