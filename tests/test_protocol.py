"""The wire format, checked against eufy-security-client's layouts byte by byte."""

import json
import struct

import pytest

from smartlock.protocol import (
    CMD_TRANSFER_PAYLOAD,
    BleCommand,
    LockStatus,
    ParsePayload,
    ProtocolError,
    SmartLockCommand,
    aes_key,
    build_ble_frame,
    build_command,
    decode_reply,
    decrypt,
    encode_lock,
    encode_status_query,
    encrypt,
    is_smart_lock_t8520p,
    lock_iv,
    parse_ble_frame,
    write_payload,
)

USER = "0123456789abcdef0123456789abcdef01234567"  # 40 chars, like a eufy user id
SERIAL = "T8520K9000000001"
NOW = 1_761_955_200


def test_model_check_matches_is_lock_wifi_t8520p():
    assert is_smart_lock_t8520p("T8520K9000000002")
    assert not is_smart_lock_t8520p("T8520K1000000002")  # the original T8520
    assert not is_smart_lock_t8520p("T8510P902335009")
    assert not is_smart_lock_t8520p("T8520K")


def test_key_is_last_12_chars_then_big_endian_time():
    key = aes_key(USER, 0x01020304)
    assert key == USER[-12:].encode() + b"\x01\x02\x03\x04"
    with pytest.raises(ProtocolError):
        aes_key("short", 1)


def test_iv_is_serial_zero_padded():
    assert lock_iv(SERIAL) == SERIAL.encode()
    assert lock_iv("T8520") == b"T8520" + bytes(11)


def test_cbc_round_trip_and_pkcs7():
    key, iv = aes_key(USER, NOW), lock_iv(SERIAL)
    for size in (0, 1, 15, 16, 17, 40):
        data = bytes(range(size))
        ct = encrypt(data, key, iv)
        assert len(ct) % 16 == 0 and len(ct) > size
        assert decrypt(ct, key, iv) == data
    with pytest.raises(ProtocolError):
        decrypt(encrypt(b"x", key, iv), aes_key(USER, NOW + 1), iv)


def test_write_payload_tags_start_at_a1():
    # WritePayload: split byte -95 (0xA1), then length & 255, then the bytes.
    assert write_payload(b"\x01\x02", b"abc") == b"\xa1\x02\x01\x02\xa2\x03abc"


def test_status_query_layout():
    body = encode_status_query(USER, now=NOW)
    assert body[:6] == b"\xa1\x04" + struct.pack("<I", NOW)
    assert body[6:8] == bytes([0xA2, len(USER)])
    assert body[8:] == USER.encode()


def test_lock_and_unlock_bodies():
    locking = ParsePayload(encode_lock(USER, True, "Alex", "0003", now=NOW))
    unlocking = ParsePayload(encode_lock(USER, False, "Alex", "0003", now=NOW))
    assert locking.read_data(-95) == struct.pack("<I", NOW)
    assert locking.read_data(-94) == USER.encode()
    assert locking.read_data(-93) == b"\x00"  # 0 locks
    assert unlocking.read_data(-93) == b"\x01"  # 1 unlocks
    assert locking.read_data(-92) == b"Alex"
    assert locking.read_data(-91) == b"\x00\x03"
    with pytest.raises(ProtocolError):
        encode_lock(USER, True, "Alex", "not-hex")


def test_parse_payload_reads_int8_fields_and_missing_ones():
    fields = ParsePayload(write_payload(b"\x63", b"\x04"))
    assert fields.read_int8(-95) == 99
    assert fields.read_int8(-94) == 4
    assert fields.read_int8(-90) == 0
    assert fields.read_data(-90) == b""
    assert ParsePayload(b"").read_int8(-95) == 0


def test_ble_frame_layout():
    frame = build_ble_frame(BleCommand.ON_OFF_LOCK, b"\xaa\xbb")
    assert frame[:2] == b"\xff\x09"
    assert struct.unpack("<h", frame[2:4])[0] == len(frame)
    assert frame[4:7] == b"\x03\x00\x02"  # version 3, unknown 0, function type 2
    assert struct.unpack(">H", frame[7:9])[0] == (1 << 14) + 35  # encrypted, ON_OFF_LOCK
    assert frame[9:-1] == b"\xaa\xbb"
    xor = 0
    for value in frame[:-1]:
        xor ^= value
    assert frame[-1] == xor


def test_ble_frame_round_trip_and_rejections():
    frame = build_ble_frame(BleCommand.QUERY_STATUS_IN_LOCK, b"\x01\x02\x03")
    parsed = parse_ble_frame(frame)
    assert parsed.command_code == 34
    assert parsed.encrypted and not parsed.partial
    assert parsed.function_type == 2 and parsed.version == 3
    assert parsed.data == b"\x01\x02\x03"
    with pytest.raises(ProtocolError):
        parse_ble_frame(frame[:-1] + bytes([frame[-1] ^ 1]))
    with pytest.raises(ProtocolError):
        parse_ble_frame(b"\xff\x09\x00")


def test_command_envelope_matches_get_smart_lock_p2p_command():
    data = encode_status_query(USER, now=NOW)
    body = json.loads(
        build_command(
            serial=SERIAL,
            admin_user_id=USER,
            command=SmartLockCommand.QUERY_STATUS_IN_LOCK,
            data=data,
            sequence=42,
            lock_time=NOW,
        )
    )
    assert list(body) == ["account_id", "cmd", "mChannel", "mValue3", "payload"]
    assert body["account_id"] == USER
    assert body["cmd"] == CMD_TRANSFER_PAYLOAD == 1940
    assert body["mChannel"] == 0 and body["mValue3"] == 0
    payload = body["payload"]
    assert list(payload) == ["apiCommand", "lock_payload", "seq_num", "time"]
    assert payload["apiCommand"] == 6012
    assert payload["seq_num"] == 42
    assert payload["time"] == NOW
    frame = parse_ble_frame(bytes.fromhex(payload["lock_payload"]))
    assert frame.command_code == BleCommand.QUERY_STATUS_IN_LOCK
    assert decrypt(frame.data, aes_key(USER, NOW), lock_iv(SERIAL)) == data


def lock_notify(command: BleCommand, return_code: int, *fields: bytes, lock_time=NOW) -> dict:
    """A 1940 notify payload as the lock sends it (time in hex, data encrypted)."""
    data = bytes([return_code & 0xFF]) + write_payload(*fields)
    frame = build_ble_frame(command, encrypt(data, aes_key(USER, lock_time), lock_iv(SERIAL)))
    return {"lock_payload": frame.hex(), "time": format(lock_time, "x"), "dev_sn": SERIAL}


def test_decode_status_reply():
    reply = decode_reply(
        lock_notify(BleCommand.QUERY_STATUS_IN_LOCK, 0, b"\x43", b"\x04"), USER, SERIAL
    )
    assert reply is not None
    assert reply.command is BleCommand.QUERY_STATUS_IN_LOCK
    assert reply.return_code == 0
    assert reply.battery == 67
    assert reply.status == LockStatus.LOCKED


def test_decode_lock_reply_has_no_status():
    reply = decode_reply(lock_notify(BleCommand.ON_OFF_LOCK, 0), USER, SERIAL)
    assert reply is not None and reply.command is BleCommand.ON_OFF_LOCK
    assert reply.status is None and reply.battery is None


def test_decode_negative_return_code_and_bad_key():
    reply = decode_reply(lock_notify(BleCommand.ON_OFF_LOCK, -3), USER, SERIAL)
    assert reply is not None and reply.return_code == -3
    with pytest.raises(ProtocolError):
        decode_reply(lock_notify(BleCommand.ON_OFF_LOCK, 0), "f" * 40, SERIAL)


def test_decode_partial_frame_is_skipped():
    frame = bytearray(build_ble_frame(BleCommand.NOTIFY, bytes(16)))
    frame[7] |= 0x80  # partial
    frame[-1] = 0
    for value in frame[:-1]:
        frame[-1] ^= value
    assert decode_reply({"lock_payload": frame.hex(), "time": "0"}, USER, SERIAL) is None
