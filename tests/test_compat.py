"""The handshake fix, against the real eufy-home-security."""

import os
import struct

import compat
from eufy_home_security.p2p import crypto
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.session.keys import SessionKeys

LOCK = "T8520K9000000002"
DID = "EUPRAKM-123456-ABCDE"
CLEAR_RSA_SUBHEADER = bytes([1, 0, 0, 0, 0, 0])  # version 1 (RSA), encryption 0 (clear)

compat.apply()


def node_static_key(serial: str, did: str) -> bytes:
    """eufy-security-client's getP2PCommandEncryptionKey."""
    dash = did.index("-")
    return (serial[-7:] + did[dash : dash + 9]).encode()


def test_library_static_key_is_level_1_key():
    assert static_key(LOCK, DID) == node_static_key(LOCK, DID)


def test_short_reply_passes_the_size_check():
    assert session_module.CONN_INIT_MIN_LEN <= 36


def test_short_rsa_reply_becomes_a_static_key_session():
    # What the lock sent: u16 cipher id, u16 unknown, a 32-byte blob (36 bytes).
    payload = struct.pack("<HH", 7, 1) + os.urandom(32)
    conn_init = session_module.parse_conn_init(
        payload, CLEAR_RSA_SUBHEADER, static_key(LOCK, DID)
    )
    assert conn_init.rsa
    assert conn_init.cipher_id == crypto.CONN_INIT_NO_CIPHER


def test_full_rsa_reply_is_untouched():
    payload = struct.pack("<I", 7) + os.urandom(128)
    conn_init = session_module.parse_conn_init(
        payload, CLEAR_RSA_SUBHEADER, static_key(LOCK, DID)
    )
    assert conn_init.cipher_id == 7 and len(conn_init.body) == 128


def test_keyless_lock_session_sends_type_1():
    keys = SessionKeys(LOCK)
    keys.rsa_keyless = True
    assert keys.session_encryption == crypto.FRAME_STATIC_ECB
    camera = SessionKeys("T8170X0000000001")
    camera.rsa_keyless = True
    assert camera.session_encryption == crypto.FRAME_PLAIN  # others unchanged


def test_apply_is_idempotent():
    before = session_module.parse_conn_init
    assert compat.apply()
    assert session_module.parse_conn_init is before
