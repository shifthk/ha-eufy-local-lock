"""Teach ``eufy-home-security`` the session setup eufy's Wi-Fi smart locks use.

The library's handshake follows the HomeBase 3 and the cameras: the station answers
CONN_INIT (P2P 1100, ``CMD_GATEWAYINFO`` in eufy-security-client) with either an
ECIES blob or a 128-byte RSA blob carrying a session key. A T8520P answers with a
**short** reply instead: 36 bytes, ``i32 -103`` (``ERROR_INVALID_COMMAND``) and 32
zero bytes. It negotiates no session key at all.

The library has the mode for that (an RSA session without a key, ``rsa_keyless``,
as for a CONN_INIT naming no cipher) but never reaches it for a lock: its CONN_INIT
matcher drops replies shorter than ``4 + 128`` bytes, and the 36 bytes would parse
as cipher 0xFFFFFF99. This module reads a short RSA-version reply as "no cipher".

In that mode the library sends commands the way the eufy app does without a key:
under the static key (type 1) to six old camera models, **in clear (type 0)** to
every other. That matches the lock, which sends its own frames in clear and
silently ignored commands sent under the static key. Nothing else changes, and
nothing changes for a reply the library already accepted.
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

_LOGGER = logging.getLogger(__name__)

_applied = False


def apply() -> bool:
    """Patch the library once; False (with a warning) when its layout is not the one
    this was written for, in which case nothing is changed."""
    global _applied
    if _applied:
        return True
    try:
        lib_version = version("eufy-home-security")
    except PackageNotFoundError:
        lib_version = "unknown"
    try:
        from eufy_home_security.p2p import crypto
        from eufy_home_security.p2p import session as session_module
    except ImportError as err:
        _LOGGER.warning("eufy-home-security %s: cannot apply the lock handshake fix: %s", lib_version, err)
        return False

    needed = (
        hasattr(session_module, "CONN_INIT_MIN_LEN")
        and hasattr(session_module, "parse_conn_init")
        and hasattr(crypto, "CONN_INIT_RSA_BLOB_LEN")
        and hasattr(crypto, "CONN_INIT_NO_CIPHER")
        and hasattr(crypto, "ConnInit")
    )
    if not needed:
        _LOGGER.warning(
            "eufy-home-security %s does not have the layout this integration patches; "
            "the lock's session setup may fail",
            lib_version,
        )
        return False

    original_parse = session_module.parse_conn_init
    rsa_blob_len = crypto.CONN_INIT_RSA_BLOB_LEN
    no_cipher = crypto.CONN_INIT_NO_CIPHER
    conn_init_cls = crypto.ConnInit

    def parse_conn_init(payload: bytes, subheader: bytes, static_key: bytes):
        conn_init = original_parse(payload, subheader, static_key)
        if conn_init.rsa and len(conn_init.body) < rsa_blob_len:
            # No session key negotiated (the lock answers -103): a keyless session.
            code = conn_init.cipher_id - (1 << 32) if conn_init.cipher_id >= 1 << 31 else conn_init.cipher_id
            _LOGGER.debug(
                "short CONN_INIT (code %d, %d-byte body): session without a key",
                code,
                len(conn_init.body),
            )
            return conn_init_cls(conn_init.version, no_cipher, conn_init.body)
        return conn_init

    session_module.parse_conn_init = parse_conn_init
    session_module.CONN_INIT_MIN_LEN = 4
    _applied = True
    _LOGGER.debug("eufy-home-security %s: smart-lock session setup enabled", lib_version)
    return True
