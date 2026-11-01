"""Teach ``eufy-home-security`` the session setup eufy's Wi-Fi smart locks use.

The library's handshake follows the HomeBase 3 and the cameras: the station answers
CONN_INIT (P2P 1100, ``CMD_GATEWAYINFO`` in eufy-security-client) with either an
ECIES blob or a 128-byte RSA blob carrying a session key. A T8520P answers with a
**short** reply instead (36 bytes: a cipher id and a 32-byte blob no RSA key opens).
eufy-security-client then falls back to "encryption level 1": every command is
AES-128-ECB under the static key derived from the serial and P2P id, frame
encryption type 1. The library has exactly that mode (an RSA session without a key,
``rsa_keyless``) but never reaches it for a lock, for three reasons this module
removes:

1. its CONN_INIT matcher drops replies shorter than ``4 + 128`` bytes;
2. it parses the cipher id as 32 bits where the lock means 16, and would go on to
   fetch that cipher's RSA key for a blob no RSA key opens;
3. without a session key it sends type 1 only to six camera models, clear to others.

The patch is narrow: a short RSA-version reply (which failed before, always) is read
as "no cipher", which the library already handles by running under the static key;
and smart-lock serial prefixes join the models that get type 1 then. Nothing changes
for a reply the library already accepted.
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

_LOGGER = logging.getLogger(__name__)

#: Serial prefixes of the smart locks that take level-1 (static key, type 1) commands.
SMART_LOCK_PREFIXES = ("T8520", "T8510", "T8506", "T8502", "T85L0", "T85V0", "T85P0")

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
        from eufy_home_security.p2p.session import keys as keys_module
    except ImportError as err:
        _LOGGER.warning("eufy-home-security %s: cannot apply the lock handshake fix: %s", lib_version, err)
        return False

    needed = (
        hasattr(session_module, "CONN_INIT_MIN_LEN")
        and hasattr(session_module, "parse_conn_init")
        and hasattr(keys_module, "STATIC_KEY_FALLBACK_MODELS")
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
            # eufy-security-client: RSA decrypt fails, encryption level 1.
            _LOGGER.debug(
                "short CONN_INIT (%d-byte blob, cipher %d): static-key session",
                len(conn_init.body),
                conn_init.cipher_id & 0xFFFF,
            )
            return conn_init_cls(conn_init.version, no_cipher, conn_init.body)
        return conn_init

    session_module.parse_conn_init = parse_conn_init
    session_module.CONN_INIT_MIN_LEN = 4
    keys_module.STATIC_KEY_FALLBACK_MODELS = tuple(
        dict.fromkeys((*keys_module.STATIC_KEY_FALLBACK_MODELS, *SMART_LOCK_PREFIXES))
    )
    _applied = True
    _LOGGER.debug("eufy-home-security %s: smart-lock session setup enabled", lib_version)
    return True
