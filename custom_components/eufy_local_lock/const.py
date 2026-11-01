"""Constants for the eufy Smart Lock (local) integration."""

from typing import Final

DOMAIN: Final = "eufy_local_lock"

CONF_SERIAL: Final = "serial"
CONF_COUNTRY: Final = "country"
CONF_SHORT_USER_ID: Final = "short_user_id"
CONF_USER_NAME: Final = "user_name"
CONF_POLL_MINUTES: Final = "poll_minutes"
#: Stored at setup so that the lock is reached without the eufy cloud afterwards.
CONF_OWNER_ID: Final = "owner_id"
CONF_P2P_DID: Final = "p2p_did"
CONF_ACCOUNT_USER: Final = "account_user"
CONF_FIRMWARE: Final = "firmware"
#: Option: wake the lock through eufy's rendezvous servers (needs eufy reachable).
CONF_CLOUD_WAKE: Final = "cloud_wake"

DEFAULT_POLL_MINUTES: Final = 5
MIN_POLL_MINUTES: Final = 1
MAX_POLL_MINUTES: Final = 60

#: Version of the per-lock store that holds the library's session cache (login
#: session, owner id, cipher keys), keyed by lock serial.
STORE_VERSION: Final = 1


def store_key(serial: str) -> str:
    return f"{DOMAIN}.{serial}"
