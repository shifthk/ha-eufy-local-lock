"""Constants for the eufy Smart Lock (local) integration."""

from typing import Final

DOMAIN: Final = "eufy_local_lock"

CONF_SERIAL: Final = "serial"
CONF_COUNTRY: Final = "country"
CONF_SHORT_USER_ID: Final = "short_user_id"
CONF_USER_NAME: Final = "user_name"
CONF_POLL_MINUTES: Final = "poll_minutes"

DEFAULT_POLL_MINUTES: Final = 5
MIN_POLL_MINUTES: Final = 1
MAX_POLL_MINUTES: Final = 60

#: Version of the per-lock store that holds the library's session cache (login
#: session, owner id, cipher keys), keyed by lock serial.
STORE_VERSION: Final = 1


def store_key(serial: str) -> str:
    return f"{DOMAIN}.{serial}"
