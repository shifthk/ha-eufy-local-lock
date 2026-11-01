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
#: The lock's PPPP rendezvous servers (``app_conn``), which wake it from sleep.
CONF_APP_CONN: Final = "app_conn"
#: Option (on by default): wake a sleeping lock through eufy's rendezvous servers.
#: Off: LAN search only, no eufy contact at all, but a sleeping lock does not answer.
CONF_CLOUD_WAKE: Final = "cloud_wake"
DEFAULT_CLOUD_WAKE: Final = True
#: Option (off by default): hold the LAN session open with a silent status check
#: every KEEPALIVE_SECONDS, so the lock stays awake and needs no further wake. Costs
#: battery; eufy is used again only if the session drops.
CONF_KEEP_CONNECTED: Final = "keep_connected"
DEFAULT_KEEP_CONNECTED: Final = False
#: The lock closes a session itself about 16 s after the last command.
KEEPALIVE_SECONDS: Final = 10

#: Timed checks are LAN only (they never wake the lock through eufy), so they are
#: cheap; often enough to catch the lock while it is awake after a keypad use.
DEFAULT_POLL_MINUTES: Final = 1
MIN_POLL_MINUTES: Final = 1
MAX_POLL_MINUTES: Final = 60

#: Version of the per-lock store that holds the library's session cache (login
#: session, owner id, cipher keys), keyed by lock serial.
STORE_VERSION: Final = 1


def store_key(serial: str) -> str:
    return f"{DOMAIN}.{serial}"
