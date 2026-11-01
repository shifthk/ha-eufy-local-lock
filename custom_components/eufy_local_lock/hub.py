"""One lock: its P2P session and the lock client (the eufy account only at setup,
or at runtime with the cloud-wake option)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from eufy_home_security import EufySecurity
from eufy_home_security.exceptions import (
    AuthenticationError,
    EufySecurityError,
    SessionReplacedError,
)
from eufy_home_security.inclusion import Reach
from eufy_home_security.p2p.crypto import CONN_INIT_NO_CIPHER
from eufy_home_security.p2p.session import P2PCredentials, StationSession

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_HOST, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import compat
from .const import (
    CONF_ACCOUNT_USER,
    CONF_CLOUD_WAKE,
    CONF_COUNTRY,
    CONF_FIRMWARE,
    CONF_OWNER_ID,
    CONF_P2P_DID,
    CONF_POLL_MINUTES,
    CONF_SERIAL,
    CONF_SHORT_USER_ID,
    CONF_USER_NAME,
    DEFAULT_POLL_MINUTES,
    DOMAIN,
    STORE_VERSION,
    store_key,
)
from .smartlock import (
    LockCommandError,
    LockIdentity,
    LockState,
    LockTimeoutError,
    SmartLockClient,
)

_LOGGER = logging.getLogger(__name__)

# The lock's short CONN_INIT reply needs eufy-security-client's "level 1" fallback.
compat.apply()

type EufyLockConfigEntry = ConfigEntry[LockCoordinator]


class EntryStore:
    """The library's ``Store`` protocol over a private HA store."""

    def __init__(self, hass: HomeAssistant, serial: str) -> None:
        self._store: Store[dict[str, Any]] = Store(
            hass, STORE_VERSION, store_key(serial), private=True
        )

    async def async_load(self) -> dict[str, Any] | None:
        return await self._store.async_load()

    async def async_save(self, data: dict[str, Any]) -> None:
        await self._store.async_save(data)

    async def async_remove(self) -> None:
        await self._store.async_remove()


def build_account(
    hass: HomeAssistant, data: dict[str, Any], store: Any, *, host: str | None = None
) -> EufySecurity:
    """An account limited to the one lock (no other station is built or contacted)."""
    serial = data.get(CONF_SERIAL)
    return EufySecurity(
        async_get_clientsession(hass),
        data[CONF_EMAIL],
        data.get(CONF_PASSWORD),
        store=store,
        country=data.get(CONF_COUNTRY) or hass.config.country or "",
        timezone=str(hass.config.time_zone or ""),
        station_hosts={serial: host} if serial and host else None,
        stations={serial: Reach.LOCAL} if serial else None,
    )


#: What a local-only session needs, stored in the entry at setup.
LOCAL_KEYS = (CONF_OWNER_ID, CONF_P2P_DID, CONF_ACCOUNT_USER, CONF_USER_NAME, CONF_SHORT_USER_ID)


async def async_lock_details(account: EufySecurity, serial: str) -> dict[str, Any]:
    """The lock's details a local session needs, from the account (its cached device
    list and owner id when it has them)."""
    devices = {d.device_sn: d for d in await account.cloud.async_get_devices()}
    device = devices.get(serial)
    if device is None or not device.p2p_did:
        raise ConfigEntryNotReady("the eufy account no longer lists this lock")
    return {
        CONF_OWNER_ID: await account.cloud.async_get_station_owner_id(serial),
        CONF_P2P_DID: device.p2p_did,
        CONF_ACCOUNT_USER: account.cloud.user_name,
        CONF_FIRMWARE: device.main_sw_version,
    }


def local_session(data: Mapping[str, Any], host: str | None) -> StationSession:
    """A P2P session to the lock that needs nothing from eufy: found by LAN search
    (no rendezvous wake), credentials from the entry. The lock negotiates no cipher,
    so no cipher key is needed either."""
    owner_id, user = data[CONF_OWNER_ID], data[CONF_ACCOUNT_USER]

    async def credentials(*, refresh: bool, cipher_id: int | None) -> P2PCredentials:
        if cipher_id not in (None, CONN_INIT_NO_CIPHER):
            _LOGGER.warning(
                "the lock asks for cipher %s; local-only mode has no key for it. "
                "Turn on the cloud-wake option or set the lock up again",
                cipher_id,
            )
        return P2PCredentials(
            account_id=owner_id,
            user_name=user,
            ecc_private_key="",
            cipher_id=CONN_INIT_NO_CIPHER if cipher_id is None else cipher_id,
            rsa_private_key=None,
        )

    return StationSession(
        data[CONF_SERIAL],
        credentials,
        host=host,
        did=data[CONF_P2P_DID],
        on_demand=True,  # a battery lock: connect per command, let it sleep after
        wake_provider=None,  # no rendezvous servers: LAN search only
    )


class LockCoordinator(DataUpdateCoordinator[LockState]):
    """Polls the lock now and then; the lock's own pushes update it in between."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        minutes = entry.options.get(CONF_POLL_MINUTES, DEFAULT_POLL_MINUTES)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} {entry.data[CONF_SERIAL]}",
            update_interval=timedelta(minutes=minutes),
        )
        self.serial: str = entry.data[CONF_SERIAL]
        self.account: EufySecurity | None = None
        """Only with the cloud-wake option; local-only runs without one."""
        self.session: Any = None
        self.client: SmartLockClient | None = None
        self.firmware: str | None = None
        self._remove_listener: Any = None

    async def async_start(self) -> None:
        """Build the lock's P2P session from what setup stored and start listening.

        Local only by default: nothing here talks to eufy. The session is built from
        the owner id, P2P id and address saved at setup, and found by LAN search
        alone. With the "cloud wake" option the account is used as before, so that
        eufy's rendezvous servers can wake a sleeping lock.
        """
        entry = self.config_entry
        assert entry is not None
        host = entry.options.get(CONF_HOST) or entry.data.get(CONF_HOST)
        if not all(entry.data.get(key) for key in LOCAL_KEYS):
            # Set up before the details were stored: read them from the cached
            # session (the cloud's device list and owner id are cached), once.
            details = await self._async_account_call(
                lambda account: async_lock_details(account, self.serial), host
            )
            self.hass.config_entries.async_update_entry(
                entry, data={**entry.data, **details}
            )
        data = entry.data
        self.firmware = data.get(CONF_FIRMWARE)
        if entry.options.get(CONF_CLOUD_WAKE):
            session = await self._async_cloud_session(host)
        else:
            session = local_session(data, host)
        self.session = session
        self.client = SmartLockClient(
            session,
            LockIdentity(
                serial=self.serial,
                admin_user_id=data[CONF_OWNER_ID],
                user_name=data[CONF_USER_NAME],
                short_user_id=data[CONF_SHORT_USER_ID],
            ),
        )
        self.client.start()
        self._remove_listener = self.client.add_listener(self.async_set_updated_data)

    async def _async_account_call(self, call: Any, host: str | None) -> Any:
        """Run ``call(account)`` on the cached eufy session, mapping its errors to
        HA's; the account is closed afterwards."""
        entry = self.config_entry
        assert entry is not None
        account = build_account(
            self.hass, dict(entry.data), EntryStore(self.hass, self.serial), host=host
        )
        try:
            await account.async_login()  # the cached session: no request
            return await call(account)
        except SessionReplacedError as err:
            raise ConfigEntryAuthFailed(
                "another eufy login took over this account's session"
            ) from err
        except AuthenticationError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except EufySecurityError as err:
            raise ConfigEntryNotReady(f"eufy account unavailable: {err}") from err
        finally:
            await account.async_close()

    async def _async_cloud_session(self, host: str | None) -> Any:
        """The account's own session for the lock, which wakes it through eufy's
        rendezvous servers (and so needs eufy reachable)."""
        entry = self.config_entry
        assert entry is not None
        self.account = build_account(
            self.hass, dict(entry.data), EntryStore(self.hass, self.serial), host=host
        )
        try:
            await self.account.async_login()
            await self.account.async_discover()
        except SessionReplacedError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except AuthenticationError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except EufySecurityError as err:
            raise ConfigEntryNotReady(f"eufy account unavailable: {err}") from err
        station = self.account.stations.get(self.serial)
        if station is None:
            raise ConfigEntryNotReady("the eufy account no longer lists this lock")
        return station.session

    async def async_stop(self) -> None:
        if self._remove_listener is not None:
            self._remove_listener()
        if self.client is not None:
            await self.client.async_stop()
        if self.account is not None:
            await self.account.async_close()
        elif self.session is not None:
            await self.session.async_close()

    async def _async_update_data(self) -> LockState:
        assert self.client is not None
        try:
            return await self.client.async_refresh()
        except SessionReplacedError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except (EufySecurityError, LockTimeoutError, LockCommandError) as err:
            raise UpdateFailed(f"lock did not answer: {err}") from err

    async def async_set_locked(self, locked: bool) -> LockState:
        assert self.client is not None
        state = await self.client.async_set_locked(locked)
        self.async_set_updated_data(state)
        return state
