"""One lock: the eufy account (cloud, used once), its P2P session and the lock client."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from eufy_home_security import EufySecurity
from eufy_home_security.exceptions import (
    AuthenticationError,
    EufySecurityError,
    SessionReplacedError,
)
from eufy_home_security.inclusion import Reach

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_EMAIL, CONF_HOST, CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from . import compat
from .const import (
    CONF_COUNTRY,
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
        self.client: SmartLockClient | None = None
        self.firmware: str | None = None
        self._remove_listener: Any = None

    async def async_start(self) -> None:
        """Log in from the cache, build the lock's session and read its status."""
        entry = self.config_entry
        assert entry is not None
        host = entry.options.get(CONF_HOST) or entry.data.get(CONF_HOST)
        self.account = build_account(
            self.hass, dict(entry.data), EntryStore(self.hass, self.serial), host=host
        )
        try:
            # Reuses the cached session: no cloud request once set up. The cloud is
            # needed again only if the cache is lost or eufy rotates the lock's keys.
            await self.account.async_login()
            await self.account.async_discover()
            owner_id = await self.account.cloud.async_get_station_owner_id(self.serial)
        except SessionReplacedError as err:
            raise ConfigEntryAuthFailed(
                "another eufy login took over this account's session"
            ) from err
        except AuthenticationError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except EufySecurityError as err:
            raise ConfigEntryNotReady(f"eufy account unavailable: {err}") from err
        station = self.account.stations.get(self.serial)
        if station is None:
            raise ConfigEntryNotReady("the eufy account no longer lists this lock")
        device = self.account.listed_devices.get(self.serial)
        self.firmware = device.main_sw_version if device is not None else None
        self.client = SmartLockClient(
            station.session,
            LockIdentity(
                serial=self.serial,
                admin_user_id=owner_id,
                user_name=entry.data[CONF_USER_NAME],
                short_user_id=entry.data[CONF_SHORT_USER_ID],
            ),
        )
        self.client.start()
        self._remove_listener = self.client.add_listener(self.async_set_updated_data)

    async def async_stop(self) -> None:
        if self._remove_listener is not None:
            self._remove_listener()
        if self.client is not None:
            await self.client.async_stop()
        if self.account is not None:
            await self.account.async_close()

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
