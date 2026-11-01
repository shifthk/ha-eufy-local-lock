"""Diagnostics: what the lock last said and how the P2P session is doing (no secrets)."""

from __future__ import annotations

import dataclasses
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_EMAIL, CONF_HOST, CONF_PASSWORD
from homeassistant.core import HomeAssistant

from .const import CONF_SERIAL, CONF_SHORT_USER_ID, CONF_USER_NAME
from .hub import EufyLockConfigEntry

TO_REDACT = {CONF_EMAIL, CONF_PASSWORD, CONF_HOST, CONF_SERIAL, CONF_SHORT_USER_ID, CONF_USER_NAME}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: EufyLockConfigEntry
) -> dict[str, Any]:
    coordinator = entry.runtime_data
    state = coordinator.data
    session: dict[str, Any] | None = None
    if coordinator.account is not None:
        station = coordinator.account.stations.get(coordinator.serial)
        if station is not None:
            stats = station.session.stats()
            session = dataclasses.asdict(stats) if dataclasses.is_dataclass(stats) else str(stats)
    return {
        "entry": async_redact_data(dict(entry.data), TO_REDACT),
        "options": async_redact_data(dict(entry.options), TO_REDACT),
        "last_update_success": coordinator.last_update_success,
        "state": None if state is None else dataclasses.asdict(state),
        "session": session,
    }
