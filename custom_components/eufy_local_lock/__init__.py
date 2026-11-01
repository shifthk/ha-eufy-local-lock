"""eufy Smart Lock (local): lock and unlock a eufy T8520P over the LAN, no eufy cloud
in the loop (the cloud is used once, at setup, for the lock's keys)."""

from __future__ import annotations

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import CONF_SERIAL
from .hub import EntryStore, EufyLockConfigEntry, LockCoordinator

PLATFORMS: list[Platform] = [Platform.LOCK, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: EufyLockConfigEntry) -> bool:
    coordinator = LockCoordinator(hass, entry)
    try:
        await coordinator.async_start()
    except Exception:
        await coordinator.async_stop()
        raise
    # The lock may leave a status query unanswered (it may be asleep, or report only
    # after a command): set up regardless, so lock and unlock can still be sent, and
    # let the state stay unknown until the lock says something.
    await coordinator.async_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: EufyLockConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_stop()
    return unloaded


async def async_remove_entry(hass: HomeAssistant, entry: EufyLockConfigEntry) -> None:
    """Forget the cached eufy session and keys along with the entry."""
    await EntryStore(hass, entry.data[CONF_SERIAL]).async_remove()


async def _async_options_updated(hass: HomeAssistant, entry: EufyLockConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
