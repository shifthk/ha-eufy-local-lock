"""The lock entity."""

from __future__ import annotations

from typing import Any

from eufy_home_security.exceptions import EufySecurityError

from homeassistant.components.lock import LockEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .entity import EufyLockEntity
from .hub import EufyLockConfigEntry, LockCoordinator
from .smartlock import LockCommandError, LockStatus, LockTimeoutError

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: EufyLockConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    async_add_entities([EufySmartLock(entry.runtime_data)])


class EufySmartLock(EufyLockEntity, LockEntity):
    _attr_name = None  # the device's own name

    def __init__(self, coordinator: LockCoordinator) -> None:
        super().__init__(coordinator, "lock")
        self._target: bool | None = None

    @property
    def is_locked(self) -> bool | None:
        state = self.coordinator.data
        return None if state is None else state.is_locked

    @property
    def is_jammed(self) -> bool:
        state = self.coordinator.data
        return state is not None and state.status == LockStatus.JAMMED

    @property
    def is_locking(self) -> bool:
        return self._target is True

    @property
    def is_unlocking(self) -> bool:
        return self._target is False

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        state = self.coordinator.data
        return {"lock_status_code": None if state is None else state.status}

    async def async_lock(self, **kwargs: Any) -> None:
        await self._async_set(True)

    async def async_unlock(self, **kwargs: Any) -> None:
        await self._async_set(False)

    async def _async_set(self, locked: bool) -> None:
        self._target = locked
        self.async_write_ha_state()
        try:
            state = await self.coordinator.async_set_locked(locked)
        except LockCommandError as err:
            raise HomeAssistantError(
                f"The lock refused to {'lock' if locked else 'unlock'} "
                f"(code {err.return_code})"
            ) from err
        except (LockTimeoutError, EufySecurityError) as err:
            raise HomeAssistantError(f"The lock did not answer: {err}") from err
        finally:
            self._target = None
            self.async_write_ha_state()
        if state.status == LockStatus.JAMMED:
            raise HomeAssistantError("The lock reports a jammed bolt")
