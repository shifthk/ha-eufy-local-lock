"""Base entity: one device per lock."""

from __future__ import annotations

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .hub import LockCoordinator


class EufyLockEntity(CoordinatorEntity[LockCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: LockCoordinator, key: str) -> None:
        super().__init__(coordinator)
        serial = coordinator.serial
        self._attr_unique_id = f"{serial}_{key}"
        entry = coordinator.config_entry
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, serial)},
            manufacturer="eufy",
            model="Smart Lock (T8520P)",
            model_id=serial[:5],
            serial_number=serial,
            sw_version=coordinator.firmware,
            name=entry.title if entry is not None else "eufy lock",
        )
