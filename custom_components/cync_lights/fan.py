"""Platform for Cync fan integration."""
from __future__ import annotations

import logging
from typing import Any, Optional

from homeassistant.components.fan import (
    FanEntity,
    FanEntityFeature,
    FanEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .cync_hub import CyncHub, CyncSwitch

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cync fans from a config entry."""
    hub: CyncHub = hass.data[DOMAIN][config_entry.entry_id]

    new_devices = []
    for switch in hub.cync_switches.values():
        if (
            not switch._update_callback
            and switch.fan
            and switch.device_id in config_entry.options.get("switches", [])
        ):
            new_devices.append(CyncFanEntity(switch))

    if new_devices:
        async_add_entities(new_devices)


class CyncFanEntity(FanEntity):
    """Representation of a Cync Fan Switch Entity."""

    _attr_should_poll = False
    _attr_supported_features = FanEntityFeature.SET_SPEED

    def __init__(self, cync_switch: CyncSwitch) -> None:
        """Initialize the fan entity."""
        self.cync_switch = cync_switch
        self._attr_unique_id = f"cync_switch_{self.cync_switch.device_id}"
        self._attr_name = self.cync_switch.name
        self._attr_speed_count = 4  # Assuming the fan supports 4 speeds
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.cync_switch.device_id)},
            manufacturer="Cync by Savant",
            name=f"{self.cync_switch.name} ({self.cync_switch.home_name})",
            suggested_area=self.cync_switch.room.name if self.cync_switch.room else None,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the fan entity is added to Home Assistant."""
        self.cync_switch.register(self.async_write_ha_state, self.hass)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the fan entity is about to be removed from Home Assistant."""
        self.cync_switch.reset()

    @property
    def is_on(self) -> bool:
        """Return True if the fan is on."""
        return self.cync_switch.power_state

    @property
    def percentage(self) -> Optional[int]:
        """Return the current speed percentage."""
        return self.cync_switch.brightness

    @callback
    def async_set_percentage(self, percentage: int) -> None:
        """Set the speed percentage of the fan."""
        if percentage == 0:
            self.hass.async_create_task(self.async_turn_off())
        else:
            self.hass.async_create_task(self.async_turn_on(percentage=percentage))

    async def async_turn_on(
        self,
        percentage: Optional[int] = None,
        preset_mode: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Turn on the fan."""
        brightness = round(percentage * 255 / 100) if percentage is not None else None
        await self.cync_switch.turn_on(None, brightness, None)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the fan."""
        await self.cync_switch.turn_off()