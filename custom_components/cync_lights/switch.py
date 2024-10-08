"""Platform for Cync switch integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .cync_hub import CyncHub, CyncSwitch

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cync switches from a config entry."""
    hub: CyncHub = hass.data[DOMAIN][config_entry.entry_id]

    new_devices = []
    for switch_id, cync_switch in hub.cync_switches.items():
        if (
            not cync_switch._update_callback
            and cync_switch.plug
            and switch_id in config_entry.options.get("switches", [])
        ):
            new_devices.append(CyncPlugEntity(cync_switch))

    if new_devices:
        async_add_entities(new_devices)


class CyncPlugEntity(SwitchEntity):
    """Representation of a Cync Plug Switch Entity."""

    _attr_should_poll = False
    _attr_device_class = SwitchDeviceClass.OUTLET

    def __init__(self, cync_switch: CyncSwitch) -> None:
        """Initialize the plug switch entity."""
        self.cync_switch = cync_switch
        self._attr_unique_id = f"cync_plug_{self.cync_switch.device_id}"
        self._attr_name = self.cync_switch.name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.cync_switch.device_id)},
            manufacturer="Cync by Savant",
            name=f"{self.cync_switch.name} ({self.cync_switch.home_name})",
            suggested_area=self.cync_switch.room.name if self.cync_switch.room else None,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the entity is added to Home Assistant."""
        self.cync_switch.register(self.async_write_ha_state)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the entity is about to be removed from Home Assistant."""
        self.cync_switch.reset()

    @property
    def is_on(self) -> bool:
        """Return True if the switch is on."""
        return self.cync_switch.power_state

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the switch."""
        await self.cync_switch.turn_on(None, None, None)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the switch."""
        await self.cync_switch.turn_off()
