"""Platform for Cync light integration."""
from __future__ import annotations

import logging
from typing import Any, Optional

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP,
    ATTR_RGB_COLOR,
    COLOR_MODE_BRIGHTNESS,
    COLOR_MODE_COLOR_TEMP,
    COLOR_MODE_RGB,
    ColorMode,
    LightEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .cync_hub import CyncHub, CyncSwitch, CyncRoom

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cync lights from a config entry."""
    hub: CyncHub = hass.data[DOMAIN][config_entry.entry_id]

    new_devices = []

    # Add rooms as light entities
    for room_id, room in hub.cync_rooms.items():
        if (
            not room._update_callback
            and room_id in config_entry.options.get("rooms", [])
        ):
            new_devices.append(CyncRoomLightEntity(room))

    # Add subgroups as light entities
    for subgroup_id, subgroup in hub.cync_rooms.items():
        if (
            not subgroup._update_callback
            and subgroup_id in config_entry.options.get("subgroups", [])
        ):
            new_devices.append(CyncRoomLightEntity(subgroup))

    # Add switches as light entities
    for switch_id, switch in hub.cync_switches.items():
        if (
            not switch._update_callback
            and switch_id in config_entry.options.get("switches", [])
            and not switch.plug
            and not switch.fan
        ):
            new_devices.append(CyncSwitchLightEntity(switch))

    if new_devices:
        async_add_entities(new_devices)


class CyncRoomLightEntity(LightEntity):
    """Representation of a Cync Room as a Light Entity."""

    _attr_should_poll = False

    def __init__(self, cync_room: CyncRoom) -> None:
        """Initialize the light entity."""
        self.cync_room = cync_room
        self._attr_unique_id = f"cync_room_{self.cync_room.room_id}"
        self._attr_name = f"{self.cync_room.name}"
        self._attr_supported_color_modes = set()
        if self.cync_room.support_rgb:
            self._attr_supported_color_modes.add(ColorMode.RGB)
        if self.cync_room.support_color_temp:
            self._attr_supported_color_modes.add(ColorMode.COLOR_TEMP)
        if self.cync_room.support_brightness:
            self._attr_supported_color_modes.add(ColorMode.BRIGHTNESS)
        else:
            self._attr_supported_color_modes.add(ColorMode.ONOFF)

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.cync_room.room_id)},
            manufacturer="Cync by Savant",
            name=f"{self.cync_room.name} ({self.cync_room.home_name})",
            suggested_area=self.cync_room.name,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the entity is added to hass."""
        self.cync_room.register(self.async_write_ha_state)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the entity is about to be removed from hass."""
        self.cync_room.reset()

    @property
    def is_on(self) -> bool:
        """Return True if the light is on."""
        return self.cync_room.power_state

    @property
    def brightness(self) -> Optional[int]:
        """Return the brightness of the light."""
        return self.cync_room.brightness

    @property
    def color_temp_kelvin(self) -> Optional[int]:
        """Return the color temperature of the light in Kelvin."""
        return self.cync_room.color_temp_kelvin

    @property
    def rgb_color(self) -> Optional[tuple[int, int, int]]:
        """Return the RGB color value."""
        if self.cync_room.rgb["active"]:
            return (
                self.cync_room.rgb["r"],
                self.cync_room.rgb["g"],
                self.cync_room.rgb["b"],
            )
        return None

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return the maximum color temperature in Kelvin."""
        return self.cync_room.max_color_temp_kelvin

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return the minimum color temperature in Kelvin."""
        return self.cync_room.min_color_temp_kelvin

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp = kwargs.get(ATTR_COLOR_TEMP)
        await self.cync_room.turn_on(rgb, brightness, color_temp)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        await self.cync_room.turn_off()


class CyncSwitchLightEntity(LightEntity):
    """Representation of a Cync Switch as a Light Entity."""

    _attr_should_poll = False

    def __init__(self, cync_switch: CyncSwitch) -> None:
        """Initialize the light entity."""
        self.cync_switch = cync_switch
        self._attr_unique_id = f"cync_switch_{self.cync_switch.device_id}"
        self._attr_name = f"{self.cync_switch.name}"
        self._attr_supported_color_modes = set()
        if self.cync_switch.support_rgb:
            self._attr_supported_color_modes.add(ColorMode.RGB)
        if self.cync_switch.support_color_temp:
            self._attr_supported_color_modes.add(ColorMode.COLOR_TEMP)
        if self.cync_switch.support_brightness:
            self._attr_supported_color_modes.add(ColorMode.BRIGHTNESS)
        else:
            self._attr_supported_color_modes.add(ColorMode.ONOFF)

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.cync_switch.device_id)},
            manufacturer="Cync by Savant",
            name=f"{self.cync_switch.name} ({self.cync_switch.home_name})",
            suggested_area=self.cync_switch.room.name if self.cync_switch.room else None,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the entity is added to hass."""
        self.cync_switch.register(self.async_write_ha_state)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the entity is about to be removed from hass."""
        self.cync_switch.reset()

    @property
    def is_on(self) -> bool:
        """Return True if the light is on."""
        return self.cync_switch.power_state

    @property
    def brightness(self) -> Optional[int]:
        """Return the brightness of the light."""
        return self.cync_switch.brightness

    @property
    def color_temp_kelvin(self) -> Optional[int]:
        """Return the color temperature of the light in Kelvin."""
        return self.cync_switch.color_temp_kelvin

    @property
    def rgb_color(self) -> Optional[tuple[int, int, int]]:
        """Return the RGB color value."""
        if self.cync_switch.rgb["active"]:
            return (
                self.cync_switch.rgb["r"],
                self.cync_switch.rgb["g"],
                self.cync_switch.rgb["b"],
            )
        return None

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return the maximum color temperature in Kelvin."""
        return self.cync_switch.max_color_temp_kelvin

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return the minimum color temperature in Kelvin."""
        return self.cync_switch.min_color_temp_kelvin

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp = kwargs.get(ATTR_COLOR_TEMP)
        await self.cync_switch.turn_on(rgb, brightness, color_temp)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        await self.cync_switch.turn_off()
