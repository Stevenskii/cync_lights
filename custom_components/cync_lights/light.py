"""Platform for light integration."""

from __future__ import annotations

from typing import Any, Tuple

import logging

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_RGB_COLOR,
    ColorMode,
    LightEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cync light entities from a config entry."""
    hub = hass.data[DOMAIN][config_entry.entry_id]

    new_devices = []

    config_rooms = config_entry.options.get("rooms", {})
    config_subgroups = config_entry.options.get("subgroups", {})
    config_switches = config_entry.options.get("switches", {})

    for room_name, room in hub.cync_rooms.items():
        if not room._update_callback and (
            room_name in config_rooms or room_name in config_subgroups
        ):
            new_devices.append(CyncRoomEntity(room))

    for switch_id, cync_switch in hub.cync_switches.items():
        if (
            not cync_switch._update_callback
            and not cync_switch.plug
            and not cync_switch.fan
            and switch_id in config_switches
        ):
            new_devices.append(CyncSwitchEntity(cync_switch))

    if new_devices:
        async_add_entities(new_devices)


class CyncRoomEntity(LightEntity):
    """Representation of a Cync Room Light Entity."""

    _attr_should_poll = False

    def __init__(self, room) -> None:
        """Initialize the light."""
        self.room = room

    async def async_added_to_hass(self) -> None:
        """Run when this Entity has been added to HA."""
        self.room.register(self.async_write_ha_state, self.hass)

    async def async_will_remove_from_hass(self) -> None:
        """Entity being removed from hass."""
        self.room.reset()

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this entity."""
        room_name = self.room.parent_room if self.room.is_subgroup else self.room.name
        return DeviceInfo(
            identifiers={(DOMAIN, f"{room_name} ({self.room.home_name})")},
            manufacturer="Cync by Savant",
            name=f"{room_name} ({self.room.home_name})",
            suggested_area=room_name,
        )

    @property
    def icon(self) -> str | None:
        """Icon of the entity."""
        return "mdi:lightbulb-group-outline" if self.room.is_subgroup else "mdi:lightbulb-group"

    @property
    def unique_id(self) -> str:
        """Return Unique ID string."""
        switches_ids = '-'.join(sorted(self.room.switches))
        subgroups_ids = '-'.join(sorted(self.room.subgroups))
        uid = f"cync_room_{switches_ids}_{subgroups_ids}"
        return uid

    @property
    def name(self) -> str:
        """Return the name of the room."""
        return self.room.name

    @property
    def is_on(self) -> bool:
        """Return true if light is on."""
        return self.room.power_state

    @property
    def brightness(self) -> int | None:
        """Return the brightness of this room between 0..255."""
        if self.room.brightness is not None:
            return round(self.room.brightness * 255 / 100)
        return None

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature."""
        return self.room.max_color_temp_kelvin

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature."""
        return self.room.min_color_temp_kelvin

    @property
    def color_temp_kelvin(self) -> int | None:
        """Return color temperature in kelvin."""
        return self.room.color_temp_kelvin

    @property
    def rgb_color(self) -> Tuple[int, int, int] | None:
        """Return the RGB color tuple of this light."""
        rgb = self.room.rgb
        if rgb:
            return (rgb['r'], rgb['g'], rgb['b'])
        return None

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        """Return set of supported color modes."""
        modes = set()
        if self.room.support_color_temp:
            modes.add(ColorMode.COLOR_TEMP)
        if self.room.support_rgb:
            modes.add(ColorMode.RGB)
        if self.room.support_brightness:
            modes.add(ColorMode.BRIGHTNESS)
        if not modes:
            modes.add(ColorMode.ONOFF)
        return modes

    @property
    def color_mode(self) -> ColorMode:
        """Return the active color mode."""
        if self.room.support_rgb and self.room.rgb.get('active'):
            return ColorMode.RGB
        if self.room.support_color_temp:
            return ColorMode.COLOR_TEMP
        if self.room.support_brightness:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb_color = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp_kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        await self.room.turn_on(rgb_color, brightness, color_temp_kelvin)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        await self.room.turn_off()


class CyncSwitchEntity(LightEntity):
    """Representation of a Cync Switch Light Entity."""

    _attr_should_poll = False

    def __init__(self, cync_switch) -> None:
        """Initialize the light."""
        self.cync_switch = cync_switch

    async def async_added_to_hass(self) -> None:
        """Run when this Entity has been added to HA."""
        self.cync_switch.register(self.async_write_ha_state, self.hass)

    async def async_will_remove_from_hass(self) -> None:
        """Entity being removed from hass."""
        self.cync_switch.reset()

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this entity."""
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.cync_switch.room.name} ({self.cync_switch.home_name})")},
            manufacturer="Cync by Savant",
            name=f"{self.cync_switch.room.name} ({self.cync_switch.home_name})",
            suggested_area=self.cync_switch.room.name,
        )

    @property
    def unique_id(self) -> str:
        """Return Unique ID string."""
        return f'cync_switch_{self.cync_switch.device_id}'

    @property
    def name(self) -> str:
        """Return the name of the switch."""
        return self.cync_switch.name

    @property
    def is_on(self) -> bool:
        """Return true if light is on."""
        return self.cync_switch.power_state

    @property
    def brightness(self) -> int | None:
        """Return the brightness of this switch between 0..255."""
        if self.cync_switch.brightness is not None:
            return round(self.cync_switch.brightness * 255 / 100)
        return None

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature."""
        return self.cync_switch.max_color_temp_kelvin

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature."""
        return self.cync_switch.min_color_temp_kelvin

    @property
    def color_temp_kelvin(self) -> int | None:
        """Return the color temperature of this light for HA."""
        return self.cync_switch.color_temp_kelvin

    @property
    def rgb_color(self) -> Tuple[int, int, int] | None:
        """Return the RGB color tuple of this light switch."""
        rgb = self.cync_switch.rgb
        if rgb:
            return (rgb['r'], rgb['g'], rgb['b'])
        return None

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        """Return set of supported color modes."""
        modes = set()
        if self.cync_switch.support_color_temp:
            modes.add(ColorMode.COLOR_TEMP)
        if self.cync_switch.support_rgb:
            modes.add(ColorMode.RGB)
        if self.cync_switch.support_brightness:
            modes.add(ColorMode.BRIGHTNESS)
        if not modes:
            modes.add(ColorMode.ONOFF)
        return modes

    @property
    def color_mode(self) -> ColorMode:
        """Return the active color mode."""
        if self.cync_switch.support_rgb and self.cync_switch.rgb.get('active'):
            return ColorMode.RGB
        if self.cync_switch.support_color_temp:
            return ColorMode.COLOR_TEMP
        if self.cync_switch.support_brightness:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb_color = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp_kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        await self.cync_switch.turn_on(rgb_color, brightness, color_temp_kelvin)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        await self.cync_switch.turn_off()
