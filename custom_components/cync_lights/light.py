"""Platform for Cync light integration."""

from __future__ import annotations

from typing import Any, Tuple

import logging

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_EFFECT,
    ATTR_FLASH,
    ATTR_RGB_COLOR,
    ATTR_TRANSITION,
    ColorMode,
    LightEntity,
    LightEntityDescription,
    LightEntityFeature,
    FLASH_SHORT,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_COLOR_TEMP
from homeassistant.core import HomeAssistant
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

    _fixed_color_mode: ColorMode | None = None
    entity_description = LightEntityDescription(
        key="cync_light", has_entity_name=True, name=None
    )

    def __init__(self, room) -> None:
        """Initialize the light."""
        self.room = room
        self._attr_name = self.room.name
        self._attr_unique_id = self._generate_unique_id()
        self._attr_should_poll = False
        self._attr_supported_features = LightEntityFeature(0)

        # Determine supported color modes based on capabilities
        supported_color_modes = set()
        if self.room.support_rgb:
            supported_color_modes.add(ColorMode.RGB)
        if self.room.support_color_temp:
            supported_color_modes.add(ColorMode.COLOR_TEMP)
        if self.room.support_brightness:
            supported_color_modes.add(ColorMode.BRIGHTNESS)
            self._attr_supported_features |= LightEntityFeature.TRANSITION
        else:
            supported_color_modes.add(ColorMode.ONOFF)

        # Set fixed color mode if only one mode is supported
        if len(supported_color_modes) == 1:
            self._fixed_color_mode = next(iter(supported_color_modes))

        self._attr_supported_color_modes = supported_color_modes

        # Handle effects if supported
        self._attr_effect_list = []
        if self.room.hub.effect_mapping:
            self._attr_effect_list = list(self.room.hub.effect_mapping.keys())
            self._attr_supported_features |= LightEntityFeature.EFFECT

        # Add flash support
        self._attr_supported_features |= LightEntityFeature.FLASH

    def _generate_unique_id(self) -> str:
        """Generate unique ID for the entity."""
        switches_ids = '-'.join(sorted(self.room.switches))
        subgroups_ids = '-'.join(sorted(self.room.subgroups))
        uid = f"cync_room_{switches_ids}_{subgroups_ids}"
        return uid

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
        return (
            "mdi:lightbulb-group-outline"
            if self.room.is_subgroup
            else "mdi:lightbulb-group"
        )

    @property
    def unique_id(self) -> str:
        """Return Unique ID string."""
        return self._attr_unique_id

    @property
    def name(self) -> str:
        """Return the name of the room."""
        return self._attr_name

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
    def color_temp_kelvin(self) -> int | None:
        """Return color temperature in Kelvin."""
        return self.room.color_temp_kelvin

    @property
    def rgb_color(self) -> Tuple[int, int, int] | None:
        """Return the RGB color tuple of this light."""
        rgb = self.room.rgb
        if rgb and rgb.get('active'):
            return (rgb['r'], rgb['g'], rgb['b'])
        return None

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        """Return set of supported color modes."""
        return self._attr_supported_color_modes

    @property
    def color_mode(self) -> ColorMode:
        """Return the active color mode."""
        if self._fixed_color_mode:
            # The light supports only a single color mode
            return self._fixed_color_mode

        # Determine the active color mode
        if self.room.support_rgb and self.room.rgb.get('active'):
            return ColorMode.RGB
        if self.room.support_color_temp and self.room.color_temp_kelvin is not None:
            return ColorMode.COLOR_TEMP
        if self.room.support_brightness:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    @property
    def effect_list(self) -> list[str] | None:
        """Return the list of supported effects."""
        return self._attr_effect_list

    @property
    def effect(self) -> str | None:
        """Return the current effect."""
        if hasattr(self.room, 'current_effect'):
            return self.room.current_effect or None
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the optional state attributes."""
        attributes = {
            "room_mode": getattr(self.room, 'mode', None),
            "color_temp_kelvin": self.color_temp_kelvin,
        }
        return attributes

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb_color = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp_kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        if not color_temp_kelvin and ATTR_COLOR_TEMP in kwargs:
            # Convert mireds to Kelvin
            color_temp_kelvin = int(1000000 / kwargs[ATTR_COLOR_TEMP])
        effect = kwargs.get(ATTR_EFFECT)
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)

        # Handle effect "None" to stop any active effect
        if effect == "None":
            effect = None

        await self.room.turn_on(
            rgb_color=rgb_color,
            brightness=brightness,
            color_temp_kelvin=color_temp_kelvin,
            effect=effect,
            flash=flash,
            transition=transition,
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)
        await self.room.turn_off(flash=flash, transition=transition)


class CyncSwitchEntity(LightEntity):
    """Representation of a Cync Switch Light Entity."""

    _fixed_color_mode: ColorMode | None = None
    entity_description = LightEntityDescription(
        key="cync_switch_light", has_entity_name=True, name=None
    )

    def __init__(self, cync_switch) -> None:
        """Initialize the light."""
        self.cync_switch = cync_switch
        self._attr_name = self.cync_switch.name
        self._attr_unique_id = f'cync_switch_{self.cync_switch.device_id}'
        self._attr_should_poll = False
        self._attr_supported_features = LightEntityFeature(0)

        # Determine supported color modes based on capabilities
        supported_color_modes = set()
        if self.cync_switch.support_rgb:
            supported_color_modes.add(ColorMode.RGB)
        if self.cync_switch.support_color_temp:
            supported_color_modes.add(ColorMode.COLOR_TEMP)
        if self.cync_switch.support_brightness:
            supported_color_modes.add(ColorMode.BRIGHTNESS)
            self._attr_supported_features |= LightEntityFeature.TRANSITION
        else:
            supported_color_modes.add(ColorMode.ONOFF)

        # Set fixed color mode if only one mode is supported
        if len(supported_color_modes) == 1:
            self._fixed_color_mode = next(iter(supported_color_modes))

        self._attr_supported_color_modes = supported_color_modes

        # Handle effects if supported
        self._attr_effect_list = []
        if self.cync_switch.hub.effect_mapping:
            self._attr_effect_list = list(self.cync_switch.hub.effect_mapping.keys())
            self._attr_supported_features |= LightEntityFeature.EFFECT

        # Add flash support
        self._attr_supported_features |= LightEntityFeature.FLASH

    async def async_added_to_hass(self) -> None:
        """Run when this Entity has been added to HA."""
        self.cync_switch.register(self.async_write_ha_state, self.hass)

    async def async_will_remove_from_hass(self) -> None:
        """Entity being removed from hass."""
        self.cync_switch.reset()

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry information for this entity."""
        if self.cync_switch.room:
            room_name = self.cync_switch.room.name
        else:
            room_name = "Unknown Room"

        return DeviceInfo(
            identifiers={(DOMAIN, f"{room_name} ({self.cync_switch.home_name})")},
            manufacturer="Cync by Savant",
            name=f"{room_name} ({self.cync_switch.home_name})",
            suggested_area=room_name,
        )

    @property
    def unique_id(self) -> str:
        """Return Unique ID string."""
        return self._attr_unique_id

    @property
    def name(self) -> str:
        """Return the name of the switch."""
        return self._attr_name

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
    def color_temp_kelvin(self) -> int | None:
        """Return the color temperature of this light in Kelvin."""
        return self.cync_switch.color_temp_kelvin

    @property
    def rgb_color(self) -> Tuple[int, int, int] | None:
        """Return the RGB color tuple of this light switch."""
        rgb = self.cync_switch.rgb
        if rgb and rgb.get('active'):
            return (rgb['r'], rgb['g'], rgb['b'])
        return None

    @property
    def supported_color_modes(self) -> set[ColorMode]:
        """Return set of supported color modes."""
        return self._attr_supported_color_modes

    @property
    def color_mode(self) -> ColorMode:
        """Return the active color mode."""
        if self._fixed_color_mode:
            # The light supports only a single color mode
            return self._fixed_color_mode

        # Determine the active color mode
        if self.cync_switch.support_rgb and self.cync_switch.rgb.get('active'):
            return ColorMode.RGB
        if self.cync_switch.support_color_temp and self.cync_switch.color_temp_kelvin is not None:
            return ColorMode.COLOR_TEMP
        if self.cync_switch.support_brightness:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    @property
    def effect_list(self) -> list[str] | None:
        """Return the list of supported effects."""
        return self._attr_effect_list

    @property
    def effect(self) -> str | None:
        """Return the current effect."""
        if hasattr(self.cync_switch, 'current_effect'):
            return self.cync_switch.current_effect or None
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the optional state attributes."""
        attributes = {
            "switch_mode": getattr(self.cync_switch, 'mode', None),
            "color_temp_kelvin": self.color_temp_kelvin,
        }
        return attributes

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        rgb_color = kwargs.get(ATTR_RGB_COLOR)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp_kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        if not color_temp_kelvin and ATTR_COLOR_TEMP in kwargs:
            # Convert mireds to Kelvin
            color_temp_kelvin = int(1000000 / kwargs[ATTR_COLOR_TEMP])
        effect = kwargs.get(ATTR_EFFECT)
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)

        # Handle effect "None" to stop any active effect
        if effect == "None":
            effect = None

        await self.cync_switch.turn_on(
            rgb_color=rgb_color,
            brightness=brightness,
            color_temp_kelvin=color_temp_kelvin,
            effect=effect,
            flash=flash,
            transition=transition,
        )

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)
        await self.cync_switch.turn_off(flash=flash, transition=transition)
