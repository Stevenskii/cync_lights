"""Platform for Cync light integration."""

from __future__ import annotations

from typing import Any, Tuple, List

import logging
import asyncio  # Ensure asyncio is imported

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_COLOR_TEMP,
    ATTR_EFFECT,
    ATTR_FLASH,
    ATTR_RGB_COLOR,
    ATTR_TRANSITION,
    ColorMode,
    LightEntity,
    LightEntityFeature,
)
from homeassistant.helpers.entity_group import async_create_group  # Correct import
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
    """Set up Cync light entities from a config entry."""
    hub: CyncHub = hass.data[DOMAIN][config_entry.entry_id]

    new_switches = []
    config_switches = config_entry.options.get("switches", {})

    # Add individual switch entities
    for switch_id, cync_switch in hub.cync_switches.items():
        if (
            not cync_switch._update_callback
            and not cync_switch.plug
            and not cync_switch.fan
            and switch_id in config_switches
        ):
            new_switches.append(CyncSwitchEntity(cync_switch))

    if new_switches:
        async_add_entities(new_switches)

    # Handle group creation or updating for each room
    for room_name, room in hub.cync_rooms.items():
        group_entity_id = f"group.cync_{room.room_id}"
        group_name = f"{room.name} Lights"

        # Get all switch entity IDs in the room
        switch_entity_ids = [
            f"light.cync_switch_{switch.device_id}"
            for switch in hub.cync_switches.values()
            if switch.device_id in room.switches
        ]

        if not switch_entity_ids:
            continue  # No switches in this room

        # Check if the group already exists
        group_state = hass.states.get(group_entity_id)
        if group_state:
            # Group exists, get existing members
            existing_entities = group_state.attributes.get("entity_id", [])
            # Merge with new switch entities, avoiding duplicates
            updated_entities = list(set(existing_entities + switch_entity_ids))
            # Update the group with the new entities
            try:
                await async_create_group(
                    hass,
                    group_entity_id,
                    group_name,
                    updated_entities,
                )
                _LOGGER.info(f"Updated group '{group_name}' with switches: {switch_entity_ids}")
            except Exception as e:
                _LOGGER.error(f"Failed to update group '{group_name}': {e}")
        else:
            # Group does not exist, create it
            try:
                await async_create_group(
                    hass,
                    group_entity_id,
                    group_name,
                    switch_entity_ids,
                )
                _LOGGER.info(f"Created group '{group_name}' with switches: {switch_entity_ids}")
            except Exception as e:
                _LOGGER.error(f"Failed to create group '{group_name}': {e}")


class CyncSwitchEntity(LightEntity):
    """Representation of a Cync Switch (Bulb) Light Entity."""

    def __init__(self, cync_switch: CyncSwitch) -> None:
        """Initialize the light."""
        self.cync_switch = cync_switch
        self._attr_name = self.cync_switch.name
        self._attr_unique_id = f'cync_switch_{self.cync_switch.device_id}'
        self._attr_should_poll = False
        self._attr_supported_features = LightEntityFeature(0)

        # Determine supported color modes based on capabilities
        supported_color_modes = set()
        if self.cync_switch.support_rgb and self.cync_switch.support_color_temp:
            supported_color_modes = {ColorMode.RGB, ColorMode.COLOR_TEMP}
        elif self.cync_switch.support_rgb:
            supported_color_modes = {ColorMode.RGB}
        elif self.cync_switch.support_color_temp:
            supported_color_modes = {ColorMode.COLOR_TEMP}
        elif self.cync_switch.support_brightness:
            supported_color_modes = {ColorMode.BRIGHTNESS}
        else:
            supported_color_modes = {ColorMode.ONOFF}

        self._attr_supported_color_modes = supported_color_modes

        # Handle effects if supported
        self._attr_effect_list = []
        if self.cync_switch.hub.effect_mapping:
            self._attr_effect_list = list(self.cync_switch.hub.effect_mapping.keys())
            self._attr_supported_features |= LightEntityFeature.EFFECT

        # Add flash support
        self._attr_supported_features |= LightEntityFeature.FLASH

        # Add transition support if brightness is supported
        if self.cync_switch.support_brightness:
            self._attr_supported_features |= LightEntityFeature.TRANSITION

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
            identifiers={(DOMAIN, self.cync_switch.device_id)},
            manufacturer="Cync by Savant",
            name=self.cync_switch.name,
            suggested_area=self.cync_switch.room.name if self.cync_switch.room else "Unknown Room",
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
    def color_temp(self) -> int | None:
        """Return color temperature in mireds."""
        if self.cync_switch.color_temp_kelvin is not None and self.cync_switch.color_temp_kelvin > 0:
            return int(1000000 / self.cync_switch.color_temp_kelvin)
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
        if self.cync_switch.support_rgb and self.cync_switch.rgb.get('active'):
            return ColorMode.RGB
        if self.cync_switch.support_color_temp and self.cync_switch.color_temp_kelvin:
            return ColorMode.COLOR_TEMP
        if ColorMode.BRIGHTNESS in self.supported_color_modes:
            return ColorMode.BRIGHTNESS
        return ColorMode.ONOFF

    @property
    def effect_list(self) -> list[str] | None:
        """Return the list of supported effects."""
        return self._attr_effect_list

    @property
    def effect(self) -> str | None:
        """Return the current effect."""
        return getattr(self.cync_switch, 'current_effect', None)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        """Return the optional state attributes."""
        return {"color_temp_kelvin": self.color_temp_kelvin}

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Turn on the light."""
        _LOGGER.debug("Turning on light: %s with kwargs: %s", self.name, kwargs)
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        color_temp_kelvin = kwargs.get(ATTR_COLOR_TEMP_KELVIN)
        rgb_color = kwargs.get(ATTR_RGB_COLOR)

        if not color_temp_kelvin and ATTR_COLOR_TEMP in kwargs:
            # Convert mireds to Kelvin
            try:
                color_temp_kelvin = int(1000000 / kwargs[ATTR_COLOR_TEMP])
            except (ValueError, ZeroDivisionError) as e:
                _LOGGER.error("Invalid color_temp value: %s", e)
                color_temp_kelvin = None

        effect = kwargs.get(ATTR_EFFECT)
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)

        # Handle effect "None" to stop any active effect
        if effect == "None":
            effect = None

        try:
            await self.cync_switch.turn_on(
                brightness=brightness,
                color_temp_kelvin=color_temp_kelvin,
                rgb_color=rgb_color,
                effect=effect,
                flash=flash,
                transition=transition,
            )
        except Exception as e:
            _LOGGER.error("Error turning on light %s: %s", self.name, e)

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        flash = kwargs.get(ATTR_FLASH)
        transition = kwargs.get(ATTR_TRANSITION)
        try:
            await self.cync_switch.turn_off(flash=flash, transition=transition)
        except Exception as e:
            _LOGGER.error("Error turning off light %s: %s", self.name, e)
