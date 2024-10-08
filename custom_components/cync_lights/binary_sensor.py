"""Platform for Cync binary sensor integration."""
from __future__ import annotations

import logging
from typing import Any, Optional

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .cync_hub import CyncHub, CyncMotionSensor, CyncAmbientLightSensor

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Cync binary sensors from a config entry."""
    hub: CyncHub = hass.data[DOMAIN][config_entry.entry_id]

    new_devices = []

    # Setup motion sensors
    for sensor_id, sensor in hub.cync_motion_sensors.items():
        if (
            not sensor._update_callback
            and sensor_id in config_entry.options.get("motion_sensors", [])
        ):
            new_devices.append(CyncMotionSensorEntity(sensor))

    # Setup ambient light sensors
    for sensor_id, sensor in hub.cync_ambient_light_sensors.items():
        if (
            not sensor._update_callback
            and sensor_id in config_entry.options.get("ambient_light_sensors", [])
        ):
            new_devices.append(CyncAmbientLightSensorEntity(sensor))

    if new_devices:
        async_add_entities(new_devices)


class CyncMotionSensorEntity(BinarySensorEntity):
    """Representation of a Cync Motion Sensor."""

    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.MOTION

    def __init__(self, motion_sensor: CyncMotionSensor) -> None:
        """Initialize the motion sensor entity."""
        self.motion_sensor = motion_sensor
        self._attr_unique_id = f"cync_motion_sensor_{self.motion_sensor.device_id}"
        self._attr_name = f"{self.motion_sensor.name} Motion"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.motion_sensor.device_id)},
            manufacturer="Cync by Savant",
            name=f"{self.motion_sensor.name} ({self.motion_sensor.home_name})",
            suggested_area=self.motion_sensor.room.name
            if self.motion_sensor.room
            else None,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the entity is added to Home Assistant."""
        self.motion_sensor.register(self.async_write_ha_state)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the entity is about to be removed from Home Assistant."""
        self.motion_sensor.reset()

    @property
    def is_on(self) -> bool:
        """Return True if motion is detected."""
        return self.motion_sensor.motion


class CyncAmbientLightSensorEntity(BinarySensorEntity):
    """Representation of a Cync Ambient Light Sensor."""

    _attr_should_poll = False
    _attr_device_class = BinarySensorDeviceClass.LIGHT

    def __init__(self, ambient_light_sensor: CyncAmbientLightSensor) -> None:
        """Initialize the ambient light sensor entity."""
        self.ambient_light_sensor = ambient_light_sensor
        self._attr_unique_id = f"cync_ambient_light_sensor_{self.ambient_light_sensor.device_id}"
        self._attr_name = f"{self.ambient_light_sensor.name} Ambient Light"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self.ambient_light_sensor.device_id)},
            manufacturer="Cync by Savant",
            name=f"{self.ambient_light_sensor.name} ({self.ambient_light_sensor.home_name})",
            suggested_area=self.ambient_light_sensor.room.name
            if self.ambient_light_sensor.room
            else None,
        )

    async def async_added_to_hass(self) -> None:
        """Call when the entity is added to Home Assistant."""
        self.ambient_light_sensor.register(self.async_write_ha_state)

    async def async_will_remove_from_hass(self) -> None:
        """Call when the entity is about to be removed from Home Assistant."""
        self.ambient_light_sensor.reset()

    @property
    def is_on(self) -> bool:
        """Return True if ambient light is detected."""
        return self.ambient_light_sensor.ambient_light
