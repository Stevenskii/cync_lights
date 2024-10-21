"""The Cync Room Lights integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .cync_hub import CyncHub

# Import platforms at module level to avoid blocking calls during event loop
from . import light, binary_sensor, switch, fan

PLATFORMS: list[str] = ["light", "binary_sensor", "switch", "fan"]

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    """Set up Cync Room Lights from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Retrieve configuration data
    data = entry.data
    options = entry.options

    # Initialize CyncHub with SSL option
    hub = CyncHub(
        hass=hass,
        data=data,
        options=options
    )
    hass.data[DOMAIN][entry.entry_id] = hub

    # Forward the entry setups to the platforms
    for platform in PLATFORMS:
        hass.async_create_task(
            await hass.config_entries.async_forward_entry_setups(entry, platform)
        )

    return True

async def async_unload_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    """Unload a config entry."""
    hub: CyncHub = hass.data[DOMAIN].pop(entry.entry_id)
    hub.shutdown()

    # Unload platforms
    unload_ok = True
    for platform in PLATFORMS:
        platform_unload = await hass.config_entries.async_forward_entry_unload(entry, platform)
        unload_ok = unload_ok and platform_unload

    return unload_ok
