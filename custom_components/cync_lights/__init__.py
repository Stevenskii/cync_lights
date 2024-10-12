"""The Cync Room Lights integration."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .cync_hub import CyncHub

# Import platforms at module level to avoid blocking calls during event loop
from . import light, binary_sensor, switch, fan

PLATFORMS: list[str] = ["light", "binary_sensor", "switch", "fan"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Cync Room Lights from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    hub = CyncHub(entry.data, entry.options)
    hass.data[DOMAIN][entry.entry_id] = hub
    hub.start_tcp_client()

    # Forward the entry setups without causing a blocking call
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hub: CyncHub = hass.data[DOMAIN][entry.entry_id]
    hub.disconnect()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok