import asyncio
import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.helpers import entity_platform

from .cync_hub import CyncHub
from .const import DOMAIN, CONF_USERNAME, CONF_PASSWORD

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["light", "binary_sensor", "switch", "fan"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Cync Lights from a config entry."""
    username = entry.data[CONF_USERNAME]
    password = entry.data[CONF_PASSWORD]
    host = entry.data.get(CONF_HOST)
    port = entry.data.get(CONF_PORT)

    # Create CyncHub instance
    hub = CyncHub(hass, entry.data, entry.options)

    try:
        # Authenticate with the Cync API
        auth_result = await hub.authenticate(username, password)
        if not auth_result.get('authorized', False):
            _LOGGER.error("Failed to authenticate with Cync API")
            return False

        # Get configuration data from Cync API
        cync_config = await hub.get_cync_config()
        if not cync_config:
            _LOGGER.error("Failed to get Cync configuration")
            return False

        # Store hub object in Home Assistant's data store
        hass.data.setdefault(DOMAIN, {})
        hass.data[DOMAIN][entry.entry_id] = hub

        # Set up platforms (light, binary_sensor, switch, fan)
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

        _LOGGER.info("Successfully set up Cync Lights integration")
        return True

    except Exception as e:
        _LOGGER.error(f"Error setting up Cync Lights integration: {e}")
        return False


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a Cync Lights config entry."""
    hub = hass.data[DOMAIN].pop(entry.entry_id, None)

    if hub:
        await hub.shutdown()

    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    return unload_ok
