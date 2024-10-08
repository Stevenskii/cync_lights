"""Config flow for Cync Room Lights integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import config_validation as cv

from .const import DOMAIN
from .cync_hub import CyncUserData

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required("username"): str,
        vol.Required("password"): str,
    }
)

STEP_TWO_FACTOR_CODE_SCHEMA = vol.Schema(
    {
        vol.Required("two_factor_code"): str,
    }
)


async def cync_login(hub: CyncUserData, user_input: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input."""
    response = await hub.authenticate(user_input["username"], user_input["password"])
    if response["authorized"]:
        return {
            "title": f'cync_lights_{user_input["username"]}',
            "data": {
                "cync_credentials": hub.auth_code,
                "user_input": user_input,
            },
        }
    if response.get("two_factor_code_required"):
        raise TwoFactorCodeRequired
    raise InvalidAuth


async def submit_two_factor_code(
    hub: CyncUserData, user_input: dict[str, Any]
) -> dict[str, Any]:
    """Validate the two-factor code."""
    response = await hub.auth_two_factor(user_input["two_factor_code"])
    if response["authorized"]:
        return {
            "title": f'cync_lights_{hub.username}',
            "data": {
                "cync_credentials": hub.auth_code,
                "user_input": {
                    "username": hub.username,
                    "password": hub.password,
                },
            },
        }
    raise InvalidAuth


class CyncConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Cync Room Lights."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self.cync_hub = CyncUserData()
        self.data: dict[str, Any] = {}
        self.options: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await cync_login(self.cync_hub, user_input)
                info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            except TwoFactorCodeRequired:
                return await self.async_step_two_factor_code()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during login")
                errors["base"] = "unknown"
            else:
                self.data = info
                await self.async_set_unique_id(user_input["username"])
                self._abort_if_unique_id_configured()
                return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle two-factor authentication."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await submit_two_factor_code(self.cync_hub, user_input)
                info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during two-factor authentication")
                errors["base"] = "unknown"
            else:
                self.data = info
                await self.async_set_unique_id(self.cync_hub.username)
                self._abort_if_unique_id_configured()
                return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="two_factor_code",
            data_schema=STEP_TWO_FACTOR_CODE_SCHEMA,
            errors=errors,
        )

    async def async_step_select_switches(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Allow the user to select rooms and switches."""
        if user_input is not None:
            self.options = user_input
            return self.async_create_entry(
                title=self.data["title"], data=self.data["data"], options=self.options
            )

        cync_config = self.data["data"]["cync_config"]
        rooms = cync_config["rooms"]
        devices = cync_config["devices"]

        rooms_options = {
            room: f'{info["name"]} ({info["home_name"]})'
            for room, info in rooms.items()
            if not info.get("isSubgroup", False)
        }
        subgroups_options = {
            room: f'{info["name"]} ({info.get("parent_room", "")}:{info["home_name"]})'
            for room, info in rooms.items()
            if info.get("isSubgroup", False)
        }
        switches_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("ONOFF", False) and info.get("MULTIELEMENT", 1) == 1
        }
        motion_sensors_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("MOTION", False)
        }
        ambient_light_sensors_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("AMBIENT_LIGHT", False)
        }

        switches_data_schema = vol.Schema(
            {
                vol.Optional("rooms"): cv.multi_select(rooms_options),
                vol.Optional("subgroups"): cv.multi_select(subgroups_options),
                vol.Optional("switches"): cv.multi_select(switches_options),
                vol.Optional("motion_sensors"): cv.multi_select(motion_sensors_options),
                vol.Optional("ambient_light_sensors"): cv.multi_select(
                    ambient_light_sensors_options
                ),
            }
        )

        return self.async_show_form(
            step_id="select_switches", data_schema=switches_data_schema
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        """Get the options flow handler."""
        return CyncOptionsFlowHandler(config_entry)


class CyncOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for Cync integration."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry
        self.cync_hub = CyncUserData()
        self.data: dict[str, Any] = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            re_authenticate = user_input.get("re_authenticate") == "Yes"
            if re_authenticate:
                return await self.async_step_re_auth()
            return await self.async_step_select_switches()

        data_schema = vol.Schema(
            {
                vol.Required("re_authenticate", default="No"): vol.In(["Yes", "No"]),
            }
        )

        return self.async_show_form(step_id="init", data_schema=data_schema)

    async def async_step_re_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Re-authenticate with the service."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                user_data = self.config_entry.data["user_input"]
                info = await cync_login(self.cync_hub, user_data)
                info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            except TwoFactorCodeRequired:
                return await self.async_step_two_factor_code()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during re-authentication")
                errors["base"] = "unknown"
            else:
                self.data = info
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=self.data["data"]
                )
                return await self.async_step_select_switches()

        return self.async_show_form(step_id="re_auth", errors=errors)

    async def async_step_two_factor_code(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle two-factor authentication during options flow."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                info = await submit_two_factor_code(self.cync_hub, user_input)
                info["data"]["cync_config"] = await self.cync_hub.get_cync_config()
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception during two-factor authentication")
                errors["base"] = "unknown"
            else:
                self.data = info
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=self.data["data"]
                )
                return await self.async_step_select_switches()

        return self.async_show_form(
            step_id="two_factor_code",
            data_schema=STEP_TWO_FACTOR_CODE_SCHEMA,
            errors=errors,
        )

    async def async_step_select_switches(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Allow the user to select rooms and switches in options flow."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        cync_config = self.config_entry.data.get("cync_config", {})
        rooms = cync_config.get("rooms", {})
        devices = cync_config.get("devices", {})

        existing_options = self.config_entry.options

        rooms_options = {
            room: f'{info["name"]} ({info["home_name"]})'
            for room, info in rooms.items()
            if not info.get("isSubgroup", False)
        }
        subgroups_options = {
            room: f'{info["name"]} ({info.get("parent_room", "")}:{info["home_name"]})'
            for room, info in rooms.items()
            if info.get("isSubgroup", False)
        }
        switches_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("ONOFF", False) and info.get("MULTIELEMENT", 1) == 1
        }
        motion_sensors_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("MOTION", False)
        }
        ambient_light_sensors_options = {
            device_id: f'{info["name"]} ({info["room_name"]}:{info["home_name"]})'
            for device_id, info in devices.items()
            if info.get("AMBIENT_LIGHT", False)
        }

        switches_data_schema = vol.Schema(
            {
                vol.Optional(
                    "rooms",
                    default=existing_options.get("rooms", []),
                ): cv.multi_select(rooms_options),
                vol.Optional(
                    "subgroups",
                    default=existing_options.get("subgroups", []),
                ): cv.multi_select(subgroups_options),
                vol.Optional(
                    "switches",
                    default=existing_options.get("switches", []),
                ): cv.multi_select(switches_options),
                vol.Optional(
                    "motion_sensors",
                    default=existing_options.get("motion_sensors", []),
                ): cv.multi_select(motion_sensors_options),
                vol.Optional(
                    "ambient_light_sensors",
                    default=existing_options.get("ambient_light_sensors", []),
                ): cv.multi_select(ambient_light_sensors_options),
            }
        )

        return self.async_show_form(
            step_id="select_switches", data_schema=switches_data_schema
        )


class TwoFactorCodeRequired(HomeAssistantError):
    """Error to indicate that a two-factor code is required."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid authentication."""
