import logging
import threading
import asyncio
import struct
import aiohttp
import math
import ssl
import traceback
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

API_AUTH = "https://api.gelighting.com/v2/user_auth"
API_REQUEST_CODE = "https://api.gelighting.com/v2/two_factor/email/verifycode"
API_2FACTOR_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"

Capabilities = {
    "ONOFF": [1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24,
              25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48,
              49, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67,
              68, 80, 81, 82, 83, 85, 128, 129, 130, 131, 132, 133, 134, 135, 136,
              137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
              150, 151, 152, 153, 154, 155, 156, 158, 159, 160, 161, 162, 163,
              164, 165, 169, 170],
    "BRIGHTNESS": [1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22,
                   23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                   48, 49, 55, 56, 80, 81, 82, 83, 85, 128, 129, 130, 131, 132,
                   133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
                   145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156,
                   158, 159, 160, 161, 162, 163, 164, 165, 169, 170],
    "COLORTEMP": [5, 6, 7, 8, 10, 11, 14, 15, 19, 20, 21, 22, 23, 25, 26, 28,
                  29, 30, 31, 32, 33, 34, 35, 80, 82, 83, 85, 129, 130, 131, 132,
                  133, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
                  146, 147, 153, 154, 155, 156, 158, 159, 160, 161, 162, 163,
                  164, 165, 169, 170],
    "RGB": [6, 7, 8, 21, 22, 23, 30, 31, 32, 33, 34, 35, 131, 132, 133, 137,
            138, 139, 140, 141, 142, 143, 146, 147, 153, 154, 155, 156, 158,
            159, 160, 161, 162, 163, 164, 165, 169, 170],
    "MOTION": [37, 49, 54],
    "AMBIENT_LIGHT": [37, 49, 54],
    "WIFICONTROL": [36, 37, 38, 39, 40, 48, 49, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81, 128, 129,
                    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
                    141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
                    152, 153, 154, 155, 156, 158, 159, 160, 161, 162, 163,
                    164, 165, 169, 170],
    "PLUG": [64, 65, 66, 67, 68],
    "FAN": [81],
    "MULTIELEMENT": {'67': 2}
}

# Define custom exceptions
class UnreachableError(Exception):
    pass

class RemoteCallError(Exception):
    pass

class LostConnection(Exception):
    """Lost connection to Cync Server"""

class ShuttingDown(Exception):
    """Cync client shutting down"""

class InvalidCyncConfiguration(Exception):
    """Cync configuration is not supported"""

# Packet types
PACKET_TYPE_AUTH = 1
PACKET_TYPE_SYNC = 4
PACKET_TYPE_PIPE = 7
PACKET_TYPE_PIPE_SYNC = 8

# Pipe subtypes
PACKET_PIPE_TYPE_SET_STATUS = 0xd0
PACKET_PIPE_TYPE_SET_LUM = 0xd2
PACKET_PIPE_TYPE_SET_CT = 0xe2
PACKET_PIPE_TYPE_GET_STATUS = 0xdb
PACKET_PIPE_TYPE_GET_STATUS_PAGINATED = 0x52

# Constants
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_HOST = "cm.gelighting.com"
DEFAULT_PORT = 23778

class Packet:
    def __init__(self, packet_type: int, is_response: bool, data: bytes):
        self.type = packet_type
        self.is_response = is_response
        self.data = data

    def encode(self) -> bytes:
        """
        Encode the packet into raw binary form.
        """
        type_byte = (self.type << 4) | 3  # Assuming version 3
        if self.is_response:
            type_byte |= 8
        length = len(self.data)
        header = struct.pack(">B I", type_byte, length)
        return header + self.data
    
    @staticmethod
    def decode(raw_data: bytes) -> 'Packet':
        """
        Decode raw binary data into a Packet object.
        """
        if len(raw_data) < 5:
            raise ValueError("Insufficient data for header")
        type_byte = raw_data[0]
        packet_type = type_byte >> 4
        is_response = (type_byte & 8) != 0
        length = struct.unpack(">I", raw_data[1:5])[0]
        if len(raw_data) < 5 + length:
            raise ValueError("Insufficient data for payload")
        data = raw_data[5:5 + length]
        return Packet(packet_type, is_response, data)

    def __str__(self):
        return f"Packet(type={self.type}, response={self.is_response}, data={self.data.hex()})"

class StatusPaginatedResponse:
    def __init__(self, device: int, brightness: int, ct: int, is_on: bool, use_rgb: bool, rgb: Tuple[int, int, int]):
        self.device = device
        self.brightness = brightness
        self.ct = ct
        self.is_on = is_on
        self.use_rgb = use_rgb
        self.rgb = rgb

    def __repr__(self):
        return (f"StatusPaginatedResponse(device={self.device}, brightness={self.brightness}, "
                f"ct={self.ct}, is_on={self.is_on}, use_rgb={self.use_rgb}, rgb={self.rgb})")

class CyncHub:
    def __init__(
        self,
        hass: Any,
        data: Dict[str, Any],
        options: Dict[str, Any],
    ) -> None:
        """
        Initialize the CyncHub.
        """
        self.hass = hass
        self.host = data.get("host", DEFAULT_HOST)
        self.port = data.get("port", DEFAULT_PORT)
        self.login_code = bytearray(data['cync_credentials'])
        self.use_ssl = options.get("use_ssl", True)

        # Initialize device attributes
        self.home_devices = data['cync_config']['home_devices']
        self.home_controllers = data['cync_config']['home_controllers']
        self.switchID_to_homeID = data['cync_config']['switchID_to_homeID']
        self.connected_devices = {home_id: [] for home_id in self.home_controllers.keys()}
        self.shutting_down = False
        self.cync_rooms = {room_id: CyncRoom(room_id, room_info, self) for room_id, room_info in data['cync_config']['rooms'].items()}
        self.cync_switches = {
            device_id: CyncSwitch(device_id, switch_info, self.cync_rooms.get(switch_info['room'], None), self)
            for device_id, switch_info in data['cync_config']['devices'].items() if switch_info.get("ONOFF", False)
        }
        self.cync_motion_sensors = {
            device_id: CyncMotionSensor(device_id, device_info, self.cync_rooms.get(device_info['room'], None))
            for device_id, device_info in data['cync_config']['devices'].items() if device_info.get("MOTION", False)
        }
        self.cync_ambient_light_sensors = {
            device_id: CyncAmbientLightSensor(device_id, device_info, self.cync_rooms.get(device_info['room'], None))
            for device_id, device_info in data['cync_config']['devices'].items() if device_info.get("AMBIENT_LIGHT", False)
        }
        self.switchID_to_deviceIDs = {
            device_info.switch_id: [dev_id for dev_id, dev_info in self.cync_switches.items() if dev_info.switch_id == device_info.switch_id]
            for device_id, device_info in self.cync_switches.items() if int(device_info.switch_id) > 0
        }
        self.connected_devices_updated = False
        self.effect_mapping = self._parse_light_shows(data['cync_config'])
        [room.initialize() for room in self.cync_rooms.values() if room.is_subgroup]
        [room.initialize() for room in self.cync_rooms.values() if not room.is_subgroup]

        self.ssl_context: Optional[ssl.SSLContext] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.logged_in = False
        self.shutting_down = False

        self.buffer = b''
        self.packet_handlers: Dict[int, Callable[[bool, bytes], asyncio.Future]] = {}

        self.seq_num = 0
        self.seq_lock = threading.Lock()

        self.pending_commands: Dict[int, Dict[str, Any]] = {}
        self.pending_commands_lock = threading.Lock()
        [room.initialize() for room in self.cync_rooms.values() if room.is_subgroup]
        [room.initialize() for room in self.cync_rooms.values() if not room.is_subgroup]
    
        # Schedule the connect method
        self.hass.loop.create_task(self.connect())

    def get_seq_num(self):
        """Thread-safe method to get the next sequence number."""
        with self.seq_lock:
            self.seq_num += 1
            if self.seq_num > 65535:
                self.seq_num = 1  # Reset if exceeds max value
            return self.seq_num

    def _parse_light_shows(self, cync_config):
        """Parse lightShows data from cync_config and create a mapping."""
        effect_mapping = {}
        homes = cync_config.get('homes', {})
        for home_id, home_info in homes.items():
            light_shows = home_info.get('lightShows', [])
            for show in light_shows:
                effect_name = show['name']
                effect_index = show['index']
                effect_mapping[effect_name] = show
        return effect_mapping

    async def setup_ssl_context(self) -> None:
        """
        Set up SSL context asynchronously using Home Assistant's async_add_executor_job.
        """
        if self.use_ssl:
            _LOGGER.debug("Setting up SSL context asynchronously.")
            self.ssl_context = await self.hass.async_add_executor_job(ssl.create_default_context)
            _LOGGER.debug("SSL context setup complete.")
        else:
            self.ssl_context = None
            _LOGGER.debug("SSL is disabled for CyncHub.")

    async def connect(self):
        """
        Establish TCP connection and authenticate, with retries and task management.
        """
        _LOGGER.debug("CyncHub connect() method called.")
        while not self.shutting_down:
            try:
                await self.setup_ssl_context()  # Setup SSL context asynchronously
                
                # Attempt to establish a secure connection
                try:
                    _LOGGER.debug("Trying to establish SSL connection on port 23779.")
                    self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=self.ssl_context)
                except Exception:
                    _LOGGER.warning("SSL connection failed. Retrying with SSL context check disabled.")
                    if self.ssl_context:
                        self.ssl_context.check_hostname = False
                        self.ssl_context.verify_mode = ssl.CERT_NONE
                    try:
                        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=self.ssl_context)
                    except Exception:
                        _LOGGER.warning("SSL context failed. Falling back to unsecured connection.")
                        self.reader, self.writer = await asyncio.open_connection(self.host, 23778)
                
                _LOGGER.debug("TCP connection established.")
    
                # Send login code
                self.writer.write(self.login_code)
                await self.writer.drain()
                _LOGGER.debug(f"Sent login code: {self.login_code.hex()}")
    
                # Await login response
                login_response = await self.reader.read(1000)
                _LOGGER.debug(f"Login response: {login_response.hex()}")
    
                if not login_response:
                    _LOGGER.error("Authentication failed: no response from server")
                    raise Exception("Authentication failed: no response from server")
    
                # Process login response
                if login_response.startswith(b'\x18\x00\x00\x00\x02\x00\x00'):
                    self.logged_in = True
                    _LOGGER.info("Successfully authenticated with the server.")
                else:
                    _LOGGER.error(f"Authentication failed with response data: {login_response.hex()}")
                    raise Exception("Authentication failed with response data.")
    
                # Create tasks for handling TCP messages and other maintenance tasks
                read_tcp_messages = asyncio.create_task(self.read_tcp_messages(), name="Read TCP Messages")
                # Additional tasks can be added here if needed
    
                # Wait for the read_tcp_messages task to complete
                await read_tcp_messages
    
            except Exception as e:
                _LOGGER.error(f"Exception in connect(): {type(e).__name__}: {e}")
                _LOGGER.debug("Traceback:", exc_info=True)
                await asyncio.sleep(5)  # Retry connection after a delay if an error occurs

    async def read_tcp_messages(self):
        """
        Continuously read and process TCP messages from the server.
        """
        while not self.shutting_down:
            try:
                data = await self.reader.read(1024)
                if not data:
                    _LOGGER.error("Connection closed by the server.")
                    self.logged_in = False
                    raise LostConnection
                self.buffer += data
                _LOGGER.debug(f"Received raw data: {data.hex()}")

                while True:
                    if len(self.buffer) < 5:
                        break  # Not enough data for header
                    # Peek at the header
                    header = self.buffer[:5]
                    type_byte = header[0]
                    packet_type = type_byte >> 4
                    is_response = (type_byte & 8) != 0
                    packet_length = struct.unpack(">I", header[1:5])[0]
                    _LOGGER.debug(f"Packet Type: {packet_type}, Is Response: {is_response}, Packet Length: {packet_length}")

                    if packet_length == 0:
                        _LOGGER.warning(f"Received packet with length 0. Skipping byte: {self.buffer[0]:02X}")
                        self.buffer = self.buffer[1:]
                        continue

                    if len(self.buffer) < 5 + packet_length:
                        break  # Wait for the full packet

                    packet_data = self.buffer[5:5 + packet_length]
                    self.buffer = self.buffer[5 + packet_length:]
                    _LOGGER.debug(f"Packet Content: {packet_data.hex()}")

                    # Handle the packet
                    await self.handle_packet(packet_type, is_response, packet_data)

            except LostConnection:
                _LOGGER.error("Lost connection to Cync server.")
                break
            except Exception as e:
                _LOGGER.error(f"Exception in read_tcp_messages: {e}")
                _LOGGER.debug("Traceback:", exc_info=True)
                await asyncio.sleep(5)  # Wait before retrying

        raise ShuttingDown

    async def handle_packet(self, packet_type: int, is_response: bool, data: bytes):
        """
        Dispatch packet to the appropriate handler based on packet_type.
        """
        try:
            if packet_type == PACKET_TYPE_AUTH:
                await self.handle_packet_type_auth(is_response, data)
            elif packet_type == PACKET_TYPE_SYNC:
                await self.handle_packet_type_sync(is_response, data)
            elif packet_type == PACKET_TYPE_PIPE:
                await self.handle_packet_type_pipe(is_response, data)
            elif packet_type == PACKET_TYPE_PIPE_SYNC:
                await self.handle_packet_type_pipe_sync(is_response, data)
            else:
                _LOGGER.warning(f"Unhandled packet type: {packet_type}, Length: {len(data)}")
        except Exception as e:
            _LOGGER.error(f"Error handling packet type {packet_type}: {e}")
            _LOGGER.debug("Traceback:", exc_info=True)

    async def handle_packet_type_auth(self, is_response: bool, data: bytes):
        """
        Handle authentication response packets.
        """
        if is_response:
            if data.startswith(b'\x00\x00'):
                _LOGGER.info("Authentication acknowledged by server.")
            else:
                _LOGGER.error(f"Authentication failed with response data: {data.hex()}")
        else:
            _LOGGER.warning("Received unexpected Auth packet as a request.")

    async def handle_packet_type_sync(self, is_response: bool, data: bytes):
        """
        Handle sync packets.
        """
        if is_response:
            _LOGGER.debug("Received Sync response packet.")
            # Implement sync response handling if necessary
        else:
            _LOGGER.debug("Received Sync request packet.")
            # Implement sync request handling if necessary

    async def handle_packet_type_pipe(self, is_response: bool, data: bytes):
        """
        Handle pipe packets based on their subtype.
        """
        if not data:
            _LOGGER.warning("Received empty Pipe packet.")
            return

        subtype = data[0]
        payload = data[1:]
        _LOGGER.debug(f"Pipe Subtype: {subtype}, Payload Length: {len(payload)}")

        if subtype == PACKET_PIPE_TYPE_SET_STATUS:
            await self.handle_pipe_set_status(is_response, payload)
        elif subtype == PACKET_PIPE_TYPE_SET_LUM:
            await self.handle_pipe_set_lum(is_response, payload)
        elif subtype == PACKET_PIPE_TYPE_SET_CT:
            await self.handle_pipe_set_ct(is_response, payload)
        elif subtype == PACKET_PIPE_TYPE_GET_STATUS_PAGINATED:
            await self.handle_pipe_get_status_paginated(is_response, payload)
        else:
            _LOGGER.warning(f"Unhandled Pipe subtype: {subtype}")

    async def handle_packet_type_pipe_sync(self, is_response: bool, data: bytes):
        """
        Handle Pipe Sync packets.
        """
        if is_response:
            _LOGGER.debug("Received Pipe Sync response packet.")
            # Implement Pipe Sync response handling if necessary
        else:
            _LOGGER.debug("Received Pipe Sync request packet.")
            # Implement Pipe Sync request handling if necessary

    async def handle_pipe_set_status(self, is_response: bool, payload: bytes):
        """
        Handle Set Status pipe packets.
        """
        if is_response:
            if len(payload) < 6:
                _LOGGER.error("Set Status acknowledgment packet too short.")
                return
            seq_num = struct.unpack(">H", payload[4:6])[0]
            _LOGGER.debug(f"Received Set Status acknowledgment for sequence {seq_num}")
            self.execute_callback(seq_num)
        else:
            _LOGGER.debug("Received Set Status request packet.")
            # Implement Set Status request handling if necessary
    
    
    async def handle_pipe_set_lum(self, is_response: bool, payload: bytes):
        """
        Handle Set Lum pipe packets.
        """
        if is_response:
            if len(payload) < 6:
                _LOGGER.error("Set Lum acknowledgment packet too short.")
                return
            seq_num = struct.unpack(">H", payload[4:6])[0]
            _LOGGER.debug(f"Received Set Lum acknowledgment for sequence {seq_num}")
            self.execute_callback(seq_num)
        else:
            _LOGGER.debug("Received Set Lum request packet.")
            # Implement Set Lum request handling if necessary
    
    
    async def handle_pipe_set_ct(self, is_response: bool, payload: bytes):
        """
        Handle Set CT pipe packets.
        """
        if is_response:
            if len(payload) < 6:
                _LOGGER.error("Set CT acknowledgment packet too short.")
                return
            seq_num = struct.unpack(">H", payload[4:6])[0]
            _LOGGER.debug(f"Received Set CT acknowledgment for sequence {seq_num}")
            self.execute_callback(seq_num)
        else:
            _LOGGER.debug("Received Set CT request packet.")
            # Implement Set CT request handling if necessary
    async def handle_pipe_subtype_17(self, is_response: bool, payload: bytes):
        """
        Handle Pipe Subtype 17: Acknowledgment for Set Status.
        """
        if is_response:
            if len(payload) >= 6:
                seq_num = struct.unpack(">H", payload[4:6])[0]
                _LOGGER.debug(f"Received Pipe subtype 17 acknowledgment for sequence {seq_num}")
                # Retrieve command info
                command_info = self.pending_commands.get(seq_num)
                if command_info:
                    device = command_info['device']
                    action = command_info['action']
                    if action == 'turn_on':
                        device.update_switch(state=True)
                    elif action == 'turn_off':
                        device.update_switch(state=False)
                self.execute_callback(seq_num)
            else:
                _LOGGER.warning("Pipe subtype 17 payload too short.")
        else:
            _LOGGER.warning("Received unexpected Pipe subtype 17 as a request.")
    
    async def handle_pipe_subtype_18(self, is_response: bool, payload: bytes):
        """
        Handle Pipe Subtype 18: Acknowledgment for Set Luminosity.
        """
        if is_response:
            if len(payload) >= 6:
                seq_num = struct.unpack(">H", payload[4:6])[0]
                _LOGGER.debug(f"Received Pipe subtype 18 acknowledgment for sequence {seq_num}")
                # Retrieve command info
                command_info = self.pending_commands.get(seq_num)
                if command_info:
                    device = command_info['device']
                    action = command_info['action']
                    brightness = command_info.get('brightness')
                    device.update_switch(brightness=brightness)
                self.execute_callback(seq_num)
            else:
                _LOGGER.warning("Pipe subtype 18 payload too short.")
        else:
            _LOGGER.warning("Received unexpected Pipe subtype 18 as a request.")
    
    async def handle_pipe_subtype_37(self, is_response: bool, payload: bytes):
        """
        Handle Pipe Subtype 37: Acknowledgment for Set Color Temperature.
        """
        if is_response:
            if len(payload) >= 6:
                seq_num = struct.unpack(">H", payload[4:6])[0]
                _LOGGER.debug(f"Received Pipe subtype 37 acknowledgment for sequence {seq_num}")
                # Retrieve command info
                command_info = self.pending_commands.get(seq_num)
                if command_info:
                    device = command_info['device']
                    action = command_info['action']
                    color_temp_kelvin = command_info.get('color_temp_kelvin')
                    device.update_switch(color_temp_kelvin=color_temp_kelvin)
                self.execute_callback(seq_num)
            else:
                _LOGGER.warning("Pipe subtype 37 payload too short.")
        else:
            _LOGGER.warning("Received unexpected Pipe subtype 37 as a request.")
    
    
    
    async def handle_pipe_get_status_paginated(self, is_response: bool, payload: bytes):
        """
        Handle Get Status Paginated pipe packets.
        """
        if is_response:
            _LOGGER.debug("Received Get Status Paginated response packet.")
            responses = self.parse_status_paginated_response(payload)
            for response in responses:
                _LOGGER.debug(f"Device {response.device} - Status: {'On' if response.is_on else 'Off'}, "
                            f"Brightness: {response.brightness}, CT: {response.ct}, RGB: {response.rgb}")
                # Update device states in Home Assistant accordingly
                # This requires integration with Home Assistant's state management
        else:
            _LOGGER.debug("Received Get Status Paginated request packet.")
            # Implement Get Status Paginated request handling if necessary
    
    
    def parse_status_paginated_response(self, payload: bytes) -> List[StatusPaginatedResponse]:
        """
        Parse the Status Paginated Response payload.
        """
        responses = []
        try:
            # Example parsing logic based on Go project's DecodeStatusPaginatedResponse
            # Adjust byte offsets as per actual protocol specifications
            # Assuming:
            # Byte 1: Device
            # Byte 9: IsOn
            # Byte 13: Brightness
            # Byte 17: CT (Color Tone)
            # Byte 21-23: RGB
    
            if len(payload) < 24:
                _LOGGER.error("Status Paginated Response payload too short.")
                return responses
    
            while len(payload) >= 24:
                device = payload[1]
                is_on = payload[9] != 0
                brightness = payload[13]
                ct = payload[17]
                use_rgb = payload[17] == 0xfe
                rgb = (payload[21], payload[22], payload[23]) if use_rgb else (0, 0, 0)
    
                response = StatusPaginatedResponse(
                    device=device,
                    brightness=brightness,
                    ct=ct,
                    is_on=is_on,
                    use_rgb=use_rgb,
                    rgb=rgb
                )
                responses.append(response)
                _LOGGER.debug(f"Parsed StatusPaginatedResponse: {response}")
    
                payload = payload[24:]
        except Exception as e:
            _LOGGER.error(f"Error parsing Status Paginated Response: {e}")
            _LOGGER.debug("Payload:", exc_info=True)
        return responses
    
    def execute_callback(self, seq_num: int):
        """
        Execute the callback associated with a sequence number.
        Also, update the device state based on the action.
        """
        with self.pending_commands_lock:
            command_info = self.pending_commands.pop(seq_num, None)
    
        if command_info:
            callback = command_info['callback']
            device = command_info['device']
            action = command_info['action']
            try:
                callback(seq_num)  # Existing callback execution
                _LOGGER.debug(f"Executed callback for sequence {seq_num} on device {device.device_id} for action '{action}'")
                # Update the device state based on the action
                if action == 'turn_on':
                    device._state = True
                elif action == 'turn_off':
                    device._state = False
                elif action == 'set_brightness':
                    # Assuming brightness is already set in the callback
                    pass
                elif action == 'set_color_temp':
                    # Assuming color_temp_kelvin is already set in the callback
                    pass
                elif action == 'set_rgb':
                    # Assuming RGB is already set in the callback
                    pass
                else:
                    _LOGGER.warning(f"Unknown action '{action}' for device {device.device_id}")
                # Notify Home Assistant of the state change asynchronously
                if device:
                    asyncio.run_coroutine_threadsafe(device.publish_update(), self.hass.loop)
            except Exception as e:
                _LOGGER.error(f"Error executing callback for sequence {seq_num}: {e}")
        else:
            _LOGGER.warning(f"No pending command found for sequence {seq_num}.")



    async def send_request(
        self,
        packet: Packet,
        callback: Optional[Callable[[int], None]] = None,
        device: Optional['CyncSwitch'] = None,
        action: Optional[str] = None
    ) -> Optional[int]:
        """
        Send a request packet to the server with an optional callback for acknowledgment.
        Additional context: device and action.

        Args:
            packet (Packet): The packet to send.
            callback (Optional[Callable[[int], None]]): Function to call upon acknowledgment.
            device (Optional['CyncSwitch']): The device associated with the command.
            action (Optional[str]): The action being performed.

        Returns:
            Optional[int]: The sequence number of the sent packet, if applicable.
        """
        if not self.logged_in or not self.writer:
            _LOGGER.error("Cannot send request: Not authenticated or writer not available.")
            return None

        encoded_packet = packet.encode()
        try:
            self.writer.write(encoded_packet)
            await self.writer.drain()
            _LOGGER.debug(f"Sent packet: {encoded_packet.hex()} | Packet: {packet}")

            seq_num = self.extract_seq_num(packet)
            if callback and device and action and seq_num:
                with self.pending_commands_lock:
                    self.pending_commands[seq_num] = {
                        'callback': callback,
                        'device': device,
                        'action': action
                    }
                _LOGGER.debug(f"Registered callback for sequence {seq_num} with device {device.device_id} and action '{action}'")
            return seq_num
        except Exception as e:
            _LOGGER.error(f"Error sending request: {e}")
            _LOGGER.debug("Exception details:", exc_info=True)
            return None

    def extract_seq_num(self, packet: Packet) -> Optional[int]:
        """
        Extract the sequence number from a packet.

        Args:
            packet (Packet): The packet from which to extract the sequence number.

        Returns:
            Optional[int]: The extracted sequence number, or None if extraction fails.
        """
        try:
            if packet.type != PACKET_TYPE_PIPE:
                _LOGGER.warning(f"Packet type {packet.type} is not PIPE. Sequence number extraction skipped.")
                return None
            # Correctly extract sequence number from bytes 4-5
            if len(packet.data) < 6:
                _LOGGER.error("Packet data too short to extract sequence number.")
                return None
            seq_num = struct.unpack(">H", packet.data[4:6])[0]
            return seq_num
        except Exception as e:
            _LOGGER.error(f"Error extracting sequence number: {e}")
            _LOGGER.debug("Exception details:", exc_info=True)
            return None

    # Packet creation methods
    def create_set_status_packet(self, device_id: int, seq: int, device_index: int, status: int) -> Packet:
        # Device ID: 4 bytes, big-endian
        device_id_bytes = device_id.to_bytes(4, 'big')
        # Sequence Number: 2 bytes, big-endian
        seq_num_bytes = struct.pack(">H", seq)
        # Additional fixed bytes
        fixed_bytes = bytes([0x00]) + struct.pack(">H", 0x7e00) + bytes([1, 0, 0, 0xf8])
        # Subtype: 1 byte
        subtype_byte = PACKET_PIPE_TYPE_SET_STATUS.to_bytes(1, 'big')
        # Payload: device_index (2 bytes, big-endian), command-specific data
        payload = struct.pack(">H", device_index) + bytes([status])
        # Payload Length: 1 byte
        payload_length = len(payload).to_bytes(1, 'big')
        # Combine all parts
        data = device_id_bytes + seq_num_bytes + fixed_bytes + subtype_byte + payload_length + payload + bytes([0x00, 0x00, 0x00])
        
        packet = Packet(
            packet_type=PACKET_TYPE_PIPE,
            is_response=False,
            data=data
        )
        _LOGGER.debug(f"Created Set Status Packet: {packet}")
        return packet



    def create_set_lum_packet(self, device_id: int, seq: int, device_index: int, brightness: int) -> Packet:
        if brightness < 1 or brightness > 100:
            raise ValueError("Brightness must be between 1 and 100.")
        # Device ID: 4 bytes, big-endian
        device_id_bytes = device_id.to_bytes(4, 'big')
        # Sequence Number: 2 bytes, big-endian
        seq_num_bytes = struct.pack(">H", seq)
        # Additional fixed bytes
        fixed_bytes = bytes([0x00]) + struct.pack(">H", 0x7e00) + bytes([1, 0, 0, 0xf8])
        # Subtype: 1 byte
        subtype_byte = PACKET_PIPE_TYPE_SET_LUM.to_bytes(1, 'big')
        # Payload: device_index (2 bytes, big-endian), command-specific data
        payload = struct.pack(">H", device_index) + bytes([brightness])
        # Payload Length: 1 byte
        payload_length = len(payload).to_bytes(1, 'big')
        # Combine all parts
        data = device_id_bytes + seq_num_bytes + fixed_bytes + subtype_byte + payload_length + payload + bytes([0x00, 0x00, 0x00])
        
        packet = Packet(
            packet_type=PACKET_TYPE_PIPE,
            is_response=False,
            data=data
        )
        _LOGGER.debug(f"Created Set Lum Packet: {packet}")
        return packet

    
    def create_set_ct_packet(self, device_id: int, seq: int, device_index: int, ct: int) -> Packet:
        if ct < 0 or ct > 100:
            raise ValueError("Color tone must be between 0 and 100.")
        # Device ID: 4 bytes, big-endian
        device_id_bytes = device_id.to_bytes(4, 'big')
        # Sequence Number: 2 bytes, big-endian
        seq_num_bytes = struct.pack(">H", seq)
        # Additional fixed bytes
        fixed_bytes = bytes([0x00]) + struct.pack(">H", 0x7e00) + bytes([1, 0, 0, 0xf8])
        # Subtype: 1 byte
        subtype_byte = PACKET_PIPE_TYPE_SET_CT.to_bytes(1, 'big')
        # Payload: device_index (2 bytes, big-endian), command-specific data
        payload = struct.pack(">H", device_index) + bytes([0x05, ct])
        # Payload Length: 1 byte
        payload_length = len(payload).to_bytes(1, 'big')
        # Combine all parts
        data = device_id_bytes + seq_num_bytes + fixed_bytes + subtype_byte + payload_length + payload + bytes([0x00, 0x00, 0x00])
        
        packet = Packet(
            packet_type=PACKET_TYPE_PIPE,
            is_response=False,
            data=data
        )
        _LOGGER.debug(f"Created Set CT Packet: {packet}")
        return packet
    
    def create_set_rgb_packet(self, device_id: int, seq: int, device_index: int, r: int, g: int, b: int) -> Packet:
        # Device ID: 4 bytes, big-endian
        device_id_bytes = device_id.to_bytes(4, 'big')
        # Sequence Number: 2 bytes, big-endian
        seq_num_bytes = struct.pack(">H", seq)
        # Additional fixed bytes
        fixed_bytes = bytes([0x00]) + struct.pack(">H", 0x7e00) + bytes([1, 0, 0, 0xf8])
        # Subtype: 1 byte (Assuming CT subtype for RGB as per Go API)
        subtype_byte = PACKET_PIPE_TYPE_SET_CT.to_bytes(1, 'big')
        # Payload: device_index (2 bytes, big-endian), command-specific data
        payload = struct.pack(">H", device_index) + bytes([0x04, r, g, b])
        # Payload Length: 1 byte
        payload_length = len(payload).to_bytes(1, 'big')
        # Combine all parts
        data = device_id_bytes + seq_num_bytes + fixed_bytes + subtype_byte + payload_length + payload + bytes([0x00, 0x00, 0x00])
        
        packet = Packet(
            packet_type=PACKET_TYPE_PIPE,
            is_response=False,
            data=data
        )
        _LOGGER.debug(f"Created Set RGB Packet: {packet}")
        return packet
    
    def create_get_status_paginated_packet(self, device_id: int, seq: int) -> Packet:
        data = bytearray([
            0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00
        ])
        # Embed the sequence number into bytes 1-2 of the data if required
        # Assuming Get Status Paginated doesn't require seq_num, based on protocol
        packet = Packet(
            packet_type=PACKET_TYPE_PIPE,
            is_response=False,
            data=bytes([PACKET_PIPE_TYPE_GET_STATUS_PAGINATED]) + bytes(data)
        )
        _LOGGER.debug(f"Created Get Status Paginated Packet: {packet}")
        return packet


    # Command sending methods
    async def set_device_status(
        self,
        device_id: int,
        device_index: int,
        status: int,
        callback: Optional[Callable[[int], None]] = None,
        device: Optional['CyncSwitch'] = None,
        action: Optional[str] = None
    ) -> None:
        """
        Send a Set Status command to a device.
        """
        seq_num = self.get_seq_num()
        packet = self.create_set_status_packet(device_id, seq_num, device_index, status)
        await self.send_request(packet, callback, device=device, action=action)
        


    async def set_device_lum(
        self,
        device_id: int,
        device_index: int,
        brightness: int,
        callback: Optional[Callable[[str], None]] = None,  # Added comma
        device: Optional['CyncSwitch'] = None,
        action: Optional[str] = None
    ) -> None:
        """
        Send a Set Lum command to a device.
        """
        seq_num = self.get_seq_num()
        packet = self.create_set_lum_packet(device_id, seq_num, device_index, brightness)
        await self.send_request(packet, callback, device=device, action=action)

    async def set_device_ct(
        self,
        device_id: int,
        device_index: int,
        ct: int,
        callback: Optional[Callable[[str], None]] = None
        device: Optional['CyncSwitch'] = None,
        action: Optional[str] = None
    ) -> None:
        """
        Send a Set CT command to a device.
        """
        seq_num = self.get_seq_num()
        packet = self.create_set_ct_packet(device_id, seq_num, device_index, ct)
        await self.send_request(packet, callback, device=device, action=action)

    async def set_device_rgb(
        self,
        device_id: int,
        device_index: int,
        r: int,
        g: int,
        b: int,
        callback: Optional[Callable[[str], None]] = None
        device: Optional['CyncSwitch'] = None,
        action: Optional[str] = None
    ) -> None:
        """
        Send a Set RGB command to a device.
        """
        seq_num = self.get_seq_num()
        packet = self.create_set_rgb_packet(device_id, seq_num, device_index, r, g, b)
        await self.send_request(packet, callback, device=device, action=action)

    async def get_device_status_paginated(
        self,
        device_id: int,
        callback: Optional[Callable[[str], None]] = None
    ) -> None:
        """
        Send a Get Status Paginated command to a device.
        """
        seq_num = self.get_seq_num()
        packet = self.create_get_status_paginated_packet(device_id, seq_num)
        await self.send_request(packet, callback)

    # Shutdown method to gracefully close the connection
    def shutdown(self):
        """
        Gracefully shut down the CyncHub.
        """
        self.shutting_down = True
        if self.writer:
            self.hass.loop.create_task(self._close_writer())

    async def _close_writer(self):
        """
        Close the writer asynchronously.
        """
        self.writer.close()
        await self.writer.wait_closed()
        _LOGGER.info("CyncHub has been shut down.")

class CyncRoom:
    def __init__(self, room_id: str, room_info: Dict[str, Any], hub) -> None:
        """Initialize the Cync Room."""
        self.hub = hub
        self.room_id = room_id
        self.home_id = room_id.split('-')[0]
        self.name = room_info.get('name', 'unknown')
        self.home_name = room_info.get('home_name', 'unknown')
        self.parent_room = room_info.get('parent_room', 'unknown')
        self.mesh_id = int(room_info.get('mesh_id', 0)).to_bytes(2, 'little')
        self.power_state = False
        self.brightness = 0
        self.color_temp_kelvin = 0
        self.rgb = {'r': 0, 'g': 0, 'b': 0, 'active': False}
        self.switches = room_info.get('switches', [])
        self.subgroups = room_info.get('subgroups', [])
        self.is_subgroup = room_info.get('isSubgroup', False)
        self.all_room_switches = self.switches.copy()
        self.controllers: List[str] = []
        self.default_controller = room_info.get('room_controller', self.hub.home_controllers[self.home_id][0])
        self._update_callback: Optional[Callable[[], None]] = None
        self._update_parent_room: Optional[Callable[[], None]] = None
        self.support_brightness = False
        self.support_color_temp = False
        self.support_rgb = False
        self.switches_support_brightness = []
        self.switches_support_color_temp = []
        self.switches_support_rgb = []
        self.groups_support_brightness = []
        self.groups_support_color_temp = []
        self.groups_support_rgb = []
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def initialize(self):
        """Initialize supported features and register update functions for switches and subgroups."""
        self.switches_support_brightness = [
            device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_brightness
        ]
        self.switches_support_color_temp = [
            device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_color_temp
        ]
        self.switches_support_rgb = [
            device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_rgb
        ]
        self.groups_support_brightness = [
            room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_brightness
        ]
        self.groups_support_color_temp = [
            room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_color_temp
        ]
        self.groups_support_rgb = [
            room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_rgb
        ]
        self.support_brightness = (len(self.switches_support_brightness) + len(self.groups_support_brightness)) > 0
        self.support_color_temp = (len(self.switches_support_color_temp) + len(self.groups_support_color_temp)) > 0
        self.support_rgb = (len(self.switches_support_rgb) + len(self.groups_support_rgb)) > 0
        for switch_id in self.switches:
            self.hub.cync_switches[switch_id].register_room_updater(self.update_room)
        for subgroup in self.subgroups:
            self.hub.cync_rooms[subgroup].register_room_updater(self.update_room)
            self.all_room_switches.extend(self.hub.cync_rooms[subgroup].switches)
        for subgroup in self.subgroups:
            self.hub.cync_rooms[subgroup].all_room_switches = self.all_room_switches

    def register(self, update_callback) -> None:
        """Register callback to be called when the room changes state."""
        self._update_callback = update_callback

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def register_room_updater(self, parent_updater):
        """Register callback for parent room updates."""
        self._update_parent_room = parent_updater

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature in Kelvin."""
        return 7000  # Adjust according to your devices' specifications

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature in Kelvin."""
        return 2000  # Adjust according to your devices' specifications

    async def turn_on(
        self,
        brightness: Optional[int] = None,
        color_temp_kelvin: Optional[int] = None,
        **kwargs: Any
    ) -> None:
        """Turn on the room lights."""
        attempts = 0
        update_received = False
        seq_ct = None  # Initialize seq_ct to None
        seq_brightness = None
        seq_status = None
        seq_rgb = None  # Initialize seq_rgb if needed for RGB support
    
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            # Unique sequence numbers for each command
            seq_status = self.hub.get_seq_num()
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller
    
            # Handle brightness
            if brightness is not None:
                brightness_value = brightness
            else:
                brightness_value = self.brightness if self.brightness else 100  # Default to 100% if no brightness is set
    
            # Handle color temperature
            if color_temp_kelvin is not None:
                # Calculate color_temp as a percentage
                color_temp = round(
                    (
                        (color_temp_kelvin - self.min_color_temp_kelvin) /
                        (self.max_color_temp_kelvin - self.min_color_temp_kelvin)
                    ) * 100
                )
            else:
                color_temp = 50  # Default mid value
    
            # Send Set Status (On) with unique seq_num
            status_packet = self.hub.create_set_status_packet(controller, seq_status, device_index=0, status=1)
            await self.hub.send_request(status_packet, self.command_received)
    
            # Send Set Brightness with unique seq_num
            seq_brightness = self.hub.get_seq_num()
            brightness_packet = self.hub.create_set_lum_packet(controller, seq_brightness, device_index=0, brightness=brightness_value)
            await self.hub.send_request(brightness_packet, self.command_received)
    
            # Send Set Color Temperature with unique seq_num
            if self.support_color_temp:
                seq_ct = self.hub.get_seq_num()
                color_temp_packet = self.hub.create_set_ct_packet(controller, seq_ct, device_index=0, ct=color_temp)
                await self.hub.send_request(color_temp_packet, self.command_received)
    
            # Wait for all acknowledgments
            await asyncio.sleep(self._command_timeout)
    
            # Check if all commands have been acknowledged
            if (
                not self.hub.pending_commands.get(seq_status) and
                not self.hub.pending_commands.get(seq_brightness) and
                (not self.support_color_temp or not self.hub.pending_commands.get(seq_ct))
            ):
                update_received = True
            else:
                attempts += 1
                _LOGGER.debug(f"Attempt {attempts} to turn on the room lights.")

    async def turn_off(self, **kwargs: Any) -> None:
        """Turn off the room lights."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = self.hub.get_seq_num()
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller
    
            # Send Set Status (Off) with unique seq_num
            status_packet = self.hub.create_set_status_packet(controller, seq, device_index=0, status=0)
            await self.hub.send_request(status_packet, self.command_received)
    
            # Wait for acknowledgment
            await asyncio.sleep(self._command_timeout)
    
            # Check if the command has been acknowledged
            if not self.hub.pending_commands.get(seq):
                update_received = True
            else:
                attempts += 1
                _LOGGER.debug(f"Attempt {attempts} to turn off the room lights.")

    def command_received(self, seq: int):
        """Handle command acknowledgment from the Cync server."""
        self.hub.pending_commands.pop(seq, None)

    def update_room(self):
        """Update the current state of the room."""
        _brightness = self.brightness
        _color_temp = self.color_temp_kelvin
        _rgb = self.rgb.copy()  # Make a copy to avoid mutating the original
        _power_state = any(
            self.hub.cync_switches[device_id].power_state for device_id in self.switches
        ) or any(
            self.hub.cync_rooms[room_id].power_state for room_id in self.subgroups
        )

        if self.support_brightness:
            total_brightness = sum(
                self.hub.cync_switches[device_id].brightness for device_id in self.switches
            ) + sum(
                self.hub.cync_rooms[room_id].brightness for room_id in self.subgroups
            )
            count = len(self.switches) + len(self.subgroups)
            _brightness = round(total_brightness / count) if count > 0 else 0
        else:
            _brightness = 100 if _power_state else 0

        if self.support_color_temp:
            total_color_temp = sum(
                self.hub.cync_switches[device_id].color_temp_kelvin for device_id in self.switches_support_color_temp
            ) + sum(
                self.hub.cync_rooms[room_id].color_temp_kelvin for room_id in self.groups_support_color_temp
            )
            count = len(self.switches_support_color_temp) + len(self.groups_support_color_temp)
            _color_temp = round(total_color_temp / count) if count > 0 else 0
        else:
            _color_temp = self.color_temp_kelvin

        if self.support_rgb:
            count = len(self.switches_support_rgb) + len(self.groups_support_rgb)
            total_r = sum(
                self.hub.cync_switches[device_id].rgb['r'] for device_id in self.switches_support_rgb
            ) + sum(
                self.hub.cync_rooms[room_id].rgb['r'] for room_id in self.groups_support_rgb
            )
            total_g = sum(
                self.hub.cync_switches[device_id].rgb['g'] for device_id in self.switches_support_rgb
            ) + sum(
                self.hub.cync_rooms[room_id].rgb['g'] for room_id in self.groups_support_rgb
            )
            total_b = sum(
                self.hub.cync_switches[device_id].rgb['b'] for device_id in self.switches_support_rgb
            ) + sum(
                self.hub.cync_rooms[room_id].rgb['b'] for room_id in self.groups_support_rgb
            )
            if count > 0:
                _rgb['r'] = round(total_r / count)
                _rgb['g'] = round(total_g / count)
                _rgb['b'] = round(total_b / count)
            else:
                _rgb['r'] = _rgb['g'] = _rgb['b'] = 0

            _rgb['active'] = any(
                self.hub.cync_switches[device_id].rgb.get('active', False) for device_id in self.switches_support_rgb
            ) or any(
                self.hub.cync_rooms[room_id].rgb.get('active', False) for room_id in self.groups_support_rgb
            )
        else:
            _rgb = self.rgb

        # Check if any state has changed
        if (
            _power_state != self.power_state or
            _brightness != self.brightness or
            _color_temp != self.color_temp_kelvin or
            _rgb != self.rgb
        ):
            self.power_state = _power_state
            self.brightness = _brightness
            self.color_temp_kelvin = _color_temp
            self.rgb = _rgb
            self.publish_update()
            if self._update_parent_room:
                asyncio.run_coroutine_threadsafe(self._update_parent_room(), self.hub.hass.loop)

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices."""
        connected_devices = self.hub.connected_devices[self.home_id]
        controllers = [
            self.hub.cync_switches[dev_id].switch_id
            for dev_id in self.all_room_switches if dev_id in connected_devices
        ]
        others_available = [
            self.hub.cync_switches[dev_id].switch_id
            for dev_id in connected_devices if dev_id not in self.all_room_switches
        ]
        self.controllers = controllers + others_available if connected_devices else [self.default_controller]

    def publish_update(self):
        """Publish the update to Home Assistant."""
        if self._update_callback:
            asyncio.run_coroutine_threadsafe(self._update_callback(), self.hub.hass.loop)

class CyncSwitch:
    def __init__(self, device_id, switch_info, room, hub) -> None:
        self.hub = hub
        self.device_id = device_id
        self.switch_id = switch_info.get('switch_id', '0')
        self.home_id = [
            home_id for home_id, home_devices in self.hub.home_devices.items()
            if self.device_id in home_devices
        ][0]
        self.name = switch_info.get('name', 'unknown')
        self.home_name = switch_info.get('home_name', 'unknown')
        self.mesh_id = switch_info.get('mesh_id', 0).to_bytes(2, 'little')
        self.mesh_id_int = int.from_bytes(self.mesh_id, 'big')  # Convert mesh_id to integer
        self.room = room
        self.power_state = False
        self.brightness = 0
        self.color_temp_kelvin = 0
        self.rgb = {'r': 0, 'g': 0, 'b': 0, 'active': False}
        self.effect = None
        self.transition = None
        self.default_controller = int(switch_info.get('switch_controller', self.hub.home_controllers[self.home_id][0]))
        self.controllers: List[int] = []
        self._update_callback: Optional[Callable[[], None]] = None
        self._update_parent_room: Optional[Callable[[], None]] = None
        self.support_brightness = switch_info.get('BRIGHTNESS', False)
        self.support_color_temp = switch_info.get('COLORTEMP', False)
        self.support_rgb = switch_info.get('RGB', False)
        self.support_effects = True  # Assuming effects are supported
        self.plug = switch_info.get('PLUG', False)
        self.fan = switch_info.get('FAN', False)
        self.elements = switch_info.get('MULTIELEMENT', 1)
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def register(self, update_callback) -> None:
        """Register callback, called when switch changes state."""
        self._update_callback = update_callback

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def register_room_updater(self, parent_updater):
        """Register callback for room updates."""
        self._update_parent_room = parent_updater

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature in Kelvin."""
        return 7000  # Adjust according to your devices' specifications

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature in Kelvin."""
        return 2000  # Adjust according to your devices' specifications

    async def turn_on(
        self,
        brightness: Optional[int] = None,
        color_temp_kelvin: Optional[int] = None,
        rgb_color: Optional[Tuple[int, int, int]] = None,
        effect: Optional[str] = None,
        transition: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        """Turn on the light with optional brightness, color temperature, RGB color, effect, and transition."""
        attempts = 0
        update_received = False
        seq_ct = None
        seq_brightness = None
        seq_rgb = None
        seq_status = None
    
        # Convert brightness to percentage if needed
        if brightness is not None:
            brightness_value = max(1, min(100, round((brightness / 255) * 100)))
        else:
            brightness_value = self.brightness if self.brightness else 100  # Default to 100% if no brightness is set
    
        # Handle color temperature
        if color_temp_kelvin is not None:
            color_temp = max(0, min(100, round(
                (
                    (color_temp_kelvin - self.min_color_temp_kelvin) /
                    (self.max_color_temp_kelvin - self.min_color_temp_kelvin)
                ) * 100
            )))
        else:
            color_temp = None
    
        # Handle RGB color
        if rgb_color is not None:
            r, g, b = rgb_color
        else:
            r, g, b = self.rgb['r'], self.rgb['g'], self.rgb['b']
    
        # Handle effects
        if effect is not None:
            # Implement effect handling logic here
            self.effect = effect
            # For example, map the effect name to an effect index or code
            effect_index = self.hub.effect_mapping.get(effect)
            if effect_index is not None:
                # Send effect command to the device
                pass  # Placeholder for effect command implementation
    
        # Handle transition
        if transition is not None:
            # Implement transition handling logic here
            self.transition = transition
            # For example, set the transition time for the device
            pass  # Placeholder for transition command implementation
    
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            # Unique sequence numbers for each command
            seq_status = self.hub.get_seq_num()
            controller = int(self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller)
    
            # Send Set Status (On) with unique seq_num
            status_packet = self.hub.create_set_status_packet(controller, seq_status, self.mesh_id_int, 1)
            await self.hub.send_request(status_packet, self.command_received)
    
            # Send Set Brightness with unique seq_num
            if self.support_brightness:
                seq_brightness = self.hub.get_seq_num()
                brightness_packet = self.hub.create_set_lum_packet(controller, seq_brightness, self.mesh_id_int, brightness_value)
                await self.hub.send_request(brightness_packet, self.command_received)
    
            # Send Set Color Temperature with unique seq_num
            if self.support_color_temp and color_temp is not None:
                seq_ct = self.hub.get_seq_num()
                color_temp_packet = self.hub.create_set_ct_packet(controller, seq_ct, self.mesh_id_int, ct=color_temp)
                await self.hub.send_request(color_temp_packet, self.command_received)
    
            # Send Set RGB with unique seq_num
            if self.support_rgb and rgb_color is not None:
                seq_rgb = self.hub.get_seq_num()
                rgb_packet = self.hub.create_set_rgb_packet(controller, seq_rgb, self.mesh_id_int, r, g, b)
                await self.hub.send_request(rgb_packet, self.command_received)
    
            # Implement effect and transition commands here if applicable
    
            # Wait for all acknowledgments
            await asyncio.sleep(self._command_timeout)
    
            # Check if all commands have been acknowledged
            pending = [
                self.hub.pending_commands.get(seq_status),
                self.hub.pending_commands.get(seq_brightness) if self.support_brightness else None,
                self.hub.pending_commands.get(seq_ct) if self.support_color_temp else None,
                self.hub.pending_commands.get(seq_rgb) if self.support_rgb else None
            ]
    
            if not any(pending):
                update_received = True
            else:
                attempts += 1
                _LOGGER.debug(f"Attempt {attempts} to turn on the switch.")

    async def turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = self.hub.get_seq_num()
            controller = int(self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller)

            # Send Set Status (Off)
            status_packet = self.hub.create_set_status_packet(controller, seq, self.mesh_id_int, 0)
            await self.hub.send_request(status_packet)

            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq, None) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    def command_received(self, seq: int):
        """Handle command acknowledgment from the Cync server."""
        _LOGGER.debug(f"Command received for sequence {seq}")
        self.hub.pending_commands.pop(seq, None)

    def update_switch(self, state, brightness, color_temp=None, rgb=None):
        """Update the state of the switch as updates are received from the Cync server."""
        if color_temp is not None:
            # Calculate color_temp_kelvin from color_temp percentage
            self.color_temp_kelvin = round(
                (self.max_color_temp_kelvin - self.min_color_temp_kelvin) *
                (color_temp / 100) +
                self.min_color_temp_kelvin
            )

        if rgb is not None:
            self.rgb = rgb

        # Use the brightness provided by Cync (0-100) directly
        if brightness is not None:
            self.brightness = brightness

        previous_state = (self.power_state, self.brightness, self.color_temp_kelvin, self.rgb)
        new_state = (state, brightness, self.color_temp_kelvin, self.rgb)

        if previous_state != new_state:
            self.power_state = state
            self.brightness = brightness if self.support_brightness and state else 100 if state else 0
            self.color_temp_kelvin = self.color_temp_kelvin
            self.rgb = rgb if rgb is not None else self.rgb
            self.publish_update()
            if self._update_parent_room:
                self._update_parent_room()

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices."""
        connected_devices = self.hub.connected_devices[self.home_id]
        controllers = []
        if connected_devices:
            if int(self.switch_id) > 0 and self.device_id in connected_devices:
                controllers.append(int(self.switch_id))
            if self.room:
                controllers.extend(
                    int(self.hub.cync_switches[device_id].switch_id)
                    for device_id in self.room.all_room_switches
                    if device_id in connected_devices and device_id != self.device_id
                )
            others_available = [
                int(self.hub.cync_switches[device_id].switch_id)
                for device_id in connected_devices
                if int(self.hub.cync_switches[device_id].switch_id) not in controllers
            ]
            # Remove duplicates while preserving order
            unique_others = []
            seen = set()
            for ctrl in others_available:
                if ctrl not in seen:
                    unique_others.append(ctrl)
                    seen.add(ctrl)
            self.controllers = controllers + unique_others
        else:
            self.controllers = [self.default_controller]

    def publish_update(self):
        """Publish the update to Home Assistant."""
        if self._update_callback:
            asyncio.run_coroutine_threadsafe(self._update_callback(), self.hub.hass.loop)


class CyncMotionSensor:

    def __init__(self, device_id, device_info, room):

        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.motion = False
        self._update_callback = None
        self._hass = None

    def register(self, update_callback) -> None:
        """Register callback, called when sensor changes state."""
        self._update_callback = update_callback

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def update_motion_sensor(self, motion):
        self.motion = motion
        self.publish_update()

    def publish_update(self):
        if self._update_callback:
            asyncio.run_coroutine_threadsafe(self._update_callback(), self.hub.hass.loop)



class CyncAmbientLightSensor:

    def __init__(self, device_id, device_info, room):

        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.ambient_light = False
        self._update_callback = None
        self._hass = None

    def register(self, update_callback) -> None:
        """Register callback, called when sensor changes state."""
        self._update_callback = update_callback

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def update_ambient_light_sensor(self, ambient_light):
        self.ambient_light = ambient_light
        self.publish_update()

    def publish_update(self):
        if self._update_callback:
            asyncio.run_coroutine_threadsafe(self._update_callback(), self.hub.hass.loop)


class CyncUserData:
    """Class to handle user authentication and data retrieval."""

    def __init__(self) -> None:
        """Initialize the user data."""
        self.username: str = ''
        self.password: str = ''
        self.auth_code: Optional[List[int]] = None
        self.user_credentials: Dict[str, Any] = {}
        self.cync_config: Dict[str, Any] = {}

    async def authenticate(self, username: str, password: str) -> Dict[str, Any]:
        """Authenticate with the API and get a token."""
        self.username = username
        self.password = password
        auth_data = {
            'corp_id': "1007d2ad150c4000",
            'email': self.username,
            'password': self.password
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(API_AUTH, json=auth_data) as resp:
                if resp.status == 200:
                    self.user_credentials = await resp.json()
                    self._generate_login_code()
                    return {'authorized': True}
                elif resp.status == 400:
                    return await self._request_two_factor_code(session)
                else:
                    _LOGGER.error("Authentication failed with status code: %s", resp.status)
                    return {'authorized': False, 'two_factor_code_required': False}

    async def _request_two_factor_code(self, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """Request two-factor code."""
        request_code_data = {
            'corp_id': "1007d2ad150c4000",
            'email': self.username,
            'local_lang': "en-us"
        }
        async with session.post(API_REQUEST_CODE, json=request_code_data) as resp:
            if resp.status == 200:
                return {'authorized': False, 'two_factor_code_required': True}
            else:
                _LOGGER.error("Two-factor code request failed with status code: %s", resp.status)
                return {'authorized': False, 'two_factor_code_required': False}

    async def auth_two_factor(self, code: str) -> Dict[str, Any]:
        """Authenticate with two-factor code."""
        two_factor_data = {
            'corp_id': "1007d2ad150c4000",
            'email': self.username,
            'password': self.password,
            'two_factor': code,
            'resource': "abcdefghijklmnop"
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(API_2FACTOR_AUTH, json=two_factor_data) as resp:
                if resp.status == 200:
                    self.user_credentials = await resp.json()
                    self._generate_login_code()
                    return {'authorized': True}
                else:
                    _LOGGER.error("Two-factor authentication failed with status code: %s", resp.status)
                    return {'authorized': False}

    def _generate_login_code(self) -> None:
        """Generate the login code from user credentials."""
        authorize = self.user_credentials['authorize']
        user_id = int(self.user_credentials.get('user_id') or self.user_credentials.get('user'))
        login_code = (
            bytes.fromhex('13000000')
            + (10 + len(authorize)).to_bytes(1, 'big')
            + bytes.fromhex('03')
            + user_id.to_bytes(4, 'big')
            + len(authorize).to_bytes(2, 'big')
            + authorize.encode('ascii')
            + bytes.fromhex('0000b4')
        )
        self.auth_code = list(login_code)

    async def get_cync_config(self) -> Dict[str, Any]:
        """Retrieve the Cync configuration."""
        home_devices: Dict[str, List[str]] = {}
        home_controllers: Dict[str, List[str]] = {}
        switchID_to_homeID: Dict[str, str] = {}
        devices: Dict[str, Any] = {}
        rooms: Dict[str, Any] = {}
        homes = await self._get_homes()
        if not homes:
            _LOGGER.error("No homes found for user.")
            raise InvalidCyncConfiguration("No homes found for user.")

        for home in homes:
            home_id = str(home['id'])
            product_id = home['product_id']
            home_info = await self._get_home_properties(product_id, home_id)
            if not home_info:
                continue

            if (
                'groupsArray' in home_info
                and 'bulbsArray' in home_info
                and home_info['groupsArray']
                and home_info['bulbsArray']
            ):
                try:
                    await self._process_home_info(
                        home_id,
                        home,
                        home_info,
                        home_devices,
                        home_controllers,
                        switchID_to_homeID,
                        devices,
                        rooms
                    )
                except Exception as e:
                    _LOGGER.error("Error processing home info: %s", e)
                    continue

        if not rooms or not devices or not home_controllers or not home_devices or not switchID_to_homeID:
            _LOGGER.error("Invalid Cync configuration detected.")
            raise InvalidCyncConfiguration("Invalid Cync configuration detected.")

        self.cync_config = {
            'rooms': rooms,
            'devices': devices,
            'home_devices': home_devices,
            'home_controllers': home_controllers,
            'switchID_to_homeID': switchID_to_homeID
        }
        return self.cync_config

    async def _get_homes(self) -> List[Dict[str, Any]]:
        """Get a list of homes for a particular user."""
        headers = {'Access-Token': self.user_credentials['access_token']}
        user_id = self.user_credentials.get('user_id') or self.user_credentials.get('user')
        async with aiohttp.ClientSession() as session:
            async with session.get(
                API_DEVICES.format(user=user_id),
                headers=headers
            ) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    return response
                else:
                    _LOGGER.error("Failed to get homes with status code: %s", resp.status)
                    return []

    async def _get_home_properties(self, product_id: int, device_id: str) -> Optional[Dict[str, Any]]:
        """Get properties for a single home."""
        headers = {'Access-Token': self.user_credentials['access_token']}
        async with aiohttp.ClientSession() as session:
            async with session.get(
                API_DEVICE_INFO.format(product_id=product_id, device_id=device_id),
                headers=headers
            ) as resp:
                if resp.status == 200:
                    response = await resp.json()
                    return response
                else:
                    _LOGGER.error(
                        "Failed to get properties for home %s with status code: %s",
                        device_id, resp.status
                    )
                    return None

    async def _process_home_info(
        self,
        home_id: str,
        home: Dict[str, Any],
        home_info: Dict[str, Any],
        home_devices: Dict[str, List[str]],
        home_controllers: Dict[str, List[str]],
        switchID_to_homeID: Dict[str, str],
        devices: Dict[str, Any],
        rooms: Dict[str, Any]
    ) -> None:
        """Process home information and populate devices and rooms."""
        bulbs_array = home_info['bulbsArray']
        groups_array = home_info['groupsArray']
        max_index = max(
            ((device['deviceID'] % int(home_id)) % 1000) + ((device['deviceID'] % int(home_id)) // 1000) * 256
            for device in bulbs_array
        ) + 1
        home_devices[home_id] = [""] * max_index
        home_controllers[home_id] = []
        for device in bulbs_array:
            device_type = device['deviceType']
            device_id = str(device['deviceID'])
            current_index = ((device['deviceID'] % int(home_id)) % 1000) + ((device['deviceID'] % int(home_id)) // 1000) * 256
            home_devices[home_id][current_index] = device_id

            devices[device_id] = {
                'name': device.get('displayName', 'Unknown'),
                'mesh_id': current_index,
                'switch_id': str(device.get('switchID', 0)),
                'ONOFF': device_type in Capabilities['ONOFF'],
                'BRIGHTNESS': device_type in Capabilities["BRIGHTNESS"],
                "COLORTEMP": device_type in Capabilities["COLORTEMP"],
                "RGB": device_type in Capabilities["RGB"],
                "MOTION": device_type in Capabilities["MOTION"],
                "AMBIENT_LIGHT": device_type in Capabilities["AMBIENT_LIGHT"],
                "WIFICONTROL": device_type in Capabilities["WIFICONTROL"],
                "PLUG": device_type in Capabilities["PLUG"],
                "FAN": device_type in Capabilities["FAN"],
                'home_name': home.get('name', 'Unknown'),
                'room': '',
                'room_name': ''
            }
            if str(device_type) in Capabilities['MULTIELEMENT'] and current_index < 256:
                devices[device_id]['MULTIELEMENT'] = Capabilities['MULTIELEMENT'][str(device_type)]
            if devices[device_id].get('WIFICONTROL', False) and device.get('switchID', 0) > 0:
                switch_id_str = str(device['switchID'])
                switchID_to_homeID[switch_id_str] = home_id
                devices[device_id]['switch_controller'] = switch_id_str
                if switch_id_str not in home_controllers[home_id]:
                    home_controllers[home_id].append(switch_id_str)
        if not home_controllers[home_id]:
            _LOGGER.warning("No controllers found in home %s. Skipping home.", home_id)
            # Remove devices from this home
            for device in bulbs_array:
                device_id = str(device['deviceID'])
                devices.pop(device_id, None)
            home_devices.pop(home_id, None)
            home_controllers.pop(home_id, None)
            return

        for room in groups_array:
            if room.get('deviceIDArray') or room.get('subgroupIDArray'):
                room_id = f"{home_id}-{room['groupID']}"
                room_controller = home_controllers[home_id][0]
                device_ids = room.get('deviceIDArray', [])
                available_controllers = [
                    devices[home_devices[home_id][(dev_id % int(home_id)) % 1000 + ((dev_id % int(home_id)) // 1000) * 256]]['switch_controller']
                    for dev_id in device_ids
                    if 'switch_controller' in devices[home_devices[home_id][(dev_id % int(home_id)) % 1000 + ((dev_id % int(home_id)) // 1000) * 256]]
                ]
                if available_controllers:
                    room_controller = available_controllers[0]
                for dev_id in device_ids:
                    index = (dev_id % int(home_id)) % 1000 + ((dev_id % int(home_id)) // 1000) * 256
                    device = devices[home_devices[home_id][index]]
                    device['room'] = room_id
                    device['room_name'] = room.get('displayName', 'Unknown')
                    if 'switch_controller' not in device and device.get('ONOFF', False):
                        device['switch_controller'] = room_controller
                rooms[room_id] = {
                    'name': room.get('displayName', 'Unknown'),
                    'mesh_id': room['groupID'],
                    'room_controller': room_controller,
                    'home_name': home.get('name', 'Unknown'),
                    'switches': [
                        home_devices[home_id][(dev_id % int(home_id)) % 1000 + ((dev_id % int(home_id)) // 1000) * 256]
                        for dev_id in device_ids
                        if devices[home_devices[home_id][(dev_id % int(home_id)) % 1000 + ((dev_id % int(home_id)) // 1000) * 256]].get('ONOFF', False)
                    ],
                    'isSubgroup': room.get('isSubgroup', False),
                    'subgroups': [
                        f"{home_id}-{subgroup_id}" for subgroup_id in room.get('subgroupIDArray', [])
                    ]
                }
        # Update parent rooms for subgroups
        for room_id, room_info in rooms.items():
            if not room_info.get("isSubgroup", False) and room_info.get("subgroups"):
                for subgroup_id in room_info["subgroups"].copy():
                    subgroup = rooms.get(subgroup_id)
                    if subgroup:
                        subgroup["parent_room"] = room_info["name"]
                    else:
                        _LOGGER.warning("Subgroup %s not found. Removing from room %s.", subgroup_id, room_id)
                        room_info["subgroups"].remove(subgroup_id)
