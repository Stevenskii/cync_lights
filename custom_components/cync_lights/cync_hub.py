import logging
import asyncio
import struct
import aiohttp
import math
import ssl
import traceback
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import json

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
              150, 151, 152, 153, 154, 156, 158, 159, 160, 161, 162, 163,
              164, 165],
    "BRIGHTNESS": [1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22,
                   23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
                   48, 49, 55, 56, 80, 81, 82, 83, 85, 128, 129, 130, 131, 132,
                   133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144,
                   145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 156,
                   158, 159, 160, 161, 162, 163, 164, 165],
    "COLORTEMP": [5, 6, 7, 8, 10, 11, 14, 15, 19, 20, 21, 22, 23, 25, 26, 28,
                  29, 30, 31, 32, 33, 34, 35, 80, 82, 83, 85, 129, 130, 131, 132,
                  133, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145,
                  146, 147, 153, 154, 156, 158, 159, 160, 161, 162, 163,
                  164, 165],
    "RGB": [6, 7, 8, 21, 22, 23, 30, 31, 32, 33, 34, 35, 131, 132, 133, 137,
            138, 139, 140, 141, 142, 143, 146, 147, 153, 154, 156, 158, 159,
            160, 161, 162, 163, 164, 165],
    "MOTION": [37, 49, 54],
    "AMBIENT_LIGHT": [37, 49, 54],
    "WIFICONTROL": [36, 37, 38, 39, 40, 48, 49, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81, 128, 129,
                    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
                    141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
                    152, 153, 154, 156, 158, 159, 160, 161, 162, 163,
                    164, 165],
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

# Packet types (from cync-lan)
PACKET_TYPE_REQUEST = 0x73  # Status and brightness request
PACKET_TYPE_PING = 0x0D  # 13 in decimal
PACKET_TYPE_PIPE = 0x07  # 7 in decimal

# Pipe types (from cync-lan)
PACKET_PIPE_TYPE_SET_STATUS = 0xD0  # Set status (on/off)
PACKET_PIPE_TYPE_SET_LUM = 0xD2  # Set brightness
PACKET_PIPE_TYPE_SET_CT = 0xE2  # Set color temperature
PACKET_PIPE_TYPE_SET_RGB = 0xD4  # Set RGB color

# Pipe subtypes for acknowledgments (from cync-lan)
PACKET_PIPE_SUBTYPE_ACK_SET_STATUS = 17  # Acknowledgment for setting status
PACKET_PIPE_SUBTYPE_ACK_SET_LUM = 18  # Acknowledgment for setting brightness
PACKET_PIPE_SUBTYPE_ACK_SET_CT = 37  # Acknowledgment for setting color temperature

# Constants
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_HOST = "cm.gelighting.com"
DEFAULT_PORT = 23778

class Packet:
    def __init__(self, packet_type: int, is_response: bool, data: bytes, seq: int = None):
        self.type = packet_type
        self.is_response = is_response
        self.data = data
        self.seq = seq  # Sequence number for tracking

    def encode(self) -> bytes:
        """Encode the packet into raw binary form."""
        type_byte = self.type

        # Set the response flag if necessary
        # Assuming bit 3 (0x08) is the response flag based on previous implementation
        if self.is_response:
            type_byte |= 0x08

        # Calculate the length of the payload
        length = len(self.data)

        # Construct the header: 1 byte type, 4 bytes length (big endian)
        header = struct.pack(">B I", type_byte, length)

        # Return the complete packet
        return header + self.data

    def __str__(self):
        return f"Packet(type=0x{self.type:02X}, response={self.is_response}, data={self.data.hex()})"

def hexdump(data):
    return ' '.join(f'{byte:02X}' for byte in data)

class CyncHub:
    def __init__(self, hass: Any, data: Dict[str, Any], options: Dict[str, Any]):
        """Initialize the CyncHub."""
        self.hass = hass
        self.host = data.get("host", DEFAULT_HOST)
        self.port = data.get("port", DEFAULT_PORT)
        self.login_code = bytearray(data['cync_credentials'])
        self.use_ssl = options.get("use_ssl", True)
        self.ssl_context = None
        self.reader, self.writer, self.logged_in, self.shutting_down = None, None, False, False

        self.home_devices = data['cync_config']['home_devices']
        self.home_controllers = data['cync_config']['home_controllers']
        self.switchID_to_homeID = data['cync_config']['switchID_to_homeID']
        self.connected_devices = {home_id: [] for home_id in self.home_controllers.keys()}
        self.cync_rooms = {room_id: CyncRoom(room_id, room_info, self) for room_id, room_info in data['cync_config']['rooms'].items()}
        self.cync_switches = {device_id: CyncSwitch(device_id, switch_info, self.cync_rooms.get(switch_info['room']), self)
                              for device_id, switch_info in data['cync_config']['devices'].items() if switch_info.get("ONOFF", False)}

        self.seq_num = 0
        self.seq_lock = asyncio.Lock()
        self.pending_commands = {}
        self.pending_commands_lock = asyncio.Lock()

        self.buffer = b''  # Buffer for reading TCP data

        self.effect_mapping = self._parse_light_shows(data['cync_config'])  # Re-added light show parsing
        self.hass.loop.create_task(self.connect())

    async def get_seq_num(self) -> int:
        """Thread-safe method to get the next sequence number."""
        async with self.seq_lock:
            self.seq_num = (self.seq_num + 1) % 65536
            return self.seq_num

    def _parse_light_shows(self, cync_config) -> Dict[str, Any]:
        """Parse lightShows data from cync_config and create a mapping."""
        effect_mapping = {}
        for home_info in cync_config.get('homes', {}).values():
            for show in home_info.get('lightShows', []):
                effect_mapping[show['name']] = show
        return effect_mapping

    async def setup_ssl_context(self) -> None:
        """Set up SSL context asynchronously."""
        if self.use_ssl:
            self.ssl_context = await self.hass.async_add_executor_job(ssl.create_default_context)
        else:
            self.ssl_context = None

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
                except Exception as e:
                    _LOGGER.debug(f"SSL connection failed: {e}. Retrying with SSL context check disabled.")
                    if self.ssl_context:
                        self.ssl_context.check_hostname = False
                        self.ssl_context.verify_mode = ssl.CERT_NONE
                    try:
                        self.reader, self.writer = await asyncio.open_connection(self.host, self.port, ssl=self.ssl_context)
                    except Exception as e:
                        _LOGGER.debug(f"Retrying without SSL context: {e}. Falling back to unsecured connection.")
                        self.reader, self.writer = await asyncio.open_connection(self.host, DEFAULT_PORT)

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
                    _LOGGER.debug("Successfully authenticated with the server.")
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

    async def read_tcp_messages(self) -> None:
        """Continuously read and process TCP messages from the server."""
        while not self.shutting_down:
            try:
                data = await self.reader.read(1024)
                if not data:
                    raise LostConnection("Connection closed by server")

                self.buffer += data
                while len(self.buffer) >= 5:
                    header = self.buffer[:5]
                    packet_type, is_response = (header[0] & 0xF0) >> 4, (header[0] & 0x08) != 0
                    packet_length = struct.unpack(">I", header[1:5])[0]
                    if len(self.buffer) < 5 + packet_length:
                        break
                    packet_data = self.buffer[5:5 + packet_length]
                    self.buffer = self.buffer[5 + packet_length:]
                    await self.handle_packet(packet_type, is_response, packet_data)
            except LostConnection:
                _LOGGER.warning("Lost connection to the server.")
                break
            except Exception as e:
                _LOGGER.error(f"Error while reading TCP messages: {e}")
                await asyncio.sleep(5)

    async def handle_packet(self, packet_type: int, is_response: bool, packet_data: bytes) -> None:
        """Handle incoming packets based on their type."""
        if packet_type == PACKET_TYPE_PING:
            _LOGGER.debug("Received PING packet.")
            # Optionally, respond to the PING if necessary
        elif packet_type == PACKET_TYPE_PIPE:
            _LOGGER.debug("Received PIPE packet.")
            await self.process_pipe_packet(is_response, packet_data)
        elif packet_type == 0x04:
            _LOGGER.debug("Received packet type 4 (Initial Client State).")
            await self.process_type_4_packet(is_response, packet_data)
        elif packet_type == 0x08:
            _LOGGER.debug("Received packet type 8 (Iteration Request).")
            await self.process_type_8_packet(is_response, packet_data)
        else:
            _LOGGER.warning(f"Unhandled packet type: {packet_type}")
            _LOGGER.debug(f"Packet data ({len(packet_data)} bytes): {hexdump(packet_data)}")

    async def process_type_4_packet(self, is_response: bool, data: bytes) -> None:
        """Process packet type 4 (Initial Client State)."""
        _LOGGER.debug("Processing packet type 4 (Initial Client State).")
        _LOGGER.debug(f"Packet data: {hexdump(data)}")

        # Ensure there is enough data to extract the controller ID
        if len(data) < 4:
            _LOGGER.error("Packet data too short to extract controller ID.")
            return

        # Extract controller ID
        controller_id = int.from_bytes(data[0:4], 'big')

        # Initialize variables
        device_index = None
        power_status = None
        brightness = None
        color_temp = None
        r = g = b = None

        if len(data) >= 22:
            # Packet is long enough to extract all fields

            # Extract device index (mesh_id) from data[19:21]
            device_index = int.from_bytes(data[19:21], 'little')

            # Extract power status from data[5]
            power_status_byte = data[5]
            power_status = bool(power_status_byte & 0x01)

            # Extract brightness from data[12]
            brightness = data[12]

            # Extract color temperature from data[13]
            color_temp = data[13]

            # Extract RGB values from data[14:17]
            r = data[14]
            g = data[15]
            b = data[16]

            _LOGGER.debug(f"Controller ID: {controller_id}, Device Index (Mesh ID): {device_index}")

            # Find the device using mesh_id
            device = next((dev for dev in self.cync_switches.values() if dev.mesh_id == device_index), None)
            if not device:
                _LOGGER.warning(f"No device found with mesh_id {device_index}")
                return

            _LOGGER.debug(
                f"Device ID: {device.device_id}, Power Status: {power_status}, "
                f"Brightness: {brightness}, Color Temp: {color_temp}, RGB: ({r}, {g}, {b})"
            )

            # Update the device state with available data
            device.update_switch(
                state=power_status,
                brightness=brightness,
                color_temp=color_temp,
                rgb={'r': r, 'g': g, 'b': b}
            )
        elif len(data) >= 7:
            device_index = data[4]
            power_status_byte = data[5]
            power_status = bool(power_status_byte & 0x01)

            _LOGGER.debug(f"Packet data: {hexdump(data)}")
            _LOGGER.debug(f"Controller ID: {controller_id}")
            _LOGGER.debug(f"Extracted device_index (mesh_id): {device_index} from data[4]: {data[4]:02X}")
            _LOGGER.debug(f"Extracted power_status_byte: {power_status_byte:02X} from data[5]: {data[5]:02X}")
            _LOGGER.debug(f"Power Status: {power_status}")

            # Find the device using mesh_id
            device = next((dev for dev in self.cync_switches.values() if dev.mesh_id == device_index), None)
            if not device:
                _LOGGER.warning(f"No device found with mesh_id {device_index}")
                return

            # Update the device state with minimal data
            device.update_switch(state=power_status)
        else:
            _LOGGER.error("Packet data too short to extract device index and power status.")
            return

    async def process_type_8_packet(self, is_response: bool, data: bytes) -> None:
        """Process packet type 8 (Iteration Request)."""
        _LOGGER.debug("Processing packet type 8 (Iteration Request).")

        if len(data) >= 20:
            # Extract controller ID
            controller_id = int.from_bytes(data[0:4], 'big')
            # Extract device index (mesh_id) using 'little' endianness
            device_index = int.from_bytes(data[21:23], 'little')
            _LOGGER.debug(f"Iteration Request data: {hexdump(data)}")
            _LOGGER.debug(f"Controller ID: {controller_id}, Device Index (Mesh ID): {device_index}")

            # Find the device
            device = next((dev for dev in self.cync_switches.values() if dev.mesh_id == device_index), None)
            if not device:
                _LOGGER.warning(f"No device found with mesh_id {device_index}")
                return

            # Extract power status
            power_status = bool(data[8])
            # Extract brightness
            brightness = data[9]
            # Extract color temperature
            color_temp = data[10]
            # Extract RGB values
            r = data[11]
            g = data[12]
            b = data[13]

            _LOGGER.debug(f"Device ID: {device.device_id}, Power Status: {power_status}, Brightness: {brightness}, Color Temp: {color_temp}, RGB: ({r}, {g}, {b})")

            # Update the device state
            device.update_switch(
                state=power_status,
                brightness=brightness,
                color_temp=color_temp,
                rgb={'r': r, 'g': g, 'b': b}
            )
        else:
            _LOGGER.error("Invalid packet data for packet type 8.")

    @staticmethod
    def parse_pipe_packet(data: bytes) -> Dict[str, Any]:
        """Parse PIPE packet data and return a dictionary of extracted values."""
        parsed = {}
        
        # Controller ID
        if len(data) >= 4:
            parsed['controller_id'] = int.from_bytes(data[0:4], 'big')
        else:
            parsed['controller_id'] = None
        
        # Mesh ID
        if len(data) >= 21:
            parsed['mesh_id'] = int.from_bytes(data[19:21], 'little')
        else:
            parsed['mesh_id'] = None
        
        # Power Status
        if len(data) > 8:
            parsed['power_status'] = bool(data[8] & 0x01)
        else:
            parsed['power_status'] = False
        
        # Brightness
        if len(data) > 9:
            brightness_raw = data[9]
            parsed['brightness'] = max(0, min(100, round((brightness_raw / 255) * 100)))
        else:
            parsed['brightness'] = 0
        
        # Color Temperature
        if len(data) > 10:
            color_temp_raw = data[10]
            parsed['color_temp_kelvin'] = max(2000, min(7000, 2000 + (color_temp_raw * 50)))  # Placeholder conversion
        else:
            parsed['color_temp_kelvin'] = None
        
        # RGB
        if len(data) >= 14:
            parsed['rgb'] = {
                'r': data[11],
                'g': data[12],
                'b': data[13]
            }
        else:
            parsed['rgb'] = {'r': 0, 'g': 0, 'b': 0}
        
        return parsed

    async def process_pipe_packet(self, is_response: bool, data: bytes) -> None:
        """Process PIPE packets."""
        if is_response:
            if len(data) >= 6:
                seq_num = struct.unpack(">H", data[4:6])[0]
                _LOGGER.debug(f"Acknowledgment received for sequence {seq_num}")
                await self.execute_callback(seq_num)
            else:
                _LOGGER.error("Invalid acknowledgment packet")
        else:
            _LOGGER.debug(f"Processing PIPE request with data: {hexdump(data)}")

            # Call the static method using self
            parsed_data = self.parse_pipe_packet(data)
            
            if not parsed_data.get('mesh_id'):
                _LOGGER.error("Cannot parse PIPE packet without mesh_id.")
                return
            
            device = next((dev for dev in self.cync_switches.values() if dev.mesh_id == parsed_data['mesh_id']), None)
            if not device:
                _LOGGER.warning(f"No device found with mesh_id {parsed_data['mesh_id']}")
                return
            
            device.update_switch(
                state=parsed_data.get('power_status', False),
                brightness=parsed_data.get('brightness', 0),
                color_temp=parsed_data.get('color_temp_kelvin'),
                rgb=parsed_data.get('rgb', {'r': 0, 'g': 0, 'b': 0})
            )

    def update_device_state(self, device_id: int, **kwargs):
        """Update the state of a device."""
        # Find the device object using the device_id
        device = self.find_device_by_id(device_id)
        if not device:
            _LOGGER.warning(f"Device with ID {device_id} not found.")
            return

        # Update device attributes
        for key, value in kwargs.items():
            setattr(device, key, value)

        # Notify about the state change
        device.publish_update()

    async def send_request(self, packet: Packet, callback=None, *args, **kwargs):
        async def send():
            try:
                self.writer.write(packet.encode())
                await self.writer.drain()
                _LOGGER.debug(f"Sent packet data: {packet.encode().hex()}")
                if callback and packet.seq is not None:
                    async with self.pending_commands_lock:
                        self.pending_commands[packet.seq] = callback
            except Exception as e:
                _LOGGER.error(f"Failed to send packet: {e}")
                if callback and packet.seq is not None:
                    async with self.pending_commands_lock:
                        if packet.seq in self.pending_commands:
                            del self.pending_commands[packet.seq]
        self.hass.loop.create_task(send())

    def extract_seq_num(self, packet: Packet) -> Optional[int]:
        """Extract sequence number from a packet."""
        if packet.type != PACKET_TYPE_REQUEST or len(packet.data) < 6:
            return None
        return struct.unpack(">H", packet.data[4:6])[0]

    async def execute_callback(self, seq_num: int):
        """Execute the callback associated with the given sequence number."""
        async with self.pending_commands_lock:
            if seq_num in self.pending_commands:
                callback = self.pending_commands.pop(seq_num)
                if asyncio.iscoroutinefunction(callback):
                    await callback(seq_num)
                else:
                    callback(seq_num)
            else:
                _LOGGER.warning(f"No pending command for sequence {seq_num}")

    # Packet creation methods
    def create_set_status_packet(self, controller_id: int, seq: int, device_index: int, status: int) -> Packet:
        # Validate inputs
        if not (0 <= controller_id <= 0xFFFFFFFF):
            raise ValueError(f"Controller ID {controller_id} out of range for unsigned int.")
        if not (0 <= seq <= 0xFFFF):
            raise ValueError(f"Sequence number {seq} out of range for unsigned short.")
        if status not in (0, 1):
            raise ValueError(f"Status {status} must be 0 or 1.")

        mesh_id_bytes = device_index.to_bytes(2, 'little')

        # Calculate checksum
        checksum = (430 + mesh_id_bytes[0] + mesh_id_bytes[1] + status) % 256

        # Construct payload only (exclude the manual header)
        payload = (
            controller_id.to_bytes(4, 'big')
            + seq.to_bytes(2, 'big')
            + bytes.fromhex('007e00000000f8d00d000000000000')
            + mesh_id_bytes
            + bytes.fromhex('d00000')
            + status.to_bytes(1, 'big')
            + bytes.fromhex('0000')
            + checksum.to_bytes(1, 'big')
            + bytes.fromhex('7e')
        )

        _LOGGER.debug(f"Set Status Payload: {payload.hex()}")
        _LOGGER.debug(f"Controller ID: {controller_id}, Seq: {seq}, Device Index: {device_index}, Status: {status}, mesh_id_bytes: {mesh_id_bytes.hex()}, checksum: {checksum}")
        return Packet(PACKET_TYPE_REQUEST, False, payload, seq)

    def create_set_brightness_packet(self, controller_id: int, seq: int, device_index: int, brightness: int) -> Packet:
        # Ensure brightness is within 0 to 100
        brightness = max(0, min(100, brightness))

        mesh_id_bytes = device_index.to_bytes(2, 'little')

        # Calculate checksum
        checksum = (469 + mesh_id_bytes[0] + mesh_id_bytes[1] + brightness) % 256

        # Construct payload only
        payload = (
            controller_id.to_bytes(4, 'big')
            + seq.to_bytes(2, 'big')
            + bytes.fromhex('007e00000000f8e10c000000000000')
            + mesh_id_bytes
            + bytes.fromhex('e1000005')
            + brightness.to_bytes(1, 'big')
            + checksum.to_bytes(1, 'big')
            + bytes.fromhex('7e')
        )

        _LOGGER.debug(f"Set Brightness Payload: {payload.hex()}")
        return Packet(PACKET_TYPE_REQUEST, False, payload, seq)

    def create_set_ct_packet(self, controller_id: int, seq: int, device_index: int, ct: int) -> Packet:
        # Ensure ct (color temperature) is within 0 to 100
        ct = max(0, min(100, ct))

        mesh_id_bytes = device_index.to_bytes(2, 'little')

        # Calculate checksum
        checksum = (469 + mesh_id_bytes[0] + mesh_id_bytes[1] + ct) % 256

        # Construct payload only
        payload = (
            controller_id.to_bytes(4, 'big')
            + seq.to_bytes(2, 'big')
            + bytes.fromhex('007e00000000f8e20c000000000000')
            + mesh_id_bytes
            + bytes.fromhex('e2000005')
            + ct.to_bytes(1, 'big')
            + checksum.to_bytes(1, 'big')
            + bytes.fromhex('7e')
        )

        _LOGGER.debug(f"Set Color Temperature Payload: {payload.hex()}")
        return Packet(PACKET_TYPE_REQUEST, False, payload, seq)

    def create_set_rgb_packet(self, controller_id: int, seq: int, device_index: int, r: int, g: int, b: int) -> Packet:
        # Ensure RGB values are within 0 to 255
        r = max(0, min(255, r))
        g = max(0, min(255, g))
        b = max(0, min(255, b))

        mesh_id_bytes = device_index.to_bytes(2, 'little')

        # Calculate checksum
        checksum = (496 + mesh_id_bytes[0] + mesh_id_bytes[1] + 1 + 100 + 254 + r + g + b) % 256

        # Construct payload only
        payload = (
            controller_id.to_bytes(4, 'big')
            + seq.to_bytes(2, 'big')
            + bytes.fromhex('007e00000000f8f010000000000000')
            + mesh_id_bytes
            + bytes.fromhex('f00000')
            + bytes([1])  # Status (1 for on)
            + bytes([100])  # Brightness (100%)
            + bytes([254])  # Color temperature (254 indicates RGB mode)
            + bytes([r, g, b])
            + checksum.to_bytes(1, 'big')
            + bytes.fromhex('7e')
        )

        _LOGGER.debug(f"Set RGB Payload: {payload.hex()}")
        _LOGGER.debug(f"Controller ID: {controller_id}, Seq: {seq}, Device Index: {device_index}, RGB: ({r}, {g}, {b}), checksum: {checksum}")
        return Packet(PACKET_TYPE_REQUEST, False, payload, seq)

    # Shutdown method to gracefully close the connection
    def shutdown(self):
        self.shutting_down = True
        if self.writer:
            self.hass.loop.create_task(self._close_writer())

    async def _close_writer(self):
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
        self.mesh_id = int(room_info.get('mesh_id', 0))
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
        return 7000

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature in Kelvin."""
        return 2000

    async def turn_on(
        self,
        brightness: Optional[int] = None,
        color_temp_kelvin: Optional[int] = None,
        rgb_color: Optional[Tuple[int, int, int]] = None,
        effect: Optional[str] = None,
        transition: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        """Turn on the room lights with optional brightness, color temperature, RGB color, effect, and transition."""
        _LOGGER.debug(
            f"Room '{self.name}': Sending turn_on command with brightness={brightness}, "
            f"color_temp_kelvin={color_temp_kelvin}, rgb_color={rgb_color}"
        )
        attempts = 0
        max_attempts = int(self._command_retry_time / self._command_timeout)
        success = False

        while not success and attempts < max_attempts:
            try:
                # Acquire a unique sequence number
                seq_status = await self.hub.get_seq_num()
                controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

                # Send Set Status (On)
                status_packet = self.hub.create_set_status_packet(
                    controller_id=controller,
                    seq=seq_status,
                    device_index=self.mesh_id,
                    status=1  # 1 to turn on
                )

                # Define acknowledgment callback
                async def on_ack_status(seq):
                    _LOGGER.debug(f"Room '{self.name}': Acknowledgment received for Set Status (On), seq={seq}")

                # Send the Set Status packet
                await self.hub.send_request(status_packet, callback=on_ack_status)

                # Initialize a list to track pending sequence numbers
                pending_seqs = [seq_status]

                # Handle Brightness
                if self.support_brightness and brightness is not None:
                    brightness_value = max(0, min(100, round((brightness / 255) * 100)))
                    seq_brightness = await self.hub.get_seq_num()
                    brightness_packet = self.hub.create_set_brightness_packet(
                        controller_id=controller,
                        seq=seq_brightness,
                        device_index=self.mesh_id,
                        brightness=brightness_value
                    )

                    async def on_ack_brightness(seq):
                        _LOGGER.debug(f"Room '{self.name}': Acknowledgment received for Set Brightness, seq={seq}")

                    await self.hub.send_request(brightness_packet, callback=on_ack_brightness)
                    pending_seqs.append(seq_brightness)

                # Handle Color Temperature
                if self.support_color_temp and color_temp_kelvin is not None:
                    # Scale color temperature to 0-100%
                    color_temp_scaled = max(0, min(100, round(
                        ((color_temp_kelvin - self.min_color_temp_kelvin) /
                         (self.max_color_temp_kelvin - self.min_color_temp_kelvin)) * 100
                    )))
                    seq_ct = await self.hub.get_seq_num()
                    ct_packet = self.hub.create_set_ct_packet(
                        controller_id=controller,
                        seq=seq_ct,
                        device_index=self.mesh_id,
                        ct=color_temp_scaled
                    )

                    async def on_ack_ct(seq):
                        _LOGGER.debug(f"Room '{self.name}': Acknowledgment received for Set Color Temp, seq={seq}")

                    await self.hub.send_request(ct_packet, callback=on_ack_ct)
                    pending_seqs.append(seq_ct)

                # Handle RGB Color
                if self.support_rgb and rgb_color is not None:
                    r, g, b = [max(0, min(255, val)) for val in rgb_color]
                    seq_rgb = await self.hub.get_seq_num()
                    rgb_packet = self.hub.create_set_rgb_packet(
                        controller_id=controller,
                        seq=seq_rgb,
                        device_index=self.mesh_id,
                        r=r,
                        g=g,
                        b=b
                    )

                    async def on_ack_rgb(seq):
                        _LOGGER.debug(f"Room '{self.name}': Acknowledgment received for Set RGB, seq={seq}")

                    await self.hub.send_request(rgb_packet, callback=on_ack_rgb)
                    pending_seqs.append(seq_rgb)

                # Optionally handle effects and transitions here
                # ...

                # Wait for acknowledgments within the timeout period
                await asyncio.sleep(self._command_timeout)

                # Check if all sequences have been acknowledged
                async with self.hub.pending_commands_lock:
                    pending = any(seq in self.hub.pending_commands for seq in pending_seqs)

                if not pending:
                    _LOGGER.info(f"Room '{self.name}': Successfully turned on the lights.")
                    success = True
                else:
                    attempts += 1
                    _LOGGER.warning(
                        f"Room '{self.name}': Attempt {attempts} to turn on the lights failed. Retrying..."
                    )

            except Exception as e:
                _LOGGER.error(f"Room '{self.name}': Exception during turn_on: {e}", exc_info=True)
                attempts += 1
                await asyncio.sleep(self._command_timeout)

        if not success:
            _LOGGER.error(f"Room '{self.name}': Failed to turn on the lights after {attempts} attempts.")

    async def turn_off(self, **kwargs: Any) -> None:
        """Turn off the room lights."""
        _LOGGER.debug(f"Room '{self.name}': Sending turn_off command.")
        attempts = 0
        max_attempts = int(self._command_retry_time / self._command_timeout)
        success = False

        while not success and attempts < max_attempts:
            try:
                # Acquire a unique sequence number
                seq = await self.hub.get_seq_num()
                controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

                # Send Set Status (Off)
                status_packet = self.hub.create_set_status_packet(
                    controller_id=controller,
                    seq=seq,
                    device_index=self.mesh_id,
                    status=0  # 0 to turn off
                )

                # Define acknowledgment callback
                async def on_ack_status_off(seq_num):
                    _LOGGER.debug(f"Room '{self.name}': Acknowledgment received for Set Status (Off), seq={seq_num}")

                # Send the Set Status packet
                await self.hub.send_request(status_packet, callback=on_ack_status_off)

                # Initialize a list to track pending sequence numbers
                pending_seqs = [seq]

                # Wait for acknowledgment within the timeout period
                await asyncio.sleep(self._command_timeout)

                # Check if the sequence has been acknowledged
                async with self.hub.pending_commands_lock:
                    pending = any(seq in self.hub.pending_commands for seq in pending_seqs)

                if not pending:
                    _LOGGER.info(f"Room '{self.name}': Successfully turned off the lights.")
                    success = True
                else:
                    attempts += 1
                    _LOGGER.warning(
                        f"Room '{self.name}': Attempt {attempts} to turn off the lights failed. Retrying..."
                    )

            except Exception as e:
                _LOGGER.error(f"Room '{self.name}': Exception during turn_off: {e}", exc_info=True)
                attempts += 1
                await asyncio.sleep(self._command_timeout)

        if not success:
            _LOGGER.error(f"Room '{self.name}': Failed to turn off the lights after {attempts} attempts.")

    def command_received(self, seq: int):
        """Handle command acknowledgment from the Cync server."""
        _LOGGER.debug(f"Command received for sequence {seq}")

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
                self.hub.cync_switches[device_id].brightness for device_id in self.switches_support_brightness
            ) + sum(
                self.hub.cync_rooms[room_id].brightness for room_id in self.groups_support_brightness
            )
            count = len(self.switches_support_brightness) + len(self.groups_support_brightness)
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
            self.hub.hass.loop.call_soon_threadsafe(self._update_callback)

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
        self.mesh_id = switch_info.get('mesh_id', 0)
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
        _LOGGER.debug(
            f"Switch '{self.name}': Sending turn_on command with brightness={brightness}, "
            f"color_temp_kelvin={color_temp_kelvin}, rgb_color={rgb_color}"
        )
        attempts = 0
        max_attempts = int(self._command_retry_time / self._command_timeout)
        success = False

        while not success and attempts < max_attempts:
            try:
                # Acquire a unique sequence number
                seq_status = await self.hub.get_seq_num()
                controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

                # Send Set Status (On)
                status_packet = self.hub.create_set_status_packet(
                    controller_id=controller,
                    seq=seq_status,
                    device_index=self.mesh_id,
                    status=1  # 1 to turn on
                )

                # Define acknowledgment callback
                async def on_ack_status(seq):
                    _LOGGER.debug(f"Switch '{self.name}': Acknowledgment received for Set Status (On), seq={seq}")

                # Send the Set Status packet
                await self.hub.send_request(status_packet, callback=on_ack_status)

                # Initialize a list to track pending sequence numbers
                pending_seqs = [seq_status]

                # Handle Brightness
                if self.support_brightness and brightness is not None:
                    brightness_value = max(0, min(100, round((brightness / 255) * 100)))
                    seq_brightness = await self.hub.get_seq_num()
                    brightness_packet = self.hub.create_set_brightness_packet(
                        controller_id=controller,
                        seq=seq_brightness,
                        device_index=self.mesh_id,
                        brightness=brightness_value
                    )

                    async def on_ack_brightness(seq):
                        _LOGGER.debug(f"Switch '{self.name}': Acknowledgment received for Set Brightness, seq={seq}")

                    await self.hub.send_request(brightness_packet, callback=on_ack_brightness)
                    pending_seqs.append(seq_brightness)

                # Handle Color Temperature
                if self.support_color_temp and color_temp_kelvin is not None:
                    # Scale color temperature to 0-100%
                    color_temp_scaled = max(0, min(100, round(
                        ((color_temp_kelvin - self.min_color_temp_kelvin) /
                         (self.max_color_temp_kelvin - self.min_color_temp_kelvin)) * 100
                    )))
                    seq_ct = await self.hub.get_seq_num()
                    ct_packet = self.hub.create_set_ct_packet(
                        controller_id=controller,
                        seq=seq_ct,
                        device_index=self.mesh_id,
                        ct=color_temp_scaled
                    )

                    async def on_ack_ct(seq):
                        _LOGGER.debug(f"Switch '{self.name}': Acknowledgment received for Set Color Temp, seq={seq}")

                    await self.hub.send_request(ct_packet, callback=on_ack_ct)
                    pending_seqs.append(seq_ct)

                # Handle RGB Color
                if self.support_rgb and rgb_color is not None:
                    r, g, b = [max(0, min(255, val)) for val in rgb_color]
                    seq_rgb = await self.hub.get_seq_num()
                    rgb_packet = self.hub.create_set_rgb_packet(
                        controller_id=controller,
                        seq=seq_rgb,
                        device_index=self.mesh_id,
                        r=r,
                        g=g,
                        b=b
                    )

                    async def on_ack_rgb(seq):
                        _LOGGER.debug(f"Switch '{self.name}': Acknowledgment received for Set RGB, seq={seq}")

                    await self.hub.send_request(rgb_packet, callback=on_ack_rgb)
                    pending_seqs.append(seq_rgb)

                # Optionally handle effects and transitions here
                # ...

                # Wait for acknowledgments within the timeout period
                await asyncio.sleep(self._command_timeout)

                # Check if all sequences have been acknowledged
                async with self.hub.pending_commands_lock:
                    pending = any(seq in self.hub.pending_commands for seq in pending_seqs)

                if not pending:
                    _LOGGER.info(f"Switch '{self.name}': Successfully turned on the light.")
                    success = True
                else:
                    attempts += 1
                    _LOGGER.warning(
                        f"Switch '{self.name}': Attempt {attempts} to turn on the light failed. Retrying..."
                    )

            except Exception as e:
                _LOGGER.error(f"Switch '{self.name}': Exception during turn_on: {e}", exc_info=True)
                attempts += 1
                await asyncio.sleep(self._command_timeout)

        if not success:
            _LOGGER.error(f"Switch '{self.name}': Failed to turn on the light after {attempts} attempts.")

    async def turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        _LOGGER.debug(f"Switch '{self.name}': Sending turn_off command.")
        attempts = 0
        max_attempts = int(self._command_retry_time / self._command_timeout)
        success = False

        while not success and attempts < max_attempts:
            try:
                # Acquire a unique sequence number
                seq = await self.hub.get_seq_num()
                controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

                # Send Set Status (Off)
                status_packet = self.hub.create_set_status_packet(
                    controller_id=controller,
                    seq=seq,
                    device_index=self.mesh_id,
                    status=0  # 0 to turn off
                )

                # Define acknowledgment callback
                async def on_ack_status_off(seq_num):
                    _LOGGER.debug(f"Switch '{self.name}': Acknowledgment received for Set Status (Off), seq={seq_num}")

                # Send the Set Status packet
                await self.hub.send_request(status_packet, callback=on_ack_status_off)

                # Initialize a list to track pending sequence numbers
                pending_seqs = [seq]

                # Wait for acknowledgment within the timeout period
                await asyncio.sleep(self._command_timeout)

                # Check if the sequence has been acknowledged
                async with self.hub.pending_commands_lock:
                    pending = any(seq in self.hub.pending_commands for seq in pending_seqs)

                if not pending:
                    _LOGGER.info(f"Switch '{self.name}': Successfully turned off the light.")
                    success = True
                else:
                    attempts += 1
                    _LOGGER.warning(
                        f"Switch '{self.name}': Attempt {attempts} to turn off the light failed. Retrying..."
                    )

            except Exception as e:
                _LOGGER.error(f"Switch '{self.name}': Exception during turn_off: {e}", exc_info=True)
                attempts += 1
                await asyncio.sleep(self._command_timeout)

        if not success:
            _LOGGER.error(f"Switch '{self.name}': Failed to turn off the light after {attempts} attempts.")

    def command_received(self, seq: int):
        """Handle command acknowledgment from the Cync server."""
        _LOGGER.debug(f"Command received for sequence {seq}")

    def update_switch(self, state: bool, brightness: int, color_temp: Optional[int] = None, rgb: Optional[Dict[str, int]] = None):
        """Update the state of the switch as updates are received from the Cync server."""
        updated = False

        if color_temp is not None:
            # Clamp color temperature within supported range
            self.color_temp_kelvin = max(self.min_color_temp_kelvin, min(self.max_color_temp_kelvin, color_temp))
            updated = True

        if rgb is not None:
            # Clamp RGB values
            self.rgb = {
                'r': max(0, min(255, rgb.get('r', self.rgb['r']))),
                'g': max(0, min(255, rgb.get('g', self.rgb['g']))),
                'b': max(0, min(255, rgb.get('b', self.rgb['b'])))
            }
            updated = True

        if brightness is not None:
            # Clamp brightness within 0-100%
            self.brightness = max(0, min(100, brightness))
            updated = True

        # Update power state only if it has changed
        if state != self.power_state:
            self.power_state = state
            updated = True

        if updated:
            _LOGGER.debug(f"Device '{self.name}' updated: State={self.power_state}, Brightness={self.brightness}, "
                        f"Color Temp={self.color_temp_kelvin}, RGB={self.rgb}")
            self.publish_update()
            if self._update_parent_room:
                asyncio.create_task(self._update_parent_room())

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices."""
        connected_devices = self.hub.connected_devices[self.home_id]
        controllers = []
        if connected_devices:
            if int(self.switch_id) > 0 and self.device_id in connected_devices:
                controllers.append(int(self.switch_id))
            if self.room:
                controllers.extend(
                    int(self.hub.cync_switches[dev_id].switch_id)
                    for dev_id in self.room.all_room_switches
                    if dev_id in connected_devices and dev_id != self.device_id
                )
            others_available = [
                int(self.hub.cync_switches[dev_id].switch_id)
                for dev_id in connected_devices
                if int(self.hub.cync_switches[dev_id].switch_id) not in controllers
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
            self.hub.hass.loop.call_soon_threadsafe(self._update_callback)

class CyncMotionSensor:
    def __init__(self, device_id, device_info, room, hub):
        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.motion = False
        self._update_callback = None
        self.hub = hub

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
            self.hub.hass.loop.call_soon_threadsafe(self._update_callback)

class CyncAmbientLightSensor:
    def __init__(self, device_id, device_info, room, hub):
        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.ambient_light = False
        self._update_callback = None
        self.hub = hub

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
            self.hub.hass.loop.call_soon_threadsafe(self._update_callback)

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
                    self._process_home_info(
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