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

# Packet types (from cync-lan)
PACKET_TYPE_AUTH = 1
PACKET_TYPE_SYNC = 4
PACKET_TYPE_PIPE = 7
PACKET_TYPE_PIPE_SYNC = 8
PACKET_TYPE_REQUEST = 0x73  # Status and brightness request
PACKET_TYPE_PING = 0xD3  # Heartbeat/Ping packet type

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
    def __init__(self, packet_type: int, is_response: bool, data: bytes):
        self.type = packet_type
        self.is_response = is_response
        self.data = data

    def encode(self) -> bytes:
        """Encode the packet into raw binary form."""
        type_byte = (self.type << 4) | 3  # Assuming version 3
        if self.is_response:
            type_byte |= 8
        length = len(self.data)
        header = struct.pack(">B I", type_byte, length)
        return header + self.data

    @staticmethod
    def decode(raw_data: bytes) -> 'Packet':
        """Decode raw binary data into a Packet object."""
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
        self.seq_lock = threading.Lock()
        self.pending_commands = {}
        self.pending_commands_lock = threading.Lock()

        self.buffer = b''  # Buffer for reading TCP data

        self.effect_mapping = self._parse_light_shows(data['cync_config'])  # Re-added light show parsing
        self.hass.loop.create_task(self.connect())

    def get_seq_num(self) -> int:
        """Thread-safe method to get the next sequence number."""
        with self.seq_lock:
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
                    packet_type, is_response = header[0] >> 4, (header[0] & 8) != 0
                    packet_length = struct.unpack(">I", header[1:5])[0]
                    if len(self.buffer) < 5 + packet_length:
                        break
                    packet_data = self.buffer[5:5 + packet_length]
                    self.buffer = self.buffer[5 + packet_length:]
                    await self.handle_packet(packet_type, is_response, packet_data)
            except LostConnection:
                break
            except Exception as e:
                _LOGGER.error(f"Error while reading TCP messages: {e}")
                await asyncio.sleep(5)
        raise ShuttingDown

    async def handle_packet(self, packet_type: int, is_response: bool, data: bytes) -> None:
        """Handle packet based on type."""
        try:
            if packet_type == PACKET_TYPE_PIPE:
                await self.process_pipe_packet(is_response, data)
            else:
                _LOGGER.warning(f"Unhandled packet type: {packet_type}")
        except Exception as e:
            _LOGGER.error(f"Error handling packet: {e}")

    async def process_pipe_packet(self, is_response: bool, data: bytes) -> None:
        """Process PIPE packets."""
        if is_response:
            if len(data) >= 6:
                seq_num = struct.unpack(">H", data[4:6])[0]
                _LOGGER.debug(f"Acknowledgment received for sequence {seq_num}")
                self.execute_callback(seq_num)
            else:
                _LOGGER.error("Invalid acknowledgment packet")
        else:
            _LOGGER.warning("Unhandled PIPE request received")

    def execute_callback(self, seq_num: int) -> None:
        """Execute the callback associated with the sequence number."""
        with self.pending_commands_lock:
            command_info = self.pending_commands.pop(seq_num, None)

        if command_info:
            callback = command_info.get('callback')
            if callback:
                callback(seq_num)

    async def send_request(self, packet: Packet, callback: Optional[Callable[[int], None]] = None, device: Optional['CyncSwitch'] = None) -> Optional[int]:
        """Send a request packet with an optional callback."""
        if not self.logged_in or not self.writer:
            _LOGGER.error("Not authenticated or writer unavailable")
            return None

        encoded_packet = packet.encode()
        try:
            self.writer.write(encoded_packet)
            await self.writer.drain()
            seq_num = self.extract_seq_num(packet)

            if callback and device:
                with self.pending_commands_lock:
                    self.pending_commands[seq_num] = {'callback': callback, 'device': device}
            return seq_num
        except Exception as e:
            _LOGGER.error(f"Error sending request: {e}")
            return None

    def extract_seq_num(self, packet: Packet) -> Optional[int]:
        """Extract sequence number from a packet."""
        if packet.type != PACKET_TYPE_PIPE or len(packet.data) < 6:
            return None
        return struct.unpack(">H", packet.data[4:6])[0]

    # Packet creation methods
    def create_set_status_packet(self, controller_id: int, seq: int, device_index: int, status: int) -> Packet:
        data = bytearray()

        data.extend(struct.pack(">B", PACKET_TYPE_REQUEST))  # Packet Type (0x73 for status)
        data.extend(bytes([0x00, 0x00, 0x00]))  # Zero padding
        data.extend(struct.pack(">B", 0x1f))  # Packet Length
        data.extend(struct.pack(">B", status))  # Status (0x01 to turn on, 0x00 to turn off)
        data.extend(struct.pack(">I H", controller_id, seq))  # Controller ID and sequence number
        data.extend(struct.pack(">H", device_index))  # Device index
        data.extend(bytes([0x7e, 0x00, 0x00, 0x00]))  # Fixed segment
        data.extend(struct.pack(">I", 0xf8d00d))  # Additional status-related bytes
        data.extend(struct.pack(">B", status))  # Final status byte

        return Packet(PACKET_TYPE_PIPE, False, bytes(data))

    def create_set_brightness_packet(self, controller_id: int, seq: int, device_index: int, brightness: int) -> Packet:
        data = bytearray()

        data.extend(struct.pack(">B", PACKET_TYPE_REQUEST))
        data.extend(bytes([0x00, 0x00, 0x00]))  # Zero padding
        data.extend(struct.pack(">B", 0x1d))  # Packet Length
        data.extend(struct.pack(">B", 0x02))  # Brightness Command
        data.extend(struct.pack(">B", brightness))  # Brightness Value
        data.extend(struct.pack(">I H", controller_id, seq))  # Controller ID and sequence number
        data.extend(struct.pack(">H", device_index))  # Device Index
        data.extend(bytes([0x7e, 0x00, 0x00, 0x00]))  # Fixed segment
        data.extend(struct.pack(">B", brightness))  # Final brightness byte

        return Packet(PACKET_TYPE_PIPE, False, bytes(data))

    def create_set_ct_packet(self, controller_id: int, seq: int, device_index: int, ct: int) -> Packet:
        if ct < 0 or ct > 100:
            raise ValueError("Color temperature must be between 0 and 100.")

        data = bytearray()

        data.extend(struct.pack(">B", PACKET_TYPE_REQUEST))
        data.extend(bytes([0x00, 0x00, 0x00]))  # Zero padding
        data.extend(struct.pack(">B", 0x1e))  # Packet Length
        data.extend(struct.pack(">B", 0x03))  # CT Command
        data.extend(struct.pack(">B", ct))  # Color temperature value
        data.extend(struct.pack(">I H", controller_id, seq))  # Controller ID and sequence number
        data.extend(struct.pack(">H", device_index))  # Device Index
        data.extend(bytes([0x7e, 0x00, 0x00, 0x00]))  # Fixed segment
        data.extend(struct.pack(">B", ct))  # Final CT byte

        return Packet(PACKET_TYPE_PIPE, False, bytes(data))

    def create_set_rgb_packet(self, controller_id: int, seq: int, device_index: int, r: int, g: int, b: int) -> Packet:
        data = bytearray()

        data.extend(struct.pack(">B", PACKET_PIPE_TYPE_SET_RGB))  # Packet Type for RGB color
        data.extend(bytes([0x00, 0x00, 0x00]))  # Zero padding
        data.extend(struct.pack(">B", 0x20))  # Packet Length (0x20 based on cync-lan)
        data.extend(struct.pack(">B", 0x04))  # RGB Command (0x04)
        data.extend(struct.pack(">BBB", r, g, b))  # Red, Green, and Blue values
        data.extend(struct.pack(">I H", controller_id, seq))  # Device-specific information
        data.extend(struct.pack(">H", device_index))  # Device Mesh ID or Index
        data.extend(bytes([0x7e, 0x00, 0x00, 0x00]))  # Fixed section from cync-lan
        data.extend(struct.pack(">I", 0xf8e20e))  # Padding/flags for RGB
        return Packet(PACKET_TYPE_PIPE, False, bytes(data))

    def create_ping_packet(self) -> Packet:
        data = bytearray()
        data.extend(struct.pack(">B", PACKET_TYPE_PING))  # Packet Type for ping (0xd3 in this case)
        data.extend(bytes([0x00, 0x00, 0x00, 0x00]))  # Zero padding (matches cync-lan)
        return Packet(PACKET_TYPE_PING, False, bytes(data))

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
        self.mesh_id = int(room_info.get('mesh_id', 0)).to_bytes(2, 'little')
        self.mesh_id_int = int.from_bytes(self.mesh_id, 'big')
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
        **kwargs: Any
    ) -> None:
        """Turn on the room lights."""
        attempts = 0
        update_received = False
        seq_ct = None
        seq_brightness = None
        seq_status = None
        seq_rgb = None

        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            # Unique sequence numbers for each command
            seq_status = self.hub.get_seq_num()
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

            # Handle brightness
            brightness_value = brightness if brightness is not None else self.brightness or 100

            # Handle color temperature
            color_temp = round(
                (
                    (color_temp_kelvin - self.min_color_temp_kelvin) /
                    (self.max_color_temp_kelvin - self.min_color_temp_kelvin)
                ) * 100
            ) if color_temp_kelvin is not None else 50  # Default mid value

            # Send Set Status (On) with unique seq_num and correct device_index
            status_packet = self.hub.create_set_status_packet(
                controller,
                seq_status,
                device_index=self.mesh_id_int,  # Use mesh_id_int
                status=1
            )
            await self.hub.send_request(status_packet, self.command_received, device=self, action='turn_on_or_off', desired_state=True)

            # Send Set Brightness with unique seq_num and correct device_index
            if self.support_brightness:
                seq_brightness = self.hub.get_seq_num()
                brightness_packet = self.hub.create_set_brightness_packet(
                    controller,
                    seq_brightness,
                    device_index=self.mesh_id_int,  # Use mesh_id_int
                    brightness=brightness_value
                )
                await self.hub.send_request(brightness_packet, self.command_received, device=self, action='set_brightness', brightness=brightness_value)

            # Send Set Color Temperature with unique seq_num and correct device_index
            if self.support_color_temp:
                seq_ct = self.hub.get_seq_num()
                color_temp_packet = self.hub.create_set_ct_packet(
                    controller,
                    seq_ct,
                    device_index=self.mesh_id_int,  # Use mesh_id_int
                    ct=color_temp
                )
                await self.hub.send_request(color_temp_packet, self.command_received, device=self, action='set_color_temp', color_temp_kelvin=color_temp_kelvin)

            # Wait for all acknowledgments
            await asyncio.sleep(self._command_timeout)

            # Check if all commands have been acknowledged
            if (
                not self.hub.pending_commands.get((controller << 8) | seq_status) and
                not self.hub.pending_commands.get((controller << 8) | seq_brightness) and
                (not self.support_color_temp or not self.hub.pending_commands.get((controller << 8) | seq_ct))
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

            # Send Set Status (Off) with unique seq_num and correct device_index
            status_packet = self.hub.create_set_status_packet(
                controller,
                seq,
                device_index=self.mesh_id_int,  # Use mesh_id_int
                status=0
            )
            await self.hub.send_request(status_packet, self.command_received, device=self, action='turn_on_or_off', desired_state=False)

            # Wait for acknowledgment
            await asyncio.sleep(self._command_timeout)

            # Check if the command has been acknowledged
            if not self.hub.pending_commands.get((controller << 8) | seq):
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
        self.mesh_id_int = int.from_bytes(self.mesh_id, 'big')
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
                brightness_packet = self.hub.create_set_brightness_packet(controller, seq_brightness, self.mesh_id_int, brightness_value)
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
