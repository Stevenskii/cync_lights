"""Module for managing the Cync Hub and associated devices."""

from __future__ import annotations

import asyncio
import logging
import math
import ssl
import struct
import threading
from typing import Any, Callable, Dict, List, Optional

import aiohttp

_LOGGER = logging.getLogger(__name__)

API_AUTH = "https://api.gelighting.com/v2/user_auth"
API_REQUEST_CODE = "https://api.gelighting.com/v2/two_factor/email/verifycode"
API_2FACTOR_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"

Capabilities = {
    "ONOFF": [
        1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 49, 51,
        52, 53, 54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81,
        82, 83, 85, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139,
        140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
        154, 155, 156, 158, 159, 160, 161, 162, 163, 164, 165, 169, 170,
    ],
    "BRIGHTNESS": [
        1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 48, 49, 55, 56, 80,
        81, 82, 83, 85, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138,
        139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152,
        153, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164, 165, 169, 170,
    ],
    "COLORTEMP": [
        5, 6, 7, 8, 10, 11, 14, 15, 19, 20, 21, 22, 23, 25, 26, 28, 29, 30, 31,
        32, 33, 34, 35, 80, 82, 83, 85, 129, 130, 131, 132, 133, 135, 136, 137,
        138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 153, 154, 155, 156,
        158, 159, 160, 161, 162, 163, 164, 165, 169, 170,
    ],
    "RGB": [
        6, 7, 8, 21, 22, 23, 30, 31, 32, 33, 34, 35, 131, 132, 133, 137, 138,
        139, 140, 141, 142, 143, 146, 147, 153, 154, 155, 156, 158, 159, 160,
        161, 162, 163, 164, 165, 169, 170,
    ],
    "MOTION": [37, 49, 54],
    "AMBIENT_LIGHT": [37, 49, 54],
    "WIFICONTROL": [
        36, 37, 38, 39, 40, 48, 49, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61, 62,
        63, 64, 65, 66, 67, 68, 80, 81, 128, 129, 130, 131, 132, 133, 134, 135,
        136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
        150, 151, 152, 153, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164,
        165, 169, 170,
    ],
    "PLUG": [64, 65, 66, 67, 68],
    "FAN": [81],
    "MULTIELEMENT": {'67': 2},
}


class LostConnection(Exception):
    """Exception for lost connection to Cync Server."""


class ShuttingDown(Exception):
    """Exception when Cync client is shutting down."""


class InvalidCyncConfiguration(Exception):
    """Exception for invalid Cync configuration."""


class CyncHub:
    """Class representing the Cync Hub."""

    def __init__(self, user_data: dict, options: dict) -> None:
        """Initialize the Cync Hub."""
        self.thread: Optional[threading.Thread] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.login_code = bytearray(user_data['cync_credentials'])
        self.logged_in = False
        self.home_devices = user_data['cync_config']['home_devices']
        self.home_controllers = user_data['cync_config']['home_controllers']
        self.switchID_to_homeID = user_data['cync_config']['switchID_to_homeID']
        self.connected_devices = {home_id: [] for home_id in self.home_controllers.keys()}
        self.shutting_down = False
        self.cync_rooms: Dict[str, CyncRoom] = {}
        self.cync_switches: Dict[str, CyncSwitch] = {}
        self.cync_motion_sensors: Dict[str, CyncMotionSensor] = {}
        self.cync_ambient_light_sensors: Dict[str, CyncAmbientLightSensor] = {}
        self.switchID_to_deviceIDs: Dict[str, List[str]] = {}
        self.connected_devices_updated = False
        self.options = options
        self._seq_num = 0
        self.pending_commands: Dict[str, Callable[[str], None]] = {}

        # Initialize devices
        self._initialize_devices(user_data)

    def _initialize_devices(self, user_data: dict) -> None:
        """Initialize devices and rooms."""
        rooms_data = user_data['cync_config']['rooms']
        devices_data = user_data['cync_config']['devices']

        for room_id, room_info in rooms_data.items():
            self.cync_rooms[room_id] = CyncRoom(room_id, room_info, self)

        for device_id, device_info in devices_data.items():
            if device_info.get("ONOFF", False):
                room = self.cync_rooms.get(device_info['room'], None)
                self.cync_switches[device_id] = CyncSwitch(device_id, device_info, room, self)

            if device_info.get("MOTION", False):
                room = self.cync_rooms.get(device_info['room'], None)
                self.cync_motion_sensors[device_id] = CyncMotionSensor(device_id, device_info, room)

            if device_info.get("AMBIENT_LIGHT", False):
                room = self.cync_rooms.get(device_info['room'], None)
                self.cync_ambient_light_sensors[device_id] = CyncAmbientLightSensor(device_id, device_info, room)

        self.switchID_to_deviceIDs = {
            switch.switch_id: [
                dev_id
                for dev_id, dev in self.cync_switches.items()
                if dev.switch_id == switch.switch_id
            ]
            for dev_id, switch in self.cync_switches.items()
            if int(switch.switch_id) > 0
        }

        for room in self.cync_rooms.values():
            if room.is_subgroup:
                room.initialize()

        for room in self.cync_rooms.values():
            if not room.is_subgroup:
                room.initialize()

    def start_tcp_client(self) -> None:
        """Start the TCP client in a new thread."""
        self.thread = threading.Thread(target=self._start_tcp_client, daemon=True)
        self.thread.start()

    def _start_tcp_client(self) -> None:
        """Initialize the event loop and start the TCP client."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect())

    def disconnect(self) -> None:
        """Disconnect from the hub."""
        self.shutting_down = True
        if self.loop and self.writer:
            for home_controllers in self.home_controllers.values():
                for controller in home_controllers:
                    seq = self.get_seq_num()
                    state_request = (
                        bytes.fromhex('7300000018')
                        + int(controller).to_bytes(4, 'big')
                        + seq.to_bytes(2, 'big')
                        + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                    )
                    self.loop.call_soon_threadsafe(self.send_request, state_request)

    async def _connect(self) -> None:
        """Establish connection to the Cync server."""
        while not self.shutting_down:
            try:
                context = ssl.create_default_context()
                try:
                    self.reader, self.writer = await asyncio.open_connection(
                        'cm.gelighting.com', 23779, ssl=context
                    )
                except Exception:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    try:
                        self.reader, self.writer = await asyncio.open_connection(
                            'cm.gelighting.com', 23779, ssl=context
                        )
                    except Exception:
                        self.reader, self.writer = await asyncio.open_connection(
                            'cm.gelighting.com', 23778
                        )
            except Exception as e:
                _LOGGER.error("Connection error: %s", e)
                await asyncio.sleep(5)
            else:
                read_tcp_messages = asyncio.create_task(self._read_tcp_messages(), name="Read TCP Messages")
                maintain_connection = asyncio.create_task(self._maintain_connection(), name="Maintain Connection")
                update_state = asyncio.create_task(self._update_state(), name="Update State")
                update_connected_devices = asyncio.create_task(self._update_connected_devices(), name="Update Connected Devices")
                read_write_tasks = [read_tcp_messages, maintain_connection, update_state, update_connected_devices]
                try:
                    done, pending = await asyncio.wait(read_write_tasks, return_when=asyncio.FIRST_EXCEPTION)
                    for task in done:
                        name = task.get_name()
                        exception = task.exception()
                        if exception:
                            _LOGGER.error("Task %s raised exception: %s", name, exception)
                    for task in pending:
                        task.cancel()
                    if not self.shutting_down:
                        _LOGGER.error("Connection to Cync server reset, restarting in 15 seconds")
                        await asyncio.sleep(15)
                    else:
                        _LOGGER.debug("Cync client shutting down")
                except Exception as e:
                    _LOGGER.error("Exception in _connect: %s", e)

    async def _read_tcp_messages(self) -> None:
        """Read messages from the TCP connection."""
        if self.writer:
            self.writer.write(self.login_code)
            await self.writer.drain()
        if self.reader:
            await self.reader.read(1000)
        self.logged_in = True
        while not self.shutting_down:
            if not self.reader:
                break
            data = await self.reader.read(1000)
            if len(data) == 0:
                self.logged_in = False
                raise LostConnection
            while len(data) >= 12:
                packet_type = int(data[0])
                packet_length = struct.unpack(">I", data[1:5])[0]
                packet = data[5:packet_length + 5]
                try:
                    if packet_length == len(packet):
                        self._process_packet(packet_type, packet, packet_length)
                except Exception as e:
                    _LOGGER.error("Error processing packet: %s", e)
                data = data[packet_length + 5:]
        raise ShuttingDown

    def _process_packet(self, packet_type: int, packet: bytes, packet_length: int) -> None:
        """Process received packet from the TCP stream."""
        # Implement packet processing logic here
        pass  # Placeholder for actual implementation

    async def _maintain_connection(self) -> None:
        """Send keep-alive messages to maintain the connection."""
        while not self.shutting_down:
            await asyncio.sleep(180)
            if self.writer:
                self.writer.write(bytes.fromhex('d300000000'))
                await self.writer.drain()
        raise ShuttingDown

    def _add_connected_devices(self, switch_id: str, home_id: str) -> None:
        """Add devices to the list of connected devices."""
        for dev in self.switchID_to_deviceIDs.get(switch_id, []):
            if dev not in self.connected_devices[home_id]:
                self.connected_devices[home_id].append(dev)
                if self.connected_devices_updated:
                    for dev in self.cync_switches.values():
                        dev.update_controllers()
                    for room in self.cync_rooms.values():
                        room.update_controllers()

    async def _update_connected_devices(self) -> None:
        """Update the list of connected devices periodically."""
        while not self.shutting_down:
            self.connected_devices_updated = False
            for devices in self.connected_devices.values():
                devices.clear()
            while not self.logged_in:
                await asyncio.sleep(2)
            attempts = 0
            while True in [
                len(devices) < len(self.home_controllers[home_id]) * 0.5
                for home_id, devices in self.connected_devices.items()
            ] and attempts < 10:
                for home_id, home_controllers in self.home_controllers.items():
                    for controller in home_controllers:
                        seq = self.get_seq_num()
                        ping = (
                            bytes.fromhex('a300000007')
                            + int(controller).to_bytes(4, 'big')
                            + seq.to_bytes(2, 'big')
                            + bytes.fromhex('00')
                        )
                        self.loop.call_soon_threadsafe(self.send_request, ping)
                        await asyncio.sleep(0.15)
                await asyncio.sleep(2)
                attempts += 1
            for dev in self.cync_switches.values():
                dev.update_controllers()
            for room in self.cync_rooms.values():
                room.update_controllers()
            self.connected_devices_updated = True
            await asyncio.sleep(3600)
        raise ShuttingDown

    async def _update_state(self) -> None:
        """Update the state of devices after connection is established."""
        while not self.connected_devices_updated:
            await asyncio.sleep(2)
        for connected_devices in self.connected_devices.values():
            if connected_devices:
                controller = self.cync_switches[connected_devices[0]].switch_id
                seq = self.get_seq_num()
                state_request = (
                    bytes.fromhex('7300000018')
                    + int(controller).to_bytes(4, 'big')
                    + seq.to_bytes(2, 'big')
                    + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                )
                self.loop.call_soon_threadsafe(self.send_request, state_request)
        while any(
            dev._update_callback is None for dev in self.cync_switches.values()
        ) and any(
            room._update_callback is None for room in self.cync_rooms.values()
        ):
            await asyncio.sleep(2)
        for dev in self.cync_switches.values():
            dev.publish_update()
        for room in self.cync_rooms.values():
            room.publish_update()

    def send_request(self, request: bytes) -> None:
        """Send a request to the Cync server."""
        async def send() -> None:
            if self.writer:
                self.writer.write(request)
                await self.writer.drain()
        if self.loop:
            self.loop.create_task(send())

    def combo_control(
        self,
        state: bool,
        brightness: int,
        color_tone: int,
        rgb: List[int],
        switch_id: str,
        mesh_id: bytes,
        seq: int,
    ) -> None:
        """Send combo control command."""
        # Implement the combo control logic here
        pass  # Placeholder for actual implementation

    def turn_on(self, switch_id: str, mesh_id: bytes, seq: int) -> None:
        """Send command to turn on a device."""
        # Implement the turn on logic here
        pass  # Placeholder for actual implementation

    def turn_off(self, switch_id: str, mesh_id: bytes, seq: int) -> None:
        """Send command to turn off a device."""
        # Implement the turn off logic here
        pass  # Placeholder for actual implementation

    def set_color_temp(self, color_temp: int, switch_id: str, mesh_id: bytes, seq: int) -> None:
        """Set the color temperature of a device."""
        # Implement the set color temperature logic here
        pass  # Placeholder for actual implementation

    def get_seq_num(self) -> int:
        """Get the next sequence number."""
        if self._seq_num == 65535:
            self._seq_num = 1
        else:
            self._seq_num += 1
        return self._seq_num

# Implement the CyncRoom, CyncSwitch, CyncMotionSensor, CyncAmbientLightSensor classes
# ensuring no code is executed at module level

class CyncRoom:
    """Representation of a Cync Room."""

    def __init__(self, room_id: str, room_info: dict, hub: CyncHub) -> None:
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
        self.switches_support_brightness: List[str] = []
        self.switches_support_color_temp: List[str] = []
        self.switches_support_rgb: List[str] = []
        self.groups_support_brightness: List[str] = []
        self.groups_support_color_temp: List[str] = []
        self.groups_support_rgb: List[str] = []
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def initialize(self) -> None:
        """Initialize supported features and register update functions."""
        # Implementation as before
        pass

    # Rest of the methods for CyncRoom

class CyncSwitch:
    """Representation of a Cync Switch."""

    def __init__(self, device_id: str, switch_info: dict, room: Optional[CyncRoom], hub: CyncHub) -> None:
        """Initialize the Cync Switch."""
        # Implementation as before
        pass

    # Rest of the methods for CyncSwitch

class CyncMotionSensor:
    """Representation of a Cync Motion Sensor."""

    def __init__(self, device_id: str, device_info: dict, room: Optional[CyncRoom]) -> None:
        """Initialize the motion sensor."""
        # Implementation as before
        pass

    # Rest of the methods for CyncMotionSensor

class CyncAmbientLightSensor:
    """Representation of a Cync Ambient Light Sensor."""

    def __init__(self, device_id: str, device_info: dict, room: Optional[CyncRoom]) -> None:
        """Initialize the ambient light sensor."""
        # Implementation as before
        pass

    # Rest of the methods for CyncAmbientLightSensor

class CyncUserData:
    """Class to handle user authentication and data retrieval."""

    def __init__(self):
        """Initialize the user data."""
        self.username = ''
        self.password = ''
        self.auth_code = None
        self.user_credentials = {}

    async def authenticate(self, username: str, password: str) -> dict:
        """Authenticate with the API and get a token."""
        # Implementation as before
        pass

    async def auth_two_factor(self, code: str) -> dict:
        """Authenticate with two-factor code."""
        # Implementation as before
        pass

    async def get_cync_config(self) -> dict:
        """Retrieve the Cync configuration."""
        # Implementation as before
        pass

    async def _get_homes(self) -> list:
        """Get a list of homes for the user."""
        # Implementation as before
        pass

    async def _get_home_properties(self, product_id: str, device_id: str) -> dict:
        """Get properties for a single home."""
        # Implementation as before
        pass

