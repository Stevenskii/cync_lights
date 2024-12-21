import logging
import asyncio
import struct
import aiohttp
import ssl
import json
import math
from typing import Any, Callable, Dict, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

# Define API endpoints and constants
API_AUTH = "https://api.gelighting.com/v2/user_auth"
API_REQUEST_CODE = "https://api.gelighting.com/v2/two_factor/email/verifycode"
API_2FACTOR_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"

# Device capabilities
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
    "WIFICONTROL": [36, 37, 38, 39, 40, 48, 49, 51, 52, 53, 54, 55, 56, 57,
                    58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81, 128, 129,
                    130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140,
                    141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
                    152, 153, 154, 156, 158, 159, 160, 161, 162, 163,
                    164, 165]
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
PACKET_TYPE_REQUEST = 0x73  # Type 115 Sending control commands to devices
PACKET_TYPE_131 = 0x83 # Type 131 Receiving state updates and sensor data
PACKET_TYPE_INITIAL = 0x43 # Type 67 Receiving initial state packets after authentication
PACKET_TYPE_DEV_ACK = 0xAB # Type 171 Acknowledging and adding connected devices
PACKET_TYPE_ACK = 0x7B # Type 123 Acknowledgment of commands sent to the server
PACKET_TYPE_PING = 0xA3 # Type 163 Sending ping requests to check controller connectivity
PACKET_TYPE_KEEPALIVE = 0xD3 # Type 211 Sending keep-alive messages to maintain connection

# Constants
DEFAULT_TIMEOUT = 10  # seconds
DEFAULT_HOST = "cm.gelighting.com"
DEFAULT_PORT = 23778
SSL_PORT = 23779

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

    @staticmethod
    def hexdump(data):
        return ' '.join(f'{byte:02X}' for byte in data)

class CyncHub:
    def __init__(self, hass: Any, data: Dict[str, Any]):
        """Initialize the Hub"""
        self.hass = hass
        self.host = data.get("host", DEFAULT_HOST)
        self.port = data.get("port", DEFAULT_PORT)
        self.ssl_port = data.get("sslport", SSL_PORT)
        self.login_code = bytearray(data['cync_credentials'])
        self.use_ssl = True
        self.ssl_context = None
        self.reader, self.writer, self.logged_in, self.shutting_down = None, None, False, False
        self.home_devices = data['cync_config']['home_devices']
        self.home_controllers = data['cync_config']['home_controllers']
        self.switchID_to_homeID = data['cync_config']['switchID_to_homeID']
        self.connected_devices = {home_id: [] for home_id in self.home_controllers.keys()}
        self.connected_devices_updated = False
        self.cync_switches = {
            device_id: CyncSwitch(device_id, switch_info, self)
            for device_id, switch_info in data['cync_config']['devices'].items()
            if switch_info.get("ONOFF", False)
        }
        self.seq_num = 0
        self.seq_lock = asyncio.Lock()
        self.pending_commands = {}
        self.pending_commands_lock = asyncio.Lock()
        # Initialize the send and receive queue
        self.send_queue = asyncio.Queue()
        self.seq_to_mesh_id: Dict[int, int] = {}
        self.seq_to_mesh_id_lock = asyncio.Lock()

        self.effect_mapping = self.parse_light_shows(data['cync_config'])  # Re-added light show parsing


    async def setup_ssl_context(self) -> None:
        """Set up SSL context asynchronously."""
        if self.use_ssl:
            self.ssl_context = await self.hass.async_add_executor_job(ssl.create_default_context)
        else:
            self.ssl_context = None

    def parse_light_shows(self, cync_config) -> Dict[str, Any]:
        """Parse lightShows data from cync_config and create a mapping."""
        effect_mapping = {}
        for home_info in cync_config.get('homes', {}).values():
            for show in home_info.get('lightShows', []):
                effect_mapping[show['name']] = show
        return effect_mapping

    async def get_seq_num(self) -> int:
        """Thread-safe method to get the next sequence number."""
        async with self.seq_lock:
            self.seq_num = (self.seq_num + 1) % 65536
            return self.seq_num

    async def disconnect(self):
        self.shutting_down = True
        for home_controllers in self.home_controllers.values(): #send packets to server to generate data to be read which will initiate shutdown
            for controller in home_controllers:
                seq = await self.get_seq_num()
                state_request = bytes.fromhex('7300000018') + int(controller).to_bytes(4,'big') + seq.to_bytes(2,'big') + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                self.hass.async_create_task(self._send_request(state_request))

    async def connect(self):
        """Establish a TCP connection, authenticate, and start background tasks."""
        _LOGGER.debug("CyncHub connect() method called.")
        try:
            await self.setup_ssl_context()
    
            # Attempt to establish a secure connection first
            try:
                _LOGGER.debug("Trying to establish SSL connection on port %d.", self.ssl_port)
                self.reader, self.writer = await asyncio.open_connection(
                    self.host, self.ssl_port, ssl=self.ssl_context
                )
            except Exception as e:
                _LOGGER.debug("SSL connection failed: %s. Retrying with SSL disabled.", e)
                if self.ssl_context:
                    self.ssl_context.check_hostname = False
                    self.ssl_context.verify_mode = ssl.CERT_NONE
                try:
                    self.reader, self.writer = await asyncio.open_connection(
                        self.host, self.port, ssl=self.ssl_context
                    )
                except Exception as e2:
                    _LOGGER.debug("Retrying without SSL context: %s. Falling back to plain TCP.", e2)
                    self.reader, self.writer = await asyncio.open_connection(self.host, DEFAULT_PORT)
    
            # Send login code and await response
            _LOGGER.debug("Sending login code: %s", self.login_code.hex())
            self.writer.write(self.login_code)
            await self.writer.drain()
            login_response = await self.reader.read(1000)
            _LOGGER.debug("Received login response: %s", login_response.hex())
    
            # Check authentication
            if not login_response.startswith(b"\x18\x00\x00\x00\x02\x00\x00"):
                _LOGGER.error("Authentication failed with response data: %s", login_response.hex())
                return  # Or raise Exception(...)
    
            self.logged_in = True
            _LOGGER.debug("Successfully authenticated with the server.")
    
            # Spawn background tasks but do NOT block on them
            self.hass.async_create_task(self._read_tcp_messages(), name="Read TCP Messages")
            self.hass.async_create_task(self._maintain_connection(), name="Maintain Connection")
            self.hass.async_create_task(self._update_state(), name="Update State")
            self.hass.async_create_task(self._update_connected_devices(), name="Update Connected Devices")
            return
    
        except Exception as e:
            _LOGGER.error("Exception in connect(): %s: %s", type(e).__name__, str(e))
            _LOGGER.debug("Traceback:", exc_info=True)


    async def _read_tcp_messages(self) -> None:
        """Continuously read and process TCP messages from the server."""
        try:
            while not self.shutting_down:
                data = await self.reader.read(1000)
                if len(data) == 0:
                    self.logged_in = False
                    raise LostConnection
    
                while len(data) >= 12:
                    packet_type = int(data[0])
                    packet_length = struct.unpack(">I", data[1:5])[0]
                    packet = data[5:packet_length+5]
                    try:
                        self.switch_data = {}
                        # Parse packet data
                        parsed = {}
                        if packet_length == len(packet):
                            if packet_type == PACKET_TYPE_REQUEST: #115
                                #Switch ID 0-3
                                parsed['switch_id'] = struct.unpack(">I", packet[0:4])[0]
                                switch_id = parsed['switch_id']
                                home_id = self.switchID_to_homeID[switch_id]
                                # Ensure self.switch_data has a structure for this switch_id
                                if switch_id not in self.switch_data:
                                    self.switch_data[switch_id] = {'devices': []}
                                #Response ID 4-5
                                response_id = struct.unpack(">H", packet[4:6])[0]
                                response_packet = bytes.fromhex('7300000007') + int(switch_id).to_bytes(4,'big') + response_id.to_bytes(2,'big') + bytes.fromhex('00')
                                self.hass.async_create_task(self._send_request(response_packet))
    
                                #Command ID
                                parsed['command_id'] = int(packet[13])
    
                                #State Update Packet
                                if len(packet) > 51 and parsed['command_id'] == 82:
                                    self._add_connected_devices(switch_id, home_id)
                                    packet = packet[22: ]
                                    self.switch_data[switch_id] = {'devices': []}
    
                                    while len(packet) > 24:
                                        deviceID = self.home_devices[home_id][int(packet[21])]
                                        device_data = {
                                            'deviceID': deviceID,
                                            'power_state': int(packet[8]) > 0,
                                            'brightness': int(packet[12]) if int(packet[8]) > 0 else 0,
                                            'color_temp_kelvin': 2000 + ((7000 - 2000) * (int(packet[16]) / 255)),
                                            'rgb': {
                                                'r': packet[20],
                                                'g': packet[21],
                                                'b': packet[22],
                                                'active': int(packet[16]) == 254
                                                }
                                        }
    
                                        # Add or update the device in `self.switch_data[switch_id]['devices']`
                                        self._update_device_data(switch_id, device_data)
                                        if deviceID in self.switch_data:
                                            self._update_switch(
                                                switch_id=switch_id,
                                                device_id=device_data['deviceID'],
                                                state=device_data['power_state'],
                                                brightness=device_data['brightness'],
                                                color_temp=device_data['color_temp_kelvin'],
                                                rgb=device_data['rgb']
                                            )
                                        packet = packet[24:]
        
                                #State and Brightness Packet
                                if len(packet) >= 33 and parsed['command_id'] == 219:
                                    deviceID = self.home_devices[home_id][int(packet[21])]
                                    #parse state and brightness TODO FIND OUT IF CT AND RGB
                                    device_data = {
                                            'deviceID': deviceID,
                                            'power_state': int(packet[27]) > 0,
                                            'brightness': int(packet[28]) if int(packet[27]) > 0 else 0
                                    }
                                    self._update_device_data(switch_id, device_data)
                                    if deviceID in self.switch_data:
                                            self._update_switch(
                                                switch_id=switch_id,
                                                device_id=device_data['deviceID'],
                                                state=device_data['power_state'],
                                                brightness=device_data['brightness'],
                                                color_temp=self.switch_data[switch_id]['devices'][deviceID].get('color_temp_kelvin'),
                                                rgb=self.switch_data[switch_id]['devices'][deviceID].get('rgb')
                                            )
        
                                    _LOGGER.debug(f"Packet data ({len(packet)} bytes): {Packet.hexdump(packet)}")
        
                            elif packet_type == PACKET_TYPE_131:
                            #Process 131 type instead of 115, basically a duplicate section
                                parsed['switch_id'] = struct.unpack(">I", packet[0:4])[0]
                                switch_id = parsed['switch_id']
                                home_id = self.switchID_to_homeID[switch_id]
                                if len(packet) >= 33 and parsed['command_id'] == 219:
                                    deviceID = self.home_devices[home_id][int(packet[21])]
                                #parse state and brightness change packet
                                    device_data = {
                                            'deviceID': deviceID,
                                            'power_state': int(packet[27]) > 0,
                                            'brightness': int(packet[28]) if int(packet[27]) > 0 else 0
                                    }
                                    self._update_device_data(switch_id, device_data)
                                if deviceID in self.switch_data:
                                    self._update_switch(
                                        switch_id=switch_id,
                                        device_id=device_data['deviceID'],
                                        state=device_data['power_state'],
                                        brightness=device_data['brightness'],
                                        color_temp=self.switch_data[switch_id]['devices'][deviceID].get('color_temp_kelvin'),
                                        rgb=self.switch_data[switch_id]['devices'][deviceID].get('rgb')
                                    )
        
                                _LOGGER.debug(f"Packet data ({len(packet)} bytes): {Packet.hexdump(packet)}")
        
                            elif packet_type == PACKET_TYPE_INITIAL and int(packet[4]) == 1 and int(packet[5]) == 1 and int(packet[6]) == 1: #67
                            #Process initial state packet
                                parsed['switch_id'] = struct.unpack(">I", packet[0:4])[0]
                                switch_id = parsed['switch_id']
                                home_id = self.switchID_to_homeID[switch_id]
                                packet = packet[7: ]
                                while len(packet) >= 19:
                                    deviceID = self.home_devices[home_id][int(packet[3])]
                                    device_data = {
                                            'deviceID': deviceID,
                                            'power_state': int(packet[4]) > 0,
                                            'brightness': int(packet[5]) if int(packet[4]) > 0 else 0,
                                            'color_temp_kelvin': 2000 + ((7000 - 2000) * (int(packet[6]) / 255)),
                                            'rgb': {
                                                'r': packet[7],
                                                'g': packet[8],
                                                'b': packet[9],
                                                'active': int(packet[6]) == 254
                                                }
                                        }
                                    self._update_device_data(switch_id, device_data)
                                    if deviceID in self.switch_data:
                                        self._update_switch(
                                            switch_id=switch_id,
                                            device_id=device_data['deviceID'],
                                            state=device_data['power_state'],
                                            brightness=device_data['brightness'],
                                            color_temp=device_data['color_temp_kelvin'],
                                            rgb=device_data['rgb']
                                        )
        
                            elif packet_type == PACKET_TYPE_DEV_ACK:
                                parsed['switch_id'] = struct.unpack(">I", packet[0:4])[0]
                                switch_id = parsed['switch_id']
                                home_id = self.switchID_to_homeID[switch_id]
                                device_data = {}
                                self._update_device_data(switch_id, device_data)
        
                            elif packet_type == PACKET_TYPE_ACK:
                                seq = str(struct.unpack(">H", packet[9:11])[0])
                                command_received = self.pending_commands.get(seq,None)
                                if command_received is not None:
                                    command_received(seq)
                    except Exception as e:
                        _LOGGER.error(f"Error while reading TCP messages: {e}")
                        _LOGGER.debug("Traceback:", exc_info=True)
                        await asyncio.sleep(5)  # Retry after delay
            raise ShuttingDown
        except LostConnection:
            if not self.shutting_down:
                _LOGGER.info("Lost connection. Retrying connection in 15 seconds.")
                await asyncio.sleep(15)
                self.hass.async_create_task(self.connect())
                return
        except Exception as exc:
            _LOGGER.error("Unexpected error in _read_tcp_messages: %s", exc, exc_info=True)
        finally:
            _LOGGER.debug("Exiting _read_tcp_messages loop.")

    # Helper function to add or update device data
    def _update_device_data(self, switch_id, new_device_data):
        """Add or update device data within switch_data."""
        # Check if device already exists in the list of devices for the switch_id
        existing_device = next(
            (device for device in self.switch_data[switch_id]['devices'] if device['deviceID'] == new_device_data['deviceID']),
            None
        )
        if existing_device:
            # Update existing device data
            existing_device.update(new_device_data)
        else:
            # Append new device data
            self.switch_data[switch_id]['devices'].append(new_device_data)
    
    def _add_connected_devices(self, switch_id, home_id):
        # Ensure switch_data entry exists for this switch_id
        if switch_id not in self.switch_data:
            return
    
        # Iterate over devices stored in self.switch_data for this switch_id
        for device_data in self.switch_data[switch_id].get('devices', []):
            dev_id = device_data['deviceID']
            
            # Add device to connected_devices if not already present
            if dev_id not in self.connected_devices[home_id]:
                self.connected_devices[home_id].append(dev_id)
                
                # If devices are already flagged as updated, refresh controllers for all switches
                if self.connected_devices_updated:
                    for dev in self.cync_switches.values():
                        dev.update_controllers()
    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature in Kelvin."""
        return 7000  # Adjust according to your devices' specifications

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature in Kelvin."""
        return 2000  # Adjust according to your devices' specifications

    def _update_switch(self, switch_id, device_id, state, brightness, color_temp: Optional[int] = None, rgb: Optional[Dict[str, int]] = None):
        """Update the state of the device in switch_data as updates are received from the Cync server."""

        # Find the switch and device entry in `self.switch_data`
        switch_data = self.switch_data.get(switch_id)
        if not switch_data:
            _LOGGER.warning(f"Switch ID {switch_id} not found in switch_data.")
            return

        # Locate the specific device within the switch_data
        device_data = next((device for device in switch_data['devices'] if device['deviceID'] == device_id), None)
        if not device_data:
            _LOGGER.warning(f"Device ID {device_id} not found under switch ID {switch_id}.")
            return

        # Update the device data as required
        updated = False
        if device_data['power_state'] != state:
            device_data['power_state'] = state
            updated = True

        if brightness is not None and device_data['brightness'] != brightness:
            device_data['brightness'] = brightness
            updated = True

        if color_temp is not None:
            # Clamp color temperature within supported range
            color_temp_kelvin = max(self.min_color_temp_kelvin, min(self.max_color_temp_kelvin, color_temp))
            if device_data['color_temp_kelvin'] != color_temp_kelvin:
                device_data['color_temp_kelvin'] = color_temp_kelvin
                updated = True

        if rgb is not None:
            # Clamp RGB values within 0-255
            rgb_clamped = {
                'r': max(0, min(255, rgb.get('r', device_data['rgb']['r']))),
                'g': max(0, min(255, rgb.get('g', device_data['rgb']['g']))),
                'b': max(0, min(255, rgb.get('b', device_data['rgb']['b'])))
            }
            if device_data['rgb'] != rgb_clamped:
                device_data['rgb'] = rgb_clamped
                updated = True

        if updated:
            _LOGGER.debug(
                f"Device '{device_id}' updated under switch '{switch_id}': State={device_data['power_state']}, "
                f"Brightness={device_data['brightness']}, Color Temp={device_data['color_temp_kelvin']}, "
                f"RGB={device_data['rgb']}"
            )
            self.cync_switches[device_id].publish_update()

    async def _maintain_connection(self):
        while not self.shutting_down:
            await asyncio.sleep(180)
            self.writer.write(bytes.fromhex('d300000000'))
            await self.writer.drain()
        raise ShuttingDown

    async def _send_request(self, request):
        """Actually send the data to the server in a coroutine."""
        self.writer.write(request)
        await self.writer.drain()

    async def _update_connected_devices(self):
        while not self.shutting_down:
            self.connected_devices_updated = False
            for devices in self.connected_devices.values():
                devices.clear()
            while not self.logged_in:
                await asyncio.sleep(2)
            attempts = 0
            while True in [len(devices) < len(self.home_controllers[home_id]) * 0.5 for home_id,devices in self.connected_devices.items()] and attempts < 10:
                for home_id, home_controllers in self.home_controllers.items():
                    for controller in home_controllers:
                        seq = await self.get_seq_num()
                        ping = bytes.fromhex('a300000007') + int(controller).to_bytes(4,'big') + seq.to_bytes(2,'big') + bytes.fromhex('00')
                        self.hass.async_create_task(self._send_request(ping))
                        await asyncio.sleep(0.15)
                await asyncio.sleep(2)
                attempts += 1
            for dev in self.cync_switches.values():
                dev.update_controllers()
            self.connected_devices_updated = True
            await asyncio.sleep(3600)
        raise ShuttingDown

    async def _update_state(self):
        """Fetch the initial state of devices after the initial connection."""
        # Wait until connected devices are updated
        while not self.connected_devices_updated:
            await asyncio.sleep(2)

        # Send status requests to each controller
        for home_id, connected_devices in self.connected_devices.items():
            if connected_devices:
                controller = int(self.cync_switches[connected_devices[0]].switch_id)
                seq = await self.get_seq_num()
                state_request = bytes.fromhex('7300000018') + int(controller).to_bytes(4,'big') + seq.to_bytes(2,'big') + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                self.hass.async_create_task(self._send_request(state_request))
        for dev in self.cync_switches.values():
            dev.publish_update()

    def combo_control(self,state,brightness,color_tone,rgb,switch_id,mesh_id,seq):
        combo_request = bytes.fromhex('7300000022') + int(switch_id).to_bytes(4,'big') + int(seq).to_bytes(2,'big') + bytes.fromhex('007e00000000f8f010000000000000') + mesh_id + bytes.fromhex('f00000') + (1 if state else 0).to_bytes(1,'big')  + brightness.to_bytes(1,'big') + color_tone.to_bytes(1,'big') + rgb[0].to_bytes(1,'big') + rgb[1].to_bytes(1,'big') + rgb[2].to_bytes(1,'big') + ((496 + int(mesh_id[0]) + int(mesh_id[1]) + (1 if state else 0) + brightness + color_tone + sum(rgb))%256).to_bytes(1,'big') + bytes.fromhex('7e')
        self.hass.async_create_task(self._send_request(combo_request))

    def turn_on(self,switch_id,mesh_id,seq):
        power_request = bytes.fromhex('730000001f') + int(switch_id).to_bytes(4,'big') + int(seq).to_bytes(2,'big') + bytes.fromhex('007e00000000f8d00d000000000000') + mesh_id + bytes.fromhex('d00000010000') + ((430 + int(mesh_id[0]) + int(mesh_id[1]))%256).to_bytes(1,'big') + bytes.fromhex('7e')
        self.hass.async_create_task(self._send_request(power_request))

    def turn_off(self,switch_id,mesh_id,seq):
        power_request = bytes.fromhex('730000001f') + int(switch_id).to_bytes(4,'big') + int(seq).to_bytes(2,'big') + bytes.fromhex('007e00000000f8d00d000000000000') + mesh_id + bytes.fromhex('d00000000000') + ((429 + int(mesh_id[0]) + int(mesh_id[1]))%256).to_bytes(1,'big') + bytes.fromhex('7e')
        self.hass.async_create_task(self._send_request(power_request))

    def set_color_temp(self,color_temp,switch_id,mesh_id,seq):
        color_temp_request = bytes.fromhex('730000001e') + int(switch_id).to_bytes(4,'big') + int(seq).to_bytes(2,'big') + bytes.fromhex('007e00000000f8e20c000000000000') + mesh_id + bytes.fromhex('e2000005') + color_temp.to_bytes(1,'big') + ((469 + int(mesh_id[0]) + int(mesh_id[1]) + color_temp)%256).to_bytes(1,'big') + bytes.fromhex('7e')
        self.hass.async_create_task(self._send_request(color_temp_request))


class CyncSwitch:
    def __init__(self, device_id, switch_info, hub) -> None:
        self.hub = hub
        self.device_id = device_id
        self.switch_id = switch_info.get('switch_id', '0')
        self.home_id = [
            home_id for home_id, home_devices in self.hub.home_devices.items()
            if self.device_id in home_devices
        ][0]
        self.name = switch_info.get('name', 'unknown')
        self.home_name = switch_info.get('home_name', 'unknown')
        self.room_name = switch_info.get('room_name', 'unknown')
        self.mesh_id = switch_info.get('mesh_id', 0).to_bytes(2,'little')
        self.power_state = False
        self.brightness = 0
        self.color_temp_kelvin = 0
        self.rgb = {'r': 0, 'g': 0, 'b': 0, 'active': False}
        self.effect = None
        self.transition = None
        self.default_controller = int(switch_info.get('switch_controller', self.hub.home_controllers[self.home_id][0]))
        self.controllers: List[int] = []
        self._update_callback: Optional[Callable[[], None]] = None
        self.support_brightness = switch_info.get('BRIGHTNESS', False)
        self.support_color_temp = switch_info.get('COLORTEMP', False)
        self.support_rgb = switch_info.get('RGB', False)
        self.support_effects = True  # Assuming effects are supported
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def register(self, update_callback) -> None:
        """Register callback, called when switch changes state."""
        self._update_callback = update_callback

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    @property
    def max_color_temp_kelvin(self) -> int:
        """Return maximum supported color temperature in Kelvin."""
        return 7000  # Adjust according to your devices' specifications

    @property
    def min_color_temp_kelvin(self) -> int:
        """Return minimum supported color temperature in Kelvin."""
        return 2000  # Adjust according to your devices' specifications

    async def turn_on(self, attr_rgb, attr_br, attr_ct) -> None:
            """Turn on the light."""
            attempts = 0
            update_received = False
            while not update_received and attempts < int(self._command_retry_time/self._command_timeout):
                seq = str(await self.hub.get_seq_num())
                if len(self.controllers) > 0:
                    controller = self.controllers[attempts%len(self.controllers)]
                else:
                    controller = self.default_controller
                if attr_rgb is not None and attr_br is not None:
                    if math.isclose(attr_br, max([self.rgb['r'],self.rgb['g'],self.rgb['b']])*self.brightness/100, abs_tol = 2):
                        self.hub.combo_control(True, self.brightness, 254, attr_rgb, controller, self.mesh_id, seq)
                    else:
                        self.hub.combo_control(True, round(attr_br*100/255), 255, [255,255,255], controller, self.mesh_id, seq)
                elif attr_rgb is None and attr_ct is None and attr_br is not None:
                    self.hub.combo_control(True, round(attr_br*100/255), 255, [255,255,255], controller, self.mesh_id, seq)
                elif attr_rgb is not None and attr_br is None:
                    self.hub.combo_control(True, self.brightness, 254, attr_rgb, controller, self.mesh_id, seq)
                elif attr_ct is not None:
                    ct = max(0, min(100, round(
                        ((attr_ct - self.min_color_temp_kelvin) /
                         (self.max_color_temp_kelvin - self.min_color_temp_kelvin)) * 100
                    )))
                    self.hub.turn_on(controller, self.mesh_id, seq)
                    self.hub.set_color_temp(ct, controller, self.mesh_id, seq)
                else:
                    self.hub.turn_on(controller, self.mesh_id, seq)
                self.hub.pending_commands[seq] = self.command_received
                await asyncio.sleep(self._command_timeout)
                if self.hub.pending_commands.get(seq, None) is not None:
                    self.hub.pending_commands.pop(seq)
                    attempts += 1
                else:
                    update_received = True


    async def turn_off(self, **kwargs: Any) -> None:
        """Turn off the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time/self._command_timeout):
            seq = str(await self.hub.get_seq_num())
            if len(self.controllers) > 0:
                controller = self.controllers[attempts%len(self.controllers)]
            else:
                controller = self.default_controller
            self.hub.turn_off(controller, self.mesh_id, seq)
            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq, None) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    def command_received(self, seq):
        """Handle command acknowledgment from the Cync server."""
        _LOGGER.debug(f"Command received for sequence {seq}")

    def update_switch(self,state,brightness,color_temp,rgb):
        """Update the state of the switch as updates are received from the Cync server"""
        self.update_received = True
        if self.power_state != state or self.brightness != brightness or self.color_temp != color_temp or self.rgb != rgb:
            self.power_state = state
            self.brightness = brightness if self.support_brightness and state else 100 if state else 0
            self.color_temp = color_temp
            self.rgb = rgb
            self.publish_update()

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices"""
        connected_devices = self.hub.connected_devices[self.home_id]
        controllers = []
        if len(connected_devices) > 0:
            if int(self.switch_id) > 0:
                if self.device_id in connected_devices:
                    #if this device is connected, make this the first available controller
                    controllers.append(self.switch_id)
            others_available = [self.hub.cync_switches[device_id].switch_id for device_id in connected_devices]
            for controller in controllers:
                if controller in others_available:
                    others_available.remove(controller)
            self.controllers = controllers + others_available
        else:
            self.controllers = [self.default_controller]

    def publish_update(self):
        """Publish the update to Home Assistant."""
        if self._update_callback:
            self._update_callback()

class CyncUserData:

    def __init__(self):
        self.username = ''
        self.password = ''
        self.auth_code = None
        self.user_credentials = {}

    async def authenticate(self,username,password):
        """Authenticate with the API and get a token."""
        self.username = username
        self.password = password
        auth_data = {'corp_id': "1007d2ad150c4000", 'email': self.username, 'password': self.password}
        async with aiohttp.ClientSession() as session:
            async with session.post(API_AUTH, json=auth_data) as resp:
                if resp.status == 200:
                    self.user_credentials = await resp.json()
                    login_code = bytearray.fromhex('13000000') + (10 + len(self.user_credentials['authorize'])).to_bytes(1,'big') + bytearray.fromhex('03') + self.user_credentials['user_id'].to_bytes(4,'big') + len(self.user_credentials['authorize']).to_bytes(2,'big') + bytearray(self.user_credentials['authorize'],'ascii') + bytearray.fromhex('0000b4')
                    self.auth_code = [int.from_bytes([byt],'big') for byt in login_code]
                    return {'authorized':True}
                elif resp.status == 400:
                    request_code_data = {'corp_id': "1007d2ad150c4000", 'email': self.username, 'local_lang': "en-us"}
                    async with aiohttp.ClientSession() as session:
                        async with session.post(API_REQUEST_CODE,json=request_code_data) as resp:
                            if resp.status == 200:                    
                                return {'authorized':False,'two_factor_code_required':True}
                            else:
                                return {'authorized':False,'two_factor_code_required':False}
                else:
                    return {'authorized':False,'two_factor_code_required':False}

    async def auth_two_factor(self, code):
        """Authenticate with 2 Factor Code."""
        two_factor_data = {'corp_id': "1007d2ad150c4000", 'email': self.username,'password': self.password, 'two_factor': code, 'resource':"abcdefghijklmnop"}
        async with aiohttp.ClientSession() as session:
            async with session.post(API_2FACTOR_AUTH,json=two_factor_data) as resp:
                if resp.status == 200:
                    self.user_credentials = await resp.json()
                    login_code = bytearray.fromhex('13000000') + (10 + len(self.user_credentials['authorize'])).to_bytes(1,'big') + bytearray.fromhex('03') + self.user_credentials['user_id'].to_bytes(4,'big') + len(self.user_credentials['authorize']).to_bytes(2,'big') + bytearray(self.user_credentials['authorize'],'ascii') + bytearray.fromhex('0000b4')
                    self.auth_code = [int.from_bytes([byt],'big') for byt in login_code]
                    return {'authorized':True}
                else:
                    return {'authorized':False}

    async def get_cync_config(self):
        home_devices = {}
        home_controllers = {}
        switchID_to_homeID = {}
        devices = {}
        rooms = {}
        homes = await self._get_homes()
        for home in homes:
            home_info = await self._get_home_properties(home['product_id'], home['id'])
            if home_info.get('groupsArray',False) and home_info.get('bulbsArray',False) and len(home_info['groupsArray']) > 0 and len(home_info['bulbsArray']) > 0:
                home_id = str(home['id'])
                bulbs_array_length = max([((device['deviceID'] % home['id']) % 1000) + (int((device['deviceID'] % home['id']) / 1000)*256) for device in home_info['bulbsArray']]) + 1
                home_devices[home_id] = [""]*(bulbs_array_length)
                home_controllers[home_id] = []
                for device in home_info['bulbsArray']:
                    device_type = device['deviceType']
                    device_id = str(device['deviceID'])
                    current_index = ((device['deviceID'] % home['id']) % 1000) + (int((device['deviceID'] % home['id']) / 1000)*256)
                    home_devices[home_id][current_index] = device_id
                    devices[device_id] = {'name':device['displayName'],
                        'mesh_id':current_index,
                        'switch_id':str(device.get('switchID',0)), 
                        'ONOFF': device_type in Capabilities['ONOFF'], 
                        'BRIGHTNESS': device_type in Capabilities["BRIGHTNESS"], 
                        "COLORTEMP":device_type in Capabilities["COLORTEMP"], 
                        "RGB": device_type in Capabilities["RGB"], 
                        "WIFICONTROL": device_type in Capabilities["WIFICONTROL"],
                        'home_name':home['name'], 
                        'room':'', 
                        'room_name':''
                    }
                    if devices[device_id].get('WIFICONTROL',False) and 'switchID' in device and device['switchID'] > 0:
                        switchID_to_homeID[str(device['switchID'])] = home_id
                        devices[device_id]['switch_controller'] = device['switchID']
                        home_controllers[home_id].append(device['switchID'])
                if len(home_controllers[home_id]) == 0:
                    for device in home_info['bulbsArray']:
                        device_id = str(device['deviceID'])
                        devices.pop(device_id,'')
                    home_devices.pop(home_id,'')
                    home_controllers.pop(home_id,'')
                else:
                    for room in home_info['groupsArray']:
                        if (len(room.get('deviceIDArray',[])) + len(room.get('subgroupIDArray',[]))) > 0:
                            room_id = home_id + '-' + str(room['groupID'])
                            room_controller = home_controllers[home_id][0]
                            available_room_controllers = [(id%1000) + (int(id/1000)*256) for id in room.get('deviceIDArray',[]) if 'switch_controller' in devices[home_devices[home_id][(id%1000)+(int(id/1000)*256)]]]
                            if len(available_room_controllers) > 0:
                                room_controller = devices[home_devices[home_id][available_room_controllers[0]]]['switch_controller']
                            for id in room.get('deviceIDArray',[]):
                                id = (id % 1000) + (int(id / 1000)*256)
                                devices[home_devices[home_id][id]]['room'] = room_id
                                devices[home_devices[home_id][id]]['room_name'] = room['displayName']
                                if 'switch_controller' not in devices[home_devices[home_id][id]] and devices[home_devices[home_id][id]].get('ONOFF',False):
                                    devices[home_devices[home_id][id]]['switch_controller'] = room_controller
                            rooms[room_id] = {'name':room['displayName'],
                                'mesh_id' : room['groupID'], 
                                'room_controller' : room_controller,
                                'home_name' : home['name'], 
                                'switches' : [home_devices[home_id][(i%1000)+(int(i/1000)*256)] for i in room.get('deviceIDArray',[]) if devices[home_devices[home_id][(i%1000)+(int(i/1000)*256)]].get('ONOFF',False)],
                                'isSubgroup' : room.get('isSubgroup',False),
                                'subgroups' : [home_id + '-' + str(subgroup) for subgroup in room.get('subgroupIDArray',[])]
                            }
                    for room,room_info in rooms.items():
                        if not room_info.get("isSubgroup",False) and len(subgroups := room_info.get("subgroups",[]).copy()) > 0:
                            for subgroup in subgroups:
                                if rooms.get(subgroup,None):
                                    rooms[subgroup]["parent_room"] = room_info["name"]
                                else:
                                    room_info['subgroups'].pop(room_info['subgroups'].index(subgroup))
                                    
        if len(rooms) == 0 or len(devices) == 0 or len(home_controllers) == 0 or len(home_devices) == 0 or len(switchID_to_homeID) == 0:
            raise InvalidCyncConfiguration
        else:
            return {'rooms':rooms, 'devices':devices, 'home_devices':home_devices, 'home_controllers':home_controllers, 'switchID_to_homeID':switchID_to_homeID}

    async def _get_homes(self):
        """Get a list of devices for a particular user."""
        headers = {'Access-Token': self.user_credentials['access_token']}
        async with aiohttp.ClientSession() as session:
            async with session.get(API_DEVICES.format(user=self.user_credentials['user_id']), headers=headers) as resp:
                response  = await resp.json()
                return response

    async def _get_home_properties(self, product_id, device_id):
        """Get properties for a single device."""
        headers = {'Access-Token': self.user_credentials['access_token']}
        async with aiohttp.ClientSession() as session:
            async with session.get(API_DEVICE_INFO.format(product_id=product_id, device_id=device_id), headers=headers) as resp:
                response = await resp.json()
                return response