import logging
import threading
import asyncio
import struct
import aiohttp
import math
import ssl
from typing import Any, Callable, Dict, List, Optional, Tuple

_LOGGER = logging.getLogger(__name__)

API_AUTH = "https://api.gelighting.com/v2/user_auth"
API_REQUEST_CODE = "https://api.gelighting.com/v2/two_factor/email/verifycode"
API_2FACTOR_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"

Capabilities = {
    "ONOFF": [1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
              27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 48, 49, 51, 52, 53,
              54, 55, 56, 57, 58, 59, 61, 62, 63, 64, 65, 66, 67, 68, 80, 81, 82, 83, 85,
              128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
              143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 158,
              159, 160, 161, 162, 163, 164, 165, 169, 170],
    "BRIGHTNESS": [1, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23, 24,
                   25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 48, 49, 55, 56,
                   80, 81, 82, 83, 85, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137,
                   138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151,
                   152, 153, 154, 155, 156, 158, 159, 160, 161, 162, 163, 164, 165, 169,
                   170],
    "COLORTEMP": [5, 6, 7, 8, 10, 11, 14, 15, 19, 20, 21, 22, 23, 25, 26, 28, 29, 30,
                  31, 32, 33, 34, 35, 80, 82, 83, 85, 129, 130, 131, 132, 133, 135, 136,
                  137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 153, 154, 155,
                  156, 158, 159, 160, 161, 162, 163, 164, 165, 169, 170],
    "RGB": [6, 7, 8, 21, 22, 23, 30, 31, 32, 33, 34, 35, 131, 132, 133, 137, 138, 139,
            140, 141, 142, 143, 146, 147, 153, 154, 155, 156, 158, 159, 160, 161, 162,
            163, 164, 165, 169, 170],
    "MOTION": [37, 49, 54],
    "AMBIENT_LIGHT": [37, 49, 54],
    "WIFICONTROL": [36, 37, 38, 39, 40, 48, 49, 51, 52, 53, 54, 55, 56, 57, 58, 59, 61,
                    62, 63, 64, 65, 66, 67, 68, 80, 81, 128, 129, 130, 131, 132, 133,
                    134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146,
                    147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 158, 159, 160,
                    161, 162, 163, 164, 165, 169, 170],
    "PLUG": [64, 65, 66, 67, 68],
    "FAN": [81],
    "MULTIELEMENT": {'67': 2}
}


class CyncHub:

    def __init__(self, user_data, options):

        self.thread = None
        self.loop = None
        self.reader = None
        self.writer = None
        self.login_code = bytearray(user_data['cync_credentials'])
        self.logged_in = False
        self.home_devices = user_data['cync_config']['home_devices']
        self.home_controllers = user_data['cync_config']['home_controllers']
        self.switchID_to_homeID = user_data['cync_config']['switchID_to_homeID']
        self.connected_devices = {home_id: [] for home_id in self.home_controllers.keys()}
        self.shutting_down = False
        self.cync_rooms = {room_id: CyncRoom(room_id, room_info, self) for room_id, room_info in user_data['cync_config']['rooms'].items()}
        self.cync_switches = {
            device_id: CyncSwitch(device_id, switch_info, self.cync_rooms.get(switch_info['room'], None), self)
            for device_id, switch_info in user_data['cync_config']['devices'].items() if switch_info.get("ONOFF", False)
        }
        self.cync_motion_sensors = {
            device_id: CyncMotionSensor(device_id, device_info, self.cync_rooms.get(device_info['room'], None))
            for device_id, device_info in user_data['cync_config']['devices'].items() if device_info.get("MOTION", False)
        }
        self.cync_ambient_light_sensors = {
            device_id: CyncAmbientLightSensor(device_id, device_info, self.cync_rooms.get(device_info['room'], None))
            for device_id, device_info in user_data['cync_config']['devices'].items() if device_info.get("AMBIENT_LIGHT", False)
        }
        self.switchID_to_deviceIDs = {
            device_info.switch_id: [dev_id for dev_id, dev_info in self.cync_switches.items() if dev_info.switch_id == device_info.switch_id]
            for device_id, device_info in self.cync_switches.items() if int(device_info.switch_id) > 0
        }
        self.connected_devices_updated = False
        self.options = options
        self._seq_num = 0
        self.pending_commands = {}
        [room.initialize() for room in self.cync_rooms.values() if room.is_subgroup]
        [room.initialize() for room in self.cync_rooms.values() if not room.is_subgroup]

        # Parse lightShows data and create effect mapping
        self.effect_mapping = self._parse_light_shows(user_data['cync_config'])

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

    def start_tcp_client(self):
        self.thread = threading.Thread(target=self._start_tcp_client, daemon=True)
        self.thread.start()

    def _start_tcp_client(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._connect())

    def disconnect(self):
        self.shutting_down = True
        for home_controllers in self.home_controllers.values():
            for controller in home_controllers:
                seq = self.get_seq_num()
                state_request = bytes.fromhex('7300000018') + int(controller).to_bytes(4, 'big') + seq.to_bytes(2, 'big') + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                self.loop.call_soon_threadsafe(self.send_request, state_request)

    async def _connect(self):
        while not self.shutting_down:
            try:
                context = ssl.create_default_context()
                try:
                    self.reader, self.writer = await asyncio.open_connection('cm.gelighting.com', 23779, ssl=context)
                except Exception:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    try:
                        self.reader, self.writer = await asyncio.open_connection('cm.gelighting.com', 23779, ssl=context)
                    except Exception:
                        self.reader, self.writer = await asyncio.open_connection('cm.gelighting.com', 23778)
            except Exception as e:
                _LOGGER.error(f"{type(e).__name__}: {e}")
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
                        try:
                            result = task.result()
                        except Exception as e:
                            _LOGGER.error(f"{type(e).__name__}: {e}")
                    for task in pending:
                        task.cancel()
                    if not self.shutting_down:
                        _LOGGER.error("Connection to Cync server reset, restarting in 15 seconds")
                        await asyncio.sleep(15)
                    else:
                        _LOGGER.debug("Cync client shutting down")
                except Exception as e:
                    _LOGGER.error(f"{type(e).__name__}: {e}")

    async def _read_tcp_messages(self):
        self.writer.write(self.login_code)
        await self.writer.drain()
        await self.reader.read(1000)
        self.logged_in = True
        while not self.shutting_down:
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
                        if packet_type == 115:
                            switch_id = str(struct.unpack(">I", packet[0:4])[0])
                            home_id = self.switchID_to_homeID[switch_id]

                            # Send response packet
                            response_id = struct.unpack(">H", packet[4:6])[0]
                            response_packet = bytes.fromhex('7300000007') + int(switch_id).to_bytes(4, 'big') + response_id.to_bytes(2, 'big') + bytes.fromhex('00')
                            self.loop.call_soon_threadsafe(self.send_request, response_packet)

                            if packet_length >= 33 and int(packet[13]) == 219:
                                # Parse state and brightness change packet
                                deviceID = self.home_devices[home_id][int(packet[21])]
                                state = int(packet[27]) > 0
                                brightness = int(packet[28]) if state else 0
                                color_temp = int(packet[29])
                                rgb = {'r': int(packet[30]), 'g': int(packet[31]), 'b': int(packet[32]), 'active': int(packet[29]) == 254}

                                # Scale RGB values from 0-100 to 0-255
                                rgb_scaled = {
                                    'r': int(rgb['r'] * 255 / 100),
                                    'g': int(rgb['g'] * 255 / 100),
                                    'b': int(rgb['b'] * 255 / 100),
                                    'active': rgb['active']
                                }

                                if deviceID in self.cync_switches:
                                    self.cync_switches[deviceID].update_switch(state, brightness, color_temp, rgb_scaled)
                            elif packet_length >= 25 and int(packet[13]) == 84:
                                # Parse motion and ambient light sensor packet
                                deviceID = self.home_devices[home_id][int(packet[16])]
                                motion = int(packet[22]) > 0
                                ambient_light = int(packet[24]) > 0
                                if deviceID in self.cync_motion_sensors:
                                    self.cync_motion_sensors[deviceID].update_motion_sensor(motion)
                                if deviceID in self.cync_ambient_light_sensors:
                                    self.cync_ambient_light_sensors[deviceID].update_ambient_light_sensor(ambient_light)
                            elif packet_length > 51 and int(packet[13]) == 82:
                                # Parse initial state packet
                                switch_id = str(struct.unpack(">I", packet[0:4])[0])
                                home_id = self.switchID_to_homeID[switch_id]
                                self._add_connected_devices(switch_id, home_id)
                                packet = packet[22:]
                                while len(packet) > 24:
                                    deviceID = self.home_devices[home_id][int(packet[0])]
                                    if deviceID in self.cync_switches:
                                        if self.cync_switches[deviceID].elements > 1:
                                            for i in range(self.cync_switches[deviceID].elements):
                                                device_id = self.home_devices[home_id][(i + 1) * 256 + int(packet[0])]
                                                state = int((int(packet[12]) >> i) & int(packet[8])) > 0
                                                brightness = 100 if state else 0
                                                self.cync_switches[device_id].update_switch(state, brightness)
                                        else:
                                            state = int(packet[8]) > 0
                                            brightness = int(packet[12]) if state else 0
                                            color_temp = int(packet[16])
                                            rgb = {'r': int(packet[20]), 'g': int(packet[21]), 'b': int(packet[22]), 'active': int(packet[16]) == 254}

                                            # Scale RGB values from 0-100 to 0-255
                                            rgb_scaled = {
                                                'r': int(rgb['r'] * 255 / 100),
                                                'g': int(rgb['g'] * 255 / 100),
                                                'b': int(rgb['b'] * 255 / 100),
                                                'active': rgb['active']
                                            }

                                            self.cync_switches[deviceID].update_switch(state, brightness, color_temp, rgb_scaled)
                                    packet = packet[24:]
                        elif packet_type == 131:
                            switch_id = str(struct.unpack(">I", packet[0:4])[0])
                            home_id = self.switchID_to_homeID[switch_id]
                            if packet_length >= 33 and int(packet[13]) == 219:
                                # Parse state and brightness change packet
                                deviceID = self.home_devices[home_id][int(packet[21])]
                                state = int(packet[27]) > 0
                                brightness = int(packet[28]) if state else 0
                                color_temp = int(packet[29])
                                rgb = {'r': int(packet[30]), 'g': int(packet[31]), 'b': int(packet[32]), 'active': int(packet[29]) == 254}

                                # Scale RGB values from 0-100 to 0-255
                                rgb_scaled = {
                                    'r': int(rgb['r'] * 255 / 100),
                                    'g': int(rgb['g'] * 255 / 100),
                                    'b': int(rgb['b'] * 255 / 100),
                                    'active': rgb['active']
                                }

                                if deviceID in self.cync_switches:
                                    self.cync_switches[deviceID].update_switch(state, brightness, color_temp, rgb_scaled)
                            elif packet_length >= 25 and int(packet[13]) == 84:
                                # Parse motion and ambient light sensor packet
                                deviceID = self.home_devices[home_id][int(packet[16])]
                                motion = int(packet[22]) > 0
                                ambient_light = int(packet[24]) > 0
                                if deviceID in self.cync_motion_sensors:
                                    self.cync_motion_sensors[deviceID].update_motion_sensor(motion)
                                if deviceID in self.cync_ambient_light_sensors:
                                    self.cync_ambient_light_sensors[deviceID].update_ambient_light_sensor(ambient_light)
                        elif packet_type == 67 and packet_length >= 26 and int(packet[4]) == 1 and int(packet[5]) == 1 and int(packet[6]) == 6:
                            # Parse state packet
                            switch_id = str(struct.unpack(">I", packet[0:4])[0])
                            home_id = self.switchID_to_homeID[switch_id]
                            packet = packet[7:]
                            while len(packet) >= 19:
                                if int(packet[3]) < len(self.home_devices[home_id]):
                                    deviceID = self.home_devices[home_id][int(packet[3])]
                                    if deviceID in self.cync_switches:
                                        if self.cync_switches[deviceID].elements > 1:
                                            for i in range(self.cync_switches[deviceID].elements):
                                                device_id = self.home_devices[home_id][(i + 1) * 256 + int(packet[3])]
                                                state = int((int(packet[5]) >> i) & int(packet[4])) > 0
                                                brightness = 100 if state else 0
                                                self.cync_switches[device_id].update_switch(state, brightness)
                                        else:
                                            state = int(packet[4]) > 0
                                            brightness = int(packet[5]) if state else 0
                                            color_temp = int(packet[6])
                                            rgb = {'r': int(packet[7]), 'g': int(packet[8]), 'b': int(packet[9]), 'active': int(packet[6]) == 254}

                                            # Scale RGB values from 0-100 to 0-255
                                            rgb_scaled = {
                                                'r': int(rgb['r'] * 255 / 100),
                                                'g': int(rgb['g'] * 255 / 100),
                                                'b': int(rgb['b'] * 255 / 100),
                                                'active': rgb['active']
                                            }

                                            self.cync_switches[deviceID].update_switch(state, brightness, color_temp, rgb_scaled)
                                packet = packet[19:]
                        elif packet_type == 171:
                            switch_id = str(struct.unpack(">I", packet[0:4])[0])
                            home_id = self.switchID_to_homeID[switch_id]
                            self._add_connected_devices(switch_id, home_id)
                        elif packet_type == 123:
                            seq = str(struct.unpack(">H", packet[4:6])[0])
                            command_received = self.pending_commands.get(seq, None)
                            if command_received is not None:
                                command_received(seq)
                except Exception as e:
                    _LOGGER.error(f"{type(e).__name__}: {e}")
                data = data[packet_length + 5:]
        raise ShuttingDown

    async def _maintain_connection(self):
        while not self.shutting_down:
            await asyncio.sleep(180)
            self.writer.write(bytes.fromhex('d300000000'))
            await self.writer.drain()
        raise ShuttingDown

    def _add_connected_devices(self, switch_id, home_id):
        for dev in self.switchID_to_deviceIDs.get(switch_id, []):
            if dev not in self.connected_devices[home_id]:
                self.connected_devices[home_id].append(dev)
                if self.connected_devices_updated:
                    for dev in self.cync_switches.values():
                        dev.update_controllers()
                    for room in self.cync_rooms.values():
                        room.update_controllers()

    async def _update_connected_devices(self):
        while not self.shutting_down:
            self.connected_devices_updated = False
            for devices in self.connected_devices.values():
                devices.clear()
            while not self.logged_in:
                await asyncio.sleep(2)
            attempts = 0
            while any(len(devices) < len(self.home_controllers[home_id]) * 0.5 for home_id, devices in self.connected_devices.items()) and attempts < 10:
                for home_id, home_controllers in self.home_controllers.items():
                    for controller in home_controllers:
                        seq = self.get_seq_num()
                        ping = bytes.fromhex('a300000007') + int(controller).to_bytes(4, 'big') + seq.to_bytes(2, 'big') + bytes.fromhex('00')
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

    async def _update_state(self):
        while not self.connected_devices_updated:
            await asyncio.sleep(2)
        for connected_devices in self.connected_devices.values():
            if connected_devices:
                controller = self.cync_switches[connected_devices[0]].switch_id
                seq = self.get_seq_num()
                state_request = bytes.fromhex('7300000018') + int(controller).to_bytes(4, 'big') + seq.to_bytes(2, 'big') + bytes.fromhex('007e00000000f85206000000ffff0000567e')
                self.loop.call_soon_threadsafe(self.send_request, state_request)
        while any(self.cync_switches[dev_id]._update_callback is None for dev_id in self.options["switches"]) and any(self.cync_rooms[dev_id]._update_callback is None for dev_id in self.options["rooms"]):
            await asyncio.sleep(2)
        for dev in self.cync_switches.values():
            dev.publish_update()
        for room in self.cync_rooms.values():
            room.publish_update()

    def send_request(self, request):
        async def send():
            self.writer.write(request)
            await self.writer.drain()
        self.loop.create_task(send())

    def combo_control(self, state, brightness, color_tone, rgb, switch_id, mesh_id, seq):
        """Send combo control command to adjust state, brightness, color temperature, and RGB."""
        # Scale RGB values from 0-255 to 0-100
        rgb_scaled = tuple(int(x * 100 / 255) for x in rgb)
        rgb_values = rgb_scaled
        checksum = (496 + int(mesh_id[0]) + int(mesh_id[1]) + (1 if state else 0) + brightness + color_tone + sum(rgb_values)) % 256
        combo_request = (
            bytes.fromhex('7300000022') +
            int(switch_id).to_bytes(4, 'big') +
            int(seq).to_bytes(2, 'big') +
            bytes.fromhex('007e00000000f8f010000000000000') +
            mesh_id +
            bytes.fromhex('f00000') +
            (1 if state else 0).to_bytes(1, 'big') +
            brightness.to_bytes(1, 'big') +
            color_tone.to_bytes(1, 'big') +
            rgb_values[0].to_bytes(1, 'big') +
            rgb_values[1].to_bytes(1, 'big') +
            rgb_values[2].to_bytes(1, 'big') +
            checksum.to_bytes(1, 'big') +
            bytes.fromhex('7e')
        )
        self.loop.call_soon_threadsafe(self.send_request, combo_request)

    def turn_on(self, switch_id, mesh_id, seq):
        power_request = bytes.fromhex('730000001f') + int(switch_id).to_bytes(4, 'big') + int(seq).to_bytes(2, 'big') + \
            bytes.fromhex('007e00000000f8d00d000000000000') + mesh_id + bytes.fromhex('d00000010000') + \
            ((430 + int(mesh_id[0]) + int(mesh_id[1])) % 256).to_bytes(1, 'big') + bytes.fromhex('7e')
        self.loop.call_soon_threadsafe(self.send_request, power_request)

    def turn_off(self, switch_id, mesh_id, seq):
        power_request = bytes.fromhex('730000001f') + int(switch_id).to_bytes(4, 'big') + int(seq).to_bytes(2, 'big') + \
            bytes.fromhex('007e00000000f8d00d000000000000') + mesh_id + bytes.fromhex('d00000000000') + \
            ((429 + int(mesh_id[0]) + int(mesh_id[1])) % 256).to_bytes(1, 'big') + bytes.fromhex('7e')
        self.loop.call_soon_threadsafe(self.send_request, power_request)

    def set_color_temp(self, color_temp, switch_id, mesh_id, seq):
        color_temp_request = bytes.fromhex('730000001e') + int(switch_id).to_bytes(4, 'big') + int(seq).to_bytes(2, 'big') + \
            bytes.fromhex('007e00000000f8e20c000000000000') + mesh_id + bytes.fromhex('e2000005') + \
            color_temp.to_bytes(1, 'big') + ((469 + int(mesh_id[0]) + int(mesh_id[1]) + color_temp) % 256).to_bytes(1, 'big') + bytes.fromhex('7e')
        self.loop.call_soon_threadsafe(self.send_request, color_temp_request)

    def set_effect(self, effect_name, switch_id, mesh_id, seq):
        """Set the effect on the device."""
        effect = self.effect_mapping.get(effect_name)
        if effect is None:
            _LOGGER.error(f"Effect '{effect_name}' not found.")
            return

        effect_index = effect['index']
        # Construct the command to start the light show
        effect_request = bytes.fromhex('7300000020') + int(switch_id).to_bytes(4, 'big') + int(seq).to_bytes(2, 'big') + \
            bytes.fromhex('007e00000000f8e80e000000000000') + mesh_id + bytes.fromhex('e8000002') + \
            effect_index.to_bytes(1, 'big') + ((480 + int(mesh_id[0]) + int(mesh_id[1]) + effect_index) % 256).to_bytes(1, 'big') + bytes.fromhex('7e')
        self.loop.call_soon_threadsafe(self.send_request, effect_request)

    def set_flash(self, flash, switch_id, mesh_id, seq):
        """Set the flash effect on the device."""
        # Implement flash by toggling the light on and off
        async def flash_effect():
            self.turn_on(switch_id, mesh_id, seq)
            await asyncio.sleep(0.5)
            self.turn_off(switch_id, mesh_id, seq)
            await asyncio.sleep(0.5)
            self.turn_on(switch_id, mesh_id, seq)
        self.loop.create_task(flash_effect())

    def set_transition(self, transition, switch_id, mesh_id, seq):
        """Set the transition duration on the device."""
        # Placeholder implementation; actual command structure may vary
        fade_duration = int(transition * 1000)  # Convert to milliseconds
        fade_request = bytes.fromhex('7300000022') + int(switch_id).to_bytes(4, 'big') + int(seq).to_bytes(2, 'big') + \
            bytes.fromhex('007e00000000f8f010000000000000') + mesh_id + bytes.fromhex('f00000') + \
            fade_duration.to_bytes(2, 'big') + ((496 + int(mesh_id[0]) + int(mesh_id[1]) + fade_duration) % 256).to_bytes(1, 'big') + bytes.fromhex('7e')
        self.loop.call_soon_threadsafe(self.send_request, fade_request)

    def get_seq_num(self):
        if self._seq_num == 65535:
            self._seq_num = 1
        else:
            self._seq_num += 1
        return self._seq_num


class CyncRoom:

    def __init__(self, room_id, room_info, hub) -> None:
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
        self.default_controller = room_info.get(
            'room_controller',
            self.hub.home_controllers[self.home_id][0]
        )
        self._update_callback: Optional[Callable[[], None]] = None
        self._update_parent_room: Optional[Callable[[], None]] = None
        self.support_brightness = room_info.get('BRIGHTNESS', False)
        self.support_color_temp = room_info.get('COLORTEMP', False)
        self.support_rgb = room_info.get('RGB', False)
        self.groups_support_brightness: List[str] = []
        self.groups_support_color_temp: List[str] = []
        self.groups_support_rgb: List[str] = []
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def initialize(self):
        """Initialization of supported features and registration of update function for all switches and subgroups in the room"""
        self.switches_support_brightness = [device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_brightness]
        self.switches_support_color_temp = [device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_color_temp]
        self.switches_support_rgb = [device_id for device_id in self.switches if self.hub.cync_switches[device_id].support_rgb]
        self.groups_support_brightness = [room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_brightness]
        self.groups_support_color_temp = [room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_color_temp]
        self.groups_support_rgb = [room_id for room_id in self.subgroups if self.hub.cync_rooms[room_id].support_rgb]
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

    def register(self, update_callback, hass) -> None:
        """Register callback, called when switch changes state."""
        self._update_callback = update_callback
        self._hass = hass

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def register_room_updater(self, parent_updater):
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
        rgb_color: Optional[Tuple[int, int, int]] = None,
        brightness: Optional[int] = None,
        color_temp_kelvin: Optional[int] = None,
        effect: Optional[str] = None,
        flash: Optional[str] = None,
        transition: Optional[float] = None
    ) -> None:
        """Turn on the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = str(self.hub.get_seq_num())
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

            # Handle brightness
            if brightness is not None:
                brightness_percent = round(brightness * 100 / 255)
            else:
                brightness_percent = self.brightness if self.brightness else 100  # Default to 100% if no brightness is set

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
                color_temp = 254  # Default value indicating no color temperature adjustment

            # Handle RGB
            if rgb_color is not None:
                rgb_values = tuple(int(x) for x in rgb_color)
            else:
                rgb_values = (0, 0, 0)  # Default RGB values

            # Always use combo_control to turn on the light
            self.hub.combo_control(True, brightness_percent, color_temp, rgb_values, controller, self.mesh_id, seq)

            # Handle effects, flash, and transition if supported
            if effect:
                self.hub.set_effect(effect, controller, self.mesh_id, seq)
            if flash:
                self.hub.set_flash(flash, controller, self.mesh_id, seq)
            if transition:
                self.hub.set_transition(transition, controller, self.mesh_id, seq)

            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    async def turn_off(
        self,
        flash: Optional[str] = None,
        transition: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        """Turn off the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = str(self.hub.get_seq_num())
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

            self.hub.turn_off(controller, self.mesh_id, seq)

            # Handle flash and transition if supported
            if flash:
                self.hub.set_flash(flash, controller, self.mesh_id, seq)
            if transition:
                self.hub.set_transition(transition, controller, self.mesh_id, seq)

            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq, None) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    def command_received(self, seq):
        """Remove command from hub.pending_commands when a reply is received from Cync server"""
        self.hub.pending_commands.pop(seq, None)

    def update_room(self):
        """Update the current state of the room"""
        _brightness = self.brightness
        _color_temp = self.color_temp_kelvin
        _rgb = self.rgb
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
            _brightness = round(total_brightness / (len(self.switches) + len(self.subgroups)))
        else:
            _brightness = 100 if _power_state else 0
        if self.support_color_temp:
            total_color_temp = sum(
                self.hub.cync_switches[device_id].color_temp_kelvin for device_id in self.switches_support_color_temp
            ) + sum(
                self.hub.cync_rooms[room_id].color_temp_kelvin for room_id in self.groups_support_color_temp
            )
            _color_temp = round(
                total_color_temp / (len(self.switches_support_color_temp) + len(self.groups_support_color_temp))
            )
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
            _rgb['r'] = round(total_r / count)
            _rgb['g'] = round(total_g / count)
            _rgb['b'] = round(total_b / count)
            _rgb['active'] = any(
                self.hub.cync_switches[device_id].rgb['active'] for device_id in self.switches_support_rgb
            ) or any(
                self.hub.cync_rooms[room_id].rgb['active'] for room_id in self.groups_support_rgb
            )

        if (_power_state != self.power_state or _brightness != self.brightness or
                _color_temp != self.color_temp_kelvin or _rgb != self.rgb):
            self.power_state = _power_state
            self.brightness = _brightness
            self.color_temp_kelvin = _color_temp
            self.rgb = _rgb
            self.publish_update()
            if self._update_callback:
                self._hass.add_job(self._update_callback)
            if self._update_parent_room:
                self._hass.add_job(self._update_parent_room)

    def publish_update(self):
        if self._update_callback:
            self._hass.add_job(self._update_callback)

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices"""
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


class CyncSwitch:

    def __init__(self, device_id, switch_info, room, hub):
        self.hub = hub
        self.device_id = device_id
        self.switch_id = switch_info.get('switch_id', '0')
        self.home_id = [home_id for home_id, home_devices in self.hub.home_devices.items() if self.device_id in home_devices][0]
        self.name = switch_info.get('name', 'unknown')
        self.home_name = switch_info.get('home_name', 'unknown')
        self.mesh_id = switch_info.get('mesh_id', 0).to_bytes(2, 'little')
        self.room = room
        self.power_state = False
        self.brightness = 0
        self.color_temp_kelvin = 0
        self.rgb = {'r': 0, 'g': 0, 'b': 0, 'active': False}
        self.default_controller = switch_info.get('switch_controller', self.hub.home_controllers[self.home_id][0])
        self.controllers: List[str] = []
        self._update_callback: Optional[Callable[[], None]] = None
        self._update_parent_room: Optional[Callable[[], None]] = None
        self.support_brightness = switch_info.get('BRIGHTNESS', False)
        self.support_color_temp = switch_info.get('COLORTEMP', False)
        self.support_rgb = switch_info.get('RGB', False)
        self.plug = switch_info.get('PLUG', False)
        self.fan = switch_info.get('FAN', False)
        self.elements = switch_info.get('MULTIELEMENT', 1)
        self._command_timeout = 0.5
        self._command_retry_time = 5

    def register(self, update_callback, hass) -> None:
        """Register callback, called when switch changes state."""
        self._update_callback = update_callback
        self._hass = hass

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None
        self._hass = None

    def register_room_updater(self, parent_updater):
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
        rgb_color: Optional[Tuple[int, int, int]] = None,
        brightness: Optional[int] = None,
        color_temp_kelvin: Optional[int] = None,
        effect: Optional[str] = None,
        flash: Optional[str] = None,
        transition: Optional[float] = None
    ) -> None:
        """Turn on the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = str(self.hub.get_seq_num())
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

            # Handle brightness
            if brightness is not None:
                brightness_percent = round(brightness * 100 / 255)
            else:
                brightness_percent = self.brightness if self.brightness else 100  # Default to 100% if no brightness is set

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
                color_temp = 254  # Default value indicating no color temperature adjustment

            # Handle RGB
            if rgb_color is not None:
                rgb_values = tuple(int(x) for x in rgb_color)
            else:
                rgb_values = (0, 0, 0)  # Default RGB values

            # Use combo_control to turn on the light
            self.hub.combo_control(True, brightness_percent, color_temp, rgb_values, controller, self.mesh_id, seq)

            # Handle effects, flash, and transition if supported
            if effect:
                self.hub.set_effect(effect, controller, self.mesh_id, seq)
            if flash:
                self.hub.set_flash(flash, controller, self.mesh_id, seq)
            if transition:
                self.hub.set_transition(transition, controller, self.mesh_id, seq)

            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    async def turn_off(
        self,
        flash: Optional[str] = None,
        transition: Optional[float] = None,
        **kwargs: Any
    ) -> None:
        """Turn off the light."""
        attempts = 0
        update_received = False
        while not update_received and attempts < int(self._command_retry_time / self._command_timeout):
            seq = str(self.hub.get_seq_num())
            controller = self.controllers[attempts % len(self.controllers)] if self.controllers else self.default_controller

            self.hub.turn_off(controller, self.mesh_id, seq)

            # Handle flash and transition if supported
            if flash:
                self.hub.set_flash(flash, controller, self.mesh_id, seq)
            if transition:
                self.hub.set_transition(transition, controller, self.mesh_id, seq)

            self.hub.pending_commands[seq] = self.command_received
            await asyncio.sleep(self._command_timeout)
            if self.hub.pending_commands.get(seq, None) is not None:
                self.hub.pending_commands.pop(seq)
                attempts += 1
            else:
                update_received = True

    def command_received(self, seq):
        """Remove command from hub.pending_commands when a reply is received from Cync server"""
        self.hub.pending_commands.pop(seq, None)

    def update_switch(self, state, brightness, color_temp=None, rgb=None):
        """Update the state of the switch as updates are received from the Cync server."""
        self.update_received = True

        if color_temp is not None:
            # Calculate color_temp_kelvin from color_temp percentage
            color_temp_kelvin = round(
                (self.max_color_temp_kelvin - self.min_color_temp_kelvin) *
                (color_temp / 100) +
                self.min_color_temp_kelvin
            )
        else:
            color_temp_kelvin = self.color_temp_kelvin

        if rgb is not None:
            rgb_scaled = rgb  # RGB is already scaled in the packet parsing
        else:
            rgb_scaled = self.rgb

        if (self.power_state != state or
                self.brightness != brightness or
                self.color_temp_kelvin != color_temp_kelvin or
                self.rgb != rgb_scaled):
            self.power_state = state
            self.brightness = brightness if self.support_brightness and state else 100 if state else 0
            self.color_temp_kelvin = color_temp_kelvin
            self.rgb = rgb_scaled
            self.publish_update()
            if self._update_callback:
                self._hass.add_job(self._update_callback)
            if self._update_parent_room:
                self._hass.add_job(self._update_parent_room)

    def update_controllers(self):
        """Update the list of responsive, Wi-Fi connected controller devices"""
        connected_devices = self.hub.connected_devices[self.home_id]
        controllers = []
        if connected_devices:
            if int(self.switch_id) > 0 and self.device_id in connected_devices:
                controllers.append(self.switch_id)
            if self.room:
                controllers.extend(
                    self.hub.cync_switches[device_id].switch_id
                    for device_id in self.room.all_room_switches
                    if device_id in connected_devices and device_id != self.device_id
                )
            others_available = [
                self.hub.cync_switches[device_id].switch_id
                for device_id in connected_devices
                if self.hub.cync_switches[device_id].switch_id not in controllers
            ]
            self.controllers = controllers + others_available
        else:
            self.controllers = [self.default_controller]

    def publish_update(self):
        if self._update_callback:
            self._hass.add_job(self._update_callback)


class CyncMotionSensor:

    def __init__(self, device_id, device_info, room):

        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.motion = False
        self._update_callback = None
        self._hass = None

    def register(self, update_callback, hass) -> None:
        """Register callback, called when sensor changes state."""
        self._update_callback = update_callback
        self._hass = hass

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def update_motion_sensor(self, motion):
        self.motion = motion
        self.publish_update()

    def publish_update(self):
        if self._update_callback:
            self._hass.add_job(self._update_callback)


class CyncAmbientLightSensor:

    def __init__(self, device_id, device_info, room):

        self.device_id = device_id
        self.name = device_info['name']
        self.home_name = device_info['home_name']
        self.room = room
        self.ambient_light = False
        self._update_callback = None
        self._hass = None

    def register(self, update_callback, hass) -> None:
        """Register callback, called when sensor changes state."""
        self._update_callback = update_callback
        self._hass = hass

    def reset(self) -> None:
        """Remove previously registered callback."""
        self._update_callback = None

    def update_ambient_light_sensor(self, ambient_light):
        self.ambient_light = ambient_light
        self.publish_update()

    def publish_update(self):
        if self._update_callback:
            self._hass.add_job(self._update_callback)


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


class LostConnection(Exception):
    """Lost connection to Cync Server"""


class ShuttingDown(Exception):
    """Cync client shutting down"""


class InvalidCyncConfiguration(Exception):
    """Cync configuration is not supported"""
