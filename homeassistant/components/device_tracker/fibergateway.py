"""
Support for MEO FiberGateway routers.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.thomson/
"""
import logging
import re
import telnetlib

import voluptuous as vol

import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME

# DOMAIN = 'fibergateway'
_LOGGER = logging.getLogger(__name__)

_DEVICES_REGEX = re.compile(
    # r'(^\|)(?P<hostname>.+?)(\s+)(\|)'
    r'(^\|)(?!DHCP|Hostname)(?P<hostname>.+?)(\s+)(\|)'
    r'(?P<mac>(([0-9a-f]{2}[:-]){5}([0-9a-f]{2})))\s+(\|)'
    r'(?P<ip>([0-9]{1,3}[\.]){3}[0-9]{1,3})\s+(\|)'
    r'(?P<expires>(.+?))\s+(\|)'
    r'(?P<port>(.+?))\s+(\|)'
    r'(?P<flags>(TRUE|FALSE))\s+(\|)'
    r'(?P<type>(.+?))\s+(\|)'
)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})


# pylint: disable=unused-argument
def get_scanner(hass, config):
    """Validate the configuration and return a THOMSON scanner."""
    scanner = MeoFiberGatewayDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


class MeoFiberGatewayDeviceScanner(DeviceScanner):
    """This class queries a router running THOMSON firmware."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.host = config[CONF_HOST]
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]
        self.last_results = {}

        # Test the router is accessible.
        data = self.get_fibergateway_data()
        self.success_init = data is not None

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [client['mac'] for client in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        if not self.last_results:
            return None
        for client in self.last_results:
            if client['mac'] == device:
                print('######################')
                print(client['host'])
                print('######################')
                return client['host']
        return None

    def _update_info(self):
        """Ensure the information from the THOMSON router is up to date.

        Return boolean if scanning successful.
        """
        if not self.success_init:
            return False

        _LOGGER.info("Checking ARP")
        data = self.get_fibergateway_data()
        if not data:
            return False

        # Flag C stands for CONNECTED
        active_clients = [client for client in data.values() if
                          client['status'].find('TRUE') != -1]
        self.last_results = active_clients
        return True

    def get_fibergateway_data(self):
        """Retrieve data from MEO FiberGateway and return parsed result."""
        try:
            telnet = telnetlib.Telnet(self.host)
            telnet.set_debuglevel(15)
            telnet.read_until(b'Login: ')
            telnet.write(('meo' + '\r\n').encode('ascii'))
            telnet.read_until(b'Password:')
            telnet.write(('meo' + '\r\n').encode('ascii'))
            telnet.read_until(b'/cli> ')
            telnet.write(('lan/dhcp/show\r\n').encode('ascii'))
            devices_result = telnet.read_until(b'/cli> ').split(b'\r\n')
            telnet.write('exit\r\n'.encode('ascii'))
        except EOFError:
            _LOGGER.exception("Unexpected response from router")
            return
        except ConnectionRefusedError:
            _LOGGER.exception(
                "Connection refused by router. Telnet enabled?")
            return

        devices = {}
        for device in devices_result:
            match = _DEVICES_REGEX.search(device.decode('utf-8'))
            if match:
                devices[match.group('hostname')] = {
                    'host': match.group('hostname'),
                    'mac': match.group('mac').upper(),
                    'ip': match.group('ip'),
                    'expires': match.group('expires'),
                    'port': match.group('port'),
                    'status': match.group('flags'),
                    'type': match.group('type')
                    }
        return devices
