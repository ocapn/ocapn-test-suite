## Copyright 2023 Jessica Tallon
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.

import tempfile
import sys
import socket
import os

from contrib import syrup
from netlayers.base import CapTPSocket

import stem.process


class Socks5Proxy(CapTPSocket):
    """ Basic implementation of a SOCKS5 proxy (RFC 1928) using unix sockets """

    def __init__(self, unix_socket_path):
        self._unix_socket_path = unix_socket_path
        super().__init__(socket.AF_UNIX, socket.SOCK_STREAM)
    
    def __del__(self):
        self.close()
        super().__del__()

    def _read_and_expect_protocol5(self):
        """ Read the initial protocol version and expect it to be 5 """
        protocol_version = self.recv(1)
        if protocol_version != b"\x05":
            raise Exception(f"Wrong protocol version: {protocol_version}")

    def _read_and_expect_no_auth(self):
        """ Read the authentication method and expect it to be no auth """
        auth_method = self.recv(1)
        if auth_method != b"\x00":
            raise Exception(f"Unsupported authentication method: {auth_method}")
    
    def _error_number_to_string(self, error_number) -> str:
        if error_number == b"\x00":
            return None
        elif error_number == b"\x01":
            return "General SOCKS server failure"
        elif error_number == b"\x02":
            return "Connection not allowed by ruleset"
        elif error_number == b"\x03":
            return "Network unreachable"
        elif error_number == b"\x04":
            return "Host unreachable"
        elif error_number == b"\x05":
            return "Connection refused"
        return f"Unknown error {error_number}"

    def connect(self, address, port) -> None:
        """ Connect to a remote address """
        super().connect(self._unix_socket_path)

        # Protocol version 5, mmethod 1, no auth
        self.sendall(b"\x05\x01\x00")
        self._read_and_expect_protocol5()
        self._read_and_expect_no_auth()

        # Connect to the remote address
        # Protocol version 5, command 1, reserved 0, RDNS 3
        self.sendall(b"\x05\x01\x00\x03")
        # Tor V3 onion addresses are always 62 characters long
        if len(address) != 62:
            raise Exception("Invalid tor onion V3 address: {address}")
        self.sendall(b"\x3e")
        self.sendall(address.encode("ascii"))
        self.sendall(port.to_bytes(2, "big"))
        self._read_and_expect_protocol5()

        # Read the result and check for errors
        possible_error = self._error_number_to_string(self.recv(1))
        if possible_error is not None:
            raise Exception(f"Error connecting to remote address: {possible_error}")
        # Reserved byte
        self.recv(1)
        # Address type
        address_type = self.recv(1)
        if address_type == b"\x01":
            # IPv4 address
            self.recv(4)
        elif address_type == b"\x03":
            # Domain name
            self.recv(self.recv(1)[0])
        elif address_type == b"\x04":
            # IPv6 address
            self.recv(16)
        else:
            raise Exception(f"Unknown address type: {address_type}")
        # Finally, read the port
        self.recv(2)

class OnionNetlayer:
    PORT = 9045

    def __init__(self, locator):
        self._locator = locator
        self._tor_process = None
        self._socket = None
        self._control_socket = None
        self._incoming_control_socket = None
        self._temp_dir = None
        self.service_id = None
        self.private_key = None
    
    def __del__(self):
        self.close()
    
    def connect(self):
        """ Connect to the remote machine """        
        # Create a temp directory for us to use for tor
        self._temp_dir = tempfile.TemporaryDirectory()
        unix_socket_path = os.path.join(self._temp_dir.name, "tor.sock")
        control_socket_path = os.path.join(self._temp_dir.name, "control.sock")
        data_dir_path = os.path.join(self._temp_dir.name, "data")

        # Start a Tor process
        self._tor_process = stem.process.launch_tor_with_config(
            config = {
                "SocksPort": f"unix:{unix_socket_path}",
                "ControlPort": f"unix:{control_socket_path}",
                "DataDirectory": data_dir_path,
            }
        )

        # Finally setup a socket and connect to the CapTP server
        hidden_service_uri = f"{self._locator.address}.onion"
        self._socket = Socks5Proxy(unix_socket_path)
        self._socket.connect(hidden_service_uri, self.PORT)

        # We have to setup a hidden service for them to connect to us
        self._control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._control_socket.connect(control_socket_path)
        self.service_id, self.private_key = self._add_hidden_service()
        
    def accept_incoming_captp_connection(self, timeout):
        """ Blocks until a CapTP connection is received, returning the socket """
        self._incoming_control_socket.settimeout(timeout)
        return self._incoming_control_socket.accept()

    @property
    def location(self) -> syrup.Record:
        """ Return the location of the remote machine """
        return syrup.Record(
            syrup.Symbol("ocapn-machine"),
            (syrup.Symbol("onion"), self.service_id, False),
        )

    def _read_and_expect(self, socket, expected):
        """ Read from a socket and expect a specific value """
        data = socket.recv(len(expected))
        if data != expected:
            raise Exception(f"Unexpected response from socket. Read {data}, but expected: {expected}")
    
    def _read_until_newline(self, socket) -> bytes:
        """ Read from a socket until we get a newline """
        data = bytearray()
        while True:
            data += socket.recv(1)
            if data[-1] == ord("\n"):
                return data

    def _add_hidden_service(self):
        """ Add a hidden service to the Tor process """
        # Authenticate with the control socket
        self._control_socket.sendall(b"AUTHENTICATE\r\n")
        self._read_and_expect(self._control_socket, b"250 OK\r\n")


        ocapn_sock_path = os.path.join(self._temp_dir.name, "ocapn.sock")
        self._control_socket.sendall(
            f"ADD_ONION NEW:ED25519-V3 PORT={self.PORT},unix:{ocapn_sock_path}\r\n"
            .encode("ascii")
        )

        # Read the ServiceID
        service_id = self._read_until_newline(self._control_socket).decode("ascii")
        if not service_id.startswith("250-ServiceID="):
            raise Exception(f"Unexpected response from socket: {service_id}")
        service_id = service_id[14:].strip()

        # Read the PrivateKey
        private_key = self._read_until_newline(self._control_socket).decode("ascii")
        if not private_key.startswith("250-PrivateKey="):
            raise Exception(f"Unexpected response from socket: {private_key}")
        private_key = private_key[15:].strip()

        # Setup a socket to listen for incoming connections
        self._incoming_control_socket = CapTPSocket(
            socket.AF_UNIX, socket.SOCK_DGRAM
        )
        self._incoming_control_socket.bind(ocapn_sock_path)

        return service_id, private_key
    
    def close(self):
        """ Close the connection to the remote machine """
        service_id = None
        private_key = None

        if self._socket is not None:
            self._socket.close()
            self._socket = None
        
        if self._control_socket is not None:
            self._control_socket.close()
            self._control_socket = None
        
        if self._tor_process is not None:
            self._tor_process.kill()
            self._tor_process = None
        
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
    
    def send_message(self, message):
        """ Send a message to the remote machine """
        if self._socket is None:
            raise Exception("Not connected to remote machine")

        self._socket.send_message(message)
    
    def receive_message(self, *args, **kwargs):
        """ Receive a message from the remote machine """
        if self._socket is None:
            raise Exception("Not connected to remote machine")

        return self._socket.receive_message(*args, **kwargs)