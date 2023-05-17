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

from typing import Tuple

from contrib import syrup
from netlayers.base import CapTPSocket, Netlayer

import stem.process
from utils.ocapn_uris import OCapNMachine


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
    
    def _error_number_to_string(self, error_number) -> str | None:
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
        elif error_number == b"\x06":
            return "TTL expired"
        elif error_number == b"\x07":
            return "Command not supported"
        elif error_number == b"\x08":
            return "Address type not supported"
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

class OnionNetlayer(Netlayer):
    PORT = 9045

    def __init__(self):
        self._connections = []

        # Create a temp directory for us to use for tor
        self._temp_dir = tempfile.TemporaryDirectory()
        self._unix_socket_path = os.path.join(self._temp_dir.name, "tor.sock")
        control_socket_path = os.path.join(self._temp_dir.name, "control.sock")
        data_dir_path = os.path.join(self._temp_dir.name, "data")

        # Start a Tor process
        self._tor_process = stem.process.launch_tor_with_config(
            config = {
                "SocksPort": f"unix:{self._unix_socket_path}",
                "ControlPort": f"unix:{control_socket_path}",
                "DataDirectory": data_dir_path,
            }
        )

        # We have to setup a hidden service for them to connect to us
        self._control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._control_socket.connect(control_socket_path)
        self._incoming_control_socket, self.location = self._add_hidden_service()
    
    def __del__(self):
        self.shutdown()
    
    def connect(self, ocapn_machine: OCapNMachine) -> CapTPSocket:
        """ Connect to the remote machine """
        # Finally setup a socket and connect to the CapTP server
        hidden_service_uri = f"{ocapn_machine.address}.onion"
        onion_sock = Socks5Proxy(self._unix_socket_path)
        onion_sock.connect(hidden_service_uri, self.PORT)

        connection = CapTPSocket.from_socket(onion_sock)
        self._connections.append(connection)
        return connection
        
    def accept(self) -> CapTPSocket:
        """ Blocks until a CapTP connection is received, returning the socket """
        sock, addr = self._incoming_control_socket.accept()
        connection = CapTPSocket.from_socket(sock)
        self._connections.append(connection)
        return connection

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

    def _add_hidden_service(self) -> Tuple[CapTPSocket, OCapNMachine]:
        """ Add a hidden service to the Tor process """
        if self._control_socket is None:
            raise Exception("Cannot add a hidden service after the control socket has been closed")

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
        incoming_control_socket = CapTPSocket(
            socket.AF_UNIX, socket.SOCK_DGRAM
        )
        incoming_control_socket.bind(ocapn_sock_path)

        # Create the OCapNMachine that represents this hidden service
        ocapn_machine = OCapNMachine(syrup.Symbol("onion"), service_id, False)

        return incoming_control_socket, ocapn_machine
    
    def shutdown(self):
        """ Shuts down the netlayer """
        for connection in self._connections:
            connection.close()

        # These attributes are setup in the __init__ method, so should always exist
        # however there are situations where an error occurs before they are set
        if getattr(self, "_tor_process", None) is not None:
            self._tor_process.kill()
            self._tor_process = None

        if getattr(self, "_control_socket", None) is not None:
            self._control_socket.close()
            self._control_socket = None
        
        if getattr(self, "_incoming_control_socket", None) is not None:
            self._temp_dir.cleanup()
