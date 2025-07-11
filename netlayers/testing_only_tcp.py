# Copyright 2023 Jessica Tallon
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import uuid
import socket
from urllib.parse import urlparse, urlunparse

from contrib import syrup
from netlayers.base import CapTPSocket, Netlayer

from utils.ocapn_uris import OCapNPeer
from utils.captp import CapTPSession

class TestingOnlyTCPNetlayer(Netlayer):
    """
    THIS NETLAYER IS _NOT_ SAFE. DO NOT USE IN PRODUCTION

    This netlayer has been designed with simplicity to implement as
    its primary goal. This netlayer has no security, privacy
    protections, nor forgery protection. It should not be used outside
    of testing.
    """

    def __init__(self,
                 listen_address="127.0.0.1",
                 # Ask for one to be assigned to us
                 listen_port=0,
                 listen_queue_size=100):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.bind((listen_address, listen_port))
        self.server_sock.listen(listen_queue_size)

        # refreshing both
        (listen_address, listen_port) = self.server_sock.getsockname()
        self._connections = []

        self.address, self.port = listen_address, listen_port
        self.location = OCapNPeer(
            syrup.Symbol("tcp-testing-only"),
            # This should be unique to the peer, in most netlayers it'd be
            # authenticated so a key would work well here. In testing we don't
            # care, just some unique string will do.
            uuid.uuid4().hex,
            {"port": str(listen_port),
             "host": listen_address}
        )

    def __del__(self):
        self.shutdown()

    def connect(self, ocapn_peer: OCapNPeer) -> CapTPSession:
        """ Connect to the remote peer """

        loc_socket = socket.socket()
        loc_socket.connect((ocapn_peer.hints["host"], int(ocapn_peer.hints["port"])))

        connection = CapTPSocket.from_socket(loc_socket)
        self._connections.append(connection)

        # FIXME! needs a proper-ish address
        return CapTPSession(connection, self.location, True)

    def accept(self, timeout=5) -> CapTPSession:
        """ Blocks until a CapTP connection is received, returning the socket """

        self.server_sock.settimeout(timeout)
        sock, addr = self.server_sock.accept()

        connection = CapTPSocket.from_socket(sock)
        self._connections.append(connection)

        return CapTPSession(connection, self.location,  False)

    def shutdown(self):
        """ Shuts down the netlayer """
        self.server_sock.close()
        for connection in self._connections:
            connection.close()
