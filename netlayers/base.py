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
from abc import ABC, abstractmethod
import socket

from contrib import syrup
from utils.captp_types import CapTPType, decode_captp_message
from utils.ocapn_uris import OCapNNode
from utils.captp import CapTPSession


class ReadSocketIO:
    """ Wrapper around a socket which allows us to read from it like a file """

    def __init__(self, socket, timeout=None):
        self._socket = socket
        self._buffer = bytearray()
        self._seek_position = 0
        if timeout is not None:
            self._socket.settimeout(timeout)

    def read(self, size):
        """ Read up to `size` bytes from the socket """
        amount_read_ahead = len(self._buffer) - self._seek_position
        if amount_read_ahead >= size:
            # We have enough data in the buffer, just return it
            data = self._buffer[self._seek_position:self._seek_position+size]
            self._seek_position += size
            return data

        # We need to read more data from the socket
        data = self._socket.recv(size - amount_read_ahead)
        if len(data) == 0:
            raise ConnectionAbortedError("Socket closed")
        self._buffer += data
        self._seek_position += len(data)
        return data

    def seek(self, position):
        """ Seek to a position in the buffer """
        if position < 0:
            raise Exception("Cannot seek to negative position")

        # We could allow for seeking forward, but we don't need it
        if position > self._seek_position:
            raise Exception("Cannot seek forward")

        self._seek_position = position

    def tell(self):
        """ Return the current position in the buffer """
        return self._seek_position


class CapTPSocket(socket.socket):

    def __del__(self):
        self.close()

    @classmethod
    def from_socket(cls, socket):
        """ Creates a CapTPSocket from a socket

        Important: This will detach the socket from the original socket object,
        do not continue to use the original socket object after calling this.
        """
        captp_socket = cls(fileno=socket.fileno())
        captp_socket.settimeout(socket.gettimeout())
        socket.detach()
        return captp_socket

    def send_message(self, message):
        """ Send data to the remote node """
        if isinstance(message, CapTPType):
            message = message.to_syrup()
        self.sendall(message)

    def receive_message(self, timeout=120) -> CapTPType:
        """ Receive data from the remote node """
        socketio = ReadSocketIO(self, timeout=timeout)
        encoded_message = syrup.syrup_read(socketio)
        assert isinstance(encoded_message, syrup.Record)
        return decode_captp_message(encoded_message)


class Netlayer(ABC):
    """ Base class for all netlayers """

    location: OCapNNode

    @abstractmethod
    def connect(self, ocapn_node: OCapNNode) -> CapTPSession:
        """ Connect to a remote node returning a connection """
        pass

    @abstractmethod
    def accept(self) -> CapTPSession:
        """ Accept a connection from a remote node returning a connection """
        pass
