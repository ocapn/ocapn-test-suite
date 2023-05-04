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
import socket
import time

from contrib import syrup

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
            raise Exception("Socket closed")
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
    def send_message(self, message):
        """ Send data to the remote machine """        
        encoded_message = syrup.syrup_encode(message)
        self.sendall(encoded_message)

    def receive_message(self, timeout=60):
        """ Receive data from the remote machine """
        socketio = ReadSocketIO(self, timeout=timeout)
        return syrup.syrup_read(socketio)