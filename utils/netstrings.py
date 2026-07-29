# Copyright 2026 Jessica Tallon
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
import io
from contrib.syrup import syrup_encode

class Netstring(bytes):

    @classmethod
    def read(cls, sock):
        """ Reads a netstring from the socket """
        # Read length until hitting the `:` character
        length_prefix = b""
        next_char = None
        while True:
            next_char = sock.read(1)
            if next_char == b":":
                break
            if next_char < b'0' or next_char > b'9':
                raise Exception("Expected ASCII digit when reading netstring length prefix.")
            length_prefix += next_char

        length = int(length_prefix)
        return cls(sock.read(length))
            
    def to_netstring(self):
        length = str(len(self))
        # Netstrings have their length encoded in ascii digits
        length_prefix = bytes([ord(char) for char in length])
        return length_prefix + b":" + self
