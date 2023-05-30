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

from contrib.syrup import Symbol, Record


class OCapNMachine:
    """ <ocapn-machine transport address hints> """

    def __init__(self, transport: Symbol, address: str, hints: bool):
        self.transport = transport
        self.address = address
        self.hints = hints

    @classmethod
    def from_uri(cls, uri: str):
        """ Converts from the URI fromat ocapn://<address>.<transport> """
        assert uri.startswith("ocapn://")
        uri = uri[8:]
        address, transport = uri.rsplit(".", 1)
        return cls(Symbol(transport), address, False)

    @classmethod
    def from_syrup(cls, record: Record):
        assert record.label == Symbol("ocapn-machine")
        assert len(record.args) == 3
        # TODO: probably want to support hints at a later date
        assert record.args[2] is False, "hints not supported"

        return cls(*record.args)

    def to_syrup(self) -> Record:
        return Record(
            Symbol("ocapn-machine"),
            [self.transport, self.address, self.hints]
        )
