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

import urllib.parse

from contrib.syrup import Symbol, Record, syrup_encode


class OCapNURI:

    def to_syrup_record(self):
        pass

    def to_syrup(self):
        return syrup_encode(self.to_syrup_record())


class OCapNNode(OCapNURI):
    """ <ocapn-node transport address hints> """

    def __init__(self, transport: Symbol, address: str, hints):
        self.transport = transport
        self.address = address
        self.hints = hints

    def __eq__(self, other):
        return isinstance(other, OCapNNode) and self.to_syrup() == other.to_syrup()

    @classmethod
    def from_uri(cls, uri: str):
        """ Converts from the URI fromat ocapn://<address>.<transport> """
        parsed = urllib.parse.urlparse(uri)
        assert parsed.scheme == "ocapn"
        hints = urllib.parse.parse_qsl(parsed.query, strict_parsing=True)
        designator, transport = parsed.netloc.rsplit(".", 1)
        return cls(Symbol(transport), designator, dict(hints))

    @classmethod
    def from_syrup_record(cls, record: Record):
        assert record.label == Symbol("ocapn-node")
        assert len(record.args) == 3
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("ocapn-node"),
            [self.transport, self.address, self.hints]
        )

    def to_uri(self) -> str:
        query = urllib.parse.urlencode(self.hints, doseq=True) if self.hints else ""
        return urllib.parse.urlunparse(("ocapn", self.address, "", "", query, ""))


class OCapNSturdyref(OCapNURI):
    """ <ocapn-sturdyref ocapn-node swiss-num> """

    def __init__(self, node, swiss_num):
        self.node = node
        self.swiss_num = swiss_num

    def __eq__(self, other):
        return isinstance(other, OCapNSturdyref) and self.to_syrup() == other.to_syrup()

    @classmethod
    def from_syrup_record(cls, record: Record):
        assert record.label == Symbol("ocapn-sturdyref")
        assert len(record.args) == 2
        node = OCapNNode.from_syrup_record(record.args[0])
        return cls(node, record.args[1])

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("ocapn-sturdyref"),
            [self.node.to_syrup_record(), self.swiss_num]
        )

    def to_uri(self):
        node_uri = self.node.to_uri()
        return f"{node_uri}/s/{self.swiss_num}"
