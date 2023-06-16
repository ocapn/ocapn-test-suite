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
from contrib import syrup
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from utils.ocapn_uris import OCapNMachine

from cryptography.hazmat.primitives import serialization


class CapTPPublicKey:
    """ Public key used within CapTP

    The Syrup encoded is based upon the gcrypt s-expression format and looks
    like this:

    (public-key (ecc (curve Ed25519) (flags eddsa) (q <pubkey data>))
    """
    def __init__(self, public_key: Ed25519PublicKey):
        self.public_key = public_key

    def __eq__(self, other):
        return isinstance(other, CapTPPublicKey) and \
            self.public_key.to_syrup() == other.public_key.to_syrup()

    def verify(self, *args, **kwargs):
        return self.public_key.verify(*args, **kwargs)

    @classmethod
    def from_private_key(cls, private_key):
        return cls(private_key.public_key())

    @classmethod
    def from_public_bytes(cls, *args, **kwargs):
        return cls(Ed25519PublicKey.from_public_bytes(*args, **kwargs))

    def public_bytes(self, *args, **kwargs):
        return self.public_key.public_bytes(*args, **kwargs)

    @classmethod
    def from_syrup_record(cls, data):
        assert data[0] == syrup.Symbol("public-key")
        assert data[1][0] == syrup.Symbol("ecc")
        assert data[1][1] == [syrup.Symbol("curve"), syrup.Symbol("Ed25519")]
        assert data[1][2] == [syrup.Symbol("flags"), syrup.Symbol("eddsa")]
        assert data[1][3][0] == syrup.Symbol("q")
        encoded_key = data[1][3][1]
        return cls.from_public_bytes(encoded_key)

    def to_syrup(self):
        return syrup.syrup_encode(self.to_syrup_record())

    def to_syrup_record(self):
        return [
            syrup.Symbol("public-key"),
            [
                syrup.Symbol("ecc"),
                [syrup.Symbol("curve"), syrup.Symbol("Ed25519")],
                [syrup.Symbol("flags"), syrup.Symbol("eddsa")],
                [syrup.Symbol("q"), self.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )]
            ]
        ]


class CapTPType(ABC):
    """ Base class for all CapTP types """

    @classmethod
    @abstractmethod
    def from_syrup_record(cls, record: syrup.Record):
        """ Converts from a syrup record """
        pass

    @abstractmethod
    def to_syrup_record(self) -> syrup.Record:
        """ Converts to a syrup record """
        pass

    def to_syrup(self) -> bytes:
        """ Converts to a syrup encoded byte string """
        return syrup.syrup_encode(self.to_syrup_record())

    def __repr__(self):
        record = self.to_syrup_record()
        type_name = str(record.label)
        return f"<{type_name} {record.args}>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CapTPType):
            return False
        return other.to_syrup_record() == self.to_syrup_record()


class DescImport(CapTPType, ABC):
    """ Either a DescImportObject or a DescImportPromise

    Not designed to be used directly.
    """

    def __init__(self, position: int):
        self.position = position

    def to_desc_export(self):
        """ Converts to desc:export """
        return DescExport(self.position)


class DescImportObject(DescImport):
    """ <desc:import-object position> """
    def __init__(self, position: int):
        super().__init__(position)

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:import-object")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("desc:import-object"),
            [self.position]
        )


class DescImportPromise(DescImport):
    """ <desc:import-promise position> """
    def __init__(self, position: int):
        super().__init__(position)

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:import-promise")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("desc:import-promise"),
            [self.position]
        )

    @property
    def as_export(self):
        """ Converts to desc:export """
        return DescExport(self.position)


class DescExport(CapTPType):
    """ <desc:export position> """

    def __init__(self, position: int):
        self.position = position

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:export")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("desc:export"),
            [self.position]
        )


class DescAnswer(CapTPType):
    """ <desc:answer position> """

    def __init__(self, position: int):
        self.position = position

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:answer")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("desc:answer"),
            [self.position]
        )


class DescSigEnvelope(CapTPType):
    """ <desc:sig-envelope data signature> """

    def __init__(self, object: CapTPType, signature: bytes):
        self.object = object
        self.signature = signature

    def verify(self, public_key: CapTPPublicKey) -> bool:
        """ Verifies the signature with the given public key """
        encoded_data = syrup.syrup_encode(self.object.to_syrup_record())
        try:
            public_key.verify(self.signature, encoded_data)
            return True
        except InvalidSignature:
            return False

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:sig-envelope")
        assert len(record.args) == 2

        signed_object = maybe_decode_captp_type(record.args[0])
        if not isinstance(signed_object, CapTPType):
            raise Exception(f"Expected a CapTPType, but got something else: {signed_object}")

        # Convert from the gcrypt s-expression format to bytes
        # (sig-val (eddsa (r ...) (s ...))
        encoded_signature = record.args[1]
        assert encoded_signature[0] == syrup.Symbol("sig-val")
        assert len(encoded_signature) == 2
        encoded_signature = encoded_signature[1]
        assert encoded_signature[0] == syrup.Symbol("eddsa")
        assert len(encoded_signature) == 3

        encoded_r = encoded_signature[1]
        assert encoded_r[0] == syrup.Symbol("r")
        r = encoded_r[1]

        encoded_s = encoded_signature[2]
        assert encoded_s[0] == syrup.Symbol("s")
        s = encoded_s[1]

        signature = r + s
        return cls(signed_object, signature)

    def to_syrup_record(self) -> syrup.Record:
        # The signature in CapTP is modelled after the gcrypt s-expression format
        r = self.signature[0:32]
        s = self.signature[32:]

        encoded_signature = [
            syrup.Symbol("sig-val"),
            [
                syrup.Symbol("eddsa"),
                [syrup.Symbol("r"), r],
                [syrup.Symbol("s"), s],
            ]
        ]

        return syrup.Record(
            syrup.Symbol("desc:sig-envelope"),
            [self.object.to_syrup_record(), encoded_signature]
        )


class DescHandoffGive(CapTPType):
    """
    <desc:handoff-give receiver-key
                       exporter-location
                       session
                       gifter-side
                       gift-id>
    """

    def __init__(self, receiver_key: CapTPPublicKey,
                 exporter_location: OCapNMachine, session: bytes,
                 gifter_side: CapTPPublicKey, gift_id: bytes):
        self.receiver_key = receiver_key
        self.exporter_location = exporter_location
        self.session = session
        self.gifter_side = gifter_side
        self.gift_id = gift_id

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:handoff-give")
        assert len(record.args) == 5

        receiver_key = CapTPPublicKey.from_syrup_record(record.args[0])
        exporter_location = OCapNMachine.from_syrup_record(record.args[1])

        return cls(receiver_key, exporter_location, *record.args[2:])

    def to_syrup_record(self) -> syrup.Record:
        # The receiver key is encoded in the gcrypt s-expression format
        return syrup.Record(
            syrup.Symbol("desc:handoff-give"),
            [
                self.receiver_key.to_syrup_record(),
                self.exporter_location.to_syrup_record(),
                self.session,
                self.gifter_side,
                self.gift_id
            ]
        )


class DescHandoffReceive(CapTPType):
    """
    <desc:handoff-receive receiving-session
                          receiving-side
                          handoff-count
                          signed-give>
    """
    def __init__(self, receiving_session: bytes, receiving_side: bytes,
                 handoff_count: int, signed_give: DescSigEnvelope):
        self.receiving_session = receiving_session
        # TODO: This needs fixing in the CapTP spec (important!)
        self.receiving_side = receiving_side
        self.handoff_count = handoff_count
        self.signed_give = signed_give

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("desc:handoff-receive")
        assert len(record.args) == 4

        signed_give = DescSigEnvelope.from_syrup_record(record.args[3])

        return cls(record.args[0], record.args[1], record.args[2], signed_give)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("desc:handoff-receive"),
            [
                self.receiving_session,
                self.receiving_side,
                self.handoff_count,
                self.signed_give.to_syrup_record()
            ]
        )


class OpStartSession(CapTPType):
    """ <op:start-session captp-version session-pubkey location location-sig> """
    def __init__(self, captp_version: str, session_pubkey: CapTPPublicKey,
                 location: OCapNMachine, location_sig: bytes):
        self.captp_version = captp_version
        self.session_pubkey = session_pubkey
        self.location = location
        self.location_sig = location_sig

    @property
    def valid(self) -> bool:
        """ Returns true if the location signature is valid """
        # The location is tagged in a special wrapper before signing.
        # This is to prevent the signature from being used in other contexts.
        tagged_location = syrup.Record(
            syrup.Symbol("my-location"),
            [self.location.to_syrup_record()]
        )
        # The signature is of the syrup representation of the tagged location
        encoded_location = syrup.syrup_encode(tagged_location)
        try:
            self.session_pubkey.verify(self.location_sig, encoded_location)
            return True
        except InvalidSignature:
            return False

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:start-session")
        assert len(record.args) == 4
        # The session pubkey is encoded as a gcrypt s-expression
        # (public-key (ecc (curve Ed25519) (flags eddsa) (q <pubkey data>))
        pubkey = CapTPPublicKey.from_syrup_record(record.args[1])

        # The location signature is encoded as a gcrypt s-expression
        # (sig-val (eddsa (r <r data>) (s <s data>)))
        encoded_location_sig = record.args[3]
        assert encoded_location_sig[0] == syrup.Symbol("sig-val")
        assert encoded_location_sig[1][0] == syrup.Symbol("eddsa")
        assert encoded_location_sig[1][1][0] == syrup.Symbol("r")
        assert encoded_location_sig[1][2][0] == syrup.Symbol("s")
        r = encoded_location_sig[1][1][1]
        s = encoded_location_sig[1][2][1]
        location_sig = r + s

        location = decode_captp_message(record.args[2])
        return cls(record.args[0], pubkey, location, location_sig)

    def to_syrup_record(self) -> syrup.Record:
        # Convert the location signature to the gcrypt s-expression format
        r = self.location_sig[0:32]
        s = self.location_sig[32:]
        encoded_location_sig = [
            syrup.Symbol("sig-val"),
            [
                syrup.Symbol("eddsa"),
                [syrup.Symbol("r"), r], [syrup.Symbol("s"), s]
            ]
        ]

        return syrup.Record(
            syrup.Symbol("op:start-session"),
            [self.captp_version, self.session_pubkey.to_syrup_record(),
             self.location.to_syrup_record(), encoded_location_sig]
        )


class OpBootstrap(CapTPType):
    """ <op:bootstrap answer-position resolve-me-desc> """

    def __init__(self, answer_position, resolve_me_desc: DescImport):
        self.answer_position = answer_position
        self.resolve_me_desc = resolve_me_desc

    @property
    def vow(self) -> DescAnswer:
        """ The vow for the bootstrap operation """
        return DescAnswer(self.answer_position)

    @property
    def exported_resolve_me_desc(self) -> DescExport:
        """ The exported resolve-me-desc for the bootstrap operation """
        return self.resolve_me_desc.to_desc_export()

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:bootstrap")
        assert len(record.args) == 2
        resolve_me_desc = decode_captp_message(record.args[1])
        return cls(record.args[0], resolve_me_desc)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("op:bootstrap"),
            [
                self.answer_position,
                self.resolve_me_desc.to_syrup_record()
            ]
        )


class OpListen(CapTPType):
    """ <op:listen to-desc listen-desc> """

    def __init__(self, to: DescExport, resolve_me_desc: DescImport, wants_partial: bool):
        self.to = to
        self.resolve_me_desc = resolve_me_desc
        self.want_partial = wants_partial

    @property
    def exported_resolve_me_desc(self) -> DescExport:
        """ The exported resolve_me_desc for the listen operation """
        return self.resolve_me_desc.to_desc_export()

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:listen")
        assert len(record.args) == 3
        to = decode_captp_message(record.args[0])
        resolve_me_desc = decode_captp_message(record.args[1])
        wants_partial = record.args[2]
        return cls(to, resolve_me_desc, wants_partial)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("op:listen"),
            [self.to.to_syrup_record(), self.resolve_me_desc.to_syrup_record(), self.want_partial]
        )


class OpDeliverOnly(CapTPType):
    """ <op:deliver-only to-desc args> """

    def __init__(self, to, args: list):
        self.to = to
        self.args = args

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:deliver-only")
        assert len(record.args) == 2
        to = decode_captp_message(record.args[0])
        assert isinstance(to, DescExport) or isinstance(to, DescAnswer)
        # Convert all arguments to CapTP types, if needed
        args = [maybe_decode_captp_type(arg) for arg in record.args[1]]
        return cls(to, args)

    def to_syrup_record(self) -> syrup.Record:
        # TODO: Should we convert args to syrup records, if needed.
        encoded_args = []
        for arg in self.args:
            if isinstance(arg, CapTPType):
                encoded_args.append(arg.to_syrup_record())
            else:
                encoded_args.append(arg)

        return syrup.Record(
            syrup.Symbol("op:deliver-only"),
            [self.to.to_syrup_record(), encoded_args]
        )


class OpDeliver(CapTPType):
    """ <op:deliver to args answer-position resolve-me-desc> """

    def __init__(self, to: DescExport | DescAnswer, args: list,
                 answer_position: int | None, resolve_me_desc: DescImport):
        self.to = to
        self.args = args
        self.answer_position = answer_position
        self.resolve_me_desc = resolve_me_desc

    @property
    def vow(self) -> DescAnswer | None:
        """ the DescAnswer (promise) it has a answer_position """
        if self.answer_position is None:
            return None
        return DescAnswer(self.answer_position)

    @property
    def exported_resolve_me_desc(self) -> DescExport:
        """ The resolve_me_desc as the exported object """
        return self.resolve_me_desc.to_desc_export()

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:deliver")
        assert len(record.args) == 4
        to = decode_captp_message(record.args[0])
        assert isinstance(to, DescExport) or isinstance(to, DescAnswer)
        args = [maybe_decode_captp_type(arg) for arg in record.args[1]]
        answer_position = record.args[2]
        resolve_me_desc = decode_captp_message(record.args[3])
        return cls(to, args, answer_position, resolve_me_desc)

    def to_syrup_record(self) -> syrup.Record:
        encoded_args = []
        for arg in self.args:
            if isinstance(arg, CapTPType):
                encoded_args.append(arg.to_syrup_record())
            else:
                encoded_args.append(arg)

        return syrup.Record(
            syrup.Symbol("op:deliver"),
            [
                self.to.to_syrup_record(),
                encoded_args,
                self.answer_position,
                self.resolve_me_desc.to_syrup_record()
            ]
        )


class OpAbort(CapTPType):
    """ <op:abort reason> """

    def __init__(self, reason: str):
        self.reason = reason

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:abort")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("op:abort"),
            [self.reason]
        )


class OpGcExport(CapTPType):
    """ <op:gc-export export-position wire-delta> """

    def __init__(self, export_position: int, wire_delta: int):
        self.export_position = export_position
        self.wire_delta = wire_delta

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:gc-export")
        assert len(record.args) == 2
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("op:gc-export"),
            [self.export_position, self.wire_delta]
        )


class OpGcAnswer(CapTPType):
    """ <op:gc-answer answer-position> """

    def __init__(self, answer_position: int):
        self.answer_position = answer_position

    @classmethod
    def from_syrup_record(cls, record: syrup.Record):
        assert record.label == syrup.Symbol("op:gc-answer")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> syrup.Record:
        return syrup.Record(
            syrup.Symbol("op:gc-answer"),
            [self.answer_position]
        )


CAPTP_TYPES = {
    syrup.Symbol("desc:import-object"): DescImportObject,
    syrup.Symbol("desc:import-promise"): DescImportPromise,
    syrup.Symbol("desc:answer"): DescAnswer,
    syrup.Symbol("desc:export"): DescExport,
    syrup.Symbol("desc:handoff-give"): DescHandoffGive,
    syrup.Symbol("desc:handoff-receive"): DescHandoffReceive,
    syrup.Symbol("desc:sig-envelope"): DescSigEnvelope,

    syrup.Symbol("op:start-session"): OpStartSession,
    syrup.Symbol("op:bootstrap"): OpBootstrap,
    syrup.Symbol("op:listen"): OpListen,
    syrup.Symbol("op:deliver-only"): OpDeliverOnly,
    syrup.Symbol("op:deliver"): OpDeliver,
    syrup.Symbol("op:abort"): OpAbort,
    syrup.Symbol("op:gc-export"): OpGcExport,
    syrup.Symbol("op:gc-answer"): OpGcAnswer,

    # OCapN URIs
    syrup.Symbol("ocapn-machine"): OCapNMachine,
}


def maybe_decode_captp_type(value):
    """ Decode a captp type from a syrup value, if possible """
    # NOTE: This is a bit dangerous in python as there is no tail call elimination
    if isinstance(value, (list, tuple)):
        return [maybe_decode_captp_type(v) for v in value]
    if isinstance(value, syrup.Record) and value.label in CAPTP_TYPES:
        return CAPTP_TYPES[value.label].from_syrup_record(value)
    return value


def decode_captp_message(record: syrup.Record):
    """ Decode a captp message from a syrup record """
    assert record.label in CAPTP_TYPES, f"Unknown captp type: {record.label}"
    return CAPTP_TYPES[record.label].from_syrup_record(record)
