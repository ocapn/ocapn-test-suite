from abc import ABC, abstractmethod
from contrib.syrup import *
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from contrib.syrup import Record
from utils.ocapn_uris import OCapNMachine

from cryptography.hazmat.primitives import serialization

class CapTPType(ABC):
    """ Base class for all CapTP types """
    
    @classmethod
    @abstractmethod
    def from_record(cls, record: Record):
        """ Converts from a syrup record """
        pass

    @abstractmethod
    def to_syrup_record(self) -> Record:
        """ Converts to a syrup record """
        pass

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
    def from_record(cls, record: Record):
        assert record.label == Symbol("desc:import-object")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("desc:import-object"),
            [self.position]
        )

class DescImportPromise(DescImport):
    """ <desc:import-promise position> """
    def __init__(self, position: int):
        super().__init__(position)

    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("desc:import-promise")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("desc:import-promise"),
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
    def from_record(cls, record: Record):
        assert record.label == Symbol("desc:export")
        assert len(record.args) == 1
        return cls(*record.args)
    
    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("desc:export"),
            [self.position]
        )

class DescAnswer(CapTPType):
    """ <desc:answer position> """

    def __init__(self, position: int):
        self.position = position
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("desc:answer")
        assert len(record.args) == 1
        return cls(*record.args)
    
    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("desc:answer"),
            [self.position]
        )

class DescSigEnvolope(CapTPType):
    """ <desc:sig-envolope data signature> """

    def __init__(self, data: bytes, signature: bytes):
        self.data = data
        self.signature = signature
    
    def is_valid(self, public_key: Ed25519PublicKey) -> bool:
        """ Verifies the signature with the given public key """
        try:
            public_key.verify(self.signature, self.data)
            return True
        except:
            return False
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("desc:sig-envolope")
        assert len(record.args) == 2

        # Convert from the gcrypt s-expression format to bytes
        encoded_signature = record.args[1]
        assert encoded_signature.label == Symbol("sig-val")
        assert len(encoded_signature.args) == 1
        encoded_signature = encoded_signature.args[0]
        assert encoded_signature.label == Symbol("eddsa")
        assert len(encoded_signature.args) == 2
        r = encoded_signature.args[0].args[1]
        s = encoded_signature.args[1].args[1]
        signature = r + s

        return cls(record.args[0], signature)
        
    def to_syrup_record(self) -> Record:
        # The signature in CapTP is modelled after the gcrypt s-expression format
        r = self.signature[0:32]
        s = self.signature[32:]

        encoded_signature = [
            Symbol("sig-val"),
            [
                Symbol("eddsa"),
                [Symbol("r"), r],
                [Symbol("s"), s],
            ]
        ]

        return Record(
            Symbol("desc:sig-envolope"),
            [self.data, encoded_signature]
        )

class DescHandoffGive(CapTPType):
    """
    <desc:handoff-give receiver-key
                   exporter-location
                   session
                   gifter-side
                   gift-id>
    """
    pass

class DescHandoffReceive(CapTPType):
    """
<desc:handoff-receive receiving-session
                      receiving-side
                      handoff-count
                      signed-give>
    """
    pass

class OpStartSession(CapTPType):
    """ <op:start-session captp-version session-pubkey location location-sig> """
    def __init__(self, captp_version: str, session_pubkey: Ed25519PublicKey,
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
        tagged_location = Record(
            Symbol("my-location"),
            [self.location.to_syrup_record()]
        )
        # The signature is of the syrup representation of the tagged location
        encoded_location = syrup_encode(tagged_location)
        try:
            self.session_pubkey.verify(self.location_sig, encoded_location)
            return True
        except InvalidSignature:
            return False
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:start-session")
        assert len(record.args) == 4
        # The session pubkey is encoded as a gcrypt s-expression
        # (public-key (ecc (curve Ed25519) (flags eddsa) (q <pubkey data>))
        encoded_pubkey = record.args[1]
        assert encoded_pubkey[0] == Symbol("public-key")
        assert encoded_pubkey[1][0] == Symbol("ecc")
        assert encoded_pubkey[1][1] == [Symbol("curve"), Symbol("Ed25519")]
        assert encoded_pubkey[1][2] == [Symbol("flags"), Symbol("eddsa")]
        assert encoded_pubkey[1][3][0] == Symbol("q")
        encoded_pubkey_data = encoded_pubkey[1][3][1]
        pubkey = Ed25519PublicKey.from_public_bytes(encoded_pubkey_data)

        # The location signature is encoded as a gcrypt s-expression
        # (sig-val (eddsa (r <r data>) (s <s data>)))
        encoded_location_sig = record.args[3]
        assert encoded_location_sig[0] == Symbol("sig-val")
        assert encoded_location_sig[1][0] == Symbol("eddsa")
        assert encoded_location_sig[1][1][0] == Symbol("r")
        assert encoded_location_sig[1][2][0] == Symbol("s")
        r = encoded_location_sig[1][1][1]
        s = encoded_location_sig[1][2][1]
        location_sig = r + s
        
        location = decode_captp_message(record.args[2])
        return cls(record.args[0], pubkey, location, location_sig)
    
    def to_syrup_record(self) -> Record:
        # Convert the public key to the gcrypt s-expression format
        encoded_pubkey = [
            Symbol("public-key"),
            [
                Symbol("ecc"),
                [Symbol("curve"), Symbol("Ed25519")],
                [Symbol("flags"), Symbol("eddsa")],
                [Symbol("q"), self.session_pubkey.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )]
            ]
        ]

        # Convert the location signature to the gcrypt s-expression format
        r = self.location_sig[0:32]
        s = self.location_sig[32:]
        encoded_location_sig = [
            Symbol("sig-val"),
            [
                Symbol("eddsa"),
                [Symbol("r"), r], [Symbol("s"), s]
            ]
        ]


        return Record(
            Symbol("op:start-session"),
            [self.captp_version, encoded_pubkey,
             self.location.to_syrup_record(), encoded_location_sig]
        )

class OpBootstrap(CapTPType):
    """ <op:bootstrap answer-position resolve-me-desc> """

    def __init__(self, answer_position: int, resolve_me_desc: DescImport):
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
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:bootstrap")
        assert len(record.args) == 2
        resolve_me_desc = decode_captp_message(record.args[1])
        return cls(record.args[0], resolve_me_desc)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("op:bootstrap"),
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
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:listen")
        assert len(record.args) == 3
        to = decode_captp_message(record.args[0])
        resolve_me_desc = decode_captp_message(record.args[1])
        wants_partial = record.args[2]
        return cls(to, resolve_me_desc, wants_partial)
    
    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("op:listen"),
            [self.to.to_syrup_record(), self.resolve_me_desc.to_syrup_record(), self.want_partial]
        )

class OpDeliverOnly(CapTPType):
    """ <op:deliver-only to-desc args> """

    def __init__(self, to, args: list):
        self.to = to
        self.args = args
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:deliver-only")
        assert len(record.args) == 2
        to = decode_captp_message(record.args[0])
        assert isinstance(to, DescExport) or isinstance(to, DescAnswer)
        # Convert all arguments to CapTP types, if needed
        args = [maybe_decode_captp_type(arg) for arg in record.args[1]]
        return cls(to, args)

    def to_syrup_record(self) -> Record:
        # TODO: Should we convert args to syrup records, if needed.
        encoded_args = []
        for arg in self.args:
            if isinstance(arg, CapTPType):
                encoded_args.append(arg.to_syrup_record())
            else:
                encoded_args.append(arg)
        
        return Record(
            Symbol("op:deliver-only"),
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
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:deliver")
        assert len(record.args) == 4
        to = decode_captp_message(record.args[0])
        assert isinstance(to, DescExport) or isinstance(to, DescAnswer)
        args = [maybe_decode_captp_type(arg) for arg in record.args[1]]
        answer_position = record.args[2]
        resolve_me_desc = decode_captp_message(record.args[3])
        return cls(to, args, answer_position, resolve_me_desc)

    def to_syrup_record(self) -> Record:
        encoded_args = []
        for arg in self.args:
            if isinstance(arg, CapTPType):
                encoded_args.append(arg.to_syrup_record())
            else:
                encoded_args.append(arg)

        return Record(
            Symbol("op:deliver"),
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
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:abort")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("op:abort"),
            [self.reason]
        )

class OpGcExport(CapTPType):
    """ <op:gc-export export-position wire-delta> """

    def __init__(self, export_position: int, wire_delta: int):
        self.export_position = export_position
        self.wire_delta = wire_delta
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:gc-export")
        assert len(record.args) == 2
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("op:gc-export"),
            [self.export_position, self.wire_delta]
        )

class OpGcAnswer(CapTPType):
    """ <op:gc-answer answer-position> """

    def __init__(self, answer_position: int):
        self.answer_position = answer_position
    
    @classmethod
    def from_record(cls, record: Record):
        assert record.label == Symbol("op:gc-answer")
        assert len(record.args) == 1
        return cls(*record.args)

    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("op:gc-answer"),
            [self.answer_position]
        )

CAPTP_TYPES = {
    Symbol("desc:import-object"): DescImportObject,
    Symbol("desc:import-promise"): DescImportPromise,
    Symbol("desc:answer"): DescAnswer,
    Symbol("desc:export"): DescExport,
    Symbol("desc:handoff-give"): DescHandoffGive,
    Symbol("desc:handoff-receive"): DescHandoffReceive,
    Symbol("op:start-session"): OpStartSession,
    Symbol("op:bootstrap"): OpBootstrap,
    Symbol("op:listen"): OpListen,
    Symbol("op:deliver-only"): OpDeliverOnly,
    Symbol("op:deliver"): OpDeliver,
    Symbol("op:abort"): OpAbort,
    Symbol("op:gc-export"): OpGcExport,
    Symbol("op:gc-answer"): OpGcAnswer,

    # OCapN URIs
    Symbol("ocapn-machine"): OCapNMachine,
}

def maybe_decode_captp_type(value):
    """ Decode a captp type from a syrup value, if possible """
    # NOTE: This is a bit dangerous in python as there is no tail call elimination
    if isinstance(value, (list, tuple)):
        return [maybe_decode_captp_type(v) for v in value]
    if isinstance(value, Record) and value.label in CAPTP_TYPES:
        return CAPTP_TYPES[value.label].from_record(value)
    return value

def decode_captp_message(record: Record):
    """ Decode a captp message from a syrup record """
    assert record.label in CAPTP_TYPES, f"Unknown captp type: {record.label}"
    return CAPTP_TYPES[record.label].from_record(record)