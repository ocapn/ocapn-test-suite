from contrib.syrup import *

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
    def from_record(cls, record: Record):
        assert record.label == Symbol("ocapn-machine")
        assert len(record.args) == 3
        # TODO: probably want to support hints at a later date
        assert record.args[2] == False, "hints not supported"

        return cls(*record.args)
    
    def to_syrup_record(self) -> Record:
        return Record(
            Symbol("ocapn-machine"),
            [self.transport, self.address, self.hints]
        )