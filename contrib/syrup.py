#!/usr/bin/env python

# BE FOREWRANED:
#
# This is a simple implementation in recursive descent style, mirrored
# off of the Racket/Guile scheme implementations.  However, a recursive
# descent implementation is unlikely to be all to safe in Python-land
# because there's no tail-call-elimination.

import io
import struct
import string

__all__ = [
    "SyrupDecodeError", "SyrupEncodeError", "SyrupSingleFloatsNotSupported",
    "Record", "Symbol",
    "syrup_encode", "syrup_read", "syrup_decode"
]


class SyrupDecodeError(Exception):
    pass


class SyrupEncodeError(Exception):
    pass


class SyrupSingleFloatsNotSupported(Exception):
    pass


class Record:
    def __init__(self, label, args):
        self.label = label
        self.args = list(args)

    def __repr__(self):
        return "<Record %s: %r>" % (self.label, self.args)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Record) and \
            other.label == self.label and \
            other.args == self.args


class Symbol:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "Symbol(%s)" % self.name

    def __str__(self):
        return self.name

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, Symbol) and other.name == self.name


def netstring_encode(bstr, joiner=b':'):
    octets = str(len(bstr)).encode("latin-1")
    return octets + joiner + bstr


def syrup_encode(obj):
    # Bytes are like <bytes-len>:<bytes>
    if isinstance(obj, bytes):
        return netstring_encode(obj)
    # True is t, False is f
    elif obj is True:
        return b't'
    elif obj is False:
        return b'f'
    # Integers are like <integer>+ or <integer>-
    elif isinstance(obj, int):
        if obj == 0:
            return b"0+"
        elif obj > 0:
            return str(obj).encode('latin-1') + b'+'
        else:
            return str((obj * -1)).encode('latin-1') + b'-'
    # Lists are like [<item1><item2><item3>]
    elif isinstance(obj, list):
        encoded_items = [syrup_encode(item) for item in obj]
        return b'[' + b''.join(encoded_items) + b']'
    # Dictionaries are like {<key1><val1><key2><val2>}
    # We sort by the key being fully encoded.
    elif isinstance(obj, dict):
        keys_and_encoded = [
            (syrup_encode(key), key)
            for key in obj.keys()]
        sorted_keys_and_encoded = sorted(
            keys_and_encoded,
            key=lambda x: x[0])
        encoded_hash_pairs = [
            # combine the encoded key and encode the val immediately
            ek[0] + syrup_encode(obj[ek[1]])
            for ek in sorted_keys_and_encoded]
        return b'{' + b''.join(encoded_hash_pairs) + b'}'
    # Strings are like <encoded-bytes-len>"<utf8-encoded>
    elif isinstance(obj, str):
        return netstring_encode(obj.encode('utf-8'),
                                joiner=b'"')
    # Symbols are like <encoded-bytes-len>'<utf8-encoded>
    elif isinstance(obj, Symbol):
        return netstring_encode(obj.name.encode('utf-8'),
                                joiner=b"'")
    # Only double is supported in Python.  Single-precision not supported.
    # Double flonum floats are like D<big-endian-encoded-double-float>
    elif isinstance(obj, float):
        return b'D' + struct.pack('>d', obj)
    # Records are like <<tag><arg1><arg2>> but with the outer <> for realsies
    elif isinstance(obj, Record):
        return b'<' + \
            syrup_encode(obj.label) +\
            b''.join([syrup_encode(x) for x in obj.args]) + \
            b'>'
    # Sets are like #<item1><item2><item3>$
    elif isinstance(obj, set):
        encoded_items = [syrup_encode(x) for x in obj]
        return b'#' + b''.join(sorted(encoded_items)) + b'$'
    else:
        raise SyrupEncodeError("Unsupported type: %r" % obj)


def peek_byte(f):
    orig_pos = f.tell()
    byte = f.read(1)
    f.seek(orig_pos)
    return byte


whitespace_chars = string.whitespace.encode("latin-1")
digit_chars = string.digits.encode("latin-1")


def syrup_read(f, convert_singles=False):
    def _syrup_read(f):
        return syrup_read(f, convert_singles=convert_singles)

    # consume whitespace
    while peek_byte(f) in whitespace_chars:
        f.read(1)

    next_char = peek_byte(f)

    # it's either a bytestring, string, or symbol depending on the joiner
    if next_char in digit_chars:
        _type = False
        bytes_len_str = b''
        while True:
            this_char = f.read(1)
            if this_char == b':':
                _type = "bstr"
                break
            elif this_char == b'"':
                _type = "str"
                break
            elif this_char == b"'":
                _type = "sym"
                break
            elif this_char == b"+":
                _type = "int+"
                break
            elif this_char == b"-":
                _type = "int-"
                break
            elif this_char in digit_chars:
                bytes_len_str += this_char
            else:
                raise SyrupDecodeError(
                    "Invalid digit at pos %s: %r" % (
                        f.tell() - 1, this_char))
        int_or_bytes_len = int(bytes_len_str.decode('latin-1'))
        if _type == "int+":
            return int_or_bytes_len
        elif _type == "int-":
            return int_or_bytes_len * -1
        else:
            bstr = f.read(int_or_bytes_len)
            if _type == "bstr":
                return bstr
            elif _type == "sym":
                return Symbol(bstr.decode('utf-8'))
            elif _type == "str":
                return bstr.decode('utf-8')
    # it's a list
    elif next_char in b'[(l':
        f.read(1)
        lst = []
        while True:
            if peek_byte(f) in b'])e':
                f.read(1)
                break
            else:
                lst.append(_syrup_read(f))
        return lst
    # it's a hashmap/dictionary
    elif next_char in b'{d':
        f.read(1)
        d = dict()
        while True:
            if peek_byte(f) in b'}e':
                f.read(1)
                break
            else:
                key = _syrup_read(f)
                val = _syrup_read(f)
                d[key] = val
        return d
    # it's a record
    elif next_char == b'<':
        f.read(1)
        label = _syrup_read(f)
        args = []
        while True:
            if peek_byte(f) == b'>':
                f.read(1)
                break
            else:
                args.append(_syrup_read(f))
        return Record(label, args)
    # single floats not supported in Python
    elif next_char == b'F':
        if convert_singles:
            f.read(1)
            return struct.unpack('>f', f.read(4))[0]
        else:
            raise SyrupSingleFloatsNotSupported(
                "Single floats not supported in Python and coersion disabled")
    # it's a double float
    elif next_char == b'D':
        f.read(1)
        return struct.unpack('>d', f.read(8))[0]
    # it's a boolean
    elif next_char == b'f':
        f.read(1)
        return False
    elif next_char == b't':
        f.read(1)
        return True
    # it's a set
    elif next_char == b'#':
        f.read(1)
        s = set()
        while True:
            if peek_byte(f) == b'$':
                f.read(1)
                break
            else:
                s.add(_syrup_read(f))
        return s
    else:
        raise SyrupEncodeError(
            "Unexpected character and position %s: %s" %
            (f.tell(), next_char))


def syrup_decode(bstr, convert_singles=False):
    return syrup_read(io.BytesIO(bstr), convert_singles=convert_singles)
