''' Extend SCAPY field interface for CBOR encoding.
'''
import logging
import cbor2
import scapy.fields
from scapy import volatile

LOGGER = logging.getLogger(__name__)


class DecodeError(RuntimeError):
    ''' Signal an error in CBOR decoding. '''


class CborField(scapy.fields.Field):
    ''' Abstract base type.

    :param str name: The unique field name.
    :param default: Default/initial value.
    '''

    def __init__(self, name, default=None):
        scapy.fields.Field.__init__(self, name, default, '!s')

    def addfield(self, pkt, s, val):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        s = list(s)
        s.append(self.i2m(pkt, val))
        return s

    def getfield(self, pkt, s):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        s = list(s)
        item = s.pop(0)
        val = self.m2i(pkt, item)
        return (s, val)

    def i2m(self, pkt, x):
        ''' Encode this field to a CBOR item.

        :param pkt: The packet (container) context.
        :param x: The internal data value.
        :return: The CBOR item.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return x

    def m2i(self, pkt, x):
        ''' Decode this field from a CBOR item.

        :param pkt: The packet (container) context.
        :param x: The CBOR item value.
        :return: The internal data value.
        :rtype: A value or :py:obj:`IGNORE`.
        '''
        return x

    def any2i(self, pkt, x):
        # Coerce all values to internal type
        return self.m2i(pkt, x)


ConditionalField = scapy.fields.ConditionalField


class OptionalField(object):
    ''' Optional based on the contents of the source data.

    :param missing: Values which will be treated as non-values and omitted.
        The default is None and cbor2.undefined.
    '''
    __slots__ = (
        'fld',
        'missing',
    )

    def __init__(self, fld, missing=None):
        self.fld = fld
        if missing is None:
            missing = (None, cbor2.undefined)
        self.missing = frozenset(missing)

    def getfield(self, pkt, s):
        if s:
            return self.fld.getfield(pkt, s)
        else:
            return s, None

    def addfield(self, pkt, s, val):
        if val not in self.missing:
            return self.fld.addfield(pkt, s, val)
        else:
            return s

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class ArrayWrapField(CborField):
    ''' Wrap a field with an array container.
    '''
    __slots__ = (
        'fld',
    )

    def __init__(self, fld):
        CborField.__init__(self, fld.name, fld.default)
        self.fld = fld

    def getfield(self, pkt, s):
        (s, lst) = CborField.getfield(self, pkt, s)
        (rem, val) = self.fld.getfield(pkt, lst)
        if rem:
            pass
        return s, val

    def addfield(self, pkt, s, val):
        lst = self.fld.addfield(pkt, [], val)
        s = CborField.addfield(self, pkt, s, lst)
        return s

    def __getattr__(self, attr):
        return getattr(self.fld, attr)


class FieldListField(CborField):
    ''' Similar to :py:cls:`scapy.fields.FieldListField`.
    '''
    __slots__ = (
        'fld',
    )
    islist = 1

    def __init__(self, name, default, fld):
        if default is None:
            default = []  # Create a new list for each instance
        CborField.__init__(self, name, default)
        self.fld = fld

    def i2m(self, pkt, x):
        if x is None:
            x = []
        return x

    def any2i(self, pkt, x):
        if not isinstance(x, list):
            return [self.fld.any2i(pkt, x)]
        else:
            return [self.fld.any2i(pkt, e) for e in x]

    def i2repr(self, pkt, x):
        return "[%s]" % ", ".join(self.fld.i2repr(pkt, v) for v in x)

    def addfield(self, pkt, s, val):
        val = self.i2m(pkt, val)
        for v in val:
            s = self.fld.addfield(pkt, s, v)
        return s

    def getfield(self, pkt, s):
        val = []
        while s:
            (s, v) = self.fld.getfield(pkt, s)
            val.append(v)
        return s, val


class PacketField(CborField):
    ''' Similar to :py:cls:`scapy.fields.PacketField` but
    for CBOR encoding.
    '''
    __slots__ = ["cls"]
    holds_packets = 1

    def __init__(self, name, default, cls):
        self.cls = cls
        CborField.__init__(self, name, default)

    def i2m(self, pkt, x):
        if x is None:
            return None
        return x.build()

    def m2i(self, pkt, x):
        if x is None:
            return None
        obj = self.cls()
        obj.dissect(x)
        return obj

    def any2i(self, pkt, x):
        return x


class PacketListField(PacketField):
    ''' Similar to :py:cls:`scapy.fields.PacketListField` but
    for CBOR encoding.
    '''
    islist = 1

    def getfield(self, pkt, s):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        count = len(s)

        lst = []
        for _ix in range(0, count):
            subitem = s.pop(0)
            obj = self.m2i(pkt, subitem)
            lst.append(obj)
        return (s, lst)

    def addfield(self, pkt, s, val):
        ''' Augmented signature for `s` as CBOR array instead of bytes.
        '''
        for obj in val:
            subitem = self.i2m(pkt, obj)
            s.append(subitem)
        return s


class BoolField(CborField):
    ''' A field which must be 'bool' type.
    '''

    def i2m(self, pkt, val):
        try:
            return bool(val)
        except TypeError:
            return None

    def m2i(self, pkt, val):
        try:
            return bool(val)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandChoice(False, True)


class UintField(CborField):
    ''' A field which must be 'uint' type.

    :param maxval: The maximum value allowed in this field.
        Warnings will be output if the actual value is above this limit
    '''
    __slots__ = [
        'maxval',
    ]

    def __init__(self, name, default=None, maxval=None):
        CborField.__init__(self, name, default)
        if maxval is None:
            maxval = 2 ** 64 - 1
        self.maxval = maxval

    def i2m(self, pkt, x):
        try:
            return int(x)
        except TypeError:
            return None

    def m2i(self, pkt, x):
        try:
            return int(x)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandNum(0, self.maxval)


class EnumField(UintField):
    ''' An integer containing an enumerated value.

    :param enum: Available values for the field.
    :type enum: :py:cls:`enum.IntEnum`
    '''
    __slots__ = (
        'enum',
    )

    def __init__(self, name, default, enum):
        maxval = 0
        for val in enum:
            maxval = max(maxval, int(val))
        self.enum = enum

        UintField.__init__(self, name, default, maxval)

    def m2i(self, pkt, val):
        val = UintField.m2i(self, pkt, val)
        if val is not None:
            val = self.enum(val)
        return val


class FlagsField(UintField):
    ''' An integer containing enumerated flags.

    :param flags: Available flags for the field.
    :type flags: :py:cls:`enum.IntFlag`
    '''
    __slots__ = (
        'flags',
    )

    def __init__(self, name, default, flags):
        maxval = 0
        for val in flags:
            maxval |= int(val)
        self.flags = flags

        UintField.__init__(self, name, default, maxval)

    def m2i(self, pkt, x):
        x = UintField.m2i(self, pkt, x)
        if x is not None:
            x = self.flags(x)
        return x


class TstrField(CborField):
    ''' Allow only CBOR 'tstr' value.
    '''

    def __init__(self, name, default=None):
        CborField.__init__(self, name, default)

    def i2m(self, pkt, x):
        try:
            return str(x)
        except TypeError:
            return None

    def m2i(self, pkt, x):
        try:
            return str(x)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandString(1000)


class BstrField(CborField):
    ''' Allow only CBOR 'bstr' value.
    '''

    def __init__(self, name, default=None):
        CborField.__init__(self, name, default)

    def i2repr(self, pkt, x):
        if x is None:
            return None
        from scapy.utils import repr_hex
        return "h'{}'".format(repr_hex(x))

    def i2m(self, pkt, x):
        try:
            return bytes(x)
        except TypeError:
            return None

    def m2i(self, pkt, x):
        try:
            return bytes(x)
        except TypeError:
            return None

    def randval(self):
        return volatile.RandBin(1000)


class CborEncodedField(BstrField):
    ''' An encoded CBOR data item within a 'bstr'.
    '''

    def i2m(self, pkt, val):
        try:
            enc = cbor2.dumps(val)
            return enc
        except cbor2.CBOREncodeError:
            return None

    def m2i(self, pkt, val):
        try:
            dec = cbor2.loads(val)
            return dec
        except cbor2.CBORDecodeError:
            return None
