''' Extend SCAPY packet interface for CBOR structure encoding.
'''
import copy
import logging
import cbor2
import scapy.packet
from scapy.config import conf
from .fields import (UintField, CborField)

LOGGER = logging.getLogger(__name__)


class AbstractCborStruct(scapy.packet.Packet):
    ''' An abstract data packet, which encodes as a CBOR item
    of arbitrary value.

    Complex inner types mean this packet is never iterable for multiple values.
    '''

    def __iterlen__(self):
        # no iteration
        return 1

    def __iter__(self):
        # no iteration
        yield self

    def __bytes__(self):
        ''' Encode the whole bundle as a bytestring.
        :return: The encoded bundle.
        '''
        item = self.build()
        return cbor2.dumps(item)

    def dissect(self, s):
        ''' Decode the whole bundle from a bytestring.
        :param data: The encoded bundle.
        '''
        if isinstance(s, (bytes,)):
            s = cbor2.loads(s)
        scapy.packet.Packet.dissect(self, s)


class CborArray(AbstractCborStruct):
    ''' An abstract data layer, which encodes a packet as a CBOR array.
    Any payload of this packet will be appended to the array, so it
    must itself build to an array struct.
    '''

    def self_build(self, field_pos_list=None):
        lst = []

        #LOGGER.info('CborArray.self_build fields=%s', self.fields)
        for defn in self.fields_desc:
            data_val = self.getfieldval(defn.name)
            try:
                #LOGGER.info('CborArray.self_build name=%s, data_val=%s', defn.name, data_val)
                lst = defn.addfield(self, lst, data_val)
            except Exception as err:
                if conf.debug_dissector:
                    raise
                LOGGER.error('Failed to encode field "%s" val "%s": %s', defn.name, data_val, err)

        return lst

    def post_build(self, pkt, pay):
        ''' Interpret payload as extra array items.
        '''
        if isinstance(pay, bytes):
            if pay == b'':
                pay = []
            else:
                pay = [pay]
        return scapy.packet.Packet.post_build(self, pkt, pay)

    def do_dissect(self, s):
        # do not edit array directly
        s = copy.deepcopy(s)
        for defn in self.fields_desc:
            # None is a legitimate CBOR value, so need to detect
            # if array was modified
            orig_s = s.copy()
            (s, data_val) = defn.getfield(self, s)
            #LOGGER.info('CborArray.do_dissect name=%s, data_val=%s', defn.name, data_val)
            if s != orig_s:
                self.fields[defn.name] = data_val

        return s


class CborItem(AbstractCborStruct):
    ''' A special case layer which is undecoded CBOR item storage.
    There is no packet framing (i.e. array) on this item and no payload 
    or padding is allowed.

    Only one field is allowed with an arbitrary name.
    The base class field name is 'item'.
    '''

    fields_desc = [
        CborField('item', default=None),
    ]

    def self_build(self, field_pos_list=None):
        if len(self.fields_desc) != 1:
            if conf.debug_dissector:
                raise RuntimeError('CborItem must have exactly one field')
            return None

        defn = self.fields_desc[0]
        data_val = self.getfieldval(defn.name)
        return defn.i2m(self, data_val)

    def post_build(self, pkt, pay):
        if pay == b'':
            return pkt

        if conf.debug_dissector:
            raise RuntimeError('CborItem cannot contain a payload')
        LOGGER.error('CborItem cannot contain a payload, got: %s', pay)

    def build(self):
        # Do not apply build_padding()
        p = self.do_build()
        p = self.build_done(p)
        return p

    def do_dissect(self, s):
        if len(self.fields_desc) != 1:
            if conf.debug_dissector:
                raise RuntimeError('CborItem must have exactly one field')
            return

        defn = self.fields_desc[0]
        self.fields[defn.name] = defn.m2i(self, s)


class TypeValueHead(CborArray):
    ''' A pattern for an array encoding which contains exactly two values.
    This is analogous to a type-length-value (TLV) encoding for CBOR.
    The type is a field and the value is captured in the payload of this
    packet.
    The default payload for unknown types is a :py:cls:`CborItem`.
    '''

    fields_desc = (
        UintField('type_code'),
    )

    def do_build_payload(self):
        # Wrap the payload as an array to append
        if isinstance(self.payload, scapy.packet.NoPayload):
            s = None
        else:
            s = CborArray.do_build_payload(self)
        return [s]

    def do_dissect_payload(self, s):
        # Extract the second item as the payload
        s = s[0]
        if not s:
            self.add_payload(CborItem(item=s))
        CborArray.do_dissect_payload(self, s)

    def default_payload_class(self, payload):
        return CborItem

    @classmethod
    def bind_type(cls, type_code):
        ''' Bind a block-type-specific packet-class handler.

        :param int type_code: The type to bind to the payload class.
        '''

        def func(othercls):
            scapy.packet.bind_layers(cls, othercls, type_code=type_code)
            return othercls

        return func
