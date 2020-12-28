''' Items related to established connection messaging.
'''
import enum

from scapy import fields, packet

from . import formats


class MessageHead(packet.Packet):
    ''' The common message header. '''
    fields_desc = [
        formats.UInt8Field('msg_id', default=None),
    ]

    def post_dissection(self, pkt):
        ''' remove padding from payload list after disect() completes '''
        formats.remove_padding(self)

        if not self.payload:
            raise formats.VerifyError('Message without payload')
        if isinstance(self.payload, packet.Raw):
            raise formats.VerifyError('Message with improper payload')

        packet.Packet.post_dissection(self, pkt)


class TlvHead(packet.Packet):
    ''' Generic TLV header with data as payload. '''

    @classmethod
    def bind_extension(cls, ext_id):
        ''' Bind an extension class to a derived header class.
        This decorator should be applied to extension type classes.

        :param cls: The header class to extend.
        :param ext_id: The extension type ID number.
        '''

        def func(ext_cls):
            packet.bind_layers(cls, ext_cls, type=ext_id)
            return ext_cls

        return func

    @enum.unique
    class Flag(enum.IntEnum):
        ''' Message flags.
        Flags must be in LSbit-first order.
        '''
        CRITICAL = 0x01

    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=[item.name for item in Flag]),
        formats.UInt16Field('type', default=None),
        formats.UInt16PayloadLenField('length', default=None),
    ]

    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        formats.verify_sized_item(self.length, self.payload)
        packet.Packet.post_dissection(self, pkt)


class SessionExtendHeader(TlvHead):
    ''' Session Extension Item header with data as payload. '''


class SessionInit(formats.NoPayloadPacket):
    ''' An SESS_INIT with no payload. '''

    #: Largest 64-bit size value
    SIZE_MAX = 2 ** 64 - 1

    fields_desc = [
        formats.UInt16Field('keepalive', default=0),
        formats.UInt64Field('segment_mru', default=SIZE_MAX),
        formats.UInt64Field('transfer_mru', default=SIZE_MAX),

        formats.UInt16FieldLenField('nodeid_length', default=None,
                                    length_of='nodeid_data'),
        formats.StrLenFieldUtf8('nodeid_data', default=u'',
                                length_from=lambda pkt: pkt.nodeid_length),

        formats.UInt32FieldLenField('ext_size', default=None,
                                    length_of='ext_items'),
        formats.ExtensionListField('ext_items', default=[],
                                   cls=SessionExtendHeader,
                                   length_from=lambda pkt: pkt.ext_size),
    ]

    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        (field, val) = self.getfield_and_val('nodeid_data')
        if val is not None:
            encoded = field.addfield(self, b'', val)
            formats.verify_sized_item(self.nodeid_length, encoded)

        (field, val) = self.getfield_and_val('ext_items')
        if val is not None:
            encoded = field.addfield(self, b'', val)
            formats.verify_sized_item(self.ext_size, encoded)

        packet.Packet.post_dissection(self, pkt)


class SessionTerm(formats.NoPayloadPacket):
    ''' An flag-dependent SESS_TERM message. '''

    @enum.unique
    class Flag(enum.IntEnum):
        ''' Message flags.
        Flags must be in LSbit-first order.
        '''
        REPLY = 0x01

    @enum.unique
    class Reason(enum.IntEnum):
        ''' Reason code points. '''
        UNKNOWN = 0
        IDLE_TIMEOUT = 1
        VERSION_MISMATCH = 2
        BUSY = 3
        CONTACT_FAILURE = 4
        RESOURCE_EXHAUSTION = 5

    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=[item.name for item in Flag]),
        fields.ByteEnumField('reason', default=Reason.UNKNOWN,
                             enum={item.value: item.name for item in Reason}),
    ]


class Keepalive(formats.NoPayloadPacket):
    ''' An empty KEEPALIVE message. '''


class RejectMsg(formats.NoPayloadPacket):
    ''' A REJECT with no payload. '''

    @enum.unique
    class Reason(enum.IntEnum):
        ''' Reason code points. '''
        UNKNOWN = 1
        UNSUPPORTED = 2
        UNEXPECTED = 3

    fields_desc = [
        formats.UInt8Field('rej_msg_id', default=0),
        fields.ByteEnumField('reason', default=Reason.UNKNOWN,
                             enum={item.value: item.name for item in Reason}),
    ]


class TransferExtendHeader(TlvHead):
    ''' Transfer Extension Item header with data as payload. '''


class TransferRefuse(formats.NoPayloadPacket):
    ''' An XFER_REFUSE with no payload. '''

    @enum.unique
    class Reason(enum.IntEnum):
        ''' Reason code points. '''
        UNKNOWN = 0x00
        COMPLETED = 0x01
        NO_RESOURCES = 0x02
        RETRANSMIT = 0x03
        NOT_ACCEPTABLE = 0x04
        EXT_FAILURE = 0x05

    fields_desc = [
        fields.ByteEnumField('reason', default=Reason.UNKNOWN,
                             enum={item.value: item.name for item in Reason}),
        formats.UInt64Field('transfer_id', default=0),
    ]


class TransferSegment(formats.NoPayloadPacket):
    ''' A XFER_SEGMENT with bundle data as field. '''

    @enum.unique
    class Flag(enum.IntEnum):
        ''' Message flags.
        Flags must be in LSbit-first order.
        '''
        END = 0x1
        START = 0x2

    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=[item.name for item in Flag]),
        formats.UInt64Field('transfer_id', default=0),
        fields.ConditionalField(
            cond=lambda pkt: pkt.flags & TransferSegment.Flag.START,
            fld=formats.UInt32FieldLenField(
                'ext_size', default=None, length_of='ext_items'),
        ),
        fields.ConditionalField(
            cond=lambda pkt: pkt.flags & TransferSegment.Flag.START,
            fld=formats.ExtensionListField('ext_items', default=[],
                                           cls=TransferExtendHeader,
                                           length_from=lambda pkt: pkt.ext_size),
        ),
        formats.UInt64FieldLenField('length', default=None, length_of='data'),
        formats.BlobField('data', default=b'',
                          length_from=lambda pkt: pkt.length),
    ]

    def post_dissection(self, pkt):
        ''' Verify consistency of packet. '''
        (field, val) = self.getfield_and_val('ext_items')
        if val is not None:
            encoded = field.addfield(self, b'', val)
            formats.verify_sized_item(self.ext_size, encoded)

        formats.verify_sized_item(self.length, self.getfieldval('data'))
        packet.Packet.post_dissection(self, pkt)


class TransferAck(formats.NoPayloadPacket):
    ''' An XFER_ACK with no payload. '''

    fields_desc = [
        fields.FlagsField('flags', default=0, size=8,
                          names=[item.name for item in TransferSegment.Flag]),
        formats.UInt64Field('transfer_id', default=0),
        formats.UInt64Field('length', default=None),
    ]


packet.bind_layers(MessageHead, TransferSegment, msg_id=0x1)
packet.bind_layers(MessageHead, TransferAck, msg_id=0x2)
packet.bind_layers(MessageHead, TransferRefuse, msg_id=0x3)
packet.bind_layers(MessageHead, Keepalive, msg_id=0x4)
packet.bind_layers(MessageHead, SessionTerm, msg_id=0x5)
packet.bind_layers(MessageHead, RejectMsg, msg_id=0x6)
packet.bind_layers(MessageHead, SessionInit, msg_id=0x7)
