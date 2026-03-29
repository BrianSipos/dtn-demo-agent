''' Message structure in Scapy forms
'''
import enum
from typing import List, Optional, Tuple, Type
from scapy import fields, packet


class HintHead(packet.Packet):
    ''' Each hint header '''
    fields_desc = [
        fields.BitField('hint_type', default=None, size=7),
        fields.BitField('h_flag', default=None, size=1),
        fields.LenField('length', default=None, fmt='B'),
    ]

    def extract_padding(self, data: bytes) -> Tuple[bytes, bytes]:
        pyld_len = self.getfieldval('length')
        return data[:pyld_len], data[pyld_len:]


def length_cb(pkt: Optional[packet.Packet], orig: int) -> int:
    return orig + len(pkt.payload)


def hint_cb(pkt: packet.Packet,
            _lst: List[packet.Packet],
            cur: Optional[packet.Packet],
            _remain: str) -> Optional[Type[packet.Packet]]:
    ''' Check if the last hint inidicates more hints '''
    if cur is not None:
        if cur.h_flag:
            return HintHead
    else:
        if pkt.flags & 0x8:
            return HintHead
    return None


class MessageHead(packet.Packet):
    ''' The common message header. '''
    fields_desc = [
        fields.ByteField('msg_type', default=None),
        fields.FlagsField('flags', default=None, size=4, names="H"),
        fields.BitFieldLenField('length', default=None, size=20, length_of='hints', adjust=length_cb),
        fields.PacketListField('hints', default=[], next_cls_cb=hint_cb)
    ]

    def self_build(self) -> bytes:
        # Mark all hint flags
        if self.flags is None:
            self.flags = 0x8 if self.hints else 0
        if self.hints:
            # clear only the last one
            for ix, item in enumerate(reversed(self.hints)):
                item.h_flag = 1 if ix > 0 else 0

        return super().self_build()

    def extract_padding(self, data: bytes) -> Tuple[bytes, bytes]:
        fld, fval = self.getfield_and_val('hints')
        hints_len = fld.i2len(self, fval)

        pyld_len = self.getfieldval('length') - hints_len
        return data[:pyld_len], data[pyld_len:]


class DefinitePadding(packet.Raw):
    ''' Special in-message padding container. '''


class BundlePdu(packet.Raw):
    ''' Actual service payload. '''


class _Transfer(packet.Packet):
    fields_desc = [
        fields.IntField('xfer_num', default=0),
        fields.IntField('seg_idx', default=0),
    ]


class TransferSeg(_Transfer):
    ''' Any non-last segment of a transfer.
    It will have seg_idx starting at zero.
    '''


class TransferEnd(_Transfer):
    ''' The last segment of a transfer.
    It will have the largest seg_idx value.
    '''


class TransferCancel(packet.Packet):
    fields_desc = [
        fields.IntField('xfer_num', default=0),
    ]


packet.bind_layers(MessageHead, DefinitePadding, msg_type=1)
packet.bind_layers(MessageHead, BundlePdu, msg_type=2)
packet.bind_layers(MessageHead, TransferSeg, msg_type=3)
packet.bind_layers(MessageHead, TransferEnd, msg_type=4)
packet.bind_layers(MessageHead, TransferCancel, msg_type=5)


def is_msg_cb(_pkt: packet.Packet,
              _lst: List[packet.Packet],
              _cur: Optional[packet.Packet],
              remain: bytes) -> Optional[Type[packet.Packet]]:
    ''' Check if the data starts with a message header '''
    if remain and remain[0] != 0:
        return MessageHead
    else:
        return None


class MessageSet(packet.Packet):
    ''' A sequence of messages with optional padding. '''
    fields_desc = [
        fields.PacketListField('msgs', default=[], next_cls_cb=is_msg_cb)
    ]
