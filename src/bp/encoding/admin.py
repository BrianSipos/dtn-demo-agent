''' Administrative records and types.
'''
import enum
from scapy_cbor.fields import (
    OptionalField, BoolField, EnumField, PacketField, UintField
)
from scapy_cbor.packets import (CborArray, TypeValueHead)
from .fields import (EidField, DtnTimeField)
from .blocks import Timestamp


class AdminRecord(TypeValueHead):
    ''' An administrative record bundle payload of BPbis Section 6.1.
    This is handled specially because it needs a primary block flag
    to indicate its presence.
    '''


class StatusInfo(CborArray):
    ''' Each Status assertion of BPbis Section 6.1.1.
    '''
    fields_desc = (
        BoolField('status', default=False),
        OptionalField(
            DtnTimeField('at'),
        ),
    )


class StatusInfoArray(CborArray):
    ''' The Status assertions of BPbis Section 6.1.1.
    '''
    fields_desc = (
        PacketField('received', default=StatusInfo(), cls=StatusInfo),
        PacketField('forwarded', default=StatusInfo(), cls=StatusInfo),
        PacketField('delivered', default=StatusInfo(), cls=StatusInfo),
        PacketField('deleted', default=StatusInfo(), cls=StatusInfo),
    )


@AdminRecord.bind_type(1)
class StatusReport(CborArray):
    ''' The Status Report of BPbis Section 6.1.1.
    '''
    
    @enum.unique
    class ReasonCode(enum.IntEnum):
        NO_INFO = 0,  # "No additional information"
        LIFETIME_EXP = 1,  # "Lifetime expired"
        FWD_UNI = 2,  # "Forwarded over unidirectional link"
        TX_CANCEL = 3,  # "Transmission canceled"
        DEPLETE_STORAGE = 4,  # "Depleted storage"
        DEST_EID_UNINTEL = 5,  # "Destination endpoint ID unintelligible"
        NO_ROUTE = 6,  # "No known route to destination from here"
        NO_NEXT_CONTACT = 7,  # "No timely contact with next node on route"
        BLOCK_UNINTEL = 8,  # "Block unintelligible"
        HOP_LIMIT_EXC = 9,  # "Hop limit exceeded"
    
    fields_desc = (
        PacketField('status', default=StatusInfoArray(), cls=StatusInfoArray),
        EnumField('reason_code', default=ReasonCode.NO_INFO, enum=ReasonCode),
        EidField('subj_source'),
        PacketField('subj_ts', default=Timestamp(), cls=Timestamp),
        OptionalField(
            UintField('fragment_offset'),
        ),
        OptionalField(
            UintField('payload_len'),
        ),
    )
