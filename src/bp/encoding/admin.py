''' Administrative records and types.
'''
from scapy_cbor.fields import (
    OptionalField, BoolField, PacketField, UintField
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
    fields_desc = (
        PacketField('status', default=StatusInfoArray(), cls=StatusInfoArray),
        UintField('reason_code'),
        EidField('subj_source'),
        PacketField('subj_ts', default=Timestamp(), cls=Timestamp),
        OptionalField(
            UintField('fragment_offset'),
        ),
        OptionalField(
            UintField('payload_len'),
        ),
    )
