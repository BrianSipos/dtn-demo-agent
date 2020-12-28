''' Base block and bundle encoding.
'''
import enum
import logging
import struct
import cbor2
import crcmod
from scapy.config import conf
import scapy.packet
from scapy_cbor.packets import (CborArray, CborItem)
from scapy_cbor.fields import (
    BstrField, ConditionalField, EnumField, FlagsField, UintField, PacketField
)
from .fields import (EidField, DtnTimeField)

LOGGER = logging.getLogger(__name__)


class Timestamp(CborArray):
    ''' A structured representation of an DTN Timestamp.
    The timestamp is a two-tuple of (time, sequence number)
    The creation time portion is automatically converted from a
    :py:cls:`datetime.datetime` object and text.
    '''
    fields_desc = (
        DtnTimeField('time', default=0),
        UintField('seqno', default=0),
    )


class AbstractBlock(CborArray):
    ''' Represent an abstract block with CRC fields.

    .. py:attribute:: crc_type_name
        The name of the CRC-type field.
    .. py:attribute:: crc_value_name
        The name of the CRC-value field.
    '''

    @enum.unique
    class CrcType(enum.IntEnum):
        ''' CRC type values.
        '''
        NONE = 0
        CRC16 = 1
        CRC32 = 2

    # Map from CRC type to algorithm
    CRC_DEFN = {
        CrcType.CRC16: {  # BPv7 CRC-16 X.25
            'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
            'encode': lambda val: struct.pack('>H', val)
        },
        CrcType.CRC32: {  # BPv7 CRC-32 Castagnoli
            'func': crcmod.predefined.mkPredefinedCrcFun('crc-32c'),
            'encode': lambda val: struct.pack('>L', val)
        },
    }

    crc_type_name = 'crc_type'
    crc_value_name = 'crc_value'

    def update_crc(self):
        ''' Update this block's CRC field from the current field data
        only if the current CRC (field not default) value is None.
        '''
        if self.crc_type_name is None or self.crc_value_name is None:
            return

        crc_type = self.getfieldval(self.crc_type_name)
        if crc_type == 0:
            crc_value = None
        else:
            crc_value = self.fields.get(self.crc_value_name)
            if crc_value is None:
                defn = AbstractBlock.CRC_DEFN[crc_type]
                # Encode with a zero-valued CRC field
                self.fields[self.crc_value_name] = defn['encode'](0)
                pre_crc = cbor2.dumps(self.build())
                crc_int = defn['func'](pre_crc)
                crc_value = defn['encode'](crc_int)

        self.fields[self.crc_value_name] = crc_value

    def check_crc(self):
        ''' Check the current CRC value, if enabled.
        :return: True if the CRC is disabled or it is valid.
        '''
        if self.crc_type_name is None or self.crc_value_name is None:
            return True

        crc_type = self.getfieldval(self.crc_type_name)
        crc_value = self.fields.get(self.crc_value_name)
        if crc_type == 0:
            valid = crc_value is None
        else:
            defn = AbstractBlock.CRC_DEFN[crc_type]
            # Encode with a zero-valued CRC field
            self.fields[self.crc_value_name] = defn['encode'](0)
            pre_crc = cbor2.dumps(self.build())
            crc_int = defn['func'](pre_crc)
            valid = crc_value == defn['encode'](crc_int)
            # Restore old value
            self.fields[self.crc_value_name] = crc_value

        return valid


class PrimaryBlock(AbstractBlock):
    ''' The primary block definition '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Bundle flags.
        '''
        NONE = 0
        #: bundle deletion status reports are requested.
        REQ_DELETION_REPORT = 0x040000
        #: bundle delivery status reports are requested.
        REQ_DELIVERY_REPORT = 0x020000
        #: bundle forwarding status reports are requested.
        REQ_FORWARDING_REPORT = 0x010000
        #: bundle reception status reports are requested.
        REQ_RECEPTION_REPORT = 0x004000
        #: status time is requested in all status reports.
        REQ_STATUS_TIME = 0x000040
        #: user application acknowledgement is requested.
        USER_APP_ACK = 0x000020
        #: bundle must not be fragmented.
        NO_FRAGMENT = 0x000004
        #: payload is an administrative record.
        PAYLOAD_ADMIN = 0x000002
        #: bundle is a fragment.
        IS_FRAGMENT = 0x000001

    fields_desc = (
        UintField('bp_version', default=7),
        FlagsField('bundle_flags', default=Flag.NONE, flags=Flag),
        EnumField('crc_type', default=AbstractBlock.CrcType.NONE, enum=AbstractBlock.CrcType),
        EidField('destination'),
        EidField('source'),
        EidField('report_to'),
        PacketField('create_ts', default=Timestamp(), cls=Timestamp),
        UintField('lifetime', default=0),
        ConditionalField(
            UintField('fragment_offset', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT
        ),
        ConditionalField(
            UintField('total_app_data_len', default=0),
            lambda block: block.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT
        ),
        ConditionalField(
            BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )


class CanonicalBlock(AbstractBlock):
    ''' The canonical block definition with a type-specific payload.

    Any payload of this block is encoded as the "data" field when building
    and decoded from the "data" field when dissecting.
    '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Block flags.
        Flags must be in LSbit-first order.
        '''
        NONE = 0
        #: block must be removed from bundle if it can't be processed.
        REMOVE_IF_NO_PROCESS = 0x10
        #: bundle must be deleted if block can't be processed.
        DELETE_IF_NO_PROCESS = 0x04
        #: transmission of a status report is requested if block can't be processed.
        STATUS_IF_NO_PROCESS = 0x02
        #: block must be replicated in every fragment.
        REPLICATE_IN_FRAGMENT = 0x01

    fields_desc = (
        UintField('type_code', default=None),
        UintField('block_num', default=None),
        FlagsField('block_flags', default=Flag.NONE, flags=Flag),
        EnumField('crc_type', default=AbstractBlock.CrcType.NONE, enum=AbstractBlock.CrcType),
        BstrField('data', default=None),  # block-type-specific data here
        ConditionalField(
            BstrField('crc_value'),
            lambda block: block.crc_type != 0
        ),
    )

    def add_payload(self, payload):
        AbstractBlock.add_payload(self, payload)

        # Embed payload as field overload
        if 'data' not in self.overloaded_fields:
            pay_data = cbor2.dumps(self.payload.do_build())
            self.overloaded_fields['data'] = pay_data

    def do_build_payload(self):
        # Payload is handled by add_payload()
        return b''

    def post_dissect(self, s):
        # Extract payload from fields
        pay_type = self.fields.get('type_code')
        pay_data = self.fields.get('data')
        if (pay_data is not None and pay_type is not None):
            try:
                cls = self.guess_payload_class(None)
                LOGGER.debug('CanonicalBlock.post_dissect with %s: %s', cls, cbor2.loads(pay_data))
            except KeyError:
                cls = None

            if cls is not None:
                try:
                    pay = cls(cbor2.loads(pay_data))
                    self.add_payload(pay)
                except Exception as err:
                    if conf.debug_dissector:
                        raise
                    LOGGER.warning('CanonicalBlock failed to dissect payload: %s', err)

        return AbstractBlock.post_dissect(self, s)

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


@CanonicalBlock.bind_type(6)
class PreviousNodeBlock(CborItem):
    ''' Block data from BPbis Section 4.3.1.
    '''
    fields_desc = (
        EidField('node'),
    )


@CanonicalBlock.bind_type(7)
class BundleAgeBlock(CborItem):
    ''' Block data from BPbis Section 4.3.2.
    '''
    fields_desc = (
        UintField('age'),
    )


@CanonicalBlock.bind_type(10)
class HopCountBlock(CborArray):
    ''' Block data from BPbis Section 4.3.3.
    '''
    fields_desc = (
        UintField('limit'),
        UintField('count'),
    )
