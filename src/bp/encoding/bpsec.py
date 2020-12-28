''' Blocks for BPSEC.
'''
import enum
from scapy_cbor.fields import (
    ConditionalField, ArrayWrapField,
    UintField, FlagsField, FieldListField, PacketListField,
)
from scapy_cbor.packets import (CborArray, TypeValueHead)
from .fields import EidField
from .blocks import CanonicalBlock


class SecurityParameter(TypeValueHead):
    ''' Header for a security parameter, the payload is the value.
    '''


class SecurityResult(TypeValueHead):
    ''' Header for a security result, the payload is the value.
    '''


class AbstractSecurityBlock(CborArray):
    ''' Block data from 'draft-ietf-dtn-bpsec-22' Section 3.6.
    '''

    @enum.unique
    class Flag(enum.IntFlag):
        ''' Security flags.
        Flags must be in LSbit-first order.
        '''
        NONE = 0
        PARAMETERS_PRESENT = 2 ** 0
        SOURCE_PRESENT = 2 ** 1

    fields_desc = (
        ArrayWrapField(
            FieldListField('targets', default=[], fld=UintField('block_num'))
        ),
        UintField('context_id'),
        FlagsField('context_flags', default=Flag.NONE, flags=Flag),
        ConditionalField(
            EidField('source', default=None),
            lambda block: block.context_flags & AbstractSecurityBlock.Flag.SOURCE_PRESENT
        ),
        ConditionalField(
            ArrayWrapField(
                PacketListField('parameters', default=None, cls=SecurityParameter),
            ),
            lambda block: block.context_flags & AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
        ),
        ArrayWrapField(
            PacketListField('results', default=None, cls=SecurityResult),
        ),
    )


@CanonicalBlock.bind_type(192)
class BlockIntegrityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''


@CanonicalBlock.bind_type(193)
class BlockConfidentalityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''

