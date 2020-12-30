''' Blocks for BPSEC.
'''
import enum
from scapy_cbor.fields import (
    ConditionalField, ArrayWrapField,
    CborField, UintField, FlagsField, FieldListField, PacketListField,
)
from scapy_cbor.packets import CborArray
from .fields import EidField
from .blocks import CanonicalBlock


class TypeValuePair(CborArray):
    ''' A pattern for an array encoding which contains exactly two values.
    '''

    fields_desc = (
        UintField('type_code'),
        CborField('value'),
    )


class TargetResultList(CborArray):
    ''' A list of results for a single target.
    '''
    fields_desc = (
        PacketListField('results', default=None, cls=TypeValuePair),
    )


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
                PacketListField('parameters', default=None, cls=TypeValuePair),
            ),
            lambda block: block.context_flags & AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
        ),
        ArrayWrapField(
            PacketListField('results', default=[], cls=TargetResultList),
        ),
    )


@CanonicalBlock.bind_type(192)  #FIXME: not a real allocation
class BlockIntegrityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''


@CanonicalBlock.bind_type(193)  #FIXME: not a real allocation
class BlockConfidentalityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''
