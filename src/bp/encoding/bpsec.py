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

    fields_desc = (
        ArrayWrapField(
            FieldListField('targets', default=[], fld=UintField('block_num'))
        ),
        UintField('context_id'),
        FlagsField('context_flags', default=Flag.NONE, flags=Flag),
        EidField('source'),
        ConditionalField(
            ArrayWrapField(
                PacketListField('parameters', default=None, cls=TypeValuePair),
            ),
            lambda block: block.getfieldval('context_flags') & AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
        ),
        ArrayWrapField(
            PacketListField('results', default=[], cls=TargetResultList),
        ),
    )


@CanonicalBlock.bind_type(11)
class BlockIntegrityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''


@CanonicalBlock.bind_type(12)
class BlockConfidentalityBlock(AbstractSecurityBlock):
    ''' Block data from 'draft-ietf-dtn-bpsec-22'
    '''
