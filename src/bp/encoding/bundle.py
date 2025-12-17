''' Whole bundle encodings and helper functions.
'''
import cbor2
from typing import Set
from scapy_cbor.fields import (PacketField, PacketListField)
from scapy_cbor.packets import (CborArray)
from .blocks import (PrimaryBlock, CanonicalBlock)
from .admin import AdminRecord


class Bundle(CborArray):
    ''' An entire decoded bundle contents.

    Bundles with administrative records are handled specially in that the
    AdminRecord object will be made a (scapy) payload of the "payload block"
    which is block type code 1.
    '''

    BLOCK_TYPE_PAYLOAD = 1
    BLOCK_NUM_PAYLOAD = 1

    fields_desc = (
        PacketField('primary', default=None, cls=PrimaryBlock),
        PacketListField('blocks', default=[], cls=CanonicalBlock),
    )

    def _update_from_admin(self):
        for blk in self.blocks:
            if isinstance(blk.payload, AdminRecord):
                self.primary.setfieldval('bundle_flags', self.primary.getfieldval('bundle_flags') | PrimaryBlock.Flag.PAYLOAD_ADMIN)
                blk.setfieldval('type_code', Bundle.BLOCK_TYPE_PAYLOAD)
                blk.setfieldval('btsd', bytes(blk.payload))

    def self_build(self, field_pos_list=None):
        # Special handling for admin payload
        self._update_from_admin()

        return CborArray.self_build(self, field_pos_list)

    def __bytes__(self):
        ''' Force the indefinite outer array.
        :return: The encoded bundle.
        '''
        item = self.build()
        data = b'\x9f' + b''.join(cbor2.dumps(part) for part in item) + b'\xff'
        return data

    def post_dissect(self, s):
        # Special handling for admin payload
        if self.primary and self.primary.getfieldval('bundle_flags') & PrimaryBlock.Flag.PAYLOAD_ADMIN:
            for blk in self.blocks:
                blk_data = blk.getfieldval('btsd')
                if (blk.type_code == Bundle.BLOCK_TYPE_PAYLOAD
                        and blk_data is not None):
                    pay = AdminRecord(blk_data)
                    blk.remove_payload()
                    blk.add_payload(pay)

        return CborArray.post_dissect(self, s)

    def fill_fields(self):
        ''' Fill all fields so that the bundle is the full size it needs
        to be for encoding encoding with build().
        Derived classes should populate their block-type-specific-data also.
        '''
        self._update_from_admin()
        if self.primary:
            self.primary.fill_fields()
        for blk in self.blocks:
            blk.fill_fields()

    def update_all_crc(self):
        ''' Update all CRC fields in this bundle which are not yet set.
        '''
        self._update_from_admin()
        if self.primary:
            self.primary.update_crc()
        for blk in self.blocks:
            blk.ensure_block_type_specific_data()
            blk.update_crc()

    def check_all_crc(self) -> Set[int]:
        ''' Check for CRC failures.

        :return: The set of block numbers with failed CRC check.
        '''
        fail = set()
        if self.primary:
            if not self.primary.check_crc():
                fail.add(0)
        for blk in self.blocks:
            if not blk.check_crc():
                fail.add(blk.block_num)
        return fail
