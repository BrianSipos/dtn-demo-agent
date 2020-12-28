''' Whole bundle encodings and helper functions.
'''
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

    fields_desc = (
        PacketField('primary', default=None, cls=PrimaryBlock),
        PacketListField('blocks', default=[], cls=CanonicalBlock),
    )

    def _update_from_admin(self):
        for blk in self.blocks:
            if isinstance(blk.payload, AdminRecord):
                self.primary.bundle_flags |= PrimaryBlock.Flag.PAYLOAD_ADMIN
                blk.overloaded_fields['type_code'] = 1
                blk.overloaded_fields['data'] = bytes(blk.payload)

    def self_build(self, field_pos_list=None):
        # Special handling for admin payload
        self._update_from_admin()

        return CborArray.self_build(self, field_pos_list)

    def post_dissect(self, s):
        # Special handling for admin payload
        if self.primary and self.primary.bundle_flags & PrimaryBlock.Flag.PAYLOAD_ADMIN:
            for blk in self.blocks:
                if blk.type_code == 1 and blk.data is not None:
                    pay = AdminRecord(blk.data)
                    blk.remove_payload()
                    blk.add_payload(pay)

        return CborArray.post_dissect(self, s)

    def update_all_crc(self):
        ''' Update all CRC fields in this bundle which are not yet set.
        '''
        self._update_from_admin()
        if self.primary:
            self.primary.update_crc()
        for blk in self.blocks:
            blk.update_crc()

    def check_all_crc(self):
        ''' Check for CRC failures.
        '''
        fail = set()
        if self.primary:
            if not self.primary.check_crc():
                fail.add(0)
        for blk in self.blocks:
            if not blk.check_crc():
                fail.add(blk.block_num)
        return fail
