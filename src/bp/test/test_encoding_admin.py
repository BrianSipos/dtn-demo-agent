''' Test the module :py:mod:`bp.blocks`.
'''
from scapy_cbor.packets import CborItem
from bp.encoding.admin import (AdminRecord, StatusInfo)
from bp.test.base import (BaseTestPacket)


class TestAdminRecord(BaseTestPacket):

    def testEncodeEmpy(self):
        pkt = AdminRecord()

        self.assertEqual(
            self._encode(pkt),
            [
                None,
                None
            ]
        )

    def testDecodeEmpty(self):
        item = [
            None,
            None,
        ]
        pkt = self._decode(AdminRecord, item)
        fields = dict(
            type_code=None,
        )
        self.assertEqual(pkt.fields, fields)

        self.assertTrue(isinstance(pkt.payload, CborItem), type(pkt.payload))


class TestStatusInfo(BaseTestPacket):

    def testEncode(self):
        pkt = StatusInfo(
            status=True,
            at=1000,
        )
        self.assertEqual(
            self._encode(pkt),
            [
                True,
                1000
            ]
        )

    def testDecode(self):
        item = [
            True,
            1000,
        ]
        pkt = self._decode(StatusInfo, item)
        fields = dict(
            status=True,
            at=1000,
        )
        self.assertEqual(pkt.fields, fields)
