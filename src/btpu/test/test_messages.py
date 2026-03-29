import unittest
from scapy.packet import Raw, Padding, NoPayload
from btpu.messages import (
    MessageHead, DefinitePadding, BundlePdu, TransferEnd,
    HintHead, MessageSet
)


class TestDefinitePadding(unittest.TestCase):

    def test_encode_simple(self):
        pkt = MessageHead()/DefinitePadding(load=bytes.fromhex('000000'))
        self.assertEqual(
            bytes(pkt).hex(),
            '010' + '00003' + '000000'
        )

    def test_decode_simple(self):
        pkt = MessageHead(bytes.fromhex(
            '010' + '00003' + '000000'
        ))
        self.assertEqual(pkt.msg_type, 1)
        self.assertEqual(pkt.flags, 0)
        self.assertEqual(pkt.length, 3)
        self.assertListEqual(pkt.hints, [])
        self.assertIsInstance(pkt.payload, DefinitePadding)
        self.assertEqual(pkt.payload.load, bytes.fromhex('000000'))

    def test_decode_extra(self):
        pkt = MessageHead(bytes.fromhex(
            '010' + '00003' + '000000' + '010203'
        ))
        self.assertEqual(pkt.msg_type, 1)
        self.assertEqual(pkt.flags, 0)
        self.assertEqual(pkt.length, 3)
        self.assertListEqual(pkt.hints, [])
        self.assertIsInstance(pkt.payload, DefinitePadding)
        self.assertEqual(pkt.payload.load, bytes.fromhex('000000'))
        self.assertIsInstance(pkt.payload.payload, Padding)


class TestBundle(unittest.TestCase):

    def test_encode_simple(self):
        pkt = MessageHead()/BundlePdu(load=bytes.fromhex('9fff'))
        self.assertEqual(
            bytes(pkt).hex(),
            '020' + '00002' + '9fff'
        )

    def test_encode_hint(self):
        pkt = MessageHead(
            hints=[HintHead(hint_type=0)/Raw(bytes.fromhex('02'))]
        )/BundlePdu(load=bytes.fromhex('9fff'))
        self.assertEqual(
            bytes(pkt).hex(),
            '028' + '00005' + '000102' + '9fff'
        )

    def test_decode_simple(self):
        pkt = MessageHead(bytes.fromhex(
            '020' + '00002' + '9fff'
        ))
        self.assertEqual(pkt.msg_type, 2)
        self.assertEqual(pkt.flags, 0)
        self.assertEqual(pkt.length, 2)
        self.assertListEqual(pkt.hints, [])
        self.assertIsInstance(pkt.payload, BundlePdu)
        self.assertEqual(pkt.payload.load, bytes.fromhex('9fff'))

    def test_decode_with_padding(self):
        pkt = MessageHead(bytes.fromhex(
            '020' + '00002' + '9fff' + '0000000000'
        ))
        self.assertEqual(pkt.msg_type, 2)
        self.assertEqual(pkt.flags, 0)
        self.assertEqual(pkt.length, 2)
        self.assertListEqual(pkt.hints, [])
        self.assertIsInstance(pkt.payload, BundlePdu)
        self.assertEqual(pkt.payload.load, bytes.fromhex('9fff'))
        self.assertIsInstance(pkt.payload.payload, Padding)
        self.assertEqual(pkt.payload.payload.load, bytes.fromhex('0000000000'))


class TestTransfer(unittest.TestCase):

    def test_encode_simple(self):
        pkt = MessageHead()/TransferEnd(xfer_num=1)/Raw(bytes.fromhex('9fff'))
        self.assertEqual(
            bytes(pkt).hex(),
            '040' + '0000a' + '00000001' + '00000000' + '9fff'
        )

    def test_decode_simple(self):
        pkt = MessageHead(bytes.fromhex(
            '040' + '0000a' + '00000001' + '00000000' + '9fff'
        ))
        self.assertEqual(pkt.msg_type, 4)
        self.assertEqual(pkt.flags, 0)
        self.assertEqual(pkt.length, 10)
        self.assertListEqual(pkt.hints, [])
        self.assertIsInstance(pkt.payload, TransferEnd)
        self.assertEqual(pkt.payload.xfer_num, 1)
        self.assertEqual(pkt.payload.seg_idx, 0)
        self.assertEqual(pkt.payload.payload.load, bytes.fromhex('9fff'))

    def test_encode_hint(self):
        pkt = MessageHead(
            hints=[HintHead(hint_type=0)/Raw(bytes.fromhex('02'))]
        )/TransferEnd(xfer_num=1)/Raw(bytes.fromhex('9fff'))
        self.assertEqual(
            bytes(pkt).hex(),
            '048' + '0000d' + '000102' + '00000001' + '00000000' + '9fff'
        )

    def test_decode_hint(self):
        pkt = MessageHead(bytes.fromhex(
            '048' + '0000d' + '000102' + '00000001' + '00000000' + '9fff'
        ))
        self.assertEqual(pkt.msg_type, 4)
        self.assertEqual(pkt.flags, 0x8)
        self.assertEqual(pkt.length, 13)
        self.assertListEqual(pkt.hints, [HintHead(hint_type=0, h_flag=0, length=1)/Raw(bytes.fromhex('02'))])
        self.assertIsInstance(pkt.payload, TransferEnd)
        self.assertEqual(pkt.payload.xfer_num, 1)
        self.assertEqual(pkt.payload.seg_idx, 0)
        self.assertEqual(pkt.payload.payload.load, bytes.fromhex('9fff'))


class TestMessageSet(unittest.TestCase):

    def test_encode_single(self):
        pkt = MessageSet(msgs=[
            MessageHead()/BundlePdu(load=bytes.fromhex('9fff')),
        ])
        self.assertEqual(
            bytes(pkt).hex(),
            '020' + '00002' + '9fff'
        )

    def test_encode_two(self):
        pkt = MessageSet(msgs=[
            MessageHead()/BundlePdu(load=bytes.fromhex('9fff')),
            MessageHead()/BundlePdu(load=bytes.fromhex('9fff')),
        ])
        self.assertEqual(
            bytes(pkt).hex(),
            '020' + '00002' + '9fff'
            '020' + '00002' + '9fff'
        )

    def test_decode_single(self):
        pkt = MessageSet(bytes.fromhex(
            '020' + '00002' + '9fff'
        ))
        self.assertEqual(len(pkt.msgs), 1)
        for msg in pkt.msgs:
            self.assertEqual(msg.msg_type, 2)
            self.assertEqual(msg.length, 2)
            self.assertListEqual(msg.hints, [])
            self.assertIsInstance(msg.payload, BundlePdu)
            self.assertEqual(msg.payload.load, bytes.fromhex('9fff'))
        self.assertIsInstance(pkt.payload, NoPayload)

    def test_decode_two(self):
        pkt = MessageSet(bytes.fromhex(
            '020' + '00002' + '9fff'
            '020' + '00002' + '9fff'
        ))
        self.assertEqual(len(pkt.msgs), 2)
        for msg in pkt.msgs:
            self.assertEqual(msg.msg_type, 2)
            self.assertEqual(msg.length, 2)
            self.assertListEqual(msg.hints, [])
            self.assertIsInstance(msg.payload, BundlePdu)
            self.assertEqual(msg.payload.load, bytes.fromhex('9fff'))
        self.assertIsInstance(pkt.payload, NoPayload)

    def test_decode_with_padding(self):
        pkt = MessageSet(bytes.fromhex(
            '020' + '00002' + '9fff'
            '00000000'
        ))
        self.assertEqual(len(pkt.msgs), 1)
        for msg in pkt.msgs:
            self.assertEqual(msg.msg_type, 2)
            self.assertEqual(msg.length, 2)
            self.assertListEqual(msg.hints, [])
            self.assertIsInstance(msg.payload, BundlePdu)
            self.assertEqual(msg.payload.load, bytes.fromhex('9fff'))
        self.assertIsInstance(pkt.payload, Raw)
        self.assertEqual(pkt.payload.load, bytes.fromhex('00000000'))
