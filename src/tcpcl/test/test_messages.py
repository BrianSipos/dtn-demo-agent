import binascii
import unittest

from scapy.packet import Raw

from .. import extend
from ..messages import (MessageHead,
                        SessionInit, SessionExtendHeader, SessionTerm,
                        TransferSegment, TransferExtendHeader, TransferAck,
                        TransferRefuse, Keepalive, RejectMsg)


class TestSessionInit(unittest.TestCase):
    
    def testSerializeDefault(self):
        pkt = MessageHead()/SessionInit()
        self.assertEqual(
            binascii.hexlify(bytes(pkt)),
            b'07' + b'0000' + b'ffffffffffffffff' + b'ffffffffffffffff' + b'0000' + b'00000000'
        )

    def testSerializeNoExt(self):
        pkt = MessageHead()/SessionInit(
            keepalive=300,
            nodeid_data=b'hello',
            segment_mru=1024,
            transfer_mru=10240,
        )
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)), 
            b'07' + b'012c' + b'0000000000000400' + b'0000000000002800' + b'0005' + binascii.hexlify(b'hello')
            + b'00000000'
        )

    def testDeserializeNoExt(self):
        pkt = MessageHead(binascii.unhexlify(
            b'07' + b'012c' + b'0000000000000400' + b'0000000000002800'
            + b'0005' + binascii.hexlify(b'hello') 
            + b'00000000'
        ))
        self.assertEqual(pkt.msg_id, 7)
        self.assertIsInstance(pkt.payload, SessionInit)
        self.assertEqual(pkt.payload.keepalive, 300)
        self.assertEqual(pkt.payload.segment_mru, 1024)
        self.assertEqual(pkt.payload.transfer_mru, 10240)
        self.assertEqual(pkt.payload.nodeid_data, 'hello')
        self.assertEqual(len(pkt.payload.ext_items), 0)

    def testSerializeEmptyExt(self):
        pkt = MessageHead()/SessionInit(
            keepalive=300,
            nodeid_data='hello',
            segment_mru=1024,
            transfer_mru=10240,
            ext_items=[
                SessionExtendHeader(flags='CRITICAL', type=0xfffe)/Raw(b'exthi')
            ],
        )
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)), 
            b'07' + b'012c' + b'0000000000000400' + b'0000000000002800' + b'0005' + binascii.hexlify(b'hello')
            # extensions:
            + b'0000000a'
            + b'01' + b'fffe' + b'0005' + binascii.hexlify(b'exthi')
        )

    def testDeserializeEmptyExt(self):
        pkt = MessageHead(binascii.unhexlify(
            b'07' + b'012c' + b'0000000000000400' + b'0000000000002800' + b'0005' + binascii.hexlify(b'hello')
            # extensions:
            + b'0000000a'
            + b'01' + b'fffe' + b'0005' + binascii.hexlify(b'exthi')
        ))
        self.assertEqual(pkt.msg_id, 7)
        self.assertIsInstance(pkt.payload, SessionInit)
        self.assertEqual(pkt.payload.keepalive, 300)
        self.assertEqual(pkt.payload.segment_mru, 1024)
        self.assertEqual(pkt.payload.transfer_mru, 10240)
        self.assertEqual(pkt.payload.nodeid_data, 'hello')
        self.assertEqual(len(pkt.payload.ext_items), 1)
        # Items:
        item = pkt.payload.ext_items[0]
        self.assertIsInstance(item, SessionExtendHeader)
        self.assertEqual(item.flags, SessionExtendHeader.Flag.CRITICAL)
        self.assertEqual(item.type, 0xfffe)
        self.assertEqual(item.length, 5)
        self.assertIsInstance(item.payload, Raw)
        self.assertEqual(item.payload.load, b'exthi')

class TestSessionTerm(unittest.TestCase):
    
    def testSerializeNoReason(self):
        pkt = MessageHead()/SessionTerm()
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'050000')

    def testDeserializeNoReason(self):
        pkt = MessageHead(binascii.unhexlify(b'05' + b'0000'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.reason, SessionTerm.Reason.UNKNOWN)

    def testSerializeWithReason(self):
        pkt = MessageHead()/SessionTerm(reason=3)
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'050003')

    def testDeserializeWithReason(self):
        pkt = MessageHead(binascii.unhexlify(b'05' + b'0003'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.reason, 3)

    def testSerializeAck(self):
        pkt = MessageHead()/SessionTerm(flags=SessionTerm.Flag.REPLY, reason=4)
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'050104')

    def testDeserializeAck(self):
        pkt = MessageHead(binascii.unhexlify(b'05' + b'0104'))
        self.assertEqual(pkt.msg_id, 5)
        self.assertIsInstance(pkt.payload, SessionTerm)
        self.assertEqual(pkt.payload.flags, SessionTerm.Flag.REPLY)
        self.assertEqual(pkt.payload.reason, 4)

class TestKeepalive(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/Keepalive()
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'04')

    def testDeserialize(self):
        pkt = MessageHead(binascii.unhexlify(b'0400'))
        self.assertEqual(pkt.msg_id, 4)
        self.assertIsInstance(pkt.payload, Keepalive)

class TestRejectMsg(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/RejectMsg(rej_msg_id=7, reason=RejectMsg.Reason.UNSUPPORTED)
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'060702')

    def testDeserialize(self):
        pkt = MessageHead(binascii.unhexlify(b'060702'))
        self.assertEqual(pkt.msg_id, 6)
        self.assertIsInstance(pkt.payload, RejectMsg)
        self.assertEqual(pkt.payload.rej_msg_id, 7)
        self.assertEqual(pkt.payload.reason, RejectMsg.Reason.UNSUPPORTED)

class TestTransferRefuse(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/TransferRefuse(transfer_id=1234, reason=TransferRefuse.Reason.NO_RESOURCES)
        self.assertSequenceEqual(binascii.hexlify(bytes(pkt)), b'03' + b'02' + b'00000000000004d2')

    def testDeserialize(self):
        pkt = MessageHead(binascii.unhexlify(b'03' + b'02' + b'00000000000004d2'))
        self.assertEqual(pkt.msg_id, 3)
        self.assertIsInstance(pkt.payload, TransferRefuse)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.reason, TransferRefuse.Reason.NO_RESOURCES)

class TestTransferSegment(unittest.TestCase):

    def testSerializeStartNoExt(self):
        pkt = MessageHead()/TransferSegment(flags=TransferSegment.Flag.START, transfer_id=1234, data=b'hello')
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)),
            b'01' + b'02' + b'00000000000004d2' 
            + b'00000000' 
            + b'0000000000000005' + binascii.hexlify(b'hello')
        )

    def testDeserializeStartNoExt(self):
        pkt = MessageHead(binascii.unhexlify(
            b'01' + b'02' + b'00000000000004d2' 
            + b'00000000' 
            + b'0000000000000005' + binascii.hexlify(b'hello')
        ))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.Flag.START)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), b'hello')
        
        self.assertEqual(pkt.payload.ext_size, 0)
        self.assertEqual(len(pkt.payload.ext_items), 0)

    def testSerializeStartLengthExt(self):
        pkt = MessageHead()/TransferSegment(
            flags=TransferSegment.Flag.START, 
            transfer_id=1234,
            ext_items=[
                TransferExtendHeader(flags='CRITICAL')/extend.TransferTotalLength(total_length=800)
            ],
            data=b'hello',
        )
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)),
            b'01' + b'02' + b'00000000000004d2' 
            # extensions:
            + b'0000000d'
            + b'01' + b'0001' + b'0008' + b'0000000000000320'
            # data
            + b'0000000000000005' + binascii.hexlify(b'hello')
        )

    def testDeserializeStartLengthExt(self):
        pkt = MessageHead(binascii.unhexlify(
            b'01' + b'02' + b'00000000000004d2' 
            + b'0000000d'
            + b'01' + b'0001' + b'0008' + b'0000000000000320'
            + b'0000000000000005' + binascii.hexlify(b'hello')
        ))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.Flag.START)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), b'hello')

        self.assertEqual(pkt.payload.ext_size, 13)
        self.assertEqual(len(pkt.payload.ext_items), 1)
        # Items:
        item = pkt.payload.ext_items[0]
        self.assertIsInstance(item, TransferExtendHeader)
        self.assertEqual(item.flags, TransferExtendHeader.Flag.CRITICAL)
        self.assertEqual(item.type, 1)
        self.assertEqual(item.length, 8)
        self.assertIsInstance(item.payload, extend.TransferTotalLength)
        self.assertEqual(item.payload.total_length, 800)

    def testSerializeMidData(self):
        pkt = MessageHead()/TransferSegment(transfer_id=1234, data=b'hello')
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)),
            b'01' + b'00' + b'00000000000004d2' + b'0000000000000005' + binascii.hexlify(b'hello')
        )

    def testDeserializeMidData(self):
        pkt = MessageHead(binascii.unhexlify(
            b'01' + b'00' + b'00000000000004d2' + b'0000000000000005' + binascii.hexlify(b'hello')
        ))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, 0)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), b'hello')

    def testSerializeEndData(self):
        pkt = MessageHead()/TransferSegment(flags=TransferSegment.Flag.END, transfer_id=1234, data=b'hello')
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)), 
            b'01' + b'01' + b'00000000000004d2' + b'0000000000000005' + binascii.hexlify(b'hello')
        )

    def testDeserializeEndData(self):
        pkt = MessageHead(binascii.unhexlify(
            b'01' + b'01' + b'00000000000004d2' 
            + b'0000000000000005' + binascii.hexlify(b'hello')
        ))
        self.assertEqual(pkt.msg_id, 1)
        self.assertIsInstance(pkt.payload, TransferSegment)
        self.assertEqual(pkt.payload.flags, TransferSegment.Flag.END)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 5)
        self.assertEqual(pkt.payload.getfieldval('data'), b'hello')

class TestTransferAck(unittest.TestCase):
    
    def testSerialize(self):
        pkt = MessageHead()/TransferAck(transfer_id=1234, flags=TransferSegment.Flag.END, length=43210)
        self.assertSequenceEqual(
            binascii.hexlify(bytes(pkt)),
            b'02' + b'01' + b'00000000000004d2' + b'000000000000a8ca'
        )

    def testDeserialize(self):
        pkt = MessageHead(binascii.unhexlify(
            b'02' + b'01' + b'00000000000004d2' + b'000000000000a8ca'
        ))
        self.assertEqual(pkt.msg_id, 2)
        self.assertIsInstance(pkt.payload, TransferAck)
        self.assertEqual(pkt.payload.flags, TransferSegment.Flag.END)
        self.assertEqual(pkt.payload.transfer_id, 1234)
        self.assertEqual(pkt.payload.length, 43210)
