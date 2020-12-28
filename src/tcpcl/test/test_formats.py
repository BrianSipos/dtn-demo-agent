import binascii
import unittest

from scapy.packet import Packet

from .. import formats


class TestUInt16Field(unittest.TestCase):
    ''' Verify UInt16Field class '''
    
    class DummyPacket(Packet):
        fields_desc = [
            formats.UInt16Field('attr', None),
        ]
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = bytes(pkt)
        self.assertSequenceEqual(data, binascii.unhexlify(b'0000'))
        
        # Particular value
        testval = 0x30
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = bytes(pkt)
        self.assertSequenceEqual(data, binascii.unhexlify(b'0030'))
    
    def testDeserialize(self):
        testval = 0x40
        data = binascii.unhexlify(b'0040')
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 2)
        self.assertEqual(pkt.getfieldval('attr'), testval)

class TestSdnvField(unittest.TestCase):
    ''' Verify SdnvField class '''
    
    class DummyPacket(Packet):
        fields_desc = [
            formats.SdnvField('attr', default=None),
        ]
        
        def __init__(self, *args, **kwargs):
            Packet.__init__(self, *args, **kwargs)
            self.explicit = 1
    
    def testSerialize(self):
        pkt = self.DummyPacket()
        fld = pkt.get_field('attr')
        self.assertIsNone(fld.default)
        
        # Default value
        self.assertIsNone(pkt.getfieldval('attr'))
        self.assertIsNone(pkt.attr)
        data = bytes(pkt)
        self.assertSequenceEqual(data, binascii.unhexlify(b'00'))
        
        # Particular value
        testval = 12345
        pkt.setfieldval('attr', testval)
        self.assertEqual(pkt.getfieldval('attr'), testval)
        self.assertEqual(pkt.attr, testval)
        data = bytes(pkt)
        self.assertSequenceEqual(data, binascii.unhexlify(b'e039'))
    
    def testDeserialize(self):
        testval = 12345
        data = binascii.unhexlify(b'e039')
        pkt = self.DummyPacket(data)
        self.assertEqual(len(pkt), 2)
        self.assertEqual(pkt.getfieldval('attr'), testval)

