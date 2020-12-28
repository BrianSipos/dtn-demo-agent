import binascii
import unittest

from .. import contact


MAGIC_HEX = b'64746e21'

class TestContact(unittest.TestCase):
    
    def testSerialize(self):
        pkt = contact.Head()/contact.ContactV4()
        self.assertEqual(binascii.hexlify(bytes(pkt)),
                         MAGIC_HEX + b'04' + b'00')
        
        pkt = contact.Head()/contact.ContactV4(
            flags='CAN_TLS',
        )
        pkt.show()
        self.assertEqual(binascii.hexlify(bytes(pkt)), 
                         MAGIC_HEX + b'04' + b'01')

    def testDeserialize(self):
        pkt = contact.Head(binascii.unhexlify(MAGIC_HEX + b'04' + b'00'))
        self.assertEqual(pkt.magic, b'dtn!')
        self.assertEqual(pkt.version, 4)
        self.assertFalse(pkt.flags & contact.ContactV4.Flag.CAN_TLS)
        
        pkt = contact.Head(binascii.unhexlify(MAGIC_HEX + b'04' + b'01'))
        pkt.show()
        self.assertEqual(pkt.version, 4)
        self.assertTrue(pkt.flags & contact.ContactV4.Flag.CAN_TLS)
