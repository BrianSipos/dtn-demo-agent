''' Test the module :py:mod:`bp.blocks`.
'''
import binascii
import unittest
import scapy
from scapy.packet import (bind_layers)
from scapy_cbor.fields import (UintField, TstrField)
from scapy_cbor.packets import (CborArray, CborItem, TypeValueHead)

scapy.config.conf.debug_dissector = True


class MockItem(CborItem):
    ''' A test structure. '''
    fields_desc = [
        TstrField('item', default=None),
    ]


class TestCborItem(unittest.TestCase):

    def testEncode(self):
        pkt = MockItem(item='hi')
        cbor_item = 'hi'

        self.assertEqual(
            pkt.self_build(),
            cbor_item
        )
        self.assertEqual(
            pkt.do_build(),
            cbor_item
        )
        self.assertEqual(
            pkt.build(),
            cbor_item
        )

        self.assertEqual(
            binascii.hexlify(bytes(pkt)),
            b'626869'
        )

    def testDecodeConstructor(self):
        cbor_item = 'hi'
        pkt = MockItem(cbor_item)
        self.assertEqual('hi', pkt.item)

    def testDecodeDissect(self):
        cbor_item = 'hi'
        pkt = MockItem()
        pkt.dissect(cbor_item)
        self.assertEqual('hi', pkt.item)

    def testDecodeBytes(self):
        cbor_bytes = binascii.unhexlify(b'626869')
        pkt = MockItem(cbor_bytes)
        self.assertEqual('hi', pkt.item)


class MockArray(CborArray):
    ''' A test structure. '''
    fields_desc = [
        UintField('fld_a', default=None),
        UintField('fld_b', default=None),
    ]


class TestCborArray(unittest.TestCase):

    def testEncode(self):
        pkt = MockArray(
            fld_a=3,
            fld_b=5,
        )

        cbor_item = [3, 5]
        self.assertEqual(
            pkt.self_build(),
            cbor_item
        )

        self.assertEqual(
            pkt.do_build(),
            cbor_item
        )

        self.assertEqual(
            pkt.build(),
            cbor_item
        )

        self.assertEqual(
            binascii.hexlify(bytes(pkt)),
            b'820305'
        )

    def testDecodeConstructor(self):
        cbor_item = [3, 5]
        pkt = MockArray(cbor_item)
        fields = dict(
            fld_a=3,
            fld_b=5,
        )
        self.assertEqual(pkt.fields, fields)

    def testDecodeDissect(self):
        cbor_item = [3, 5]
        pkt = MockArray()
        pkt.dissect(cbor_item)
        fields = dict(
            fld_a=3,
            fld_b=5,
        )
        self.assertEqual(pkt.fields, fields)

    def testDecodeBytes(self):
        cbor_bytes = binascii.unhexlify(b'820305')
        pkt = MockArray(cbor_bytes)
        fields = dict(
            fld_a=3,
            fld_b=5,
        )
        self.assertEqual(pkt.fields, fields)


class MockValueHead(TypeValueHead):
    ''' Derived class for binding test. '''


class TestTypeValueHead(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super(TestTypeValueHead, cls).setUpClass()
        bind_layers(MockValueHead, MockItem, type_code=1)
        bind_layers(MockValueHead, MockArray, type_code=2)

    def testEncodeEmpty(self):
        pkt = MockValueHead()

        cbor_item = [None, None]
        self.assertEqual(
            pkt.build(),
            cbor_item
        )

    def testDecodeEmpty(self):
        cbor_item = [None, None]
        pkt = MockValueHead(cbor_item)
        self.assertTrue(isinstance(pkt.payload, CborItem), type(pkt.payload))
        fields = dict(
            item=None,
        )
        self.assertEqual(pkt.payload.fields, fields)

    def testEncodeItem(self):
        pkt = MockValueHead() / MockItem(
            item='hi',
        )

        cbor_item = [1, 'hi']
        self.assertEqual(
            pkt.build(),
            cbor_item
        )

    def testDecodeItem(self):
        cbor_item = [1, 'hi']
        pkt = MockValueHead(cbor_item)

        self.assertTrue(isinstance(pkt.payload, MockItem))
        fields = dict(
            item='hi',
        )
        self.assertEqual(pkt.payload.fields, fields)

    def testEncodeArray(self):
        pkt = MockValueHead() / MockArray(
            fld_a=3,
            fld_b=5,
        )

        cbor_item = [2, [3, 5]]
        self.assertEqual(
            pkt.build(),
            cbor_item
        )

    def testDecodeArray(self):
        cbor_item = [2, [3, 5]]
        pkt = MockValueHead(cbor_item)

        self.assertTrue(isinstance(pkt.payload, MockArray))
        fields = dict(
            fld_a=3,
            fld_b=5,
        )
        self.assertEqual(pkt.payload.fields, fields)
