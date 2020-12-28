''' Test the module :py:mod:`bp.blocks`.
'''
import binascii
import unittest
import scapy
from scapy_cbor.fields import *

scapy.config.conf.debug_dissector = True


class TestBoolField(unittest.TestCase):

    def testEncode(self):
        fld = BoolField('field')

        self.assertEqual(
            fld.i2m(None, True),
            True
        )
        self.assertEqual(
            fld.i2m(None, False),
            False
        )
        self.assertEqual(
            fld.i2m(None, 'hi'),
            True
        )

    def testDecode(self):
        fld = BoolField('field')

        self.assertEqual(
            fld.m2i(None, True),
            True
        )
        self.assertEqual(
            fld.m2i(None, False),
            False
        )
        self.assertEqual(
            fld.m2i(None, 'hi'),
            True
        )

    def testGetfield(self):
        fld = BoolField('field')
        s_init = [False, 0, 'hi']
        (s_final, val) = fld.getfield(None, s_init)
        self.assertEqual(s_final, [0, 'hi'])
        self.assertEqual(val, False)

    def testAddfield(self):
        fld = BoolField('field')
        s_init = [0, 'hi']
        val = False
        s_final = fld.addfield(None, s_init, val)
        self.assertEqual(s_final, [0, 'hi', False])


class TestUintField(unittest.TestCase):

    def testEncode(self):
        fld = UintField('field')

        self.assertEqual(
            fld.i2m(None, 0),
            0
        )
        self.assertEqual(
            fld.i2m(None, 10),
            10
        )
        with self.assertRaises(ValueError):
            fld.i2m(None, 'hi')

    def testDecode(self):
        fld = UintField('field')

        self.assertEqual(
            fld.m2i(None, 0),
            0
        )
        self.assertEqual(
            fld.m2i(None, 10),
            10
        )
        with self.assertRaises(ValueError):
            fld.m2i(None, 'hi')


class TestOptionalField(unittest.TestCase):

    def testEncode(self):
        fld = OptionalField(UintField('field'))

        self.assertEqual(
            fld.i2m(None, 10),
            10
        )
        self.assertEqual(
            fld.i2m(None, False),
            0
        )

    def testDecode(self):
        fld = OptionalField(UintField('field'))

        self.assertEqual(
            fld.m2i(None, 10),
            10
        )
        self.assertEqual(
            fld.m2i(None, False),
            0
        )

    def testGetfield(self):
        fld = OptionalField(UintField('field'))

        s_init = [10, 0, 'hi']
        (s_final, val) = fld.getfield(None, s_init)
        self.assertEqual(s_final, [0, 'hi'])
        self.assertEqual(val, 10)

        s_init = [None]
        (s_final, val) = fld.getfield(None, s_init)
        self.assertEqual(s_final, [])
        self.assertEqual(val, None)

        s_init = []
        (s_final, val) = fld.getfield(None, s_init)
        self.assertEqual(s_final, [])
        self.assertEqual(val, None)

    def testAddfield(self):
        fld = OptionalField(UintField('field'))

        s_init = [0, 'hi']
        val = 10
        s_final = fld.addfield(None, s_init, val)
        self.assertEqual(s_final, [0, 'hi', 10])

        s_init = [0, 'hi']
        val = False
        s_final = fld.addfield(None, s_init, val)
        self.assertEqual(s_final, [0, 'hi', False])

        s_init = [0, 'hi']
        val = None
        s_final = fld.addfield(None, s_init, val)
        self.assertEqual(s_final, [0, 'hi'])


class TestFieldListField(unittest.TestCase):

    def testEncode(self):
        fld = FieldListField('field', [], UintField('field'))

        self.assertEqual(
            fld.i2m(None, [0]),
            [0]
        )
        self.assertEqual(
            fld.i2m(None, [1, 2]),
            [1, 2]
        )

    def testDecode(self):
        fld = FieldListField('field', [], UintField('field'))

        self.assertEqual(
            fld.m2i(None, [0]),
            [0]
        )
        self.assertEqual(
            fld.m2i(None, [1, 2]),
            [1, 2]
        )

    def testGetfield(self):
        fld = FieldListField('field', [], UintField('field'))

        s_init = [1, 2]
        (s_final, val) = fld.getfield(None, s_init)
        self.assertEqual(s_final, [])
        self.assertEqual(val, [1, 2])

    def testAddfield(self):
        fld = FieldListField('field', [], UintField('field'))

        s_init = [0, 'hi']
        val = [1, 2]
        s_final = fld.addfield(None, s_init, val)
        self.assertEqual(s_final, [0, 'hi', 1, 2])
