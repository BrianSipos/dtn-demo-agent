''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
from bp.encoding.fields import (EidField, DtnTimeField)


class TestEidField(unittest.TestCase):

    def testEncodeEndpoint(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.i2m(None, 'dtn://node/serv'),
            item
        )

    def testDecodeEndpoint(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.m2i(None, item),
            'dtn://node/serv'
        )

    def testEncodeNodeid(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/',
        ]
        self.assertEqual(
            fld.i2m(None, 'dtn://node'), # normalized
            item
        )

    def testDecodeNodeid(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/',
        ]
        self.assertEqual(
            fld.m2i(None, item),
            'dtn://node/'
        )

    def testEncodePathonly(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '~mcast',
        ]
        self.assertEqual(
            fld.i2m(None, 'dtn:~mcast'),
            item
        )

    def testDecodePathonly(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '~mcast',
        ]
        self.assertEqual(
            fld.m2i(None, item),
            'dtn:~mcast'
        )


class TestDtnTimeField(unittest.TestCase):

    def testEncode(self):
        fld = DtnTimeField('field')

        self.assertEqual(
            fld.i2m(None, 1000),
            1000
        )

        lst = []
        lst = fld.addfield(None, lst, 1000)
        self.assertEqual(
            lst,
            [1000]
        )

    def testDecode(self):
        fld = DtnTimeField('field')

        self.assertEqual(
            fld.m2i(None, 1000),
            1000
        )

        lst = [1000]
        (lst, val) = fld.getfield(None, lst)
        self.assertEqual(lst, [])
        self.assertEqual(val, 1000)

    def testHumanEncode(self):
        fld = DtnTimeField('field')

        self.assertEqual(
            fld.i2h(None, 1000000),
            '2000-01-01T00:16:40+00:00',
        )

    def testHumanDecode(self):
        fld = DtnTimeField('field')

        self.assertEqual(
            fld.h2i(None, '2000-01-01T00:16:40+00:00'),
            1000000,
        )
