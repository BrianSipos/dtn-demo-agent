''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
import cbor2
from binascii import (hexlify, unhexlify)
from scapy.config import conf
from bp.encoding.fields import (EidField)
from bp.encoding.blocks import (Timestamp, PrimaryBlock, CanonicalBlock,
                                PreviousNodeBlock, BundleAgeBlock, 
                                HopCountBlock)
from bp.encoding.bundle import (Bundle)
from bp.test.base import (DTN_NONE, BaseTestPacket)

conf.debug_dissector = True


class TestPrimaryBlock(BaseTestPacket):

    def testEncodeDefault(self):
        blk = PrimaryBlock()
        item = [
            7,
            0,
            0,
            DTN_NONE,
            DTN_NONE,
            DTN_NONE,
            [0, 0],
            0,
        ]
        self.assertEqual(self._encode(blk), item)

    def testEncodeNofragment(self):
        blk = PrimaryBlock(
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            create_ts=Timestamp(time=1000000, seqno=5),
            lifetime=300,
        )
        self.assertEqual(
            self._encode(blk),
            [
                7,
                0,
                2,
                [EidField.TypeCode.dtn, '//dst/'],
                [EidField.TypeCode.dtn, '//src/'],
                [EidField.TypeCode.dtn, '//rpt/'],
                [1000000, 5],
                300,
                None,
            ]
        )

    def testDecodeNofragment(self):
        item = [
            7,
            0,
            2,
            [EidField.TypeCode.dtn, '//dst/'],
            [EidField.TypeCode.dtn, '//src/'],
            [EidField.TypeCode.dtn, '//rpt/'],
            [1000000, 5],
            300,
            None,
        ]
        blk = self._decode(PrimaryBlock, item)
        fields = dict(
            bp_version=7,
            bundle_flags=0,
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            create_ts=Timestamp(time=1000000, seqno=5),
            lifetime=300,
            crc_value=None,
        )
        self.assertEqual(blk.fields, fields)

    def testEncodeFragment(self):
        blk = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.IS_FRAGMENT,
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            create_ts=Timestamp(
                time='2000-01-01T00:16:40+00:00',
                seqno=3,
            ),
            lifetime=300,
            fragment_offset=1000,
            total_app_data_len=2000,
        )
        self.assertEqual(
            self._encode(blk),
            [
                7,
                1,
                2,
                [EidField.TypeCode.dtn, '//dst/'],
                [EidField.TypeCode.dtn, '//src/'],
                [EidField.TypeCode.dtn, '//rpt/'],
                [1000000, 3],
                300,
                1000,
                2000,
                None
            ]
        )

    def testDecodeFragment(self):
        item = [
            7,
            1,
            2,
            [EidField.TypeCode.dtn, '//dst/'],
            [EidField.TypeCode.dtn, '//src/'],
            [EidField.TypeCode.dtn, '//rpt/'],
            [1000000, 3],
            300,
            1000,
            2000,
            None
        ]
        blk = self._decode(PrimaryBlock, item)
        fields = dict(
            bp_version=7,
            bundle_flags=1,
            crc_type=2,
            destination='dtn://dst/',
            source='dtn://src/',
            report_to='dtn://rpt/',
            create_ts=Timestamp(time=1000000, seqno=3),
            lifetime=300,
            fragment_offset=1000,
            total_app_data_len=2000,
            crc_value=None,
        )
        self.assertEqual(blk.fields, fields)


class TestCanonicalBlock(BaseTestPacket):

    def testEncodeDefault(self):
        blk = CanonicalBlock()
        self.assertEqual(
            self._encode(blk),
            [
                None,
                None,
                0,
                0,
                None,
            ]
        )

    def testEncodeNoData(self):
        blk = CanonicalBlock(
            type_code=3,
            block_num=8,
        )
        self.assertEqual(
            self._encode(blk),
            [
                3,
                8,
                0,
                0,
                None,
            ]
        )

    def testEncodeRawData(self):
        blk = CanonicalBlock(
            type_code=1,
            block_num=8,
            btsd=b'hi'
        )
        self.assertEqual(
            self._encode(blk),
            [
                1,
                8,
                0,
                0,
                b'hi'
            ]
        )


class TestBundle(BaseTestPacket):

    def testEncodeEmpty(self):
        bdl = Bundle()
        self.assertEqual(
            self._encode(bdl),
            [
                None,  # missing primary
            ]
        )
        self.assertEqual(
            hexlify(bytes(bdl)),
            b'9ff6ff'
        )

    def testEncodeOnlyPrimary(self):
        bdl = Bundle(
            primary=PrimaryBlock(
            ),
        )
        self.assertEqual(
            self._encode(bdl),
            [
                [
                    7,
                    0,
                    0,
                    DTN_NONE,
                    DTN_NONE,
                    DTN_NONE,
                    [0, 0],
                    0,
                ],
            ]
        )
        self.assertEqual(
            hexlify(bytes(bdl)),
            b'9f8807000082010082010082010082000000ff'
        )

    def testDecodeOnlyPrimary(self):
        item = [
            [
                7,
                0,
                0,
                DTN_NONE,
                DTN_NONE,
                DTN_NONE,
                [1000, 5],
                0,
            ],
        ]
        bdl = self._decode(Bundle, item)

        self.assertIsNotNone(bdl.primary)
        blk = bdl.primary
        fields = dict(
            bp_version=7,
            bundle_flags=0,
            crc_type=0,
            destination='dtn:none',
            source='dtn:none',
            report_to='dtn:none',
            create_ts=Timestamp(time=1000, seqno=5),
            lifetime=0,
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(len(bdl.blocks), 0)

    def testEncodePayload(self):
        pyld_data = cbor2.dumps(['some', 'data'])
        bdl = Bundle(
            primary=PrimaryBlock(),
            blocks=[
                CanonicalBlock(
                    block_num=1,
                    btsd=pyld_data,
                ),
            ]
        )
        self.assertEqual(
            self._encode(bdl),
            [
                [
                    7,
                    0,
                    0,
                    DTN_NONE,
                    DTN_NONE,
                    DTN_NONE,
                    [0, 0],
                    0,
                ],
                [
                    None,
                    1,
                    0,
                    0,
                    pyld_data,
                ],
            ]
        )

    def testDecodePayload(self):
        pyld_data = cbor2.dumps(['some', 'data'])
        item = [
            [
                7,
                0,
                0,
                DTN_NONE,
                DTN_NONE,
                DTN_NONE,
                [0, 0],
                0,
            ],
            [
                1,
                8,
                0,
                0,
                pyld_data,
            ],
        ]
        bdl = self._decode(Bundle, item)

        blk = bdl.primary
        self.assertIsNotNone(blk)
        fields = dict(
            bp_version=7,
            bundle_flags=0,
            crc_type=0,
            destination='dtn:none',
            source='dtn:none',
            report_to='dtn:none',
            create_ts=Timestamp(time=0, seqno=0),
            lifetime=0,
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(len(bdl.blocks), 1)
        blk = bdl.blocks[0]
        fields = dict(
            type_code=1,
            block_num=8,
            block_flags=0,
            crc_type=0,
            btsd=pyld_data
        )
        self.assertEqual(blk.fields, fields)


class TestPreviousNodeBlock(BaseTestPacket):

    def testEncode(self):
        blk = CanonicalBlock() / PreviousNodeBlock(node='dtn://node/serv')

        item = [
            6,
            None,
            0,
            0,
            cbor2.dumps([
                EidField.TypeCode.dtn,
                '//node/serv',
            ]),
        ]
        self.assertEqual(
            self._encode(blk),
            item
        )

    def testDecode(self):
        item = [
            6,
            None,
            0,
            0,
            cbor2.dumps([
                EidField.TypeCode.dtn,
                '//node/serv',
            ]),
        ]
        blk = self._decode(CanonicalBlock, item)
        fields = dict(
            type_code=6,
            block_num=None,
            block_flags=0,
            crc_type=0,
            btsd=unhexlify('82016b2f2f6e6f64652f73657276')
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(type(blk.payload), PreviousNodeBlock)
        fields = dict(
            node='dtn://node/serv',
        )
        self.assertEqual(blk.payload.fields, fields)


class TestBundleAgeBlock(BaseTestPacket):

    def testEncode(self):
        blk = CanonicalBlock() / BundleAgeBlock(age=10)

        self.assertEqual(
            self._encode(blk),
            [
                7,
                None,
                0,
                0,
                cbor2.dumps(10),
            ]
        )

    def testDecode(self):
        item = [
            7,
            None,
            0,
            0,
            cbor2.dumps(10),
        ]
        blk = self._decode(CanonicalBlock, item)
        fields = dict(
            type_code=7,
            block_num=None,
            block_flags=0,
            crc_type=0,
            btsd=unhexlify('0a')
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(type(blk.payload), BundleAgeBlock)
        fields = dict(
            age=10,
        )
        self.assertEqual(blk.payload.fields, fields)


class TestHopCountBlock(BaseTestPacket):

    def testEncode(self):
        blk = CanonicalBlock() / HopCountBlock(
            limit=10,
            count=5,
        )

        item = [
            10,
            None,
            0,
            0,
            cbor2.dumps([10, 5]),
        ]
        self.assertEqual(
            self._encode(blk),
            item
        )

    def testDecode(self):
        item = [
            10,
            None,
            0,
            0,
            cbor2.dumps([10, 5]),
        ]
        blk = self._decode(CanonicalBlock, item)
        fields = dict(
            type_code=10,
            block_num=None,
            block_flags=0,
            crc_type=0,
            btsd=unhexlify('820a05')
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(type(blk.payload), HopCountBlock)
        fields = dict(
            limit=10,
            count=5,
        )
        self.assertEqual(blk.payload.fields, fields)
