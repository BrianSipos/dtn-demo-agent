''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
import cbor2
import scapy.packet
from scapy.config import conf
from bp.encoding import *
from binascii import (hexlify, unhexlify)

#: Encoded "dtn:none" URI
DTN_NONE = [int(EidField.TypeCode.dtn), 0]

conf.debug_dissector = True


class TestEidField(unittest.TestCase):

    def testEncode(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.i2m(None, 'dtn://node/serv'),
            item
        )

    def testDecode(self):
        fld = EidField('field')

        item = [
            EidField.TypeCode.dtn,
            '//node/serv',
        ]
        self.assertEqual(
            fld.m2i(None, item),
            'dtn://node/serv'
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
            fld.i2h(None, 1000),
            '2000-01-01T00:16:40+00:00',
        )

    def testHumanDecode(self):
        fld = DtnTimeField('field')

        self.assertEqual(
            fld.h2i(None, '2000-01-01T00:16:40+00:00'),
            1000,
        )


class BaseTestPacket(unittest.TestCase):
    ''' Include helper functions for scapy packet handling.
    '''

    def _encode(self, pkt):
        pkt.show()
        return pkt.build()

    def _decode(self, cls, item):
        pkt = cls(item)
        pkt.show()
        return pkt


class TestTimestamp(BaseTestPacket):

    def testEncodeDefault(self):
        pkt = Timestamp()
        item = [
            0,
            0,
        ]
        self.assertEqual(self._encode(pkt), item)

    def testDecodeDefault(self):
        item = [
            0,
            0,
        ]
        blk = self._decode(Timestamp, item)
        fields = dict(
            time=0,
            seqno=0,
        )
        self.assertEqual(blk.fields, fields)

    def testEncodeValue(self):
        pkt = Timestamp(
            time='2000-01-01T00:16:40+00:00',
            seqno=3,
        )
        item = [
            1000,
            3,
        ]
        self.assertEqual(self._encode(pkt), item)

    def testDecodeValue(self):
        item = [
            1000,
            3,
        ]
        blk = self._decode(Timestamp, item)
        fields = dict(
            time=1000,
            seqno=3,
        )
        self.assertEqual(blk.fields, fields)


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
            create_ts=Timestamp(time=1000, seqno=5),
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
                [1000, 5],
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
            [1000, 5],
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
            create_ts=Timestamp(time=1000, seqno=5),
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
                [1000, 3],
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
            [1000, 3],
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
            create_ts=Timestamp(time=1000, seqno=3),
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
            data=b'hi'
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
                    data=pyld_data,
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
            data=pyld_data
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
            data=unhexlify('82016b2f2f6e6f64652f73657276')
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
            data=unhexlify('0a')
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
            data=unhexlify('820a05')
        )
        self.assertEqual(blk.fields, fields)

        self.assertEqual(type(blk.payload), HopCountBlock)
        fields = dict(
            limit=10,
            count=5,
        )
        self.assertEqual(blk.payload.fields, fields)


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


class TestBlockIntegrityBlock(BaseTestPacket):

    def testEncode(self):
        pkt = BlockIntegrityBlock(
            targets=[1, 2],
            context_id=3,
            context_flags=0,
            results=[
                SecurityResult(type_code=1) / CborItem(item='hi'),
                SecurityResult(type_code=2) / CborItem(item=False),
            ]
        )
        item = [
            [1, 2],
            3,
            0,
            [
                [1, 'hi'],
                [2, False],
            ],
        ]
        self.assertEqual(self._encode(pkt), item)

    def testDecode(self):
        item = [
            [1, 2],
            3,
            0,
            [
                [1, 'hi'],
                [2, False],
            ],
        ]
        pkt = self._decode(BlockIntegrityBlock, item)
        fields = dict(
            targets=[1, 2],
            context_id=3,
            context_flags=0,
            results=[
                SecurityResult(type_code=1) / CborItem(item='hi'),
                SecurityResult(type_code=2) / CborItem(item=False),
            ]
        )
        self.assertEqual(pkt.fields, fields)
