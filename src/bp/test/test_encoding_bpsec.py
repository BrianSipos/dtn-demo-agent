''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
from bp.encoding.fields import (EidField)
from bp.encoding.bpsec import (TargetResultList, TypeValuePair, 
                               BlockIntegrityBlock)
from bp.test.base import BaseTestPacket


class TestBlockIntegrityBlock(BaseTestPacket):

    def testEncode(self):
        pkt = BlockIntegrityBlock(
            targets=[1, 2],
            context_id=3,
            context_flags=0,
            source='dtn://nodeA/',
            results=[
                TargetResultList(results=[
                    TypeValuePair(type_code=1, value='hi'),
                ]),
                TargetResultList(results=[
                    TypeValuePair(type_code=2, value=False),
                ]),
            ]
        )
        item = [
            [1, 2],
            3,
            0,
            [1, '//nodeA/'],
            [
                [
                    [1, 'hi'],
                ],
                [
                    [2, False],
                ],
            ],
        ]
        self.assertEqual(self._encode(pkt), item)

    def testDecode(self):
        item = [
            [1, 2],
            3,
            0,
            [1, '//nodeA/'],
            [
                [
                    [1, 'hi'],
                ],
                [
                    [2, False],
                ],
            ],
        ]
        pkt = self._decode(BlockIntegrityBlock, item)
        fields = dict(
            targets=[1, 2],
            context_id=3,
            context_flags=0,
            source='dtn://nodeA/',
            results=[
                TargetResultList(results=[
                    TypeValuePair(type_code=1, value='hi'),
                ]),
                TargetResultList(results=[
                    TypeValuePair(type_code=2, value=False),
                ]),
            ]
        )
        self.assertEqual(pkt.fields, fields)
