''' Test the module :py:mod:`bp.blocks`.
'''
import unittest
from scapy.config import conf
from bp.encoding.fields import (EidField)

conf.debug_dissector = True

#: Encoded "dtn:none" URI
DTN_NONE = [int(EidField.TypeCode.dtn), 0]


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
