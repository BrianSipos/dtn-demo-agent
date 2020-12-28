#!/usr/bin/python3
''' A dummy bundle data generator.
'''
import argparse
import io
import logging
import random
import shutil
import string
import struct
import sys
import enum
import unittest

import cbor2
import crcmod
from gi.repository import GLib as glib


LOGGER = logging.getLogger(__name__)

CRC_DEFN = {
    1: {  # BPv7 CRC-16 X.25
        'func': crcmod.predefined.mkPredefinedCrcFun('x-25'),
        'encode': lambda val: struct.pack('>H', val)
    },
    2: {  # BPv7 CRC-32 Castagnoli
        'func': crcmod.predefined.mkPredefinedCrcFun('crc-32c'),
        'encode': lambda val: struct.pack('>L', val)
    },
}


class TestBundleGen(unittest.TestCase):

    def testCrc16Itu(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/16.htm#crc.cat.crc-16-ibm-sdlc>
        self.assertEqual(0x906e, CRC_DEFN[1]['func'](b'123456789'))

    def testCrc32C(self):
        # Test from <http://reveng.sourceforge.net/crc-catalogue/17plus.htm#crc.cat.crc-32c>
        self.assertEqual(0xe3069283, CRC_DEFN[2]['func'](b'123456789'))


def binaryCborTag(value):
    ''' Encode CBOR as bytestring and tag the item.

    :param value: The CBOR item to encode.
    :return: The binary-enveloped item.
    '''
    # Tag 24: Encoded CBOR data item
    return cbor2.CBORTag(24, cbor2.dumps(value))


class Block(object):
    ''' Represent an abstract block with CRC fields.
    '''

    def __init__(self, fields, crc_type_ix=None, crc_field_ix=None):
        self.fields = fields
        self.crc_type_ix = crc_type_ix
        self.crc_field_ix = crc_field_ix

    def update_crc(self):
        if self.crc_type_ix is None or self.crc_field_ix is None:
            return
        defn = CRC_DEFN[self.fields[self.crc_type_ix]]

        self.fields[self.crc_field_ix] = defn['encode'](0)
        pre_crc = cbor2.dumps(self.fields)
        crc_int = defn['func'](pre_crc)
        crc_value = defn['encode'](crc_int)
        self.fields[self.crc_field_ix] = crc_value


def randtext(sizemax=100):
    size = random.randint(0, sizemax)
    return u''.join([random.choice(string.printable) for _ in range(size)])


def randbytes(sizemax=100):
    size = random.randint(0, sizemax)
    return bytes(bytearray([random.randint(0, 255) for _ in range(size)]))


def randdtntime():
    ''' Generate a random DTN time.
    20% of the time this will be the invalid/unknown time value.
    '''
    if random.uniform(0, 1) < 0.2:
        return 0
    else:
        return random.randint(1, 1e10)


def randnodeid():
    ''' Generate a random Node ID.
    50% of the time this will be a DTN URI.
    50% of the time this will be an IPN URI.
    '''
    scheme = random.choice([1, 2])
    if scheme == 1:
        if random.uniform(0, 0) < 0.2:
            ssp = 0
        else:
            ssp = randtext()
    elif scheme == 2:
        ssp = [random.randint(0, 2 ** 15), random.randint(0, 2 ** 15)]
    return [scheme, ssp]


def randtimestamp():
    ''' Generate a random timestamp tuple.
    '''
    return [randdtntime(), random.randint(0, 1e3)]


def randstatus():
    ''' Generate a random Bundle Status Report information tuple.
    50% of the time this will include a time.
    '''
    result = []
    result.append(random.choice([False, True]))
    if random.uniform(0, 1) < 0.5:
        result.append(randdtntime())
    return result


def randcboritem(maxdepth=10):
    ''' Generate an arbitrary random CBOR data structure.
    '''
    direct_types = [None, bool, int, float, bytes, str]
    contain_types = [list, dict]

    if maxdepth == 0:
        possible_types = direct_types
    else:
        possible_types = direct_types + contain_types

    itemtype = random.choice(possible_types)

    if itemtype is None:
        return None
    elif itemtype is bool:
        return random.choice([False, True])
    elif itemtype is int:
        return random.randint(-1e3, 1e3)
    elif itemtype is float:
        return random.uniform(-1e3, 1e3)
    elif itemtype is bytes:
        return randbytes()
    elif itemtype is str:
        return randtext()
    elif itemtype is list:
        size = random.randint(0, 10)
        return [randcboritem(maxdepth - 1) for _ in range(size)]
    elif itemtype is dict:
        size = random.randint(0, 10)
        return dict([
            (randtext(8), randcboritem(maxdepth - 1))
            for _ in range(size)
        ])


class Generator(object):
    ''' A 'bundle' data generator.
    '''
    
    BLOCK_NUM_PRIMARY = 1
    BLOCK_TYPE_PRIMARY = 1
    BLOCK_TYPE_BIB = 99  #FIXME: not a real allocation
    BLOCK_TYPE_BCB = 98  #FIXME: not a real allocation
    
    @enum.unique
    class BlockType(enum.IntFlag):
        ''' Non-primary block types. '''
        PREV_NODE = 6
        BUNDLE_AGE = 7
        HOP_COUNT = 10

    def create_block_data(self, block_type, block_flags, bundle_flags):
        ''' Block-type-specific data gerator.
        '''
        if block_type == self.BLOCK_TYPE_PRIMARY and bundle_flags & 0x0002:
            # Admin record
            admin_type = 1
            admin_data = [  # Status Report
                [  # Status info
                    randstatus(),  # Reporting node received bundle
                    randstatus(),  # Reporting node forwarded the bundle
                    randstatus(),  # Reporting node delivered the bundle
                    randstatus(),  # Reporting node deleted the bundle
                ],
                random.randint(0, 9),  # Reason code
                randnodeid(),  # Source Node ID
                randtimestamp(),  # Creation timestamp
            ]
            return binaryCborTag([
                admin_type,
                admin_data,
            ])
        elif block_type == self.BlockType.PREV_NODE:
            # Previous Node
            return binaryCborTag(randnodeid())
        elif block_type == self.BlockType.BUNDLE_AGE:
            # Bundle Age
            return binaryCborTag(random.randint(0, 1e10))
        elif block_type == self.BlockType.HOP_COUNT:
            # Hop Count
            return binaryCborTag([
                random.randint(0, 1e1),  # limit
                random.randint(0, 1e1),  # current
            ])
        elif block_type in (self.BLOCK_TYPE_BIB, self.BLOCK_TYPE_BCB):
            @enum.unique
            class Flag(enum.IntEnum):
                HAS_PARAMS = 0x01
                HAS_SOURCE = 0x02
            
            ctx_id = 1
            sec_flags = Flag.HAS_PARAMS | Flag.HAS_SOURCE
            return binaryCborTag([
                [ # targets
                    1, # just primary
                ],
                ctx_id,
                sec_flags,
                randnodeid(),
                [ # parameters
                    [1, b'hi'],
                ],
                [
                    [ # result target #1
                        [96, b'there'],
                    ],
                ],
            ])

        return cbor2.dumps(randcboritem())

    def create_block_random(self, block_type, bundle_flags, unused_blocknum):
        block_flags = random.getrandbits(8)
        block_num = random.choice(tuple(unused_blocknum))
        unused_blocknum.remove(block_num)
        block = Block(
            [  # extenstion
                block_type,  # block type
                block_num,  # block number
                block_flags,  # block flags
                random.randint(0, 2),  # CRC type
                self.create_block_data(block_type, block_flags, bundle_flags),  # block data
            ],
            crc_type_ix=3
        )
        has_crc = block.fields[block.crc_type_ix] != 0
        if has_crc:
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        return block

    def create_invalid_random(self):
        ''' Generate a purely random data.

        :return: A single bundle file.
        :rtype: file-like
        '''
        return io.BytesIO(randbytes(random.randint(1000, 10000)))

    def create_invalid_cbor(self):
        ''' Generate a valid-CBOR content which is not really a bundle.

        :return: A single bundle file.
        :rtype: file-like
        '''
        return io.BytesIO(cbor2.dumps(randcboritem()))

    def create_valid(self):
        ''' Generate a random, but structurally valid, encoded bundle.

        :return: A single bundle file.
        :rtype: file-like
        '''
        bundle_flags = random.getrandbits(16)
        blocks = []
        block = Block(
            [  # primary block
                7,  # BP version
                bundle_flags,  # bundle flags
                random.randint(1, 2),  # CRC type
                randnodeid(),
                randnodeid(),
                randnodeid(),
                randtimestamp(),  # creation timestamp
                random.randint(0, 24 * 60 * 60 * 1e6),  # lifetime (us)
            ],
            crc_type_ix=2,
        )
        is_fragment = block.fields[1] & 0x0001
        if is_fragment:
            block.fields.append(random.randint(0, 1e4))  # fragment offset
            block.fields.append(random.randint(0, 1e4))  # total application data unit length
        has_crc = block.fields[block.crc_type_ix] != 0
        if has_crc:
            block.fields.append(None)
            block.crc_field_ix = len(block.fields) - 1
        blocks.append(block)

        unused_blocknum = set(range(2, 30))
        # Non-payload blocks
        for _ in range(random.randint(0, 4)):
            block_type = random.choice([obj.value for obj in self.BlockType])
            block = self.create_block_random(block_type, bundle_flags, unused_blocknum)
            blocks.append(block)
        if True:
            block_type = random.choice([self.BLOCK_TYPE_BIB, self.BLOCK_TYPE_BCB])
            block = self.create_block_random(block_type, bundle_flags, unused_blocknum)
            blocks.append(block)
        # Last block is payload
        if True:
            block_type = self.BLOCK_TYPE_PRIMARY
            block = self.create_block_random(block_type, bundle_flags, {self.BLOCK_NUM_PRIMARY})
            blocks.append(block)

        buf = io.BytesIO()
        if True:
            # Self-describe CBOR Tag
            buf.write(b'\xd9\xd9\xf7')
        buf.write(b'\x9F')
        for block in blocks:
            block.update_crc()
            cbor2.dump(block.fields, buf)
        buf.write(b'\xFF')
        buf.seek(0)
        return buf


def bundle_iterable(genmode, gencount):
    ''' A generator to yield encoded bundles as file-like objects.
    '''
    gen = Generator()
    if genmode == 'fullvalid':
        # Some valid bundles
        func = gen.create_valid
    elif genmode == 'randcbor':
        # Some valid-but-random CBOR
        func = gen.create_invalid_cbor
    elif genmode == 'randbytes':
        # Some genuine random data
        func = gen.create_invalid_random

    for _ in range(gencount):
        yield func()


def agent_send_bundles(agent, contact, iterable):
    ''' A glib callback to send a sequence of bundles and then shutdown the agent.

    :type agent: :py:class:`tcpcl.agent.Agent`
    :type contact: :py:class:`tcpcl.agent.ContactHandler`
    :param iterable: An iterable object which produces file-like bundles.
    '''
    for bundle in iterable:
        contact.send_bundle_fileobj(bundle)

    def check_done():
        ''' Periodic callback to exit the event loop once the session is idle.
        '''
        LOGGER.debug('Checking idle status...')
        if contact.is_sess_idle():
            contact.terminate()
            return False
        # keep checking
        return True

    glib.timeout_add(100, check_done)

    return False


def main():
    import multiprocessing
    from dbus.mainloop.glib import DBusGMainLoop
    import tcpcl.agent

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Names of test modes enabled')
    parser.add_argument('--segment-mru', type=int, default=None,
                        help='Entity maximum segment data size')
    parser.add_argument('genmode',
                        choices=('fullvalid', 'randcbor', 'randbytes'),
                        help='Type of "bundle" to generate.')
    parser.add_argument('gencount', type=int,
                        help='Number of bundles to transfer.')
    parser.add_argument('--to-file', type=str, default=None,
                        metavar='NAMEPREFIX',
                        help='If this option is provided the bundles are written to file instead of sent over network.')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    if args.to_file:
        for (ix, bundle) in enumerate(bundle_iterable(args.genmode, args.gencount)):
            file_name = '{0}{1}.cbor'.format(args.to_file, ix)
            LOGGER.info('Writing bundle to %s', file_name)
            with open(file_name, 'wb') as outfile:
                shutil.copyfileobj(bundle, outfile)
        return 0

    # (address,port) combo to use TCPCL on
    address = ('localhost', 4556)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config_pasv = tcpcl.agent.Config()
    config_pasv.stop_on_close = True
    config_pasv.enable_test = args.enable_test
    if args.segment_mru:
        config_pasv.segment_size_mru = args.segment_mru

    def run_pasv(config):
        agent = tcpcl.agent.Agent(config)
        agent.listen(*address)
        agent.exec_loop()

    config_actv = tcpcl.agent.Config()
    config_actv.stop_on_close = True
    config_actv.enable_test = args.enable_test
    if args.segment_mru:
        config_actv.segment_size_mru = args.segment_mru

    def run_actv(config):
        agent = tcpcl.agent.Agent(config)
        path = agent.connect(*address)
        contact = agent.handler_for_path(path)
        contact.set_on_session_start(lambda: agent_send_bundles(agent, contact, bundle_iterable(args.genmode, args.gencount)))
        agent.exec_loop()

    worker_pasv = multiprocessing.Process(target=run_pasv, args=[config_pasv])
    worker_pasv.start()
    worker_actv = multiprocessing.Process(target=run_actv, args=[config_actv])
    worker_actv.start()

    worker_actv.join()
    worker_pasv.join()


if __name__ == '__main__':
    sys.exit(main())
