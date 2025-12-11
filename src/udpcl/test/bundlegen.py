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

from tcpcl.test.bundlegen import (
    Generator
)


LOGGER = logging.getLogger(__name__)


def bundle_iterable(genmode, gencount, indata):
    ''' A generator to yield encoded bundles as file-like objects.
    '''
    gen = Generator()
    if genmode == 'stdin':
        def func(): return io.BytesIO(indata)
    elif genmode == 'fullvalid':
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


def agent_xfer_bundles(agent, tx_params={}, tx_queue=[], rx_count=0):
    ''' A glib callback to send a sequence of bundles and then shutdown the agent.

    :type agent: :py:class:`udpcl.agent.Agent`
    :param tx_params: Parameters to provide with each TX item.
    :param tx_queue: An iterable object which produces file-like bundles.
    :param rx_count: The number of bundles to recieve before stopping.
    '''
    for bundle in tx_queue:
        agent.send_bundle_fileobj(bundle, tx_params)

    # capture the value as a persistant object
    rx_count = [rx_count]

    def check_done():
        ''' Periodic callback to exit the event loop once the session is idle.
        '''
        for bid in agent.recv_bundle_get_queue():
            LOGGER.debug('Ignoring received transfer ID: %s', bid)
            agent.recv_bundle_pop_data(bid)
            rx_count[0] -= 1

        idle = agent.is_transfer_idle()
        LOGGER.debug('Checking idle status: %s %s', rx_count[0], idle)
        if idle and rx_count[0] == 0:
            agent.stop()
            return False
        # keep checking
        return True

    glib.timeout_add(100, check_done)


def main():
    import multiprocessing
    from dbus.mainloop.glib import DBusGMainLoop
    import udpcl.agent

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Names of test modes enabled')
    parser.add_argument('--use-tls', type=bool, default=False,
                        help='Enable DTLS operation')
    parser.add_argument('--mtu-default', type=int, default=None,
                        help='Entity maximum transmit size')
    parser.add_argument('genmode',
                        choices=('stdin', 'fullvalid', 'randcbor', 'randbytes'),
                        help='Type of "bundle" to generate.')
    parser.add_argument('--gencount', type=int,
                        default=1,
                        help='Number of bundles to transfer.')
    parser.add_argument('--to-file', type=str, default=None,
                        metavar='NAMEPREFIX',
                        help='If this option is provided the bundles are written to file instead of sent over network.')
    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    indata = sys.stdin.buffer.read() if args.genmode == 'stdin' else None
    bit = bundle_iterable(args.genmode, args.gencount, indata)

    if args.to_file:
        for (ix, bundle) in enumerate(bit):
            file_name = '{0}{1}.cbor'.format(args.to_file, ix)
            LOGGER.info('Writing bundle to %s', file_name)
            with open(file_name, 'wb') as outfile:
                shutil.copyfileobj(bundle, outfile)
        return 0

    # (address,port) combo to use UDPCL on
    address = ('127.0.0.1', 4556)
    listening = multiprocessing.Semaphore(value=0)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config_pasv = udpcl.agent.Config()
    config_pasv.enable_test = args.enable_test
    config_pasv.dtls_enable_tx = config_pasv.require_tls = args.use_tls
    config_pasv.mtu_default = args.mtu_default

    def run_pasv(config):
        agent = udpcl.agent.Agent(config)
        agent.listen(*address)
        listening.release()
        agent_xfer_bundles(agent, rx_count=args.gencount)
        agent.exec_loop()

    config_actv = udpcl.agent.Config()
    config_actv.enable_test = args.enable_test
    config_actv.dtls_enable_tx = config_actv.require_tls = args.use_tls
    config_actv.mtu_default = args.mtu_default

    def run_actv(config):
        agent = udpcl.agent.Agent(config)
        listening.acquire()
        tx_params = dict(
            address=address[0],
            port=address[1]
        )
        agent_xfer_bundles(agent, tx_params, bit)
        agent.exec_loop()

    worker_pasv = multiprocessing.Process(target=run_pasv, args=[config_pasv])
    worker_pasv.start()
    worker_actv = multiprocessing.Process(target=run_actv, args=[config_actv])
    worker_actv.start()

    worker_actv.join()
    worker_pasv.join()


if __name__ == '__main__':
    sys.exit(main())
