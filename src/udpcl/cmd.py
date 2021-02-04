''' Command entry points.
'''
import argparse
from binascii import unhexlify
import logging
import sys
from gi.repository import GLib as glib

from udpcl.config import Config, ListenConfig
from udpcl.agent import Agent


def root_logging(log_level, log_queue=None):
    ''' Initialize multiprocessing-safe logging.
    '''
    import multiprocessing
    from logging.handlers import QueueHandler, QueueListener

    if log_queue is None:
        log_queue = multiprocessing.Queue()

        # ql gets records from the queue and sends them to the stream handler
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s PID:%(process)s TID:%(threadName)s <%(levelname)s> %(name)s: %(message)s"))
        ql = QueueListener(log_queue, handler)
        ql.start()

    # Root logger gets queued
    logger = logging.getLogger()
    logger.setLevel(log_level)
    for hdl in logger.handlers:
        logger.removeHandler(hdl)

    qh = QueueHandler(log_queue)
    logger.addHandler(qh)

    return log_queue


def main(*argv):
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--config-file', type=str,
                        help='Configuration file to load from')
    subp = parser.add_subparsers(dest='action', help='action')

    parser_listen = subp.add_parser('listen',
                                    help='Listen for TCP connections')
    parser_listen.add_argument('--address', type=str, default='',
                               help='Listen name or address')
    parser_listen.add_argument('--port', type=int, default=4556,
                               help='Listen TCP port')

    args = parser.parse_args(argv[1:])
    log_queue = root_logging(args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)
    config.validate()

    if args.action == 'listen':
        config.init_listen.append(
            ListenConfig(address=args.address, port=args.port)
        )

    agent = Agent(config)

    def init_padding():
        pad = unhexlify('00000000')
        agent.send_bundle_data('224.0.0.1', 4556, pad)
        agent.send_bundle_data('ff02::1', 4556, pad)
        return None

    #glib.idle_add(init_padding)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
