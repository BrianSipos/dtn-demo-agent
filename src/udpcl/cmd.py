''' Command entry points.
'''
import argparse
from binascii import unhexlify
import logging
import sys
from gi.repository import GLib as glib

from tcpcl.cmd import root_logging
from udpcl.config import Config, ListenConfig
from udpcl.agent import Agent


def main():
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level',
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

    args = parser.parse_args()

    root_logging(args.log_level.upper() if args.log_level else 'WARNING')
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)
    if config.log_level and not args.log_level:
        logging.getLogger().setLevel(config.log_level.upper())

    if args.action == 'listen':
        config.init_listen.append(
            ListenConfig(address=args.address, port=args.port)
        )

    agent = Agent(config)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
