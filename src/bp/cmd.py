''' Command entry points.
'''
import argparse
import logging
import sys
from urllib.parse import urlsplit
from gi.repository import GLib as glib

from tcpcl.cmd import root_logging
from bp.config import Config
from bp.agent import Agent

LOGGER = logging.getLogger(__name__)


def str2bool(val):
    ''' Require an option value to be boolean text.
    '''
    if val.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if val.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected')


def uristr(val):
    ''' Require an option value to be a URI.
    '''
    nodeid_uri = urlsplit(val)
    if not nodeid_uri.scheme:
        raise argparse.ArgumentTypeError('URI value expected')
    return val


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

    parser_ping = subp.add_parser('ping',
                                  help='Send an admin record')
    parser_ping.add_argument('destination', type=uristr)

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

    agent = Agent(config)

    for (cltype, servname) in config.cl_attach.items():
        # Immediately attach to the CL
        glib.idle_add(agent.cl_attach, cltype, servname)

    if args.action == 'ping':
        agent.ping(args.destination)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main())
