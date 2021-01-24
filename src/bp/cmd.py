''' Command entry points.
'''
import argparse
import logging
import sys
from urllib.parse import urlsplit
from gi.repository import GLib as glib
import multiprocessing

from bp.config import Config
from bp.agent import Agent
import tcpcl
import tcpcl.cmd
import udpcl

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
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--config-file', type=str,
                        help='Configuration file to load from')
    parser.add_argument('--eloop', type=str2bool, default=True,
                        help='If enabled, waits in an event loop.')
    subp = parser.add_subparsers(dest='action', help='action')

    parser_ping = subp.add_parser('ping',
                                  help='Send an admin record')
    parser_ping.add_argument('destination', type=uristr)

    args = parser.parse_args()

    log_level = args.log_level.upper()
    log_queue = tcpcl.cmd.root_logging(log_level)
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)

    agent = Agent(config)

    CHILD_INFO = {
        'tcpcl': {
            'config': tcpcl.Config,
            'agent': tcpcl.Agent,
        },
        'udpcl': {
            'config': udpcl.Config,
            'agent': udpcl.Agent,
        },
    }
    for cl_type in config.cl_fork:
        try:
            info = CHILD_INFO[cl_type]
        except KeyError:
            LOGGER.warning('Ignored unknown cl_fork name: %s', cl_type)
            continue

        cl_config = info['config']()
        with open(args.config_file, 'rb') as infile:
            cl_config.from_file(infile)

        # Fork CL child
        def run_cl(cl_config):
            tcpcl.cmd.root_logging(log_level, log_queue)
            logging.getLogger().info('CL child started: %s', cl_type)
            agent = info['agent'](cl_config)
            agent.exec_loop()
            logging.getLogger().info('CL child ended: %s', cl_type)

        LOGGER.info('Spawning CL process for %s', cl_config.bus_service)
        worker_proc = multiprocessing.Process(target=run_cl, args=[cl_config])
        worker_proc.start()
    else:
        worker_proc = None

    for (cltype, servname) in config.cl_attach.items():
        # Immediately attach to the CL
        glib.idle_add(agent.cl_attach, cltype, servname)

    if args.action == 'ping':
        agent.ping(args.destination)

    if args.eloop:
        agent.exec_loop()

    if worker_proc:
        worker_proc.join()


if __name__ == '__main__':
    sys.exit(main())
