''' Command entry points.
'''
import argparse
import logging
import sys
from tcpcl.config import Config, ListenConfig, ConnectConfig
from tcpcl.agent import Agent


def root_logging(log_level):
    ''' Initialize logging.
    '''
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s PID:%(process)s TID:%(threadName)s <%(levelname)s> %(name)s: %(message)s"
    )


def main():
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser()
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

    parser_conn = subp.add_parser('connect',
                                  help='Make a TCP connection')
    parser_conn.add_argument('address', type=str,
                             help='Host name or address')
    parser_conn.add_argument('--port', type=int, default=4556,
                             help='Host TCP port')

    args = parser.parse_args()
    root_logging(args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)

    if args.action == 'listen':
        config.init_listen.append(
            ListenConfig(address=args.address, port=args.port)
        )
    elif args.action == 'connect':
        config.init_connect.append(
            ConnectConfig(address=args.address, port=args.port)
        )

    agent = Agent(config)
    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
