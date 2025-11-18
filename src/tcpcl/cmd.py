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
    parser.add_argument('--log-level', dest='log_level',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--config-file', type=str,
                        help='Configuration file to load from')
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
    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
