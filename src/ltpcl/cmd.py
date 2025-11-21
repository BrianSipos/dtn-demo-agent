''' Command entry points.
'''
import argparse
import logging
import sys
from dbus.mainloop.glib import DBusGMainLoop
from tcpcl.cmd import root_logging
from ltpcl.config import Config
from ltpcl.agent import Agent


def main():
    ''' Agent command entry point. '''
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
    sys.exit(main())
