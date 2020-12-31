'''
Implementation of a symmetric TCPCL agent.
'''
import argparse
import logging
import socket
import sys

import dbus.service
from gi.repository import GLib as glib

import tcpcl.config
from tcpcl.session import ContactHandler


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Agent'

    def __init__(self, config, bus_kwargs=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self._bindsocks = {}
        self._obj_id = 0
        self._handlers = []
        self._path_to_handler = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/tcpcl/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

        if self._config.bus_service:
            self._bus_serv = dbus.service.BusName(
                bus=self._config.bus_conn,
                name=self._config.bus_service,
                do_not_queue=True
            )
            self.__logger.info('Registered as "%s"', self._bus_serv.get_name())

        if self._config.init_listen:
            self.listen(self._config.init_listen.address, self._config.init_listen.port)
        if self._config.init_connect:
            self.connect(self._config.init_connect.address, self._config.init_connect.port)

    def _get_obj_path(self):
        hdl_id = self._obj_id
        self._obj_id += 1
        return '/org/ietf/dtn/tcpcl/Contact{0}'.format(hdl_id)

    def _bind_handler(self, **kwargs):
        path = self._get_obj_path()
        hdl = ContactHandler(
            hdl_kwargs=kwargs,
            bus_kwargs=dict(conn=self._config.bus_conn, object_path=path)
        )

        self._handlers.append(hdl)
        self._path_to_handler[path] = hdl
        hdl.set_on_close(lambda: self._unbind_handler(hdl))

        self.connection_opened(path)
        return hdl

    def _unbind_handler(self, hdl):
        path = hdl.object_path
        self.connection_closed(path)
        self._path_to_handler.pop(path)
        self._handlers.remove(hdl)

        if not self._handlers and (self._in_shutdown or self._config.stop_on_close):
            self.stop()

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='ao')
    def get_connections(self):
        ''' Get all connections for this agent.
        :return: List of object paths.
        '''
        return self._path_to_handler.keys()

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_opened(self, objpath):
        ''' Emitted when a connection is opened. '''
        self.__logger.info('Opened handler at "%s"', objpath)

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_closed(self, objpath):
        ''' Emitted when a connection is closed. '''
        self.__logger.info('Closed handler at "%s"', objpath)

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def shutdown(self):
        ''' Gracefully terminate all open sessions.
        Once the sessions are closed then the agent may stop.

        :return: True if the agent is stopped immediately or
            False if a wait is needed.
        '''
        self.__logger.info('Shutting down agent')
        self._in_shutdown = True
        if not self._handlers:
            self.stop()
            return True

        for hdl in self._handlers:
            hdl.terminate()
        self.__logger.info('Waiting on sessions to terminate')
        return False

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''
        self.__logger.info('Stopping agent')
        for spec in tuple(self._bindsocks.keys()):
            self.listen_stop(*spec)

        for hdl in self._handlers:
            hdl.close()

        if tuple(self.locations):
            self.remove_from_connection()

        if self._on_stop:
            self._on_stop()

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(eloop.quit)
        self.__logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()

    @dbus.service.method(DBUS_IFACE, in_signature='si')
    def listen(self, address, port):
        ''' Begin listening for incoming connections and defer handling
        connections to `glib` event loop.
        '''
        bindspec = (address, port)
        if bindspec in self._bindsocks:
            raise dbus.DBusException('Already listening')

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(bindspec)

        self.__logger.info('Listening on %s:%d', address or '*', port)
        sock.listen(1)
        self._bindsocks[bindspec] = sock
        glib.io_add_watch(sock, glib.IO_IN, self._accept)

    @dbus.service.method(DBUS_IFACE, in_signature='si')
    def listen_stop(self, address, port):
        ''' Stop listening for connections on an existing port binding.
        '''
        bindspec = (address, port)
        if bindspec not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(bindspec)
        self.__logger.info('Un-listening on %s:%d', address or '*', port)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except socket.error as err:
            self.__logger.warning('Bind socket shutdown error: %s', err)
        sock.close()

    def _accept(self, bindsock, *_args, **_kwargs):
        ''' Callback to handle incoming connections.

        :return: True to continue listening.
        '''
        newsock, fromaddr = bindsock.accept()
        self.__logger.info('Connecting')
        hdl = self._bind_handler(
            config=self._config, sock=newsock, fromaddr=fromaddr)

        try:
            hdl.start()
        except IOError as err:
            self.__logger.warning('Failed: %s', err)

        return True

    @dbus.service.method(DBUS_IFACE, in_signature='si', out_signature='o')
    def connect(self, address, port):
        ''' Initiate an outgoing connection and defer handling state to
        `glib` event loop.

        :return: The new contact object path.
        :rtype: str
        '''
        self.__logger.info('Connecting')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((address, port))

        hdl = self._bind_handler(
            config=self._config, sock=sock, toaddr=(address, port))
        hdl.start()

        return hdl.object_path

    def handler_for_path(self, path):
        ''' Look up a contact by its object path.
        '''
        return self._path_to_handler[path]


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
    from urllib.parse import urlparse

    nodeid_uri = urlparse(val)
    if not nodeid_uri.scheme:
        raise argparse.ArgumentTypeError('URI value expected')
    return val


def main(*argv):
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--config-file', type=str,
                        help='Configuration file to load from')
    parser.add_argument('--tls-version', type=str,
                        help='Version name of TLS to use')
    parser.add_argument('--tls-require', default=None, type=str2bool,
                        help='Require the use of TLS for all sessions')
    parser.add_argument('--tls-ca', type=str,
                        help='Filename for CA chain')
    parser.add_argument('--tls-cert', type=str,
                        help='Filename for X.509 certificate')
    parser.add_argument('--tls-key', type=str,
                        help='Filename for X.509 private key')
    parser.add_argument('--tls-dhparam', type=str,
                        help='Filename for DH parameters')
    parser.add_argument('--tls-ciphers', type=str, default=None,
                        help='Allowed TLS cipher filter')
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

    args = parser.parse_args(argv[1:])
    log_queue = root_logging(args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = tcpcl.config.Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)

    if args.action == 'listen':
        config.init_listen = tcpcl.config.ListenConfig(address=args.address, port=args.port)
    elif args.action == 'connect':
        config.init_connect = tcpcl.config.ConnectConfig(address=args.address, port=args.port)

    agent = Agent(config)
    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
