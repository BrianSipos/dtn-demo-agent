'''
Implementation of a symmetric TCPCL agent.
'''
import argparse
import logging
import os
import socket
import ssl
import sys

import dbus.bus
import dbus.service
from gi.repository import GLib as glib

from .session import ContactHandler


class Config(object):
    ''' Agent configuration.

    .. py:attribute:: enable_test
        A set of test-mode behaviors to enable.
    .. py:attribute:: bus_conn
        The D-Bus connection object to register handlers on.
    .. py:attribute:: stop_on_close
        If True, the agent will stop when all of its contacts are closed.
    .. py:attribute:: ssl_ctx
        An :py:class:`ssl.SSLContext` object configured for this peer.
    .. py:attribute:: require_tls
        If not None, the required negotiated use-TLS state.
    .. py:attribute:: require_host_authn
        If truthy, the peer must have its host name authenticated (by TLS).
    .. py:attribute:: require_node_authn
        If truthy, the peer must have its Node ID authenticated (by TLS).
    .. py:attribute:: nodeid
        The Node ID of this entity, which is a URI.
    .. py:attribute:: keepalive_time
        The desired keepalive time to negotiate.
    .. py:attribute:: idle_time
        The session idle-timeout time.
    '''

    def __init__(self):
        self.enable_test = set()
        self.bus_conn = dbus.bus.BusConnection(dbus.bus.BUS_SESSION)
        self.stop_on_close = False
        self.ssl_ctx = None
        self.require_tls = None
        self.require_host_authn = False
        self.require_node_authn = False
        self.nodeid = u''
        self.keepalive_time = 0
        self.idle_time = 0
        #: Maximum size of RX segments in octets
        self.segment_size_mru = int(10 * (1024 ** 2))
        #: Initial TX segment size
        self.segment_size_tx_initial = int(0.1 * (1024 ** 2))
        #: Target time for dynamic TX segment size
        self.modulate_target_ack_time = None


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
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Names of test modes enabled')
    parser.add_argument('--bus-service', type=str,
                        help='D-Bus service name')
    parser.add_argument('--nodeid', type=uristr,
                        help='This entity\'s Node ID')
    parser.add_argument('--keepalive', type=int,
                        help='Keepalive time in seconds')
    parser.add_argument('--idle', type=int,
                        help='Idle time in seconds')
    parser.add_argument('--tls-disable', dest='tls_enable', default=True, action='store_false',
                        help='Disallow use of TLS on this endpoint')
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
    parser.add_argument('--stop-on-close', default=False, action='store_true',
                        help='Stop the agent when connection is closed')
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
    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()

    config.enable_test = frozenset(args.enable_test)
    if args.bus_service:
        bus_serv = dbus.service.BusName(
            bus=config.bus_conn, name=args.bus_service, do_not_queue=True)
        logging.info('Registered as "%s"', bus_serv.get_name())

    if args.tls_enable:
        version_map = {
            None: ssl.PROTOCOL_TLS,
            '1.0': ssl.PROTOCOL_TLSv1,
            '1.1': ssl.PROTOCOL_TLSv1_1,
            '1.2': ssl.PROTOCOL_TLSv1_2,
        }
        try:
            vers_enum = version_map[args.tls_version]
        except KeyError:
            raise argparse.ArgumentTypeError('Invalid TLS version "{0}"'.format(args.tls_version))

        config.ssl_ctx = ssl.SSLContext(vers_enum)
        config.ssl_ctx.keylog_filename = os.environ.get('SSLKEYLOGFILE')
        if args.tls_ciphers:
            config.ssl_ctx.set_ciphers(args.tls_ciphers)
        if args.tls_ca:
            config.ssl_ctx.load_verify_locations(cafile=args.tls_ca)
        if args.tls_cert or args.tls_key:
            if not args.tls_cert or not args.tls_key:
                raise RuntimeError('Neither or both of --tls-cert and --tls-key are needed')
            config.ssl_ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        if args.tls_dhparam:
            config.ssl_ctx.load_dh_params(args.tls_dhparam)
        config.ssl_ctx.verify_mode = ssl.CERT_OPTIONAL

    config.nodeid = args.nodeid
    config.require_tls = args.tls_require
    config.stop_on_close = args.stop_on_close

    if args.keepalive:
        config.keepalive_time = args.keepalive

    if args.idle:
        config.idle_time = args.idle
    else:
        config.idle_time = 2 * config.keepalive_time

    agent = Agent(config)
    if args.action == 'listen':
        agent.listen(args.address, args.port)
    elif args.action == 'connect':
        agent.connect(args.address, args.port)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
