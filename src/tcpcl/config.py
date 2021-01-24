''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from typing import Optional, List, Set
import logging
import os
import dbus.bus
import ssl
import yaml

LOGGER = logging.getLogger(__name__)


@dataclass
class ListenConfig():
    address: str = u'localhost'
    port: int = 4556

@dataclass
class ConnectConfig():
    address: str
    port: int = 4556


@dataclass
class Config(object):
    ''' Agent configuration.

    .. py:attribute:: keepalive_time
        The desired keepalive time to negotiate.
    .. py:attribute:: idle_time
        The session idle-timeout time.
    '''

    #: A set of test-mode behaviors to enable.
    enable_test: Set[str] = field(default_factory=set)
    #: The D-Bus address to register handlers on.
    bus_addr: Optional[str] = None
    #: DBus service name to register as
    bus_service: Optional[str] = None

    #: If provided, will listen on the specified address/port
    init_listen: List[ListenConfig] = field(default_factory=list)
    #: If provided, will connect to the specified address/port
    init_connect: List[ConnectConfig] = field(default_factory=list)
    #: If True, the agent will stop when all of its contacts are closed.
    stop_on_close: bool = False

    #: Allow use of TLS during contact negotiation
    tls_enable: bool = True
    tls_version: Optional[str] = None
    tls_ciphers: Optional[Set[str]] = None
    #: Trusted root CA PEM file
    tls_ca_file: Optional[str] = None
    #: Local certificate (chain) PEM file
    tls_cert_file: Optional[str] = None
    #: Local private key PEM file
    tls_key_file: Optional[str] = None
    tls_dhparam: Optional[str] = None
    #: If not None, the required negotiated use-TLS state.
    require_tls: Optional[bool] = None

    #: If truthy, the peer must have its host name authenticated (by TLS).
    require_host_authn: bool = False
    #: If truthy, the peer must have its Node ID authenticated (by TLS).
    require_node_authn: bool = False

    #: The Node ID of this entity, which is a URI.
    node_id: str = u''

    keepalive_time: int = 0
    idle_time: int = 0
    #: Maximum size of RX segments in octets
    segment_size_mru: int = int(10 * (1024 ** 2))
    #: Initial TX segment size
    segment_size_tx_initial: int = int(0.1 * (1024 ** 2))
    #: Target time for dynamic TX segment size
    modulate_target_ack_time: Optional[int] = None

    def from_file(self, fileobj):
        ''' Load configuration from a YAML file.
        :param fileobj: The file to read from.
        '''
        filedat = yaml.safe_load(fileobj)
        cldat = filedat.get('tcpcl', None) if filedat else None
        LOGGER.debug('Read config containing: %s', cldat)
        if not cldat:
            return

        for fld in fields(self):
            if fld.name in cldat:
                if fld.name == 'init_listen':
                    self.init_listen.append(
                        ListenConfig(**cldat[fld.name])
                    )
                elif fld.name == 'init_connect':
                    self.init_connect.append(
                        ConnectConfig(**cldat[fld.name])
                    )
                else:
                    setattr(self, fld.name, cldat[fld.name])

        if self.idle_time is None:
            self.idle_time = 2 * self.keepalive_time

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            addr_or_type = self.bus_addr if self.bus_addr else dbus.bus.BUS_SESSION
            LOGGER.debug('Connecting to DBus: %s', addr_or_type)
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn

    def get_ssl_context(self):
        ''' Get an :py:class:`ssl.SSLContext` object configured for this peer.
        '''
        if not self.tls_enable:
            return None

        version_map = {
            None: ssl.PROTOCOL_TLS,
            '1.0': ssl.PROTOCOL_TLSv1,
            '1.1': ssl.PROTOCOL_TLSv1_1,
            '1.2': ssl.PROTOCOL_TLSv1_2,
        }
        try:
            vers_enum = version_map[self.tls_version]
        except KeyError:
            raise ValueError('Invalid TLS version "{0}"'.format(self.tls_version))

        ssl_ctx = ssl.SSLContext(vers_enum)
        ssl_ctx.keylog_filename = os.environ.get('SSLKEYLOGFILE')
        if self.tls_ciphers:
            ssl_ctx.set_ciphers(self.tls_ciphers)
        if self.tls_ca_file:
            ssl_ctx.load_verify_locations(cafile=self.tls_ca_file)
        if self.tls_cert_file or self.tls_key_file:
            if not self.tls_cert_file or not self.tls_key_file:
                raise ValueError('Neither or both of tls_cert_file and tls_key_file are needed')
            ssl_ctx.load_cert_chain(certfile=self.tls_cert_file, keyfile=self.tls_key_file)
        if self.tls_dhparam:
            ssl_ctx.load_dh_params(self.tls_dhparam)
        ssl_ctx.verify_mode = ssl.CERT_OPTIONAL
        return ssl_ctx
