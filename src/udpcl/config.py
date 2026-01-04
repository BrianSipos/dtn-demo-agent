''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from datetime import timedelta
from typing import Any, Optional, Dict, List, Set
import logging
import os
import dbus.bus
import yaml

try:
    import dtls
except (ImportError, OSError):
    dtls = None

LOGGER = logging.getLogger(__name__)


@dataclass
class ListenConfig():
    # Local address to listen on
    address: str
    # Local port to listen on
    port: int = 4556
    # Multicast address membership
    multicast_member: List[Dict] = field(default_factory=list)

    @property
    def opts(self):
        ''' Encode options dictionary
        '''
        return {
            'multicast_member': self.multicast_member
        }


@dataclass
class PollConfig():
    # Remote address or DNS name to send to
    address: str
    # Remote port to send to
    port: int = 4556
    # Optional local address
    local_address: Optional[str] = None
    # Optional local port
    local_port: Optional[int] = None
    # Interval time in milliseconds
    interval_ms: int = 60000


@dataclass
class MulticastConfig():
    # Multicast TTL value
    ttl: Optional[int] = None


@dataclass
class Config(object):
    ''' Agent configuration.
    '''

    # Default log level when command option not provided
    log_level: Optional[str] = None
    # A set of test-mode behaviors to enable.
    enable_test: Set[str] = field(default_factory=set)
    # The D-Bus address to register handlers on.
    bus_addr: Optional[str] = None
    # DBus service name to register as
    bus_service: Optional[str] = None

    # Allow use of TLS for sending
    dtls_enable_tx: bool = True
    # Specific version to allow
    dtls_version: Optional[str] = None
    # OpenSSL cipher filter
    dtls_ciphers: Optional[str] = None
    # Trusted root CA PEM file
    dtls_ca_file: Optional[str] = None
    # Local certificate (chain) PEM file
    dtls_cert_file: Optional[str] = None
    # Local private key PEM file
    dtls_key_file: Optional[str] = None

    # If True, plaintext RX bundles are rejected
    require_tls: bool = False
    # If truthy, the peer must have its host name authenticated (by TLS).
#    require_host_authn: bool = False
    # If truthy, the peer must have its Node ID authenticated (by TLS).
#    require_node_authn: bool = False

    # The Node ID of this entity, which is a URI.
    node_id: str = u''

    # Default source IP to send on
    default_tx_address: Optional[str] = None
    # Default UDP port to send on
    default_tx_port: Optional[int] = None
    # Default MTU when not discoverable
    mtu_default: Optional[int] = None

    ecn_init: bool = True
    ''' True if outgoing data packets are marked as ECT(1) '''
    ecn_feedback: bool = True
    ''' True if incoming ECN-marked packets are responded to with feedback. '''
    ecn_feedback_min: timedelta = timedelta(milliseconds=20)
    ''' Maximum interval between ECN feedback '''
    ecn_feedback_max: timedelta = timedelta(milliseconds=1000)
    ''' Maximum interval between ECN feedback '''

    # Multicast options with defaults
    multicast: MulticastConfig = field(default_factory=MulticastConfig)

    # If provided, will listen on the specified address/port
    init_listen: List[ListenConfig] = field(default_factory=list)
    # If provided, will poll a peer
    polling: List[PollConfig] = field(default_factory=list)

    def from_file(self, fileobj):
        ''' Load configuration from a YAML file.
        :param fileobj: The file to read from.
        '''
        filedat = yaml.safe_load(fileobj)
        cldat = filedat.get('udpcl', None) if filedat else None
        LOGGER.debug('Read config containing: %s', cldat)
        if not cldat:
            return

        for fld in fields(self):
            if fld.name in cldat:
                if fld.name == 'multicast':
                    self.multicast = MulticastConfig(**cldat[fld.name])
                elif fld.name == 'init_listen':
                    for item in cldat[fld.name]:
                        self.init_listen.append(
                            ListenConfig(**item)
                        )
                elif fld.name == 'polling':
                    for item in cldat[fld.name]:
                        self.polling.append(
                            PollConfig(**item)
                        )
                else:
                    setattr(self, fld.name, cldat[fld.name])

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            if not self.bus_addr or self.bus_addr == 'session':
                addr_or_type = dbus.bus.BUS_SESSION
            elif self.bus_addr == 'system':
                addr_or_type = dbus.bus.BUS_SYSTEM
            else:
                addr_or_type = self.bus_addr
            LOGGER.debug('Connecting to DBus: %s', addr_or_type)
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn

    def get_ssl_connection(self, sock, server_side: bool):
        ''' Get an :py:class:`dtls.SSLConnection` object configured for this peer.
        '''
        version_map = {
            None: dtls.sslconnection.PROTOCOL_DTLS,
            '1.0': dtls.sslconnection.PROTOCOL_DTLSv1,
            '1.2': dtls.sslconnection.PROTOCOL_DTLSv1_2,
        }
        try:
            vers_enum = version_map[self.dtls_version]
        except KeyError:
            raise ValueError('Invalid TLS version "{0}"'.format(self.tls_version))

        def ssl_config_ctx(ctx):
            pass

        conn = dtls.SSLConnection(
            sock,
            do_handshake_on_connect=False,
            server_side=server_side,
            ssl_version=vers_enum,
            ciphers=self.dtls_ciphers,
            ca_certs=self.dtls_ca_file,
            keyfile=self.dtls_key_file,
            certfile=self.dtls_cert_file,
            cert_reqs=dtls.sslconnection.CERT_REQUIRED,
            cb_user_config_ssl_ctx=ssl_config_ctx,
        )
        conn._intf_ssl_ctx.set_ssl_logging(True)
        return conn
