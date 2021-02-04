''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from typing import Any, Optional, Dict, List, Set
import logging
import dbus.bus
import yaml
from mbedtls import tls

LOGGER = logging.getLogger(__name__)


@dataclass
class ListenConfig():
    address: str
    port: int = 4556
    #: Multicast address membership
    multicast_member: List[Dict] = field(default_factory=list)

    @property
    def opts(self):
        ''' Encode options dictionary
        '''
        return {
            'multicast_member': self.multicast_member
        }


@dataclass
class MulticastConfig():
    #: Multicast TTL value
    ttl: Optional[int] = None
    #: List of source addresses for IPv4 multicast
    v4sources: List[str] = field(default_factory=list)
    #: List of source devices for IPv6 multicast
    v6sources: List[str] = field(default_factory=list)


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

    #: Allow use of TLS during contact negotiation
    dtls_enable: bool = True
    dtls_version: Optional[str] = None
    dtls_ciphers: Optional[Set[str]] = None
    #: Trusted root CA PEM file
    dtls_ca_file: Optional[str] = None
    #: Local certificate (chain) PEM file
    dtls_cert_file: Optional[str] = None
    #: Local private key PEM file
    dtls_key_file: Optional[str] = None
#    tls_dhparam: Optional[str] = None
    #: If not None, the required negotiated use-TLS state.
#    require_tls: Optional[bool] = None

    #: Default MTU when not discoverable
    mtu_default: Optional[int] = None

    #: Multicast options with defaults
    multicast: MulticastConfig = field(default_factory=MulticastConfig)

    #: If provided, will listen on the specified address/port
    init_listen: List[ListenConfig] = field(default_factory=list)

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
                else:
                    setattr(self, fld.name, cldat[fld.name])

    def validate(self):
        ''' Check that this config is valid.
        :throw RuntimeError: If something is wrong.
        '''
        self.get_tls_config()

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            addr_or_type = self.bus_addr if self.bus_addr else dbus.bus.BUS_SESSION
            LOGGER.debug('Connecting to DBus: %s', addr_or_type)
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn

    def get_tls_config(self):
        ''' Get an :py:class:`mbedtls.tls.ClientContext` object configured for this peer.
        '''
        from mbedtls import x509, pk
        if not self.dtls_enable:
            return None

        version_map = {
            None: None,
            '1.0': tls.DTLSVersion.DTLSv1_0,
            '1.2': tls.DTLSVersion.DTLSv1_2,
        }
        try:
            vers_enum = version_map[self.dtls_version]
        except KeyError:
            raise ValueError('Invalid TLS version "{0}"'.format(self.dtls_version))

        trust = tls.TrustStore()
        if self.dtls_ca_file:
#            trust.add(x509.Certificate.from_file(self.dtls_ca_file))
            trust = tls.TrustStore.from_pem_file(self.dtls_ca_file)
        LOGGER.info('TRUST %s', trust)

#        cfg.keylog_filename = os.environ.get('SSLKEYLOGFILE')
#        if self.dtls_ciphers:
#            cfg.set_ciphers(self.dtls_ciphers)

        if self.dtls_cert_file or self.dtls_key_file:
            if not self.dtls_cert_file or not self.dtls_key_file:
                raise ValueError('Neither or both of tls_cert_file and tls_key_file are needed')

            cert_chain = [[], None]
            with open(self.dtls_cert_file, 'r') as infile:
                cert_chain[0].append(
                    x509.CRT.from_PEM(infile.read())
                )

            with open(self.dtls_key_file, 'r') as infile:
                infile.readline()
                print(self.dtls_key_file)
#                cert_chain[1] = pk.RSA.from_PEM(infile.read())
                cert_chain[1] = pk.RSA(pk.RSA().generate())
        else:
            cert_chain = None
        LOGGER.debug('cert from %s: %s', self.dtls_cert_file, cert_chain)

        cfg = tls.DTLSConfiguration(
            trust_store=trust,
            certificate_chain=cert_chain,
            validate_certificates=False,
            ciphers=self.dtls_ciphers,
        )
        LOGGER.info('cfg %s', cfg)
        return cfg
