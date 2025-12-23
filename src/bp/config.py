''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from typing import Optional, Set, Dict, List
import logging
import dbus.bus
import re
import yaml

LOGGER = logging.getLogger(__name__)


@dataclass
class RxRouteItem(object):
    ''' Each item in the receive routing table.
    '''
    # The regex pattern to match on the Destination EID
    eid_pattern: re.Pattern
    # The local action to perform.
    # One of: delete, deliver, forward
    action: str
    # The raw config object with additional parameters
    raw_config: object = field(default_factory=object)


@dataclass
class TxRouteItem(object):
    ''' Each item in the transmit routing table.
    '''
    # The regex pattern to match on the Destination EID
    eid_pattern: re.Pattern
    # The next-hop Node ID
    next_nodeid: str
    # Convergence layer name
    cl_type: str
    # Maximum total bundle size for this CL
    mtu: Optional[int] = None
    # The raw config object with additional parameters
    raw_config: object = field(default_factory=object)


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

    # The Node ID of this agent, which is a URI.
    node_id: str = u''
    # Receive routing
    rx_route_table: List[RxRouteItem] = field(default_factory=list)
    # Transmit routing
    tx_route_table: List[TxRouteItem] = field(default_factory=list)

    # Trusted root CA PEM file
    verify_ca_file: Optional[str] = None
    # Local certificate (chain) PEM file
    sign_cert_file: Optional[str] = None
    # Local private key PEM file
    sign_key_file: Optional[str] = None
    # Local certificate (chain) PEM file
    encr_cert_file: Optional[str] = None
    # Local private key PEM file
    encr_key_file: Optional[str] = None
    # BIB target outgoing blocks of this type
    integrity_for_blocks: Set[int] = field(default_factory=lambda: {1})
    # Include certificate chain in integrity parameters
    integrity_include_chain: bool = True

    # The bus service names of CLs to attach to
    cl_attach: Dict[str, str] = field(default_factory=dict)

    # Application-specific configurations
    apps: Dict[str, dict] = field(default_factory=dict)

    def from_file(self, fileobj):
        ''' Load configuration from a YAML file.
        :param fileobj: The file to read from.
        '''
        filedat = yaml.safe_load(fileobj)
        bpdat = filedat.get('bp', None) if filedat else None
        LOGGER.debug('Read config containing: %s', bpdat)
        if not bpdat:
            return

        for fld in fields(self):
            if fld.name in bpdat:
                if fld.name == 'rx_route_table':
                    self.rx_route_table = []
                    for item in bpdat[fld.name]:
                        try:
                            self.rx_route_table.append(RxRouteItem(
                                eid_pattern=re.compile(item['eid_pattern']),
                                action=item['action'],
                                raw_config=item
                            ))
                        except Exception as err:
                            LOGGER.error('Ignoring invalid rx_route_table entry %s because (%s): %s', item, type(err).__name__, err)
                elif fld.name == 'tx_route_table':
                    self.tx_route_table = []
                    for item in bpdat[fld.name]:
                        try:
                            self.tx_route_table.append(TxRouteItem(
                                eid_pattern=re.compile(item['eid_pattern']),
                                next_nodeid=item['next_nodeid'],
                                cl_type=item['cl_type'],
                                raw_config=item
                            ))
                        except Exception as err:
                            LOGGER.error('Ignoring invalid tx_route_table entry %s because (%s): %s', item, type(err).__name__, err)
                else:
                    setattr(self, fld.name, bpdat[fld.name])

        # Get CL bus names to attach to
        for cl_type in ('tcpcl', 'udpcl'):
            cldat = filedat.get(cl_type)
            if cldat:
                self.cl_attach[cl_type] = cldat['bus_service']

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
