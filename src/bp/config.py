''' Agent configuration data.
'''
import copy
from dataclasses import dataclass, field, fields
from typing import Optional, Set, Dict, List
import logging
import dbus.bus
import re
import yaml
from tcpcl.config import ConnectConfig

LOGGER = logging.getLogger(__name__)


@dataclass
class RouteItem(object):
    ''' Each item in the routing table.
    '''
    #: The regex pattern to match on the Destination EID
    eid_pattern: re.Pattern
    #: The next-hop Node ID
    next_nodeid: str
    #: The next-hop Transport
    next_hop: Optional[ConnectConfig]


@dataclass
class Config(object):
    ''' Agent configuration.

    .. py:attribute:: route_table
        A map from destination EID to next-hop Node ID.
    '''

    #: A set of test-mode behaviors to enable.
    enable_test: Set[str] = field(default_factory=set)
    #: The D-Bus address to register handlers on.
    bus_addr: Optional[str] = None
    #: DBus service name to register as
    bus_service: Optional[str] = None

    #: The Node ID of this agent, which is a URI.
    node_id: str = u''
    route_table: List[RouteItem] = field(default_factory=list)

    #: Trusted root CA PEM file
    tls_ca_file: Optional[str] = None
    #: Local certificate (chain) PEM file
    tls_cert_file: Optional[str] = None
    #: Local private key PEM file
    tls_key_file: Optional[str] = None

    #: The name of a CL to read config for and fork
    cl_fork: Optional[str] = None
    #: The bus service name of a CL to attach to
    cl_attach: Optional[str] = None

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
                if fld.name == 'route_table':
                    self.route_table = []
                    for item in bpdat[fld.name]:
                        item_cpy = copy.copy(item)
                        try:
                            pat = re.compile(item_cpy.pop('eid_pattern'))
                            nodeid = item_cpy.pop('next_nodeid')
                            conn = ConnectConfig(**item_cpy) if item_cpy else None
                            self.route_table.append(RouteItem(
                                eid_pattern=pat,
                                next_nodeid=nodeid,
                                next_hop=conn
                            ))
                        except Exception as err:
                            LOGGER.error('Ignoring invalid route_table entry %s because (%s): %s', item, type(err).__name__, err)
                else:
                    setattr(self, fld.name, bpdat[fld.name])

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            LOGGER.debug('Connecting to DBus')
            addr_or_type = self.bus_addr if self.bus_addr else dbus.bus.BUS_SESSION
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn
