''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from typing import Optional, Set, Dict
import logging
import dbus.bus
import yaml

LOGGER = logging.getLogger(__name__)


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
    route_table: dict = field(default_factory=dict)

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
                setattr(self, fld.name, bpdat[fld.name])

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            LOGGER.debug('Connecting to DBus')
            addr_or_type = self.bus_addr if self.bus_addr else dbus.bus.BUS_SESSION
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn
