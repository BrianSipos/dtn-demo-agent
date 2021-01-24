''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from typing import Optional, List, Set
import logging
import dbus.bus
import yaml

LOGGER = logging.getLogger(__name__)


@dataclass
class ListenConfig():
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
                if fld.name == 'init_listen':
                    self.init_listen.append(
                        ListenConfig(**cldat[fld.name])
                    )
                else:
                    setattr(self, fld.name, cldat[fld.name])

    @property
    def bus_conn(self):
        cur_conn = getattr(self, '_bus_conn', None)
        if cur_conn is None:
            addr_or_type = self.bus_addr if self.bus_addr else dbus.bus.BUS_SESSION
            LOGGER.debug('Connecting to DBus: %s', addr_or_type)
            self._bus_conn = dbus.bus.BusConnection(addr_or_type)
        return self._bus_conn