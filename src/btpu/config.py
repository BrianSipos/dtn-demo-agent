''' Agent configuration data.
'''
from dataclasses import dataclass, field, fields
from datetime import timedelta
from typing import Any, Optional, Dict, List, Set
import logging
import os
import dbus.bus
import yaml

LOGGER = logging.getLogger(__name__)


@dataclass
class ListenConfig():
    # Local interface to listen on
    ifname: str
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
    # Remote address to send to
    address: bytes
    # Optional local address
    local_address: Optional[str] = None
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

    # The Node ID of this entity, which is a URI.
    node_id: str = u''

    # Default MTU when not discoverable
    mtu_default: Optional[int] = None

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
        cldat = filedat.get('btpu', None) if filedat else None
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
