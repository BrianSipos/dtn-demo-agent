''' Prototype of Zero-Configuration BP router discovery.
'''
from gi.repository import GLib as glib
import ipaddress
import logging
import random
import re
import socket
from typing import List
import ifaddr
from zeroconf import (
    Zeroconf,
    ServiceInfo,
    ServiceBrowser,
    ServiceStateChange,
)

from bp.config import Config, TxRouteItem
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)

SVCLOCAL = '_dtn-bundle._tcp.local.'
''' Global service name to register under '''


@app('zeroconf')
class App(AbstractApplication):
    
    DBUS_IFACE = 'org.ietf.dtn.bp.zeroconf'
    ''' Interface name '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        self._zco = None
        self._browser = None

    def load_config(self, config:Config):
        super().load_config(config)
        self._config = config.apps.get(self._app_name, {})

        self._zco = Zeroconf()

        if self._config.get('offer', False):
            glib.timeout_add(1e3 * random.randint(5, 8), self._offer)
        if self._config.get('enumerate', False):
            glib.timeout_add(1e3 * random.randint(5, 8), self._enumerate)

    def _iface_addrs(self) -> List[ipaddress._IPAddressBase]:
        all_addrs = []
        for adapter in ifaddr.get_adapters():
            for ipobj in adapter.ips:
                if isinstance(ipobj.ip, tuple):
                    # ipv6
                    addr = ipobj.ip[0]
                else:
                    # ipv4
                    addr = ipobj.ip

                addrobj = ipaddress.ip_address(addr)
                if addrobj.is_loopback or addrobj.is_reserved:
                    continue

                all_addrs.append(addrobj)

        return all_addrs

    def _iface_nets(self) -> List[ipaddress._BaseNetwork]:
        all_nets = []
        for adapter in ifaddr.get_adapters():
            for ipobj in adapter.ips:
                if isinstance(ipobj.ip, tuple):
                    # ipv6
                    addr = ipobj.ip[0]
                else:
                    # ipv4
                    addr = ipobj.ip

                ifaceobj = ipaddress.ip_interface(f'{addr}/{ipobj.network_prefix}')
                if ifaceobj.ip.is_loopback or ifaceobj.ip.is_reserved:
                    continue

                all_nets.append(ifaceobj.network)

        return all_nets

    def _offer(self):
        ''' Deferred async offer on mDNS. '''

        hostname = (
            self._config.get('hostname')
            or socket.gethostname().split('.', 1)[0]
        )
        fqdn = hostname + '.local.'

        # Offer all reachable unicast addresses
        all_addrs = self._iface_addrs()
        # ignore when no usable addresses
        if not all_addrs:
            return False

        instname = self._config.get('instance', hostname)
        instlocal = f'{instname}.{SVCLOCAL}'

        servinfo = ServiceInfo(
            SVCLOCAL,
            instlocal,
            weight=1,
            server=fqdn,
            addresses=list(map(str, all_addrs)),
            port=4556,
            properties=dict(
              txtvers=1,
              protovers=4,
            ),
        )
        self._zco.register_service(servinfo)
        LOGGER.info('mDNS registered as %s on %s',
                    instlocal, all_addrs)

        return False

    def _enumerate(self):
        
        self._browser = ServiceBrowser(
            self._zco,
            [SVCLOCAL],
            handlers=[self._serv_state_change]
        )

        return False

    def _serv_state_change(self, zeroconf, service_type, name, state_change):
        all_nets = self._iface_nets()
        LOGGER.info('Iface nets: %s', all_nets)

        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            LOGGER.info('Service added: %s', info)

            addr_objs = list(map(ipaddress.ip_address, info.addresses))
            LOGGER.info('Possible addresses: %s', addr_objs)
            usable_addrs = [
                addr
                for addr in addr_objs
                if [net for net in all_nets if addr in net]
            ]
            LOGGER.info('Usable addresses: %s', usable_addrs)
            if not usable_addrs:
                return
            best_addr = str(usable_addrs[0])
            best_port = int(info.port)

            route = TxRouteItem(
                eid_pattern=re.compile(r'.*'),
                next_nodeid=None,  # FIXME needed?
                cl_type='tcpcl',
                raw_config=dict(
                    address=best_addr,
                    port=best_port,
                ),
            )
            LOGGER.info('Route item %s', route)
            self._agent.add_tx_route(route)

            self._agent.get_cla('tcpcl').connect(best_addr, best_port)
