''' Prototype of Zero-Configuration BP router discovery.
'''
import asyncio
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


async def happy_eyeballs(addresses: List, port: int) -> ipaddress._IPAddressBase:
    ''' A simplified form of RFC 8305 for a list of potential addresses.
    '''
    tasks = []
    for ipaddr in addresses:
        if ipaddr.is_reserved or ipaddr.is_link_local:
            continue
        addr = (str(ipaddr), port)
        LOGGER.info('Happy Eyeballs attempting to %s', addr)
        try:
            coro = asyncio.open_connection(*addr, proto=socket.IPPROTO_TCP)
            tasks.append(asyncio.ensure_future(coro))
        except Exception as err:
            LOGGER.warning('Happy Eyeballs failed to %s: %s', addr, err)

    # wait for a real, non-exceptional result
    finished = None
    pending = tasks
    while pending and not finished:
        LOGGER.info('Happy Eyeballs waiting on %d pending', len(pending))
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            try:
                finished = task.result()
                break
            except Exception as err:
                LOGGER.warning('Happy Eyeballs failed to %s: %s', done, err)

    for task in pending:
        task.cancel()

    _reader, writer = finished
    peername = writer.get_extra_info('peername')
    LOGGER.info('Happy Eyeballs connected to %s', peername)
    return peername[0]


@app('zeroconf')
class App(AbstractApplication):

    DBUS_IFACE = 'org.ietf.dtn.bp.zeroconf'
    ''' Interface name '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        self._zco = None
        self._browser = None

    def load_config(self, config: Config):
        super().load_config(config)
        self._config = config.apps.get(self._app_name, {})

        self._zco = Zeroconf()

        delay = self._config.get('offer', False)
        if delay is not False:
            delay = 5e3 if delay is True else max(100, int(1e3 * delay))
            glib.timeout_add(random.randint(100, int(delay)), self._offer)

        delay = self._config.get('enumerate', False)
        if delay is not False:
            delay = 5e3 if delay is True else max(100, int(1e3 * delay))
            glib.timeout_add(random.randint(100, int(delay)), self._enumerate)

    def _iface_addrs(self) -> List[ipaddress._IPAddressBase]:
        all_addrs = []
        for adapter in ifaddr.get_adapters():
            for ipobj in adapter.ips:
                if isinstance(ipobj.ip, tuple):
                    # ipv6
                    addrobj = ipaddress.IPv6Address(f'{ipobj.ip[0]}%{ipobj.ip[2]}')
                else:
                    # ipv4
                    addrobj = ipaddress.IPv4Address(ipobj.ip)

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
        if state_change == ServiceStateChange.Added:
            info = zeroconf.get_service_info(service_type, name)
            LOGGER.info('Service added: %s', info)

            addr_objs = list(map(ipaddress.ip_address, info.parsed_scoped_addresses()))
            LOGGER.info('Possible addresses: %s', addr_objs)
            if not addr_objs:
                return

            # Probe using Happy Eyeballs
            best_port = int(info.port)
            best_addr = asyncio.run(happy_eyeballs(addr_objs, best_port))

            route = TxRouteItem(
                eid_pattern=re.compile(r'.*'),
                next_nodeid=None,  # FIXME needed?
                cl_type='tcpcl',
                raw_config=dict(
                    address=best_addr,
                    port=best_port,
                ),
            )
            LOGGER.info('Add route item %s', route)
            self._agent.add_tx_route(route)

            self._agent.get_cla('tcpcl').connect(best_addr, best_port)
