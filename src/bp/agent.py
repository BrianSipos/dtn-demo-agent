''' Implementation of a symmetric BPv7 agent.
'''
import datetime
import logging
import dbus.service
from gi.repository import GLib as glib
import cbor2
from cryptography.hazmat.backends import default_backend
import scapy.volatile
import tcpcl
from scapy_cbor.util import encode_diagnostic
from bp.encoding import (
    DtnTimeField, Timestamp,
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
    PreviousNodeBlock, BundleAgeBlock, HopCountBlock,
    StatusReport
)
from bp.util import BundleContainer, ChainStep
import bp.cla
import bp.app.base

LOGGER = logging.getLogger(__name__)


class Timestamper(object):
    ''' Generate a unique Timestamp with sequence state.
    '''

    def __init__(self):
        self._time = None
        self._seqno = 0

    def __call__(self):
        ''' Generate the next timestamp.
        '''
        now_pytime = datetime.datetime.now(datetime.timezone.utc)
        now_time = DtnTimeField.datetime_to_dtntime(now_pytime)

        if self._time is not None and now_time == self._time:
            self._seqno += 1
        else:
            self._time = now_time
            self._seqno = 0

        return Timestamp(
            dtntime=self._time,
            seqno=self._seqno
        )


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.Agent'

    def __init__(self, config, bus_kwargs=None):
        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/bp/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self.timestamp = Timestamper()

        self._bus_obj = self._config.bus_conn.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        self._bus_obj.connect_to_signal('NameOwnerChanged', self._bus_name_changed, dbus_interface='org.freedesktop.DBus')

        # Bound-to CL agent for each type
        self._cl_agent = {}
        # Static processing chains
        self._rx_chain = []
        self._tx_chain = []
        self._rx_chain.append(ChainStep(
            order=0,
            name='Static routing',
            action=self._do_rx_step,
        ))
        self._tx_chain.append(ChainStep(
            order=0,
            name='Static routing',
            action=self._do_tx_step,
        ))
        # Bound delivery applications
        self._app = {}
        for (path, cls) in bp.app.base.APPLICATIONS.items():
            self._logger.debug('Registering application %s at %s', cls, path)
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path=path
            )
            app = cls(self, bus_kwargs)
            self._app[path] = app
            app.load_config(self._config)
            app.add_chains(self._rx_chain, self._tx_chain)
        self._rx_chain.sort()
        self._tx_chain.sort()
        self._show_chain(self._rx_chain, 'RX Chain')
        self._show_chain(self._tx_chain, 'TX Chain')
        # Seen bundle identities
        self._seen_bundle_ident = set()
        # Forwarding queue
        self._fwd_ctrs = []

        if self._config.bus_service:
            self._bus_serv = dbus.service.BusName(
                bus=self._config.bus_conn,
                name=self._config.bus_service,
                do_not_queue=True
            )
            self._logger.info('Registered as "%s"', self._bus_serv.get_name())

    def __del__(self):
        self.stop()

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def shutdown(self):
        ''' Gracefully terminate all open sessions.
        Once the sessions are closed then the agent may stop.

        :return: True if the agent is stopped immediately or
            False if a wait is needed.
        '''
        self._logger.info('Shutting down agent')
        self._in_shutdown = True
        self.stop()
        return True

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''

        if self._on_stop:
            self._on_stop()

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(eloop.quit)
        self._logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()

    def _bus_name_changed(self, servname, old_owner, new_owner):
        for cl_agent in self._cl_agent.values():
            if cl_agent.serv_name == servname:
                self._logger.debug('bus name change %s old %s new %s', servname, old_owner, new_owner)
                if old_owner:
                    cl_agent.unbind()
                if new_owner:
                    cl_agent.bind(self._config.bus_conn)

    def _show_chain(self, chain, name):
        parts = ['{:3.1f}: {}'.format(item.order, item.name) for item in chain]
        self._logger.debug('Items in %s:\n%s', name, '\n'.join(parts))

    def _cl_recv_bundle(self, data):
        ''' Handle a new received bundle from a CL.
        '''
        self._logger.debug('recv_bundle data %s', encode_diagnostic(cbor2.loads(data)))
        ctr = BundleContainer(Bundle(data))
        self.recv_bundle(ctr)

    def _do_rx_step(self, ctr):
        ''' Perform the static RX routing step.
        '''
        eid = ctr.bundle.primary.destination
        self._logger.info('Getting RX route for: %s', eid)
        found = None
        for item in self._config.rx_route_table:
            match = item.eid_pattern.match(eid)
            self._logger.debug('Checking pattern %s result %s', item.eid_pattern, match)
            if match is not None:
                found = item
                break
        if found:
            self._logger.debug('Route found: %s', found)
            ctr.record_action(found.action)
        return False

    def _do_tx_step(self, ctr):
        ''' Perform the static TX routing step.
        '''
        eid = ctr.bundle.primary.destination
        self._logger.info('Getting TX route for: %s', eid)
        found = None
        for item in self._config.tx_route_table:
            match = item.eid_pattern.match(eid)
            self._logger.debug('Checking pattern %s result %s', item.eid_pattern, match)
            if match is not None:
                found = item
                break
        if found:
            self._logger.debug('Route found: %s', found)
            ctr.sender = self._cl_agent[found.cl_type].send_bundle_func(**found.raw_config)

        return found

    def _fragment(self, ctr, route):
        orig_size = len(ctr.bundle)
        bundle_flags = ctr.bundle.primary.bundle_flags
        should_fragment = (
            route.mtu is not None
            and orig_size > route.mtu
            and not bundle_flags & PrimaryBlock.Flag.NO_FRAGMENT
            and not bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT
        )
        self._logger.info('Unfragmented size %d, should fragment %s', orig_size, should_fragment)

        if not should_fragment:
            # no fragmentation
            return [ctr]

        # take the payload data to fragment it
        pyld_blk = ctr.block_num(Bundle.BLOCK_NUM_PAYLOAD)
        payload_data = pyld_blk.getfieldval('btsd')
        pyld_blk.delfieldval('btsd')
        payload_size = len(payload_data)
        self._logger.info('Payload data size %d', payload_size)
        # maximum size of each fragment field
        pyld_size_enc = len(cbor2.dumps(payload_size))

        # two encoded sizes for fragment, one for payload bstr head
        non_pyld_size = orig_size - payload_size + 3 * pyld_size_enc
        self._logger.info('Non-payload size %d', non_pyld_size)
        if non_pyld_size > route.mtu:
            raise RuntimeError('Non-payload size {} too large for route MTU {}'.format(orig_size, route.mtu))

        frag_offset = 0
        ctrlist = []
        while frag_offset < len(payload_data):
            fctr = BundleContainer()
            fctr.bundle.primary = ctr.bundle.primary.copy()
            fctr.bundle.primary.bundle_flags |= PrimaryBlock.Flag.IS_FRAGMENT
            fctr.bundle.primary.fragment_offset = frag_offset
            fctr.bundle.primary.total_app_data_len = payload_size

            for blk in ctr.bundle.blocks:
                if (not ctrlist
                    or blk.block_flags & CanonicalBlock.Flag.REPLICATE_IN_FRAGMENT
                    or blk.type_code == Bundle.BLOCK_NUM_PAYLOAD):
                    fctr.bundle.blocks.append(blk.copy())
            # ensure full size (with zero-size payload)
            fctr.reload()
            fctr.bundle.fill_fields()

            non_pyld_size = len(fctr.bundle)
            # zero-length payload has one-octet encoded bstr head
            frag_size = route.mtu - (non_pyld_size - 1 + pyld_size_enc)
            self._logger.info('Fragment non-payload size %d, offset %d, (max) size %d', non_pyld_size, frag_offset, frag_size)
            frag_data = payload_data[frag_offset:(frag_offset + frag_size)]
            frag_offset += frag_size

            fctr.block_num(Bundle.BLOCK_NUM_PAYLOAD).setfieldval('btsd', frag_data)
            ctrlist.append(fctr)

        return ctrlist

    def _finish_bundle(self, ctr):
        ''' Handle the end of processing for a bundle.
        '''
        status = ctr.create_report()
        if status:
            glib.idle_add(self.send_bundle, status)

    def recv_bundle(self, ctr):
        ''' Perform agent handling of a received bundle.

        :param ctr: The bundle container just recieved.
        :type ctr: :py:cls:`BundleContainer`
        '''
        self._logger.debug('Received bundle\n%s', repr(ctr))

        invalid_crc = ctr.bundle.check_all_crc()
        if invalid_crc:
            self._logger.warning('CRC invalid for block numbers: %s', invalid_crc)
            return

        ident = ctr.bundle_ident()
        if ctr.bundle.primary.source == self._config.node_id:
            self._logger.debug('Ignoring own source identity %s', ident)
            return
        self._logger.info('Received bundle identity %s', ident)
        if ident in self._seen_bundle_ident:
            self._logger.debug('Ignoring already seen bundle %s', ident)
            return
        else:
            self._seen_bundle_ident.add(ident)

        ctr.record_action('receive')

        for step in self._rx_chain:
            self._logger.debug('Performing RX step %.1f: %s', step.order, step.name)
            if step.action(ctr):
                self._logger.debug('Step %.1f interrupted the chain', step.order)
                break

        if 'delete' in ctr.actions:
            self._logger.warning('Deleting bundle ident %s', ctr.bundle_ident())
            self._finish_bundle(ctr)
            return

        if 'deliver' in ctr.actions:
            self._logger.warning('Delivered bundle ident %s', ctr.bundle_ident())
            self._finish_bundle(ctr)
        else:
            # assume we want to forward
            self._fwd_ctrs.append(ctr)
            glib.idle_add(self._do_fwd)

    def _do_fwd(self):
        ''' Process the forwarding queue.
        :return: True if there are more items to process.
        '''
        if not self._fwd_ctrs:
            return False

        try:
            ctr = self._fwd_ctrs.pop(0)

            for blk in ctr.block_type(PreviousNodeBlock):
                ctr.remove_block(blk)
            ctr.add_block(CanonicalBlock() / PreviousNodeBlock(node=self._config.node_id))

            for blk in ctr.block_type(HopCountBlock):
                blk.payload.count += 1

            for blk in ctr.block_type(BundleAgeBlock):
                ctr.remove_block(blk)
            create_dtntime = ctr.bundle.primary.create_ts.getfieldval('dtntime')
            if create_dtntime != 0:
                now_dtntime = self.timestamp().getfieldval('dtntime')
                age = now_dtntime - create_dtntime
                ctr.add_block(CanonicalBlock() / BundleAgeBlock(age=age))

            self.send_bundle(ctr)
            # Status after send 'success'
            ctr.record_action('forward')
        except Exception as err:
            self._logger.error('Failed to forward bundle %s: %s', ctr.bundle_ident(), err)
            ctr.record_action('delete', StatusReport.ReasonCode.NO_ROUTE)

        self._finish_bundle(ctr)

    def _apply_primary(self, ctr):
        ''' Touch up primary block content from defaults.
        '''
        # apply local policy
        if ctr.bundle.primary.create_ts.getfieldval('dtntime') == 0:
            ctr.bundle.primary.create_ts = self.timestamp()
        if ctr.bundle.primary.getfieldval('lifetime') == 0:
            td = datetime.timedelta(hours=1)
            ctr.bundle.primary.lifetime = td.total_seconds() * 1e3 + td.microseconds // 1e3

    def send_bundle(self, ctr):
        ''' Perform agent handling to send a bundle.
        Part of this is to update final CRCs on all blocks and
        assign block numbers.

        :param ctr: The bundle container to send.
        :type ctr: :py:cls:`BundleContainer`
        '''
        ctr.reload()
        self._apply_primary(ctr)

        for step in self._tx_chain:
            self._logger.debug('Performing TX step %.1f: %s', step.order, step.name)
            if step.action(ctr):
                self._logger.debug('Step %.1f interrupted the chain', step.order)
                break

        ctr.fix_block_num()
        ctr.bundle.fill_fields()

        # Remember outgoing identities
        self._seen_bundle_ident.add(ctr.bundle_ident())
#FIXME        ctrlist = self._fragment(ctr, route)
        ctrlist = [ctr]
        for ctr in ctrlist:
            ctr.bundle.update_all_crc()
            self._seen_bundle_ident.add(ctr.bundle_ident())
            self._logger.debug('Sending bundle\n%s', ctr.bundle.show(dump=True))
            data = bytes(ctr.bundle)
            self._logger.info('send_bundle size %d', len(data))
            self._logger.debug('send_bundle data %s', encode_diagnostic(cbor2.loads(data)))
            ctr.sender(data)

    @dbus.service.method(DBUS_IFACE, in_signature='ss', out_signature='')
    def cl_attach(self, cltype, servname):
        ''' Listen to sessions and bundles from a CL agent.

        :param str servname: The DBus service name to listen from.
        '''
        self._logger.debug('Attaching to %s service %s', cltype, servname)

        try:
            cls = bp.cla.CL_TYPES[cltype]
        except KeyError:
            raise ValueError('Invalid cltype: {}'.format(cltype))

        agent = cls()
        agent.serv_name = servname
        agent.recv_bundle_finish = self._cl_recv_bundle
        self._cl_agent[cltype] = agent

        if self._bus_obj.NameHasOwner(servname):
            agent.bind(self._config.bus_conn)
        else:
            self._logger.info('Service %s not yet available, but will bind when available', servname)

    @dbus.service.method(DBUS_IFACE, in_signature='si', out_signature='')
    def ping(self, nodeid, datalen):
        ''' Ping with random data via the routing table.

        :param str nodeid: The destination Node ID.
        :param int datalen: The payload data length.
        '''

        cts = self.timestamp()

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.REQ_DELETION_REPORT
                | PrimaryBlock.Flag.REQ_DELIVERY_REPORT
                | PrimaryBlock.Flag.REQ_FORWARDING_REPORT
                | PrimaryBlock.Flag.REQ_RECEPTION_REPORT
                | PrimaryBlock.Flag.REQ_STATUS_TIME
                | PrimaryBlock.Flag.NO_FRAGMENT
            ),
            destination=str(nodeid),
            source=self._config.node_id,
            report_to=self._config.node_id,
            create_ts=cts,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
                btsd=bytes(scapy.volatile.RandString(datalen)),
            ),
        ]

        self.send_bundle(ctr)
