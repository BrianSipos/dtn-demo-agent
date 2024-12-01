''' Implementation of a symmetric BPv7 agent.
'''
import datetime
import logging
import traceback
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
from bp.config import TxRouteItem

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

    # Interface name
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
        # Set when shutdown() is called and waiting on sessions
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
        for (name, cls) in bp.app.base.APPLICATIONS.items():
            path = '/org/ietf/dtn/bp/app/{}'.format(name)
            self._logger.debug('Registering application %s at %s', cls, path)
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path=path
            )
            app = cls(app_name=name, agent=self, bus_kwargs=bus_kwargs)
            self._app[name] = app
            app.load_config(self._config)
            app.add_chains(self._rx_chain, self._tx_chain)
        self._rx_chain.sort()
        self._tx_chain.sort()
        self._show_chain(self._rx_chain, 'RX Chain')
        self._show_chain(self._tx_chain, 'TX Chain')
        # Seen bundle identities
        self._seen_bundle_ident = set()
        # Forwarding queue
        self._fwd_queue = []
        # Transmit queue
        self._tx_queue = []

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

    def add_tx_route(self, item:TxRouteItem):
        self._config.tx_route_table.append(item)

    def get_cla(self, name:str) -> bp.cla.AbstractAdaptor:
        return self._cl_agent[name]

    def _bus_name_changed(self, servname, old_owner, new_owner):
        for cl_agent in self._cl_agent.values():
            if cl_agent.serv_name == servname:
                self._logger.debug('bus name change %s old %s new %s', servname, old_owner, new_owner)
                if old_owner:
                    cl_agent.unbind()
                if new_owner:
                    cl_agent.bind(self._config.bus_conn)

    def _show_chain(self, chain, name):
        parts = ['{:5.1f}: {}'.format(item.order, item.name) for item in chain]
        self._logger.debug('Items in %s:\n%s', name, '\n'.join(parts))

    def _cl_peer_node_seen(self, cltype):

        def func(nodeid:str, tx_params:dict):
            ''' React to :py:meth:`cla.AbstractAdaptor.peer_node_seen` calls.
            '''
            import re
            self._logger.debug('peer_node_seen from %s node %s with %s', cltype, nodeid, tx_params)

            # Inject static route with fixed pattern
            route = TxRouteItem(
                eid_pattern=re.compile(r'^' + re.escape(nodeid)),
                next_nodeid=nodeid,
                cl_type=cltype,
                raw_config=tx_params
            )
            self._config.tx_route_table.append(route)

        return func

    def _cl_recv_bundle_finish(self, cltype):

        def func(data:bytes, metadata:dict):
            ''' React to :py:meth:`cla.AbstractAdaptor.recv_bundle_finish` calls.
            '''
            self._logger.debug('recv_bundle_finish from %s with %s', cltype, metadata)
            ctr = BundleContainer(Bundle(data))
            self.recv_bundle(ctr)

        return func

    def _do_rx_step(self, ctr):
        ''' Perform the static RX routing step.
        '''
        if 'deliver' in ctr.actions:
            return

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

        return

    def _do_tx_step(self, ctr):
        ''' Perform the static TX routing step.
        '''
        if ctr.route:
            return

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
            ctr.route = found
        else:
            self._logger.debug('No static route for: %s', eid)

        return

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
            self._logger.debug('Performing RX step %5.1f: %s', step.order, step.name)
            try:
                if step.action(ctr):
                    self._logger.debug('Step %5.1f interrupted the chain', step.order)
                    break
            except Exception as err:
                self._logger.error('Step %5.1f failed with exception: %s', step.order, err)
                self._logger.debug('%s', traceback.format_exc())
                break

        if 'delete' in ctr.actions:
            self._logger.warning('Deleting bundle %s', ctr.log_name())
            self._finish_bundle(ctr)
            return

        if 'deliver' in ctr.actions:
            self._logger.info('Delivered bundle %s', ctr.log_name())
            self._finish_bundle(ctr)

        if 'forward' in ctr.actions:
            # defer forwarded status until actually sent
            self._fwd_queue.append(ctr)
            glib.idle_add(self._do_fwd)

    def _do_fwd(self):
        ''' Process the forwarding queue.
        :return: True if there are more items to process.
        '''
        if not self._fwd_queue:
            return False

        try:
            ctr = self._fwd_queue.pop(0)

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
            self._logger.info('Forwarded bundle %s: %s', ctr.log_name())
            ctr.record_action('forward')
        except Exception as err:
            self._logger.error('Failed to forward bundle %s: %s', ctr.log_name(), err)
            self._logger.debug('%s', traceback.format_exc())
            ctr.record_action('delete', StatusReport.ReasonCode.NO_ROUTE)

        self._finish_bundle(ctr)

    def _apply_primary(self, ctr):
        ''' Touch up primary block content from defaults.
        '''
        pri_blk = ctr.bundle.primary

        if pri_blk.source is None:
            pri_blk.source = self._config.node_id

        any_report = (
            PrimaryBlock.Flag.REQ_DELETION_REPORT
            | PrimaryBlock.Flag.REQ_DELIVERY_REPORT
            | PrimaryBlock.Flag.REQ_FORWARDING_REPORT
            | PrimaryBlock.Flag.REQ_RECEPTION_REPORT
        )
        if pri_blk.bundle_flags & any_report and pri_blk.report_to is None:
            pri_blk.report_to = self._config.node_id

        if pri_blk.create_ts.getfieldval('dtntime') == 0:
            pri_blk.create_ts = self.timestamp()

        if pri_blk.getfieldval('lifetime') == 0:
            td = datetime.timedelta(hours=1)
            pri_blk.lifetime = td.total_seconds() * 1e3 + td.microseconds // 1e3

    def send_bundle(self, ctr):
        ''' Perform agent handling to send a bundle.
        Part of this is to update final CRCs on all blocks and
        assign block numbers.

        :param ctr: The bundle container to send.
        :type ctr: :py:cls:`BundleContainer`
        '''
        ctr.reload()
        self._apply_primary(ctr)
        ctr.fix_block_num()
        ctr.bundle.fill_fields()

        for step in self._tx_chain:
            self._logger.debug('Performing TX step %5.1f: %s', step.order, step.name)
            try:
                if step.action(ctr):
                    self._logger.debug('Step %5.1f interrupted the chain', step.order)
                    break
            except Exception as err:
                self._logger.error('Step %5.1f failed with exception: %s', step.order, err)
                self._logger.debug('%s', traceback.format_exc())
                break

        if ctr.route and not ctr.sender:
            # Assume the route is a TxRouteItem
            cl_obj = self._cl_agent.get(ctr.route.cl_type)
            if cl_obj:
                self._logger.info('send_bundle raw_config %s', ctr.route.raw_config)
                ctr.sender = cl_obj.send_bundle_func(ctr.route.raw_config)

        if ctr.sender is None:
            raise RuntimeError('TX chain completed with no sender for %s', ctr.log_name())

        ctr.fix_block_num()
        ctr.bundle.fill_fields()
        ctr.bundle.update_all_crc()

        # self._logger.debug('Sending bundle\n%s', ctr.bundle.show(dump=True))
        data = bytes(ctr.bundle)
        self._logger.info('send_bundle size %d', len(data))
        # self._logger.debug('send_bundle data %s', encode_diagnostic(cbor2.loads(data)))
        ctr.sender(data)

    @dbus.service.method(DBUS_IFACE, in_signature='ss', out_signature='')
    def cl_attach(self, cltype, servname):
        ''' Listen to sessions and bundles from a CL agent.

        :param str servname: The DBus service name to listen from.
        '''
        self._logger.debug('Attaching to %s service %s', cltype, servname)

        try:
            cls:bp.cla.AbstractAdaptor = bp.cla.CL_TYPES[cltype]
        except KeyError:
            raise ValueError('Invalid cltype: {}'.format(cltype))

        agent = cls(agent=self)
        agent.serv_name = servname
        agent.peer_node_seen = self._cl_peer_node_seen(cltype)
        agent.recv_bundle_finish = self._cl_recv_bundle_finish(cltype)
        self._cl_agent[cltype] = agent

        if self._bus_obj.NameHasOwner(servname):
            agent.bind(self._config.bus_conn)
            self._logger.info('Bound to %s service %s', cltype, servname)
        else:
            self._logger.info('Could not bind to %s service %s, but will bind when available', cltype, servname)

    @dbus.service.method(DBUS_IFACE, in_signature='si', out_signature='')
    def ping(self, nodeid, datalen):
        ''' Ping with random data via the routing table.

        :param str nodeid: The destination Node ID.
        :param int datalen: The payload data length.
        '''

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.REQ_DELETION_REPORT
                | PrimaryBlock.Flag.REQ_DELIVERY_REPORT
                | PrimaryBlock.Flag.REQ_FORWARDING_REPORT
                | PrimaryBlock.Flag.REQ_RECEPTION_REPORT
                | PrimaryBlock.Flag.REQ_STATUS_TIME
            ),
            destination=str(nodeid),
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
