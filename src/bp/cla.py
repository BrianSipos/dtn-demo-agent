''' Convergence layer adaptors.
'''
from abc import ABC, abstractmethod
import logging
import dbus
from gi.repository import GLib as glib
from binascii import unhexlify
import re
from bp.config import TxRouteItem

# Dictionary of CL types
CL_TYPES = {}


def cl_type(name: str):
    ''' Decorator to register a CL adaptor class.
    '''

    def func(cls):
        CL_TYPES[name] = cls
        return cls

    return func


class AbstractAdaptor(ABC):
    ''' Interface for a CL.

    :ivar agent_obj: The bus proxy object when it is valid.
    '''

    def __init__(self, agent):
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._agent = agent

        self.serv_name = None
        self.obj_path = None

        self.bus_conn = None
        self.agent_obj = None

    def bind(self, bus_conn):
        if self.agent_obj:
            return
        self._logger.debug('Binding to CL service %s %s', self.serv_name, self.obj_path)
        self.bus_conn = bus_conn
        self.agent_obj = bus_conn.get_object(self.serv_name, self.obj_path)
        self._do_bind()

    @abstractmethod
    def _do_bind(self):
        raise NotImplementedError()

    def unbind(self):
        if not self.agent_obj:
            return
        self._logger.debug('Unbinding from CL service %s', self.serv_name)
        self.agent_obj = None
        self.bus_conn = None

    def peer_node_seen(self, node_id: str, tx_params: dict):
        ''' Callback interface to a indicate when a peer is seen

        :param node_id: A potential route to use for this peer.
        '''
        raise NotImplementedError()

    def recv_bundle_finish(self, data: bytes, metadata: dict):
        ''' Callback interface to a handle received bundles.

        :param data: The actual bundle recevied.
        :param metadata: A dictionary of CL-defined supplemental data.
        '''
        raise NotImplementedError()

    @abstractmethod
    def send_bundle_func(self, tx_params: dict):
        ''' Interface to get a function to send a bundle to be sent by the CL.
        :param kwargs: Arguments from the routing table.
        '''
        raise NotImplementedError()


@cl_type('udpcl')
class UdpclAdaptor(AbstractAdaptor):
    ''' UDP Convergence layer.
    '''

    # Interface name
    DBUS_IFACE = 'org.ietf.dtn.udpcl.Agent'

    TAG_ENC = unhexlify('d9d9f7')

    def __init__(self, **kwargs):
        AbstractAdaptor.__init__(self, **kwargs)
        self.obj_path = '/org/ietf/dtn/udpcl/Agent'

    def _handle_polling_received(self, dtntime, interval_ms, node_id, address, port):
        tx_params = dict(
            address=address,
            port=port,
        )
        try:
            self.peer_node_seen(node_id, tx_params)
        except NotImplementedError:
            pass

    def _handle_recv_bundle_finish(self, bid, _length, rx_params):
        data = self.agent_obj.recv_bundle_pop_data(bid)
        data = bytes(data)
        try:
            self.recv_bundle_finish(data, rx_params)
        except NotImplementedError:
            pass

    def _do_bind(self):
        agent_iface = dbus.Interface(self.agent_obj, UdpclAdaptor.DBUS_IFACE)
        agent_iface.connect_to_signal('polling_received', self._handle_polling_received)
        agent_iface.connect_to_signal('recv_bundle_finished', self._handle_recv_bundle_finish)

    def send_bundle_func(self, tx_params: dict):
        do_tag = tx_params.get('do_tag', False)

        def sender(data):
            if do_tag:
                if not data.startswith(UdpclAdaptor.TAG_ENC):
                    data = UdpclAdaptor.TAG_ENC + data
            self.agent_obj.send_bundle_data(
                dbus.ByteArray(data),
                dbus.Dictionary(tx_params, signature='sv')
            )

        return sender


@cl_type('tcpcl')
class TcpclAdaptor(AbstractAdaptor):
    ''' TCP Convergence layer.
    '''

    # Interface name
    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Agent'

    def __init__(self, **kwargs):
        AbstractAdaptor.__init__(self, **kwargs)
        self.obj_path = '/org/ietf/dtn/tcpcl/Agent'

        self.conns = set()
        # Map from obj_path to TcpclConnection
        self._cl_conn_path = {}
        # Map from peer Node ID to TcpclConnection
        self._cl_conn_nodeid = {}
        # Bundles waiting for sessions
        self._sess_wait = {}

    def _do_bind(self):
        agent_iface = dbus.Interface(self.agent_obj, TcpclAdaptor.DBUS_IFACE)
        agent_iface.connect_to_signal('connection_opened', self._conn_attach)
        agent_iface.connect_to_signal('connection_closed', self._conn_detach)
        for conn_path in agent_iface.get_connections():
            self._conn_attach(conn_path)

    def _conn_attach(self, conn_path):
        ''' Attach to new connection object.
        '''
        self._logger.debug('Attaching to CL object %s', conn_path)
        conn_obj = self.bus_conn.get_object(self.serv_name, conn_path)
        conn_iface = dbus.Interface(conn_obj, TcpclConnection.DBUS_IFACE)

        cl_conn = TcpclConnection()
        cl_conn.serv_name = self.serv_name
        cl_conn.obj_path = conn_path
        cl_conn.conn_obj = conn_iface
        self.conns.add(cl_conn)
        self._cl_conn_path[cl_conn.obj_path] = cl_conn

        def handle_recv_bundle_finish(bid, _length, result):
            if result != 'success':
                return
            data = conn_iface.recv_bundle_pop_data(bid)
            data = dbus.ByteArray(data)
            try:
                self.recv_bundle_finish(data, {})
            except NotImplementedError:
                pass

        conn_iface.connect_to_signal('recv_bundle_finished', handle_recv_bundle_finish)

        def handle_state_change(state):
            self._logger.debug('State change to %s', state)
            if state == 'established':
                params = conn_iface.get_session_parameters()
                cl_conn = self._cl_conn_path[conn_path]
                cl_conn.nodeid = str(params['peer_nodeid'])
                cl_conn.sess_params = params
                self._logger.debug('Session established with %s', cl_conn.nodeid)
                self._cl_conn_nodeid[cl_conn.nodeid] = cl_conn
                self._conn_ready(cl_conn, cl_conn.nodeid)
                self._conn_ready(cl_conn, None)
                self._reverse_route(cl_conn)

        conn_iface.connect_to_signal('session_state_changed', handle_state_change)
        state = conn_iface.get_session_state()
        handle_state_change(state)

    def _conn_detach(self, conn_path):
        ''' Detach from a removed connection object.
        '''
        cl_conn = self._cl_conn_path[conn_path]
        self._logger.debug('Detaching from CL object %s (node %s)', conn_path, cl_conn.nodeid)
        del self._cl_conn_path[cl_conn.obj_path]
        if cl_conn.nodeid:
            del self._cl_conn_nodeid[cl_conn.nodeid]

    def _conn_ready(self, cl_conn: 'TcpclConnection', next_hop: str):
        ''' Handle a new connection being established and
        send any pending data for a next-hop.

        :param cl_conn: The connection object.
        :param next_hop: The desired next-hop or None
        '''
        pend_data = self._sess_wait.get(next_hop, [])
        for data in pend_data:
            cl_conn.send_bundle_data(data)

    def _reverse_route(self, cl_conn):
        ''' Add reverse route to node on other side of connection.
        '''
        route = TxRouteItem(
            eid_pattern=re.compile(re.escape(cl_conn.nodeid) + r'.*'),
            next_nodeid=cl_conn.nodeid,  # FIXME needed?
            cl_type='tcpcl',
            raw_config=dict(
                next_nodeid=cl_conn.nodeid,  # allow session lookup
            ),
        )
        self._logger.info('Route item %s', route)
        self._agent.add_tx_route(route)

    def connect(self, address: str, port: int):
        ''' Initiate a connection preemptively.
        '''
        self._logger.info('Connecting to [%s]:%d', address, port)
        self.agent_obj.connect(address, port)

    def send_bundle_func(self, tx_params: dict):
        ''' Get an active session or create one if needed.
        '''
        next_nodeid = tx_params.get('next_nodeid')

        def sender(data):
            # Either send immediately or put in TX queue
            if next_nodeid is None and len(self._cl_conn_nodeid) == 1:
                nodeid, cl_conn = next(iter(self._cl_conn_nodeid.items()))
                self._logger.info('Existing default session with %s', nodeid)
                cl_conn.send_bundle_data(data)
            elif next_nodeid in self._cl_conn_nodeid:
                self._logger.info('Existing session with %s', next_nodeid)
                cl_conn = self._cl_conn_nodeid[next_nodeid]
                cl_conn.send_bundle_data(data)
            else:
                self._logger.info('Need session with %s', next_nodeid)
                if next_nodeid not in self._sess_wait:
                    self._sess_wait[next_nodeid] = []
                self._sess_wait[next_nodeid].append(data)

                if next_nodeid not in self._cl_conn_nodeid:
                    address = tx_params['address']
                    port = tx_params.get('port', 4556)
                    self._logger.info('Connecting to [%s]:%d', address, port)
                    self.agent_obj.connect(address, port)

        return sender


class TcpclConnection(object):
    ''' TCP Convergence layer session keeping.

    :ivar conn_obj: The bus proxy object when it is valid.
    '''

    # Interface name
    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Contact'

    def __init__(self):
        self._logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.serv_name = None
        self.obj_path = None

        self.conn_obj = None

        # set after session negotiated
        self.sess_params = None
        self.nodeid = None

    def send_bundle_data(self, data):
        self._logger.debug('Sending bundle data size %d', len(data))
        self.conn_obj.send_bundle_data(data)
