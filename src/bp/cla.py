''' Convergence layer adaptors.
'''
import logging
import dbus
from gi.repository import GLib as glib
from binascii import unhexlify

#: Dictionary of CL types
CL_TYPES = {}


def cl_type(name: str):
    ''' Decorator to register a CL adaptor class.
    '''

    def func(cls):
        CL_TYPES[name] = cls
        return cls

    return func


class AbstractAdaptor(object):
    ''' Interface for a CL.

    :ivar agent_obj: The bus proxy object when it is valid.
    :ivar conns: List of connections on this agent.
    :ivar recv_bundle_finish: A callback to handle received bundle data.
    '''

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)

        self.serv_name = None
        self.obj_path = None

        self.bus_conn = None
        self.agent_obj = None

        self.recv_bundle_finish = None

    def bind(self, bus_conn):
        if self.agent_obj:
            return
        self._logger.debug('Binding to CL service %s %s', self.serv_name, self.obj_path)
        self.bus_conn = bus_conn
        self.agent_obj = bus_conn.get_object(self.serv_name, self.obj_path)
        self._do_bind()

    def _do_bind(self):
        raise NotImplementedError

    def unbind(self):
        if not self.agent_obj:
            return
        self._logger.debug('Unbinding from CL service %s', self.serv_name)
        self.agent_obj = None
        self.bus_conn = None

    def send_bundle_func(self, **kwargs):
        ''' Interface to get a function to send a bundle to be sent by the CL.
        :param kwargs: Arguments from the routing table.
        '''
        raise NotImplementedError


@cl_type('udpcl')
class UdpclAdaptor(AbstractAdaptor):
    ''' UDP Convergence layer.
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.udpcl.Agent'

    TAG_ENC = unhexlify('d9d9f7')

    def __init__(self):
        AbstractAdaptor.__init__(self)
        self.obj_path = '/org/ietf/dtn/udpcl/Agent'

    def _do_bind(self):

        def handle_recv_bundle_finish(bid, _length):
            data = self.agent_obj.recv_bundle_pop_data(bid)
            data = dbus.ByteArray(data)
            if callable(self.recv_bundle_finish):
                self.recv_bundle_finish(data)

        self.agent_obj.connect_to_signal('recv_bundle_finished', handle_recv_bundle_finish, dbus_interface=UdpclAdaptor.DBUS_IFACE)

    def send_bundle_func(self, **kwargs):
        address = kwargs['address']
        port = kwargs.get('port', 4556)
        do_tag = kwargs.get('do_tag', False)

        def sender(data):
            if do_tag:
                if not data.startswith(UdpclAdaptor.TAG_ENC):
                    data = UdpclAdaptor.TAG_ENC + data
            self.agent_obj.send_bundle_data(address, port, dbus.ByteArray(data))

        return sender


@cl_type('tcpcl')
class TcpclAdaptor(AbstractAdaptor):
    ''' TCP Convergence layer.
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Agent'

    def __init__(self):
        AbstractAdaptor.__init__(self)
        self.obj_path = '/org/ietf/dtn/tcpcl/Agent'

        self.conns = set()
        # Map from obj_path to TcpclConnection
        self._cl_conn_path = {}
        # Map from peer Node ID to TcpclConnection
        self._cl_conn_nodeid = {}
        # Bundles waiting for sessions
        self._sess_wait = {}

    def _do_bind(self):
        self.agent_obj.connect_to_signal('connection_opened', self._conn_attach, dbus_interface=TcpclAdaptor.DBUS_IFACE)
        self.agent_obj.connect_to_signal('connection_closed', self._conn_detach, dbus_interface=TcpclAdaptor.DBUS_IFACE)
        for conn_path in self.agent_obj.get_connections():
            self._conn_attach(conn_path)

    def _conn_attach(self, conn_path):
        ''' Attach to new connection object.
        '''
        self._logger.debug('Attaching to CL object %s', conn_path)
        conn_obj = self.bus_conn.get_object(self.serv_name, conn_path)

        cl_conn = TcpclConnection()
        cl_conn.serv_name = self.serv_name
        cl_conn.obj_path = conn_path
        cl_conn.conn_obj = conn_obj
        self.conns.add(cl_conn)
        self._cl_conn_path[cl_conn.obj_path] = cl_conn

        def handle_recv_bundle_finish(bid, _length, result):
            if result != 'success':
                return
            data = conn_obj.recv_bundle_pop_data(bid)
            data = dbus.ByteArray(data)
            if callable(self.recv_bundle_finish):
                self.recv_bundle_finish(data)

        conn_obj.connect_to_signal('recv_bundle_finished', handle_recv_bundle_finish, dbus_interface=TcpclConnection.DBUS_IFACE)

        def handle_state_change(state):
            self._logger.debug('State change to %s', state)
            if state == 'established':
                params = conn_obj.get_session_parameters()
                cl_conn = self._cl_conn_path[conn_path]
                cl_conn.nodeid = str(params['peer_nodeid'])
                cl_conn.sess_params = params
                self._logger.debug('Session established with %s', cl_conn.nodeid)
                self._cl_conn_nodeid[cl_conn.nodeid] = cl_conn
                self._conn_ready(cl_conn)

        conn_obj.connect_to_signal('session_state_changed', handle_state_change, dbus_interface=TcpclConnection.DBUS_IFACE)
        state = conn_obj.get_session_state()
        handle_state_change(state)

    def _conn_detach(self, conn_path):
        ''' Detach from a removed connection object.
        '''
        cl_conn = self._cl_conn_path[conn_path]
        self._logger.debug('Detaching from CL object %s (node %s)', conn_path, cl_conn.nodeid)
        del self._cl_conn_path[cl_conn.obj_path]
        if cl_conn.nodeid:
            del self._cl_conn_nodeid[cl_conn.nodeid]

    def _conn_ready(self, cl_conn):
        ''' Handle a new connection being established.
        
        :param cl_conn: The connection object.
        :type cl_conn: :py:cls:`TcpclConnection`
        '''
        pend_data = self._sess_wait.get(cl_conn.nodeid)
        if not pend_data:
            return
        cl_conn = self._cl_conn_nodeid[cl_conn.nodeid]
        for data in pend_data:
            cl_conn.send_bundle_data(data)

    def send_bundle_func(self, **kwargs):
        # Get an active session or create one if needed.
        next_nodeid = kwargs['next_nodeid']
        address = kwargs['address']
        port = kwargs.get('port', 4556)

        def sender(data):
            # Either send immeidately or put in TX queue
            if next_nodeid in self._cl_conn_nodeid:
                self._logger.info('Existing session with %s', next_nodeid)
                cl_conn = self._cl_conn_nodeid[next_nodeid]
                cl_conn.send_bundle_data(data)
            else:
                if next_nodeid not in self._sess_wait:
                    self._sess_wait[next_nodeid] = []
                self._sess_wait[next_nodeid].append(data)

                if next_nodeid not in self._cl_conn_nodeid:
                    self._logger.info('Connecting to %s:%d', address, port)
                    self.agent_obj.connect(address, port)

        return sender


class TcpclConnection(object):
    ''' TCP Convergence layer session keeping.

    :ivar conn_obj: The bus proxy object when it is valid.
    '''

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Contact'

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)

        self.serv_name = None
        self.obj_path = None

        self.conn_obj = None

        # set after session negotiated
        self.sess_params = None
        self.nodeid = None

    def send_bundle_data(self, data):
        self._logger.debug('Sending bundle data size %d', len(data))
        self.conn_obj.send_bundle_data(data)
