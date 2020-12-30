'''
Implementation of a symmetric BPv6 agent.
'''
import argparse
import datetime
import logging
import sys
import dbus.service
from gi.repository import GLib as glib
import cbor2
import multiprocessing
import re
from urllib.parse import urlsplit, urlunsplit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import tcpcl.agent
import tcpcl.config
from scapy_cbor.packets import CborItem
from scapy_cbor.util import encode_diagnostic
from bp.encoding import (
    DtnTimeField, Timestamp,
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
    AdminRecord, BundleAgeBlock,
    BlockIntegrityBlock, AbstractSecurityBlock, TypeValuePair, TargetResultList,
    StatusReport, StatusInfoArray, StatusInfo
)
from bp.config import Config

LOGGER = logging.getLogger(__name__)

#: Dummy context ID value
BPSEC_COSE_CONTEXT_ID = 99


class BundleContainer(object):
    ''' A high-level representation of a bundle.
    This includes logical constraints not present in :py:cls:`encoding.Bundle`
    data handling class.
    '''

    def __init__(self, bundle=None):
        if bundle is None:
            bundle = Bundle()
        self.bundle = bundle
        # Map from block number to single Block
        self._block_num = {}
        # Map from block type to list of Blocks
        self._block_type = {}

        self.reload()

    def block_num(self, num):
        return self._block_num[num]

    def block_type(self, type_code):
        ''' Look up a block by type code or data class.
        '''
        return self._block_type[type_code]

    def reload(self):
        ''' Reload derived info from the bundle.
        '''
        if self.bundle is None:
            return

        block_num = {}
        block_type = {}
        if self.bundle.payload is not None:
            block_num[0] = self.bundle.payload
        for blk in self.bundle.getfieldval('blocks'):
            blk_num = blk.getfieldval('block_num')
            if blk_num is not None:
                if blk_num in block_num:
                    raise RuntimeError('Duplicate block_num value')
                block_num[blk_num] = blk

            blk_type = blk.getfieldval('type_code')
            data_cls = type(blk.payload)
            for key in (blk_type, data_cls):
                if key not in block_type:
                    block_type[key] = []
                block_type[key].append(blk)

        self._block_num = block_num
        self._block_type = block_type

    def fix_block_num(self):
        ''' Assign unique block numbers where needed.
        '''
        last_num = 1
        for blk in self.bundle.blocks:
            if blk.getfieldval('block_num') is None:
                if blk.getfieldval('type_code') == 1:
                    set_num = 1
                else:
                    while True:
                        last_num += 1
                        if last_num not in self._block_num:
                            set_num = last_num
                            break
                blk.overloaded_fields['block_num'] = set_num

    def do_report_reception(self):
        return (
            self.bundle.primary.report_to != 'dtn:none'
            and self.bundle.primary.bundle_flags & PrimaryBlock.Flag.REQ_RECEPTION_REPORT
        )

    def create_report_reception(self, timestamp, own_nodeid):
        status_ts = bool(self.bundle.primary.bundle_flags & PrimaryBlock.Flag.REQ_STATUS_TIME)
        status_at = timestamp.getfieldval('time') if status_ts else None

        report = StatusReport(
            status=StatusInfoArray(
                received=StatusInfo(
                    status=True,
                    at=status_at,
                ),
            ),
            reason_code=0,
            subj_source=self.bundle.primary.source,
            subj_ts=self.bundle.primary.create_ts,
        )

        reply = BundleContainer()
        reply.bundle.primary = PrimaryBlock(
            bundle_flags=PrimaryBlock.Flag.PAYLOAD_ADMIN,
            destination=self.bundle.primary.report_to,
            source=own_nodeid,
            create_ts=timestamp,
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        reply.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
            ) / AdminRecord(
            ) / report,
        ]
        return reply


def get_bpsec_cose_aad(ctr, target, secblk, aad_scope):
    ''' Extract AAD from a bundle container.
    '''
    return cbor2.dumps([
        ctr.bundle.primary.build() if aad_scope & 0x1 else None,
        target.build()[:3] if aad_scope & 0x2 else None,
        secblk.build()[:3] if aad_scope & 0x4 else None,
    ])
    return b''


class ClAgent(object):
    ''' Convergence layer connectivity.

    :ivar agent_obj: The bus proxy object when it is valid.
    :ivar conns: List of connections on this agent.
    :ivar recv_bundle_finish: A callback to handle received bundle data.
    '''

    def __init__(self):
        self.serv_name = None
        self.obj_path = None

        self.bus_conn = None
        self.agent_obj = None

        self.recv_bundle_finish = None

        self.conns = set()
        # Map from obj_path to ClConnection
        self._cl_conn_path = {}
        # Map from peer Node ID to ClConnection
        self._cl_conn_nodeid = {}
        # Waiting for sessions
        self._sess_wait = {}

    def bind(self, bus_conn):
        if self.agent_obj:
            return
        LOGGER.debug('Binding to CL service %s', self.serv_name)
        self.bus_conn = bus_conn
        self.agent_obj = bus_conn.get_object(self.serv_name, self.obj_path)

        self.agent_obj.connect_to_signal('connection_opened', self._conn_attach)
        self.agent_obj.connect_to_signal('connection_closed', self._conn_detach)
        for conn_path in self.agent_obj.get_connections():
            self._conn_attach(conn_path)

    def unbind(self):
        if not self.agent_obj:
            return
        LOGGER.debug('Unbinding from CL service %s', self.serv_name)
        self.agent_obj = None
        self.bus_conn = None

    def _conn_attach(self, conn_path):
        ''' Attach to new connection object.
        '''
        LOGGER.debug('Attaching to CL object %s', conn_path)
        conn_obj = self.bus_conn.get_object(self.serv_name, conn_path)

        cl_conn = ClConnection()
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
            LOGGER.debug('handle_recv_bundle_finish data %s', cbor2.loads(data))
            if callable(self.recv_bundle_finish):
                self.recv_bundle_finish(data)

        conn_obj.connect_to_signal('recv_bundle_finished', handle_recv_bundle_finish)

        def handle_state_change(state):
            if state == 'established':
                params = conn_obj.get_session_parameters()
                cl_conn = self._cl_conn_path[conn_path]
                cl_conn.nodeid = str(params['peer_nodeid'])
                cl_conn.sess_params = params
                LOGGER.debug('Session established with %s', cl_conn.nodeid)
                self._cl_conn_nodeid[cl_conn.nodeid] = cl_conn
                self._conn_ready(cl_conn.nodeid)

        state = conn_obj.get_session_state()
        if state != 'established':
            conn_obj.connect_to_signal('session_state_changed', handle_state_change)
        handle_state_change(state)

    def _conn_detach(self, conn_path):
        ''' Detach from a removed connection object.
        '''
        cl_conn = self._cl_conn_path[conn_path]
        LOGGER.debug('Detaching from CL object %s (node %s)', conn_path, cl_conn.nodeid)
        del self._cl_conn_path[cl_conn.obj_path]
        if cl_conn.nodeid:
            del self._cl_conn_nodeid[cl_conn.nodeid]

    def _conn_ready(self, nodeid):
        cb = self._sess_wait.get(nodeid)
        if callable(cb):
            cb()

    def get_session(self, nodeid, address, port):
        ''' Get an active session or create one if needed.
        '''

        if nodeid in self._cl_conn_nodeid:
            LOGGER.info('Existing to %s', nodeid)
        else:
            LOGGER.info('Connecting to %s:%d', address, port)
            self.agent_obj.connect(address, port)

            # Wait in loop until self._conn_ready() is called
            eloop = glib.MainLoop()
            self._sess_wait[nodeid] = eloop.quit
            eloop.run()
            LOGGER.info('Connected')

        cl_conn = self._cl_conn_nodeid[nodeid]
        return cl_conn


class ClConnection(object):
    ''' Convergence layer session keeping.

    :ivar conn_obj: The bus proxy object when it is valid.
    '''

    def __init__(self):
        self.serv_name = None
        self.obj_path = None

        self.conn_obj = None

        # set after session negotiated
        self.sess_params = None
        self.nodeid = None


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
            time=self._time,
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

    DBUS_IFACE = 'org.ietf.dtn.bp.Agent'

    def __init__(self, config, bus_kwargs=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self._ca_cert = None
        if self._config.tls_ca_file:
            with open(self._config.tls_cert_file, 'rb') as infile:
                self._ca_cert = x509.load_pem_x509_certificate(infile.read())

        self._cert_chain = None
        if self._config.tls_cert_file:
            cert_chain = []
            with open(self._config.tls_cert_file, 'rb') as infile:
                chunk = b''
                while True:
                    line = infile.readline()
                    chunk += line
                    if b'END CERTIFICATE' in line.upper():
                        cert = x509.load_pem_x509_certificate(chunk)
                        cert_chain.append(cert)
                    if not line:
                        break
            self._cert_chain = tuple(cert_chain)

        self._priv_key = None
        if self._config.tls_key_file:
            with open(self._config.tls_key_file, 'rb') as infile:
                self._priv_key = serialization.load_pem_private_key(infile.read(), None, default_backend())

        self.timestamp = Timestamper()

        self._bus_obj = self._config.bus_conn.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        self._bus_obj.connect_to_signal('NameOwnerChanged', self._bus_name_changed)

        # Bound-to CL agent
        self._cl_agent = None

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/bp/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

        if self._config.bus_service:
            self._bus_serv = dbus.service.BusName(
                bus=self._config.bus_conn,
                name=self._config.bus_service,
                do_not_queue=True
            )
            self.__logger.info('Registered as "%s"', self._bus_serv.get_name())

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
        self.__logger.info('Shutting down agent')
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
        self.__logger.info('Starting event loop')
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()

    def _bus_name_changed(self, servname, old_owner, new_owner):
        if self._cl_agent and self._cl_agent.serv_name == servname:
            if old_owner:
                self._cl_agent.unbind()
            if new_owner:
                self._cl_agent.bind(self._config.bus_conn)

    def _cl_recv_bundle(self, data):
        ''' Handle a new received bundle from a CL.
        '''
        print('Saw bundle data len {}'.format(len(data)))
        ctr = BundleContainer(Bundle(data))
        self.recv_bundle(ctr)

    def _get_session_for(self, eid):
        self.__logger.info('Getting session for: %s', eid)
        if not self._cl_agent:
            raise RuntimeError('No CL bound')

        found = None
        for item in self._config.route_table:
            if item.eid_pattern.match(eid) is not None:
                found = item
                break
        if found is None:
            raise KeyError('No route to destination: {}'.format(eid))
        return self._cl_agent.get_session(
            found.next_nodeid,
            found.next_hop.address if found.next_hop else None,
            found.next_hop.port if found.next_hop else None
        )

    def recv_bundle(self, ctr):
        ''' Perform agent handling of a received bundle.

        :param ctr: The bundle container just recieved.
        :type ctr: :py:cls:`BundleContainer`
        '''
        self.__logger.info('Received bundle\n%s', ctr.bundle.show(dump=True))
        self.__logger.debug('CRC invalid for block numbers: %s', ctr.bundle.check_all_crc())

        integ_blocks = ctr.block_type(BlockIntegrityBlock)
        for bib in integ_blocks:
            if bib.payload.context_id == BPSEC_COSE_CONTEXT_ID:
                from cose import CoseMessage, CoseHeaderKeys, RSA

                # FIXME: wonky method of correlating an end-entity cert
                aad_scope = 0x7
                first_cert = None
                for param in bib.payload.parameters:
                    if param.type_code == 5:
                        aad_scope = int(param.value)
                    elif param.type_code == 3:
                        first_cert = x509.load_der_x509_certificate(param.value[0])

                cose_key = RSA.from_cryptograpy_key_obj(first_cert.public_key())

                for (ix, blk_num) in enumerate(bib.payload.targets):
                    target_blk = ctr.block_num(blk_num)
                    for result in bib.payload.results[ix].results:
                        msg_cls = CoseMessage._COSE_MSG_ID[result.type_code]

                        # replace detached payload
                        msg_enc = bytes(result.getfieldval('value'))
                        msg_dec = cbor2.loads(msg_enc)
                        msg_dec[2] = target_blk.getfieldval('data')

                        self.__logger.debug('COSE message\n%s', encode_diagnostic(msg_dec))
                        msg_obj = msg_cls.from_cose_obj(msg_dec)
                        msg_obj.external_aad = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)

                        try:
                            msg_obj.verify_signature(
                                public_key=cose_key,
                                alg=msg_obj.phdr[CoseHeaderKeys.ALG],
                            )
                            self.__logger.info('Verified signature on block num %d', blk_num)
                        except Exception as err:
                            self.__logger.error('Failed to verify signature on block num %d: %s', blk_num, err)

        if ctr.do_report_reception():
            self.send_bundle(ctr.create_report_reception(self.timestamp(), self._config.node_id))

    def send_bundle(self, ctr):
        ''' Perform agent handling to send a bundle.
        Part of this is to update final CRCs on all blocks and
        assign block numbers.

        :param ctr: The bundle container to send.
        :type ctr: :py:cls:`BundleContainer`
        '''
        dest_eid = str(ctr.bundle.primary.destination)
        cl_conn = self._get_session_for(dest_eid)

        # Apply local security policy
        ctr.reload()
        if self._priv_key:
            from binascii import hexlify
            from cose import Sign1Message, CoseHeaderKeys, CoseAlgorithms, RSA
            from cose.messages.signer import SignerParams
            import cose.keys.cosekey as cosekey

            aad_scope = 0x3

            x5chain = []
            for cert in self._cert_chain:
                x5chain.append(cert.public_bytes(serialization.Encoding.DER))

            # A little switcharoo to avoid cached overload_fields on `data`
            bib = CanonicalBlock(
                type_code=BlockIntegrityBlock._overload_fields[CanonicalBlock]['type_code']
            )
            bib_data = BlockIntegrityBlock(
                targets=[1],
                context_id=BPSEC_COSE_CONTEXT_ID,
                context_flags=AbstractSecurityBlock.Flag.PARAMETERS_PRESENT,
                parameters=[
                    TypeValuePair(type_code=3, value=x5chain),
                    TypeValuePair(type_code=5, value=aad_scope),
                ],
            )

            # Sign each target with one result per
            target_result = []
            for blk_num in bib_data.targets:
                target_blk = ctr.block_num(blk_num)
                target_plaintext = target_blk.data

                ext_aad_enc = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)
                cose_key = RSA.from_cryptograpy_key_obj(self._priv_key)
                self.__logger.debug('Signing target %d AAD %s payload %s', blk_num, hexlify(ext_aad_enc), hexlify(target_plaintext))
                msg_obj = Sign1Message(
                    phdr={
                        CoseHeaderKeys.ALG: CoseAlgorithms.PS256,
                    },
                    uhdr={
                        #FIXME: doesn't decode
                        #CoseHeaderKeys.X5_T: [0, b'hi'],
                    },
                    payload=target_plaintext,
                    # Non-encoded parameters
                    external_aad=ext_aad_enc,
                )
                msg_enc = msg_obj.encode(
                    private_key=cose_key,
                    alg=msg_obj.phdr[CoseHeaderKeys.ALG],
                    tagged=False
                )
                # detach payload
                msg_dec = cbor2.loads(msg_enc)
                msg_dec[2] = None
                msg_enc = cbor2.dumps(msg_dec)
                self.__logger.debug('COSE message\n%s', encode_diagnostic(msg_dec))

                target_result.append(
                    TypeValuePair(
                        type_code=msg_obj.cbor_tag,
                        value=msg_enc
                    )
                )

            bib.remove_payload()
            # One result per target
            bib_data.setfieldval('results', [
                TargetResultList(results=[result])
                for result in target_result
            ])
            bib.add_payload(bib_data)
            ctr.bundle.blocks.insert(0, bib)

        ctr.fix_block_num()
        ctr.bundle.update_all_crc()
        self.__logger.info('Sending bundle\n%s', ctr.bundle.show(dump=True))

        cl_conn.conn_obj.send_bundle_data(dbus.ByteArray(bytes(ctr.bundle)))

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def cl_attach(self, servname):
        ''' Listen to sessions and bundles from a CL agent.

        :param str servname: The DBus service name to listen from.
        '''
        self.__logger.debug('Attaching to CL service %s', servname)

        agent = ClAgent()
        agent.serv_name = servname
        agent.obj_path = '/org/ietf/dtn/tcpcl/Agent'
        agent.recv_bundle_finish = self._cl_recv_bundle
        self._cl_agent = agent

        if self._bus_obj.NameHasOwner(servname):
            agent.bind(self._config.bus_conn)
        else:
            self.__logger.info('Service %s not yet available, but will bind when available', servname)

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def ping(self, nodeid):
        ''' Ping via TCPCL and an admin record.

        :param str servname: The DBus service name to listen from.
        '''

        cts = self.timestamp()

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(PrimaryBlock.Flag.REQ_RECEPTION_REPORT | PrimaryBlock.Flag.REQ_STATUS_TIME),
            destination=nodeid,
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
                data=b'hello',
            ),
        ]

        self.send_bundle(ctr)


def str2bool(val):
    ''' Require an option value to be boolean text.
    '''
    if val.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if val.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    raise argparse.ArgumentTypeError('Boolean value expected')


def uristr(val):
    ''' Require an option value to be a URI.
    '''
    nodeid_uri = urlsplit(val)
    if not nodeid_uri.scheme:
        raise argparse.ArgumentTypeError('URI value expected')
    return val


def main():
    ''' Agent command entry point. '''
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    parser.add_argument('--config-file', type=str,
                        help='Configuration file to load from')
    parser.add_argument('--eloop', type=str2bool, default=True,
                        help='If enabled, waits in an event loop.')
    subp = parser.add_subparsers(dest='action', help='action')

    parser_ping = subp.add_parser('ping',
                                  help='Send an admin record')
    parser_ping.add_argument('destination', type=uristr)

    args = parser.parse_args()

    log_level = args.log_level.upper()
    log_queue = tcpcl.agent.root_logging(log_level)
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()
    if args.config_file:
        with open(args.config_file, 'rb') as infile:
            config.from_file(infile)

    agent = Agent(config)

    if config.cl_fork == 'tcpcl':
        cl_config = tcpcl.config.Config()
        with open(args.config_file, 'rb') as infile:
            cl_config.from_file(infile)

        # Fork CL child
        def run_cl(cl_config):
            tcpcl.agent.root_logging(log_level, log_queue)
            logging.getLogger().info('CL child started %s')
            agent = tcpcl.agent.Agent(cl_config)
            agent.exec_loop()
            logging.getLogger().info('CL child ended')

        LOGGER.info('Spawning CL process for %s', cl_config.bus_service)
        worker_proc = multiprocessing.Process(target=run_cl, args=[cl_config])
        worker_proc.start()
    else:
        worker_proc = None
    if config.cl_attach:
        # Immediately attach to the CL
        agent.cl_attach(config.cl_attach)

    if args.action == 'ping':
        agent.ping(args.destination)

    if args.eloop:
        agent.exec_loop()

    if worker_proc:
        worker_proc.join()


if __name__ == '__main__':
    sys.exit(main())
