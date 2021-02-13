''' Implementation of a symmetric BPv7 agent.
'''
import datetime
import logging
import dbus.service
from gi.repository import GLib as glib
import cbor2
from urllib.parse import urlsplit, urlunsplit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from certvalidator import CertificateValidator, ValidationContext
import scapy.volatile
import tcpcl
from scapy_cbor.util import encode_diagnostic
from bp.encoding import (
    DtnTimeField, Timestamp,
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
    AdminRecord,
    BlockIntegrityBlock, AbstractSecurityBlock, TypeValuePair, TargetResultList,
    StatusReport, StatusInfoArray, StatusInfo
)
import bp.cla

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
        # Block number generator
        self._last_block_num = 1
        # Map from block number to single Block
        self._block_num = {}
        # Map from block type to list of Blocks
        self._block_type = {}

        self.reload()

    def block_num(self, num):
        ''' Look up a block by unique number.

        :param num: The block number to look up.
        :return: The block with that number.
        :raise KeyError: If the number is not present.
        '''
        return self._block_num[num]

    def block_type(self, type_code):
        ''' Look up a block by type code or data class.

        :param type_code: The type code to look up.
        :return: A list of blocks of that type, which may be empty.
        '''
        return self._block_type.get(type_code, [])

    def bundle_ident(self):
        ''' Get the bundle identity (source + timestamp) as a tuple.
        '''
        pri = self.bundle.getfieldval('primary')
        ident = [
            pri.source,
            pri.create_ts.getfieldval('dtntime'),
            pri.create_ts.getfieldval('seqno')
        ]
        if pri.bundle_flags & PrimaryBlock.Flag.IS_FRAGMENT:
            ident += [
                pri.fragment_offset,
                pri.total_app_data_len,
            ]
        return tuple(ident)

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
            blk.ensure_block_type_specific_data()

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

    def get_block_num(self):
        ''' Get the next unused block number.
        :return: An unused number.
        '''
        while True:
            self._last_block_num += 1
            if self._last_block_num not in self._block_num:
                return self._last_block_num

    def fix_block_num(self):
        ''' Assign unique block numbers where needed.
        '''
        for blk in self.bundle.getfieldval('blocks'):
            if blk.getfieldval('block_num') is None:
                if blk.getfieldval('type_code') == Bundle.BLOCK_TYPE_PAYLOAD:
                    set_num = Bundle.BLOCK_NUM_PAYLOAD
                else:
                    set_num = self.get_block_num()
                blk.overloaded_fields['block_num'] = set_num

    def do_report_reception(self):
        return (
            self.bundle.primary.getfieldval('report_to') != 'dtn:none'
            and self.bundle.primary.getfieldval('bundle_flags') & PrimaryBlock.Flag.REQ_RECEPTION_REPORT
        )

    def create_report_reception(self, timestamp, own_nodeid):
        status_ts = bool(self.bundle.primary.getfieldval('bundle_flags') & PrimaryBlock.Flag.REQ_STATUS_TIME)
        status_at = timestamp.getfieldval('dtntime') if status_ts else None

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
    aad_struct = [
        ctr.bundle.primary.build() if aad_scope & 0x1 else None,
        target.build()[:3] if aad_scope & 0x2 else None,
        secblk.build()[:3] if aad_scope & 0x4 else None,
    ]
    LOGGER.debug('AAD-structure %s', aad_struct)
    return cbor2.dumps(aad_struct)


def load_pem_list(infile):
    certs = []
    chunk = b''
    while True:
        line = infile.readline()
        chunk += line
        if b'END CERTIFICATE' in line.upper():
            cert = x509.load_pem_x509_certificate(chunk, default_backend())
            certs.append(cert)
            chunk = b''
        if not line:
            return certs


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
        self._logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self._ca_certs = []
        if self._config.verify_ca_file:
            with open(self._config.verify_ca_file, 'rb') as infile:
                self._ca_certs = load_pem_list(infile)

        self._cert_chain = []
        if self._config.sign_cert_file:
            with open(self._config.sign_cert_file, 'rb') as infile:
                self._cert_chain = load_pem_list(infile)

        self._priv_key = None
        if self._config.sign_key_file:
            with open(self._config.sign_key_file, 'rb') as infile:
                self._priv_key = serialization.load_pem_private_key(infile.read(), None, default_backend())

        self.timestamp = Timestamper()

        self._bus_obj = self._config.bus_conn.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        self._bus_obj.connect_to_signal('NameOwnerChanged', self._bus_name_changed, dbus_interface='org.freedesktop.DBus')

        # Bound-to CL agent for each type
        self._cl_agent = {}
        # Seen bundle identities
        self._seen_bundle_ident = set()

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

    def _cl_recv_bundle(self, data):
        ''' Handle a new received bundle from a CL.
        '''
        self._logger.debug('_recv_bundle data %s', encode_diagnostic(cbor2.loads(data)))
        ctr = BundleContainer(Bundle(data))
        self._recv_bundle(ctr)

    def _get_route_to(self, eid):
        ''' Get a route table entry.
        '''
        self._logger.info('Getting route to: %s', eid)
        found = None
        for item in self._config.route_table:
            match = item.eid_pattern.match(eid)
            self._logger.debug('Checking pattern %s result %s', item.eid_pattern, match)
            if match is not None:
                found = item
                break
        if found is None:
            raise KeyError('No route to destination: {}'.format(eid))
        self._logger.debug('Route found: %s', found)
        return found

    def _apply_integrity(self, ctr):
        ''' If configured add a BIB.
        The container must be reloaded beforehand.
        '''
        from cose import Sign1Message, CoseHeaderKeys, CoseAlgorithms, RSA
        from cose.extensions.x509 import X5T

        if not self._priv_key:
            return

        aad_scope = 0x3
        target_block_nums = [
            blk.block_num
            for blk in ctr.bundle.blocks
            if blk.type_code in self._config.integrity_for_blocks
        ]
        if not target_block_nums:
            return

        x5chain = []
        for cert in self._cert_chain:
            x5chain.append(cert.public_bytes(serialization.Encoding.DER))

        # A little switcharoo to avoid cached overload_fields on `data`
        bib = CanonicalBlock(
            type_code=BlockIntegrityBlock._overload_fields[CanonicalBlock]['type_code'],
            block_num=ctr.get_block_num(),
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        bib_data = BlockIntegrityBlock(
            targets=target_block_nums,
            context_id=BPSEC_COSE_CONTEXT_ID,
            context_flags=(
                AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
            ),
            source=self._config.node_id,
            parameters=[
                TypeValuePair(type_code=5, value=aad_scope),
            ],
        )

        if self._config.integrity_include_chain:
            bib_data.parameters.append(
                TypeValuePair(type_code=3, value=x5chain)
            )

        # Sign each target with one result per
        target_result = []
        for blk_num in bib_data.getfieldval('targets'):
            target_blk = ctr.block_num(blk_num)
            target_blk.ensure_block_type_specific_data()
            target_plaintext = target_blk.getfieldval('btsd')

            ext_aad_enc = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)
            cose_key = RSA.from_cryptograpy_key_obj(self._priv_key)
            self._logger.debug('Signing target %d AAD %s payload %s',
                                blk_num, encode_diagnostic(ext_aad_enc),
                                encode_diagnostic(target_plaintext))
            msg_obj = Sign1Message(
                phdr={
                    CoseHeaderKeys.ALG: CoseAlgorithms.PS256,
                },
                uhdr={
                    CoseHeaderKeys.X5_T: X5T.from_certificate(CoseAlgorithms.SHA_256, x5chain[0]).encode(),
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
            self._logger.debug('Sending COSE message\n%s', encode_diagnostic(msg_dec))

            target_result.append(
                TypeValuePair(
                    type_code=msg_obj.cbor_tag,
                    value=msg_enc
                )
            )

        # One result per target
        bib_data.setfieldval('results', [
            TargetResultList(results=[result])
            for result in target_result
        ])
        bib.add_payload(bib_data)
        bib.ensure_block_type_specific_data()
        ctr.bundle.blocks.insert(0, bib)

    def _verify_integrity(self, ctr):
        ''' Check for and verify any BIBs.
        '''
        integ_blocks = ctr.block_type(BlockIntegrityBlock)
        for bib in integ_blocks:
            self._logger.debug('Verifying BIB in %d with targets %s', bib.block_num, bib.payload.targets)
            if bib.payload.context_id == BPSEC_COSE_CONTEXT_ID:
                from cose import CoseMessage, CoseHeaderKeys, RSA

                aad_scope = 0x7
                der_chains = []
                for param in bib.payload.parameters:
                    if param.type_code == 5:
                        aad_scope = int(param.value)
                    elif param.type_code == 3:
                        der_chains.append(param.value)

                bundle_at = DtnTimeField.dtntime_to_datetime(
                    ctr.bundle.primary.create_ts.getfieldval('dtntime')
                )
                val_ctx = ValidationContext(
                    trust_roots=[
                        cert.public_bytes(serialization.Encoding.DER)
                        for cert in self._ca_certs
                    ],
#                    other_certs=[
#                        cert.public_bytes(serialization.Encoding.DER)
#                        for cert in self._cert_chain
#                    ],
                    moment=bundle_at,
                )

                for (ix, blk_num) in enumerate(bib.payload.targets):
                    target_blk = ctr.block_num(blk_num)
                    for result in bib.payload.results[ix].results:
                        msg_cls = CoseMessage._COSE_MSG_ID[result.type_code]

                        # replace detached payload
                        msg_enc = bytes(result.getfieldval('value'))
                        msg_dec = cbor2.loads(msg_enc)
                        self._logger.debug('Received COSE message\n%s', encode_diagnostic(msg_dec))
                        msg_dec[2] = target_blk.getfieldval('btsd')

                        msg_obj = msg_cls.from_cose_obj(msg_dec)
                        msg_obj.external_aad = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)

                        self._logger.debug('Validating certificate at time %s', bundle_at)

                        try:
                            x5t = msg_obj.uhdr[CoseHeaderKeys.X5_T]
                            found_chains = [
                                chain for chain in der_chains
                                if x5t.matches(chain[0])
                            ]
                            self._logger.debug('Found %d chains matcing end-entity cert for %s', len(found_chains), encode_diagnostic(x5t.encode()))
                            if not found_chains:
                                raise RuntimeError('No chain matcing end-entity cert for {}'.format(x5t.encode()))
                            if len(found_chains) > 1:
                                raise RuntimeError('Multiple chains matcing end-entity cert for {}'.format(x5t.encode()))
                        except Exception as err:
                            self._logger.error('Failed to find cert chain for block num %d: %s', blk_num, err)
                            continue

                        try:
                            chain = found_chains[0]
                            self._logger.debug('Validating chain with %d certs against %d CAs', len(chain), len(self._ca_certs))
                            val = CertificateValidator(
                                end_entity_cert=chain[0],
                                intermediate_certs=chain[1:],
                                validation_context=val_ctx
                            )
                            val.validate_usage(
                                key_usage=set(),
                                #key_usage={u'digital_signature', u'non_repudiation'},
                            )
                        except Exception as err:
                            self._logger.error('Failed to verify chain on block num %d: %s', blk_num, err)
                            continue

                        peer_nodeid = bib.payload.source or ctr.bundle.primary.source
                        end_cert = x509.load_der_x509_certificate(chain[0], default_backend())
                        authn_nodeid = tcpcl.session.match_id(peer_nodeid, end_cert, x509.UniformResourceIdentifier, self._logger, 'NODE-ID')
                        if not authn_nodeid:
                            self._logger.error('Failed to authenticate peer "%s" on block num %d', peer_nodeid, blk_num)
                            continue

                        try:
                            cose_key = RSA.from_cryptograpy_key_obj(end_cert.public_key())
                            msg_obj.verify_signature(
                                public_key=cose_key,
                                alg=msg_obj.phdr[CoseHeaderKeys.ALG],
                            )
                            self._logger.info('Verified signature on block num %d', blk_num)
                        except Exception as err:
                            self._logger.error('Failed to verify signature on block num %d: %s', blk_num, err)
                            continue

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

    def _recv_bundle(self, ctr):
        ''' Perform agent handling of a received bundle.

        :param ctr: The bundle container just recieved.
        :type ctr: :py:cls:`BundleContainer`
        '''
        self._logger.debug('Received bundle\n%s', ctr.bundle.show(dump=True))

        invalid_crc = ctr.bundle.check_all_crc()
        if invalid_crc:
            self._logger.warning('CRC invalid for block numbers: %s', invalid_crc)
            return

        ident = ctr.bundle_ident()
        self._logger.info('Received bundle identity %s', ident)
        if ident in self._seen_bundle_ident:
            self._logger.debug('Ignoring already seen bundle %s', ident)
            return
        else:
            self._seen_bundle_ident.add(ident)

        self._verify_integrity(ctr)

        if ctr.do_report_reception():
            status = ctr.create_report_reception(self.timestamp(), self._config.node_id)
            glib.idle_add(self.send_bundle, status)

    def send_bundle(self, ctr):
        ''' Perform agent handling to send a bundle.
        Part of this is to update final CRCs on all blocks and
        assign block numbers.

        :param ctr: The bundle container to send.
        :type ctr: :py:cls:`BundleContainer`
        '''
        dest_eid = str(ctr.bundle.primary.getfieldval('destination'))
        route = self._get_route_to(dest_eid)
        sender = self._cl_agent[route.cl_type].send_bundle_func(**route.raw_config)

        ctr.reload()

        self._apply_integrity(ctr)

        ctr.fix_block_num()
        ctr.bundle.fill_fields()

        ctrlist = self._fragment(ctr, route)
        for ctr in ctrlist:
            ctr.bundle.update_all_crc()
            self._logger.debug('Sending bundle\n%s', ctr.bundle.show(dump=True))
            data = bytes(ctr.bundle)
            self._logger.info('send_bundle size %d', len(data))
            self._logger.debug('send_bundle data %s', encode_diagnostic(cbor2.loads(data)))
            sender(data)

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
                PrimaryBlock.Flag.REQ_RECEPTION_REPORT
                | PrimaryBlock.Flag.REQ_STATUS_TIME
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

    @dbus.service.method(DBUS_IFACE, in_signature='ay', out_signature='')
    def send_bundle_data(self, data):
        ''' Send bundle data directly.
        '''
        data = bytes(data)
        self._logger.warning("RECV %s", cbor2.loads(data))
        ctr = BundleContainer(Bundle(data))

        # apply local policy
        self._logger.info('Relaying app bundle %s', ctr.bundle)
        if ctr.bundle.primary.create_ts.getfieldval('dtntime') == 0:
            ctr.bundle.primary.create_ts = self.timestamp()
        if ctr.bundle.primary.getfieldval('lifetime') == 0:
            td = datetime.timedelta(hours=1)
            ctr.bundle.primary.lifetime = td.total_seconds() * 1e6 + td.microseconds
        self._logger.info('Relaying app bundle %s', ctr.bundle)

        self.send_bundle(ctr)
