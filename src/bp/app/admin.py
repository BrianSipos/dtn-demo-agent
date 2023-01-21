''' Administrative endpoint.
'''
from base64 import urlsafe_b64encode, urlsafe_b64decode
import cbor2
from dataclasses import dataclass, field, fields
from pycose import algorithms
import dbus
import enum
from gi.repository import GLib as glib
import logging
import math
from typing import List

from scapy_cbor.util import encode_diagnostic
from bp.encoding import (
    AbstractBlock, PrimaryBlock, CanonicalBlock,
)
from bp.util import BundleContainer, ChainStep
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)


@enum.unique
class RecordType(enum.IntEnum):
    STATUS = 1
    ACME = 65536  # FIXME: not real allocation


@enum.unique
class AcmeKey(enum.IntEnum):
    ID_CHAL = 1
    TOKEN_BUNDLE = 2
    KEY_AUTH_HASH = 3
    HASH_ALGS = 4


@dataclass
class AcmeChallenge(object):
    ''' Authorized ACME challenge data.
    '''

    #: Priority list
    HASH_ALG_LIST = [
        algorithms.Sha256
    ]

    #: base64url encoded token
    id_chal_enc: str
    #: base64url encoded token
    token_chal_enc: str = None
    #: base64url encoded token
    token_bundle_enc: str = None
    #: base64url encoded thumbprint
    key_tp_enc: str = None

    @property
    def key(self):
        return (self.id_chal_enc)

    def key_auth_hash(self, alg: algorithms._HashAlg) -> bytes:
        ''' Compute the response digest.
        '''
        key_auth = (self.token_bundle_enc + self.token_chal_enc + '.' + self.key_tp_enc)
        LOGGER.info('Key authorization string: %s', key_auth)
        digest = alg.compute_hash(key_auth.encode('utf8'))
        return digest

    @staticmethod
    def b64encode(data: bytes) -> str:
        enc = urlsafe_b64encode(data).rstrip(b'=')
        return enc.decode('latin1')

    @staticmethod
    def b64decode(enc: str) -> bytes:
        enc = enc.encode('latin1')
        enc = enc.ljust(int(math.ceil(len(enc) / 4)) * 4, b'=')
        return urlsafe_b64decode(enc)


@app('admin')
class Administrative(AbstractApplication):
    ''' Administrative element.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        self._rec_type_map = {
            RecordType.STATUS: self._recv_status,
            RecordType.ACME: self._recv_acme,
        }

        # ACME server map from (nodeid,token) to AcmeChallenge object
        self._acme_chal = {}
        # ACME client from (nodeid,token) to AcmeChallenge object
        self._acme_resp = {}

    def load_config(self, config):
        self._config = config

    def add_chains(self, rx_chain, tx_chain):
        rx_chain.append(ChainStep(
            order=-1,
            name='Administrative routing',
            action=self._rx_route
        ))
        rx_chain.append(ChainStep(
            order=30,
            name='Administrative handling',
            action=self._recv_bundle
        ))

    def _rx_route(self, ctr):
        eid = ctr.bundle.primary.destination
        if eid == self._config.node_id:
            ctr.record_action('deliver')

    def _recv_bundle(self, ctr):
        if not self._recv_for(ctr, self._config.node_id):
            return

        rec = cbor2.loads(ctr.block_num(1).getfieldval('btsd'))
        LOGGER.info('Record RX: %s', encode_diagnostic(rec))
        if not isinstance(rec, List):
            raise ValueError('Administrative record is not a list type, got %s', type(rec))
        rec_type = int(rec[0])
        handler = self._rec_type_map[rec_type]

        handler(ctr, rec[1])

        return True

    def _recv_status(self, ctr, msg):
        pass

    def _recv_acme(self, ctr, msg):
        source = ctr.bundle.primary.source
        is_request = ctr.bundle.primary.bundle_flags & PrimaryBlock.Flag.USER_APP_ACK
        LOGGER.info('ACME message from %s with id-chal %s', source, msg.get(AcmeKey.ID_CHAL))

        # partial challenge
        chal = AcmeChallenge(
            id_chal_enc=AcmeChallenge.b64encode(msg[AcmeKey.ID_CHAL]),
        )
        if is_request:
            try:
                chal = self._acme_resp[chal.key]
            except KeyError:
                LOGGER.warning('Unexpected ACME request from %s', source)
                ctr.record_action('delete')
                return
            chal.token_bundle_enc = AcmeChallenge.b64encode(msg[AcmeKey.TOKEN_BUNDLE])

            server_alg_ids = list(msg[AcmeKey.HASH_ALGS])
            client_alg_ids = {
                alg.identifier: alg
                for alg in AcmeChallenge.HASH_ALG_LIST
            }
            both_alg_ids = [aid for aid in server_alg_ids if aid in client_alg_ids]
            if not both_alg_ids:
                LOGGER.warning('No mutual acceptable hash algorithms in %s', server_alg_ids)
                ctr.record_action('delete')
                return
            alg = client_alg_ids[both_alg_ids[0]]

            msg = {
                AcmeKey.ID_CHAL: AcmeChallenge.b64decode(chal.id_chal_enc),
                AcmeKey.TOKEN_BUNDLE: AcmeChallenge.b64decode(chal.token_bundle_enc),
                AcmeKey.KEY_AUTH_HASH: [
                    alg.identifier,
                    chal.key_auth_hash(alg),
                ],
            }
            self.send_acme(ctr.bundle.primary.source, msg, False)

        else:
            try:
                chal = self._acme_chal[chal.key]
            except KeyError:
                LOGGER.warning('Unexpected ACME response from %s', source)
                ctr.record_action('delete')
                return
            expect_auth_hash = chal.key_auth_hash()
            is_valid = msg[AcmeKey.KEY_AUTH_HASH] == expect_auth_hash

            self.got_acme_response(source, chal.id_chal_enc, is_valid)

    def send_acme(self, nodeid, msg, is_request):
        rec = [
            RecordType.ACME,
            msg
        ]

        pri_flags = PrimaryBlock.Flag.PAYLOAD_ADMIN
        if is_request:
            pri_flags |= (
                PrimaryBlock.Flag.REQ_DELETION_REPORT
                | PrimaryBlock.Flag.USER_APP_ACK
            )

        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=pri_flags,
            destination=str(nodeid),
            crc_type=AbstractBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=AbstractBlock.CrcType.CRC32,
                btsd=cbor2.dumps(rec),
            ),
        ]
        self._agent.send_bundle(ctr)

    #: Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.admin'

    @dbus.service.method(DBUS_IFACE, in_signature='sss', out_signature='')
    def start_expect_acme_request(self, id_chal_enc, token_chal_enc, key_tp_enc):
        chal = AcmeChallenge(
            id_chal_enc=id_chal_enc,
            token_chal_enc=token_chal_enc,
            key_tp_enc=key_tp_enc,
        )
        self._acme_resp[chal.key] = chal

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def stop_expect_acme_request(self, id_chal_enc):
        chal = AcmeChallenge(
            id_chal_enc=id_chal_enc,
        )
        del self._acme_resp[chal.key]

    @dbus.service.method(DBUS_IFACE, in_signature='sssss', out_signature='')
    def send_acme_request(self, nodeid, id_chal_enc, token_chal_enc, token_bundle_enc, key_tp_enc):
        chal = AcmeChallenge(
            id_chal_enc=id_chal_enc,
            token_chal_enc=token_chal_enc,
            token_bundle_enc=token_bundle_enc,
            key_tp_enc=key_tp_enc,
        )
        self._acme_chal[chal.key] = chal

        msg = {
            AcmeKey.ID_CHAL: AcmeChallenge.b64decode(id_chal_enc),
            AcmeKey.TOKEN_BUNDLE: AcmeChallenge.b64decode(token_bundle_enc),
            AcmeKey.HASH_ALGS: [alg.identifier for alg in AcmeChallenge.HASH_ALG_LIST],
        }
        self.send_acme(nodeid, msg, True)

    @dbus.service.signal(DBUS_IFACE, signature='ssb')
    def got_acme_response(self, nodeid, id_chal_enc, is_valid):
        '''
        '''
