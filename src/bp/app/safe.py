''' Prototype of Security Associations with Few Exchanges (SAFE) endpoint.
'''
import abc
import cbor2
from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
from dataclasses import dataclass, field
import datetime
import dbus.service
import enum
from gi.repository import GLib
import io
import logging
from pycose import algorithms, headers
from pycose.keys import curves, keyparam, keyops, SymmetricKey
from pycose.messages import Enc0Message
from pycose.extensions.x509 import X5T
import random
from typing import ClassVar, Dict, List, Optional, Tuple, Type, Union

from bp.config import Config, TxRouteItem
from bp.encoding import (
    CanonicalBlock, PrimaryBlock,
)
from bp.util import BundleContainer, ChainStep
from bp.app.base import app, AbstractApplication
from bp.crypto import load_pem_key, load_pem_chain
from bp.safe_info import (
    SafeEntity
)
from pycose_edhoc import (
    SUITES_BY_VALUE, Method, CredStore, CredItem, cose_key
)

LOGGER = logging.getLogger(__name__)


@app('safe')
class SAFE(AbstractApplication):
    ''' SAFE protocol.
    '''

    # Interface name
    DBUS_IFACE = 'org.ietf.dtn.bp.safe'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # leave other options default for non-debug use
        self._safe = SafeEntity(
            send_pdu=self._send_adu,
            method=Method.SIGN_SIGN,
            suite=SUITES_BY_VALUE[6],
        )

        self._config = None
        self._sign_key = None
        self._sign_chain = None

    def load_config(self, config: Config):
        super().load_config(config)
        self._config = config

        if config.sign_key_file:
            with open(config.sign_key_file, 'rb') as infile:
                key = load_pem_key(infile)
            LOGGER.debug('Loaded signing key type %s', type(key).__name__)
            self._sign_key = cose_key(key)
            self._safe.authn_priv_key = self._sign_key

        if config.sign_cert_file:
            with open(config.sign_cert_file, 'rb') as infile:
                self._sign_chain = load_pem_chain(infile)
            LOGGER.debug('Loaded signing cert %s', self._sign_chain[0])

            cert_der = self._sign_chain[0].public_bytes(serialization.Encoding.DER)
            cred = CredItem(
                data=cert_der,
                pubkey=None,  # not needed here
            )
            # tprint = X5T.from_certificate(algorithms.Sha256Trunc64, cert_der)
            # self._safe.id_cred = {
            #     headers.X5t.identifier: [tprint.alg.identifier, tprint.thumbprint],
            # }
            self._safe.id_cred = {
                headers.X5chain.identifier: cert_der,  # actual certificate
            }
            self._safe.cred_store.add(self._safe.id_cred, cred)

        safe_config = self._config.apps.get(self._app_name, {})
        LOGGER.debug('safe_config %s', safe_config)

        self._safe.own_eid = safe_config.get('endpoint')
        self._safe._retx_limit_edhoc = safe_config.get('retx_limit_edhoc', 10)
        self._safe._retx_limit_normal = safe_config.get('retx_limit_normal', 10)

    def add_chains(self, rx_chain, _tx_chain):
        rx_chain.append(ChainStep(
            order=-1,
            name='SAFE routing',
            action=self._rx_route
        ))
        rx_chain.append(ChainStep(
            order=30,
            name='SAFE handling',
            action=self._recv_bundle
        ))

    def _rx_route(self, ctr: BundleContainer):
        if ctr.bundle.primary.destination == self._safe.own_eid:
            ctr.record_action('deliver')

    def _recv_bundle(self, ctr: BundleContainer) -> bool:
        if random.randrange(5) == 0:
            # ignored
            LOGGER.info('Dropping bundle')
            # return True

        # message-independent bookkeeping
        pri_blk = ctr.bundle.primary
        peer_eid = pri_blk.source

        adu = ctr.block_num(1).getfieldval('btsd')
        self._safe.recv_pdu(adu, peer_eid)

        return True

    def _send_adu(self, adu: bytes, dest: str):
        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            bundle_flags=(
                PrimaryBlock.Flag.NO_FRAGMENT
            ),
            source=self._safe.own_eid,
            destination=dest,
            crc_type=CanonicalBlock.CrcType.CRC32,
        )
        ctr.bundle.blocks = [
            CanonicalBlock(
                type_code=1,
                block_num=1,
                crc_type=CanonicalBlock.CrcType.CRC32,
                btsd=adu,
            ),
        ]
        self._agent.send_bundle(ctr)

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='')
    def start(self, peer_eid: str):
        ''' Start an Initial Authentication activity.
        '''
        self._safe.start(peer_eid)
