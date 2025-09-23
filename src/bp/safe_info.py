''' Prototype of Security Associations with Few Exchanges (SAFE) information
and state machine.
'''
import abc
import cbor2
from collections.abc import Callable
from dataclasses import dataclass, field
import datetime
import enum
from gi.repository import GLib as glib
import io
import logging
from pycose import algorithms, headers
from pycose.keys import curves, keyparam, keyops, CoseKey, SymmetricKey
from pycose.messages import Enc0Message
# from pycose.extensions.x509 import X5T
import random
from typing import ClassVar, Dict, List, Optional, Tuple, Type, Union

from pycose_edhoc import (
    AbstractKDF,
    EdhocInitiator, EdhocResponder, Method, CipherSuite, EadList, EadItem,
    CredStore, CredItem, ConnectionId, cose_key, perform_ecdh, pycose_iv_length
)

LOGGER = logging.getLogger(__name__)


@dataclass
class SimpleData:
    ''' Instances used with ActivityInfo.data '''
    tx_items: Dict[int, object] = field(default_factory=dict)
    ''' Items to be sent to a peer '''
    rx_items: Dict[int, object] = field(default_factory=dict)
    ''' Items received from a peer '''


SAFE_EAD_LABEL = 23
''' Allocated EAD label for embedded SAFE messages '''
SAFE_EXPORTER_LABEL = 32768
''' Allocated exporter label for SAFE primary SA '''


@enum.unique
class ActivityType(enum.IntEnum):
    INITIAL_AUTHN = 0
    CAPABILITY_INDICATION = 1
    SA_CREATION = 2


@enum.unique
class ActCIKeys(enum.IntEnum):
    ''' Map keys for ActivityType.CAPABILITY_INDICATION '''
    CAS = 1
    ESS = 2
    BCS = 3


@enum.unique
class ActSCKeys(enum.IntEnum):
    ''' Map keys for ActivityType.SA_CREATION '''
    LOCAL_SAI = 1
    AKE = 2
    ARN = 3
    CTXID = 4
    KUS = 5
    TSI = 6
    TSR = 7
    NTI = 8
    TBT = 9


@dataclass
class ActivityInfo(abc.ABC):
    ''' Abstract base class for activity behaviors '''

    app: 'SafeEntity'
    peer_state: 'PeerState'
    act: 'ActivityState'

    data: Optional[object] = field(default_factory=SimpleData)
    ''' Type-specific data populated by the derived class '''

    def is_finished(self) -> bool:
        raise NotImplementedError

    def get_tx_items(self) -> Optional[dict]:
        return None

    def set_rx_items(self, items: Optional[dict]):
        pass

    def state_changed(self):
        pass


_INFOS: Dict[ActivityType, Type[ActivityInfo]] = {}
''' Known activity info classes '''


def register_info(act_type: ActivityType):
    ''' Register a class derived from ActivityInfo '''
    def bind(cls: Type[ActivityInfo]):
        assert(issubclass(cls, ActivityInfo))
        _INFOS[act_type] = cls
        return cls
    return bind


@register_info(ActivityType.INITIAL_AUTHN)
class InitialAuthn(ActivityInfo):

    def __init__(self, edhoc, **kwargs):
        super().__init__(**kwargs)
        self.data = edhoc

    def is_finished(self) -> bool:
        state = (self.act.last_step_tx, self.act.last_step_rx)
        return max(state) == 3

    def state_changed(self):
        state = (self.act.last_step_tx, self.act.last_step_rx)
        if state == (-1, 0):
            # after message_1 is received
            self.app.start_activity(self.peer_state, ActivityType.CAPABILITY_INDICATION)

        if max(state) == 2:
            # message_3 has either been sent or received
            self._generate_sa()

    def process_edhoc(self, step: int, seqdata: bytes) -> EadList:
        if step == 0:
            ead = self.data.process_message_1(seqdata)
            if ead.items:
                LOGGER.error('Received EAD in message_1')
        elif step == 1:
            ead = self.data.process_message_2(seqdata)
        elif step == 2:
            ead = self.data.process_message_3(seqdata)
        elif step == 3:
            ead = self.data.process_message_4(seqdata)
        else:
            # No more EDHOC
            LOGGER.error('Received EDHOC PDU after message_4')
        return ead

    def get_edhoc(self, step: int, ead: EadList) -> bytes:
        if step == 0:
            seqdata = self.data.get_message_1()
        elif step == 1:
            # LOGGER.info('Input for EAD_2: %s', peer_state.all_normal())
            seqdata = self.data.get_message_2(ead)
        elif step == 2:
            seqdata = self.data.get_message_3(ead)
        elif step == 3:
            seqdata = self.data.get_message_4(ead)
        else:
            raise IndexError(f'No IA step {step}')
        return seqdata

    def _generate_sa(self):
        edhoc = self.data
        suite = edhoc.get_cipher_suite()
        okm = edhoc.edhoc_exporter

        prk_sa1 = okm(SAFE_EXPORTER_LABEL, b'prk_sa1', suite.app_hash_length)
        LOGGER.debug('Generated PRK_SA1 %s', prk_sa1.hex())

        ir_use = KeyUse(
            key=SymmetricKey(
                k=okm(SAFE_EXPORTER_LABEL, b'key_ir', suite.app_key_length),
                optional_params={
                    keyparam.KpAlg: suite.app_aead,
                    keyparam.KpKeyOps: [keyops.EncryptOp if self.act.as_initiator else keyops.DecryptOp],
                    keyparam.KpBaseIV: okm(SAFE_EXPORTER_LABEL, b'biv_ir', suite.app_iv_length),
                }
            )
        )
        ri_use = KeyUse(
            key=SymmetricKey(
                k=okm(SAFE_EXPORTER_LABEL, b'key_ri', suite.app_key_length),
                optional_params={
                    keyparam.KpAlg: suite.app_aead,
                    keyparam.KpKeyOps: [keyops.DecryptOp if self.act.as_initiator else keyops.EncryptOp],
                    keyparam.KpBaseIV: okm(SAFE_EXPORTER_LABEL, b'biv_ri', suite.app_iv_length),
                }
            )
        )

        if self.act.as_initiator:
            tx_use = ir_use
            rx_use = ri_use
        else:
            tx_use = ri_use
            rx_use = ir_use

        psa = PrimarySecAssn(
            local_sai=edhoc.get_own_conn_id(),
            peer_eid=self.peer_state.peer_eid,
            peer_sai=edhoc.get_peer_conn_id(),
            edhoc=edhoc,
            suite=suite,
            safe_kdf=edhoc.app_kdf,
            prk_sa1=prk_sa1,
            tx_use=tx_use,
            rx_use=rx_use,
        )
        self.app.add_primary_sa(psa)


@register_info(ActivityType.CAPABILITY_INDICATION)
class CapabilityIndication(ActivityInfo):

    def is_finished(self) -> bool:
        state = (self.act.last_step_tx, self.act.last_step_rx)
        return max(state) == 2

    def get_tx_items(self) -> Optional[dict]:
        if self.data.tx_items:
            return None

        items = {
            ActCIKeys.CAS: 1024,
            ActCIKeys.ESS: [1, 2],
            ActCIKeys.BCS: [3],
        }
        self.data.tx_items = items
        return items

    def state_changed(self):
        state = (self.act.last_step_tx, self.act.last_step_rx)
        if state == (-1, 0):
            # after first message is received
            self.app.start_activity(self.peer_state, ActivityType.SA_CREATION)


@register_info(ActivityType.SA_CREATION)
class SaCreation(ActivityInfo):

    def is_finished(self) -> bool:
        state = (self.act.last_step_tx, self.act.last_step_rx)
        return max(state) == 2

    def get_tx_items(self) -> Optional[dict]:
        if self.data.tx_items:
            return None

        psa = self.peer_state.psa
        key_hdl = (psa.edhoc if psa else self.peer_state.edhoc.info.data).get_key_handler()

        if True:
            try:
                self.data.ake_priv = self.app._ke_priv_key.pop(0)
            except IndexError:
                self.data.ake_priv = key_hdl.generate_key()
            LOGGER.debug('Using AKE private key %s', self.data.ake_priv)
        else:
            self.data.ake_priv = None

        items = {
            ActSCKeys.LOCAL_SAI: random.randbytes(6),
            ActSCKeys.ARN: random.randbytes(16),
            ActSCKeys.CTXID: 3,  # COSE Context
            ActSCKeys.KUS: {
                CoseCtxKusOptions.ALG: algorithms.A128GCM.identifier,
            },
            ActSCKeys.TBT: 1,
            ActSCKeys.TSI: None,
            ActSCKeys.TSR: None,
        }
        if self.data.ake_priv:
            items[ActSCKeys.AKE] = key_hdl.to_pub_data(self.data.ake_priv)

        self.data.tx_items = items
        return items

    def set_rx_items(self, items: Optional[dict]):
        self.data.rx_items = items

    def state_changed(self):
        state = (self.act.last_step_tx, self.act.last_step_rx)

        if max(state) == 1:
            # step 1 has either been sent or received
            self._generate_sa()

    def _generate_sa(self):
        psa = self.peer_state.psa
        key_hdl = (psa.edhoc if psa else self.peer_state.edhoc.info.data).get_key_handler()

        local_sai = ConnectionId.from_item(self.data.tx_items[ActSCKeys.LOCAL_SAI])
        peer_sai = ConnectionId.from_item(self.data.rx_items[ActSCKeys.LOCAL_SAI])

        # Consistency check
        if self.data.rx_items[ActSCKeys.CTXID] != self.data.tx_items[ActSCKeys.CTXID]:
            raise RuntimeError('inconsistent CTXID')

        if self.act.as_initiator:
            items_i, items_r = self.data.tx_items, self.data.rx_items
        else:
            items_i, items_r = self.data.rx_items, self.data.tx_items

        sai_i = ConnectionId.from_item(items_i[ActSCKeys.LOCAL_SAI])
        sai_r = ConnectionId.from_item(items_r[ActSCKeys.LOCAL_SAI])
        arn_i = items_i.get(ActSCKeys.ARN, b'')
        arn_r = items_r.get(ActSCKeys.ARN, b'')

        peer_ake_data = self.data.rx_items.get(ActSCKeys.AKE)
        if self.data.ake_priv and peer_ake_data:
            key_hdl = psa.edhoc.get_key_handler()
            g_xy = perform_ecdh(self.data.ake_priv, key_hdl.from_pub_data(peer_ake_data))
            LOGGER.debug('Generated AKE G_XY %s', g_xy.hex())
        else:
            g_xy = b''

        ctx_2 = io.BytesIO()
        enc_ctx_2 = cbor2.CBOREncoder(ctx_2)
        enc_ctx_2.encode(sai_i.value)
        enc_ctx_2.encode(sai_r.value)
        enc_ctx_2.encode(arn_i)
        enc_ctx_2.encode(arn_r)
        enc_ctx_2.encode(g_xy)
        LOGGER.debug('Generated context_2 %s', ctx_2.getvalue().hex())
        prk_sa2 = psa.safe_kdf(psa.prk_sa1, 0, ctx_2.getvalue(), psa.suite.app_hash_length)
        LOGGER.debug('Generated PRK_SA2 %s', prk_sa2.hex())

        def safe_okm(ctxid: int, context: bytes, length: int) -> bytes:
            ''' OKM generator for all secondary SA material '''
            return psa.safe_kdf(prk_sa2, ctxid, context, length)

        # FIXME: consistency and subset checking from I -> R
        ctxid = items_r[ActSCKeys.CTXID]
        if ctxid == 3:
            # COSE Context
            kus_options = items_r[ActSCKeys.KUS]
            alg_id = kus_options[CoseCtxKusOptions.ALG]

            alg = algorithms.CoseAlgorithm.from_id(alg_id)
            LOGGER.debug('Using SA algorithm %s', alg)
            if issubclass(alg, algorithms._HMAC):
                key_length = alg.get_key_length()
                ir_use = KeyUse(
                    key=SymmetricKey(
                        k=safe_okm(ctxid, b'key_ir', key_length),
                        optional_params={
                            keyparam.KpAlg: alg,
                            keyparam.KpKeyOps: [keyops.MacCreateOp if self.act.as_initiator else keyops.MacVerifyOp],
                        }
                    )
                )
                ri_use = KeyUse(
                    key=SymmetricKey(
                        k=safe_okm(ctxid, b'key_ri', key_length),
                        optional_params={
                            keyparam.KpAlg: alg,
                            keyparam.KpKeyOps: [keyops.MacVerifyOp if self.act.as_initiator else keyops.MacCreateOp],
                        }
                    )
                )
            if issubclass(alg, algorithms._EncAlg):
                key_length = alg.get_key_length()
                iv_length = pycose_iv_length(alg)
                ir_use = KeyUse(
                    key=SymmetricKey(
                        k=safe_okm(ctxid, b'key_ir', key_length),
                        optional_params={
                            keyparam.KpAlg: alg,
                            keyparam.KpKeyOps: [keyops.EncryptOp if self.act.as_initiator else keyops.DecryptOp],
                            keyparam.KpBaseIV: safe_okm(ctxid, b'biv_ir', iv_length),
                        }
                    )
                )
                ri_use = KeyUse(
                    key=SymmetricKey(
                        k=safe_okm(0, b'key_ri', key_length),
                        optional_params={
                            keyparam.KpAlg: alg,
                            keyparam.KpKeyOps: [keyops.DecryptOp if self.act.as_initiator else keyops.EncryptOp],
                            keyparam.KpBaseIV: safe_okm(0, b'biv_ri', iv_length),
                        }
                    )
                )
            else:
                raise ValueError(f'Unhandled algorithm {alg}')
        LOGGER.debug('Generated ir_use %s', ir_use.key)
        LOGGER.debug('Generated ri_use %s', ri_use.key)

        if self.act.as_initiator:
            tx_use = ir_use
            rx_use = ri_use
        else:
            tx_use = ri_use
            rx_use = ir_use

        ssa = SecondarySecAssn(
            psa=psa,
            local_sai=local_sai,
            peer_eid=self.peer_state.peer_eid,
            peer_sai=peer_sai,
            tx_use=tx_use,
            rx_use=rx_use,
        )
        self.app.add_secondary_sa(ssa)


@enum.unique
class CoseCtxKusOptions(enum.IntEnum):
    ALG = 1


@dataclass
class ActivityState:

    as_initiator: bool
    ''' True if this entity is the initiator side '''
    init_eid: str
    ''' The activity initiator EID '''
    act_idx: int
    ''' The initiator-defined index '''

    act_type: ActivityType
    ''' Activity type enumeration '''

    info: ActivityInfo = None
    ''' Activity-type specific descriptor '''

    last_step_tx: int = -1
    ''' Step last transmitted (LTX) '''
    last_step_rx: int = -1
    ''' Step last received (LRX) '''

    timer_retx: Optional[object] = None
    ''' Retransmission timer handle from :py:func:`glib.timeout_add` '''
    timer_remove: Optional[object] = None
    ''' Removal timer handle from :py:func:`glib.timeout_add` '''
    retx_count: int = 0
    ''' LTX step retransmission count.
    This resets to zero upon the first TX of each step.
    '''

    KeyType = Tuple[str, int]

    def key(self) -> KeyType:
        ''' Get a unique key for this activity '''
        return (self.init_eid, self.act_idx)

    def __str__(self) -> str:
        parts = [
            f'init_eid={self.init_eid!r}',
            f'act_idx={self.act_idx}',
            f'act_type={self.act_type.name}',
            f'LTX={self.last_step_tx}',
            f'LRX={self.last_step_rx}',
        ]
        return f'{type(self).__name__}({",".join(parts)})'

    @property
    def next_step(self) -> int:
        ''' The next step to transmit. '''
        return self.last_step_rx + 1

    def need_tx(self) -> bool:
        ''' Determine if a message needs to be sent '''
        return not self.is_finished() and self.last_step_tx <= self.last_step_rx

    def is_finished(self) -> bool:
        ''' Determine if this activity is finished.

        :return: True if the last step was sent or received already.
        '''
        if self.info is None:
            return False
        return self.info.is_finished()


@dataclass
class PeerState:
    ''' State of activities and messaging with a peer '''

    peer_eid: str
    ''' The peer EID for this state '''

    last_act_idx: int = 0
    ''' The last used activity index, which reserves the zero value. '''

    edhoc: Dict[bytes, ActivityState] = field(default_factory=dict)

    own: Dict[int, ActivityState] = field(default_factory=dict)
    peer: Dict[int, ActivityState] = field(default_factory=dict)

    psa: Optional['PrimarySecAssn'] = None
    ''' The latest SA for this peer '''

    def next_act_index(self) -> int:
        self.last_act_idx += 1
        return self.last_act_idx

    def add_activity(self, act: ActivityState):
        LOGGER.debug('Adding %s', act)
        if act.act_type == ActivityType.INITIAL_AUTHN:
            self.edhoc = act
        else:
            store = self.peer if act.init_eid == self.peer_eid else self.own
            store[act.act_idx] = act

    def remove_activity(self, act: ActivityState):
        LOGGER.debug('Removing %s', act)
        if self.edhoc == act:
            self.edhoc = None
        for store in (self.own, self.peer):
            found = None
            for key, store_act in store.items():
                if act is store_act:
                    found = key
                    break
            if found is not None:
                del store[found]

    def all_normal(self) -> List[ActivityState]:
        return tuple(self.own.values()) + tuple(self.peer.values())


@dataclass
class KeyUse:
    ''' Each derived symmetric key for an SA '''

    key: SymmetricKey
    ''' Symmetric key including base-IV '''

    op_count: int = 0
    bytes_count: int = 0

    def increment(self, plain_size: int):
        self.op_count += 1
        self.bytes_count += plain_size

    def partial_iv(self) -> bytes:
        ''' Get a partial-iv byte string based on the op_count. '''
        # avoid zero-value PIV
        piv = self.op_count + 1
        return piv.to_bytes((piv.bit_length() + 7) // 8, 'big')


@dataclass
class PrimarySecAssn:
    ''' State of a security association from Section 3.3 '''
    local_sai: ConnectionId

    peer_eid: str
    peer_sai: ConnectionId

    edhoc: Union[EdhocInitiator, EdhocResponder]
    suite: CipherSuite

    safe_kdf: AbstractKDF
    ''' The KDF function to use for PRK derivation '''
    prk_sa1: bytes
    ''' PRK from which to derive secondary SA material '''

    tx_use: KeyUse
    rx_use: KeyUse

    def __str__(self) -> str:
        parts = [
            f'local_sai={self.local_sai.value.hex()}',
            f'peer_eid={self.peer_eid!r}',
            f'peer_sai={self.peer_sai.value.hex()}',
            f'app_aead={self.suite.app_aead.__name__}',
        ]
        return f'PrimarySecAssn({",".join(parts)})'


@dataclass
class SecondarySecAssn:
    ''' State of a security association from Section 3.3 '''
    psa: PrimarySecAssn
    ''' Parent of this SA '''

    local_sai: ConnectionId

    peer_eid: str
    peer_sai: ConnectionId

    tx_use: KeyUse
    rx_use: KeyUse

    def __str__(self) -> str:
        parts = [
            f'local_sai={self.local_sai.value.hex()}',
            f'peer_eid={self.peer_eid!r}',
            f'peer_sai={self.peer_sai.value.hex()}',
        ]
        return f'SecondarySecAssn({",".join(parts)})'


Sender = Callable[[bytes, str], None]


class SafeEntity:
    ''' SAFE protocol entity.

    :param method: The method to request and allow.
    :param suite: The cipher suite to request and allow.
    :param id_cred: The local credential ID, which must be set here or
        before the first session start with any peer.
    :param ke_priv_key: A fixed list of key exchange private keys to use.
        This should be used for testing only.
    :param conn_id: A specific EDHOC connection identifier to use.
        This should be used for testing only.
    '''

    def __init__(self, send_pdu: Sender,
                 method: Method,
                 suite: CipherSuite,
                 authn_priv_key: Optional[CoseKey]=None,
                 id_cred: Optional[dict]=None,
                 cred_store: Optional[CredStore]=None,
                 ke_priv_key: Optional[List[CoseKey]]=None,
                 conn_id: Optional[bytes]=None):

        self._own_eid = None
        self._logger = None

        self.send_pdu = send_pdu
        self.method = method
        self.suite = suite
        self.authn_priv_key = authn_priv_key
        self._ke_priv_key = ke_priv_key or []
        self._conn_id = conn_id

        # EDHOC uses
        self.id_cred = id_cred
        self.cred_store = cred_store or CredStore()

        self._retx_limit_edhoc = 10
        self._retx_limit_normal = 10

        # map from peer EID to PeerState
        self._act_peer: Dict[str, PeerState] = dict()

        # primary SAs by local SAI independent of peer
        self._pri_sai: Dict[str, PrimarySecAssn] = dict()
        # primary SAs by peer EID
        self._pri_peer: Dict[str, PrimarySecAssn] = dict()

        # secondary SAs by local SAI independent of peer
        self._sec_sai: Dict[str, SecondarySecAssn] = dict()

    def recv_pdu(self, pdu: bytes, peer_eid: str):
        pdu = io.BytesIO(pdu)
        peer_state = self._peer_state(peer_eid)
        self._logger.debug('PDU RX from %s data %s', peer_eid, pdu.getvalue().hex())
        dec_pdu = cbor2.CBORDecoder(pdu)

        # pdu contents
        version = dec_pdu.decode()
        if version != 1:
            self._logger.error('Cannot handle SAFE version %d', version)
            return True
        partial_iv = dec_pdu.decode()
        pri_sa_id = ConnectionId()
        pri_sa_id.decode(dec_pdu)

        if partial_iv is None:
            # expect only one EDHOC message in remainder of PDU
            seqdata = pdu.read()

            ead = None
            if pri_sa_id.value is True:
                # new activity
                ke_priv = self._ke_priv_key.pop(0) if self._ke_priv_key else None
                resp = EdhocResponder(
                    authn_priv_key=self.authn_priv_key,
                    valid_methods=[self.method],
                    valid_suites=[self.suite],
                    cred_store=self.cred_store,
                    id_cred=self.id_cred,
                    # debug only
                    ke_priv_key=ke_priv,
                    conn_id=self._conn_id
                )

                # Assign decoded C_I before indexing
                act = ActivityState(
                    as_initiator=False,
                    init_eid=peer_state.peer_eid,
                    act_idx=0,
                    act_type=ActivityType.INITIAL_AUTHN,
                    last_step_rx=0,
                )
                act.info = InitialAuthn(resp, app=self, peer_state=peer_state, act=act)
                act.info.process_edhoc(0, seqdata)
                peer_state.add_activity(act)

            else:
                # lookup by assumed activity index and step
                act = peer_state.edhoc

                ead = act.info.process_edhoc(act.last_step_tx + 1, seqdata)
                act.last_step_rx = act.last_step_tx + 1

            self._act_state_changed(act)

            if act.is_finished():
                self._queue_remove(peer_state, act)

            if ead:
                for item in ead.items:
                    if abs(item.label) == SAFE_EAD_LABEL:
                        self._recv_msg(peer_state, item.value)

        else:
            # an established primary SA with ciphertext
            psa = self._pri_sai[pri_sa_id.value]

            self._logger.debug('Got partial-iv %s', partial_iv.hex())
            ciphertext = dec_pdu.decode()
            self._logger.debug('Got ciphertext %s', ciphertext.hex())

            aad = io.BytesIO()
            enc_aad = cbor2.CBOREncoder(aad)
            pri_sa_id.encode(enc_aad)

            enc0 = Enc0Message(
                phdr={},
                uhdr={
                    headers.Algorithm: psa.suite.app_aead,
                    headers.PartialIV: partial_iv,
                },
                payload=ciphertext,
                external_aad=aad.getvalue(),
                key=psa.rx_use.key,
            )
            self._logger.debug('Decrypting with key K=%s', enc0.key.k.hex())
            plain = enc0.decrypt()
            psa.rx_use.increment(len(plain))
            self._logger.debug('Generated plaintext %s', plain.hex())

            dec_plain = cbor2.CBORDecoder(io.BytesIO(plain))
            plain_len = len(plain)
            while dec_plain.fp.tell() < plain_len:
                self._recv_msg(peer_state, dec_plain.decode())

        # handle any responses needed to the new state
        self._queue_process_tx()

        return True

    def _get_msg_data(self, peer_state: PeerState, acts: List[ActivityState]) -> List[bytes]:
        ''' Get encoded messages for all to-be-TX activities, including
        retransmissions.
        '''
        msgdata_list = []
        for act in acts:
            if act.is_finished():
                # nothing to do
                continue

            if self._retx_limit_normal and act.retx_count > self._retx_limit_normal:
                self._logger.debug('Normal retransmission limit reached on %s', act)
                self._queue_remove(peer_state, act)
                continue
            act.retx_count += 1

            msgdata_list.append(self._gen_msg(peer_state, act))

        return msgdata_list

    def _gen_msg(self, _peer_state: PeerState, act: ActivityState) -> bytes:
        ''' Generate a message byte string and increment 
        the LTX counter on the activity.
        '''
        buf = io.BytesIO()
        enc = cbor2.CBOREncoder(buf, canonical=True)

        # message ident
        enc.encode(act.act_idx)
        enc.encode(act.next_step)

        items = self._act_get_tx_items(act)
        if items is not None:
            enc.encode(act.act_type)
            enc.encode(items)

        act.last_step_tx = act.next_step
        self._act_state_changed(act)

        msg = buf.getvalue()
        self._logger.debug('Message TX data %s', msg.hex())
        return msg

    def _recv_msg(self, peer_state: PeerState, msg: bytes):
        ''' Process an individual received SAFE message '''
        self._logger.debug('Message RX data %s', msg.hex())
        dec = cbor2.CBORDecoder(io.BytesIO(msg))

        act_idx = dec.decode()
        act_step = dec.decode()
        try:
            act_type = dec.decode()
        except cbor2.CBORDecodeEOF:
            act_type = None
        if act_type is None and act_step == 0:
            self._logger.error('Received short message on step 0')

        am_initiator = act_step % 2 == 1
        self._logger.debug('Message RX act-idx %s act-step %s am-initiator %s',
                           act_idx, act_step, am_initiator)
        store = peer_state.own if am_initiator else peer_state.peer

        if act_idx not in store:
            if act_step != 0:
                self._logger.warning('First step seen of index %d step %d', act_idx, act_step)

            act_type = ActivityType(act_type)
            act = ActivityState(
                as_initiator=False,
                init_eid=peer_state.peer_eid,
                act_idx=act_idx,
                act_type=act_type,
            )
            act.info = _INFOS[act_type](app=self, peer_state=peer_state, act=act)
            peer_state.add_activity(act)

        else:
            act = store[act_idx]

        if act_step <= act.last_step_rx:
            self._logger.warning('Ignoring duplicate RX index %d step %d', act_idx, act_step)
            return

        try:
            items = dec.decode()
        except cbor2.CBORDecodeEOF:
            items = None
        self._act_set_rx_items(act, items)

        act.last_step_rx = act_step
        self._act_state_changed(act)

        if act.is_finished():
            self._queue_remove(peer_state, act)

    def _gen_pdu_edhoc(self, peer_state: PeerState, old_lrx: int) -> Optional[bytes]:
        ''' Generate and PDU for a specific IA activity.
        '''
        act = peer_state.edhoc
        if act is None or act.last_step_rx != old_lrx:
            self._logger.debug('Ignoring PDU for EDHOC with old LRX')
            return None

        if act.is_finished():
            # nothing to do
            return None

        if self._retx_limit_edhoc and act.retx_count > self._retx_limit_edhoc:
            self._logger.debug('EDHOC retransmission limit reached')
            self._queue_remove(peer_state, act)
            return None
        act.retx_count += 1

        pdu = io.BytesIO()
        enc_pdu = cbor2.CBOREncoder(pdu)
        enc_pdu.encode(1)  # version
        enc_pdu.encode(None)  # partial-iv

        step = act.next_step
        self._logger.debug('Sending IA for step %s', step)

        if step == 0:
            self._logger.debug('Generate EAD empty')
            ead = None  # no EAD sent in plaintext

            enc_pdu.encode(True)  # peer connection ID
        else:
            act.info.data.get_peer_conn_id().encode(enc_pdu)

            # can embed other activities' messages
            pending_acts = [
                act for act in peer_state.all_normal()
                if act.act_type != ActivityType.INITIAL_AUTHN
            ]
            self._logger.debug('Generate EAD with acts: %s',
                               ', '.join(str(act) for act in pending_acts))
            msgdata_list = self._get_msg_data(peer_state, pending_acts)

            ead = EadList()
            for msgdata in msgdata_list:
                ead.items.append(EadItem(
                    label=-SAFE_EAD_LABEL,
                    value=msgdata
                ))

        seqdata = act.info.get_edhoc(step, ead)
        # EDHOC messages are pre-encoded so go directly to buffer
        pdu.write(seqdata)

        act.last_step_tx = step
        self._act_state_changed(act)

        return pdu.getvalue()

    def _gen_pdu_normal(self, peer_state: PeerState, state_map: Dict[ActivityState.KeyType, int]) -> Optional[bytes]:
        ''' Generate an PDU for all non-IA activities with a peer.

        :param peer_state: The peer to generate an PDU for.
        :param state_map: The LRX state to generate for.
        '''
        pending_acts = [
            act for act in peer_state.all_normal()
            if act.last_step_rx == state_map.get(act.key())
        ]
        self._logger.debug('Generate PDU from %s with acts: %s',
                           list(state_map.keys()),
                           ', '.join(str(act) for act in pending_acts))
        if not pending_acts:
            return None

        msgdata_list = self._get_msg_data(peer_state, pending_acts)
        if not msgdata_list:
            return None

        psa = self._pri_peer[peer_state.peer_eid]
        partial_iv = psa.tx_use.partial_iv()
        self._logger.debug('Using partial-iv %s', partial_iv.hex())

        buf = io.BytesIO()
        enc = cbor2.CBOREncoder(buf)
        enc.encode(1)  # version

        enc.encode(partial_iv)  # partial-iv
        psa.peer_sai.encode(enc)  # peer connection ID

        plain = io.BytesIO()
        enc_plain = cbor2.CBOREncoder(plain)
        for msgdata in msgdata_list:
            enc_plain.encode(msgdata)
        self._logger.debug('Generated plaintext %s', plain.getvalue().hex())

        aad = io.BytesIO()
        enc_aad = cbor2.CBOREncoder(aad)
        # FIXME bind to transport source EID?
        psa.peer_sai.encode(enc_aad)

        enc0 = Enc0Message(
            phdr={},
            uhdr={
                headers.Algorithm: psa.suite.app_aead,
                headers.PartialIV: partial_iv,
            },
            payload=plain.getvalue(),
            external_aad=aad.getvalue(),
            key=psa.tx_use.key,
        )
        self._logger.debug('Encrypting with key K=%s', enc0.key.k.hex())
        ciphertext = enc0.encrypt()
        psa.tx_use.increment(len(plain.getvalue()))
        self._logger.debug('Generated ciphertext %s', ciphertext.hex())
        enc.encode(ciphertext)

        return buf.getvalue()

    def _peer_state(self, peer_eid: str) -> PeerState:
        if peer_eid not in self._act_peer:
            self._act_peer[peer_eid] = PeerState(peer_eid)
        return self._act_peer[peer_eid]

    def _queue_process_tx(self):
        ''' Queue a call to :fun:`_process_tx` in the event loop.
        '''
        glib.idle_add(self._process_tx)

    def _process_tx(self) -> bool:
        ''' Iterate through known activities and send any needed
        messages.
        '''
        self._logger.debug('Process TX')

        for peer_state in self._act_peer.values():
            if peer_state.edhoc and not peer_state.edhoc.is_finished():
                self._process_tx_edhoc(peer_state, peer_state.edhoc)
            else:
                self._process_tx_normal(peer_state)

        # no recurrence
        return False

    def _process_tx_edhoc(self, peer_state: PeerState, act: ActivityState):
        if not act.need_tx():
            return

        act.retx_count = 0
        self._try_tx_edhoc(peer_state, act.last_step_rx)

        # set timeouts
        if act.is_finished():
            # finished after that TX
            self._queue_remove(peer_state, act)
            act = None

        if act:
            def callback(): return self._try_tx_edhoc(peer_state, act.last_step_rx)
            act.timer_retx = glib.timeout_add(2000, callback)
            self._logger.debug('Started %s retransmit timer %d', act, act.timer_retx)

    def _try_tx_edhoc(self, peer_state: PeerState, old_lrx: int) -> bool:
        self._logger.debug('Process TX EDHOC')
        pdu = self._gen_pdu_edhoc(peer_state, old_lrx)
        if pdu:
            self.send_pdu(pdu, peer_state.peer_eid)
            return True
        else:
            return False

    def _process_tx_normal(self, peer_state: PeerState):
        # Record current LRX state for all current activities
        # The retransmission callback will use these to determine
        # which activities still need to progress their LRX state
        tx_acts = [act for act in peer_state.all_normal() if act.need_tx()]
        if not tx_acts:
            return
        state_map = {
            act.key(): act.last_step_rx
            for act in tx_acts
        }

        for act in tx_acts:
            act.retx_count = 0
        self._try_tx_normal(peer_state, state_map)

        for act in tx_acts:
            if act.is_finished():
                # finished after that TX
                self._queue_remove(peer_state, act)
                del state_map[act.key()]

        if not state_map:
            # one callback for all activities in the PDU
            def callback(): return self._try_tx_normal(peer_state, state_map)
            timer_id = glib.timeout_add(2000, callback)

            for act in tx_acts:
                act.timer_retx = timer_id
                self._logger.debug('Started %s retransmit timer %d', act, act.timer_retx)

    def _try_tx_normal(self, peer_state: PeerState, state_map: Dict[ActivityState.KeyType, int]) -> bool:
        self._logger.debug('Process TX normal')
        pdu = self._gen_pdu_normal(peer_state, state_map)
        if pdu:
            self.send_pdu(pdu, peer_state.peer_eid)
            return True
        else:
            return False

    def _queue_remove(self, peer_state: PeerState, act: ActivityState):
        if not act.timer_remove:
            def callback(): return peer_state.remove_activity(act)
            act.timer_remove = glib.timeout_add(5000, callback)

    def _act_get_tx_items(self, act: ActivityState) -> Optional[dict]:
        items = act.info.get_tx_items()
        self._logger.debug('Get %s TX items %s', act, items)
        return items

    def _act_set_rx_items(self, act: ActivityState, items: Optional[dict]):
        self._logger.debug('Set %s RX items %s', act, items)
        act.info.set_rx_items(items)

    def _act_state_changed(self, act: ActivityState):
        self._logger.debug('Advanced %s, finished %s',
                           act, act.is_finished())
        act.info.state_changed()

    @property
    def own_eid(self) -> str:
        return self._own_eid

    @own_eid.setter
    def own_eid(self, eid: str):
        self._own_eid = eid
        self._logger = logging.getLogger(f'{__name__}.{type(self).__name__}({eid})')

    def start_activity(self, peer_state: PeerState, act_type: ActivityType):
        ''' Start a new activity of a specific type.
        '''
        act_type = ActivityType(act_type)
        act = ActivityState(
            as_initiator=True,
            init_eid=self._own_eid,
            act_idx=peer_state.next_act_index(),
            act_type=act_type,
        )
        act.info = _INFOS[act_type](app=self, peer_state=peer_state, act=act)
        peer_state.add_activity(act)

    def get_primary_sas(self) -> List[PrimarySecAssn]:
        return self._pri_peer.values()

    def add_primary_sa(self, psa: PrimarySecAssn):
        self._logger.debug('Adding SA %s', psa)

        self._pri_sai[psa.local_sai.value] = psa
        # FIXME allow multiple?
        self._pri_peer[psa.peer_eid] = psa
        self._act_peer[psa.peer_eid].psa = psa

    def get_secondary_sas(self) -> List[SecondarySecAssn]:
        return self._sec_sai.values()

    def add_secondary_sa(self, ssa: SecondarySecAssn):
        self._logger.info('Adding SA %s', ssa)
        self._sec_sai[ssa.local_sai.value] = ssa

    def start(self, peer_eid: str):
        ''' Start an Initial Authentication activity.
        '''
        peer_state = self._peer_state(peer_eid)

        ke_priv = self._ke_priv_key.pop(0) if self._ke_priv_key else None
        init = EdhocInitiator(
            authn_priv_key=self.authn_priv_key,
            method=self.method,
            suites=[self.suite],
            cred_store=self.cred_store,
            id_cred=self.id_cred,
            # debug only
            ke_priv_key=ke_priv,
            conn_id=self._conn_id
        )
        act = ActivityState(
            as_initiator=True,
            init_eid=self._own_eid,
            act_idx=0,
            act_type=ActivityType.INITIAL_AUTHN,
        )
        act.info = InitialAuthn(init, app=self, peer_state=peer_state, act=act)
        peer_state.add_activity(act)

        self._queue_process_tx()
