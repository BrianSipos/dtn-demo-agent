''' Prototype of Security Associations with Few Exchanges (SAFE) information
and state machine.
'''
import abc
import cbor2
from collections.abc import Callable
from dataclasses import dataclass, field
import enum
from gi.repository import GLib as glib
import io
import logging
from pycose import algorithms, headers
from pycose.keys import keyparam, keyops, CoseKey, SymmetricKey
from pycose.messages import Enc0Message
import random
from typing import ClassVar, Dict, List, Optional, Tuple, Type, cast

from pycose_edhoc import (
    AbstractKDF,
    EdhocInitiator, EdhocResponder, EdhocEntity, Method, CipherSuite, EadList, EadItem,
    CredStore, CredItem, ConnectionId, cose_key
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
    EVENT_NOTIFICATION = 2

    SA_CREATION = 3
    SA_TEARDOWN = 4

    CK_CREATION = 6
    CK_DISCARD = 7
    CK_REJECT = 8

    CP_CREATION = 9
    CP_DISCARD = 10
    CP_REJECT = 11


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
        assert issubclass(cls, ActivityInfo)
        _INFOS[act_type] = cls
        return cls
    return bind


@register_info(ActivityType.INITIAL_AUTHN)
class InitialAuthn(ActivityInfo):

    def __init__(self, edhoc: EdhocEntity, **kwargs):
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
            self._generate_psa()

    def process_edhoc(self, step: int, seqdata: bytes) -> EadList:
        edhoc = cast(EdhocEntity, self.data)
        if step == 0:
            ead = edhoc.process_message_1(seqdata)
            if ead.items:
                LOGGER.error('Received EAD in message_1')
        elif step == 1:
            ead = edhoc.process_message_2(seqdata)
        elif step == 2:
            ead = edhoc.process_message_3(seqdata)
        elif step == 3:
            ead = edhoc.process_message_4(seqdata)
        else:
            # No more EDHOC
            LOGGER.error('Received EDHOC PDU after message_4')
        return ead

    def get_edhoc(self, step: int, ead: EadList) -> bytes:
        edhoc = cast(EdhocEntity, self.data)
        if step == 0:
            seqdata = edhoc.get_message_1()
        elif step == 1:
            # LOGGER.info('Input for EAD_2: %s', peer_state.all_normal())
            seqdata = edhoc.get_message_2(ead)
        elif step == 2:
            seqdata = edhoc.get_message_3(ead)
        elif step == 3:
            seqdata = edhoc.get_message_4(ead)
        else:
            raise IndexError(f'No IA step {step}')
        return seqdata

    def _generate_psa(self):
        edhoc = cast(EdhocEntity, self.data)
        suite = edhoc.get_cipher_suite()

        if self.act.as_initiator:
            sai_i = edhoc.get_own_conn_id()
            sai_r = edhoc.get_peer_conn_id()
        else:
            sai_i = edhoc.get_peer_conn_id()
            sai_r = edhoc.get_own_conn_id()

        context = io.BytesIO()
        enc_context = cbor2.CBOREncoder(context)
        enc_context.encode(sai_i.value)
        enc_context.encode(sai_r.value)
        LOGGER.debug('Generated PSA context %s', context.getvalue().hex())
        prk_sa = edhoc.edhoc_exporter(SAFE_EXPORTER_LABEL, context.getvalue(), suite.app_hash_length)
        LOGGER.debug('Generated PRK_SA1 %s', prk_sa.hex())

        psa = PrimarySecAssn(
            local_sai=edhoc.get_own_conn_id(),
            peer_eid=self.peer_state.peer_eid,
            peer_sai=edhoc.get_peer_conn_id(),
            edhoc=edhoc,
            suite=suite,
            keystores=KeyStoreSet(
                was_initiator=self.act.as_initiator,
                app_kdf=edhoc.app_kdf,
                prk_sa=prk_sa,
            ),
        )

        # Assign initial keys
        prk_ck = None
        arn = b''
        tx_key = psa.create_content_key(kid_ck=b'', prk_ck=prk_ck, arn=arn, txi=psa.keystores.was_initiator, is_tx=True)
        psa.keystores.tx_keys[tx_key.kid] = TxContentKey(key=tx_key)
        rx_key = psa.create_content_key(kid_ck=b'', prk_ck=prk_ck, arn=arn, txi=(not psa.keystores.was_initiator), is_tx=False)
        psa.keystores.rx_keys[rx_key.kid] = RxContentKey(key=rx_key)

        self.app.add_primary_sa(psa)


@register_info(ActivityType.CAPABILITY_INDICATION)
class CapabilityIndication(ActivityInfo):

    def is_finished(self) -> bool:
        state = (self.act.last_step_tx, self.act.last_step_rx)
        return max(state) == 2

    def get_tx_items(self) -> Optional[dict]:
        sdata = cast(SimpleData, self.data)
        if sdata.tx_items:
            return None

        items = {
            ActCIKeys.CAS: 1024,
            ActCIKeys.ESS: [1, 2],
            ActCIKeys.BCS: [3],
        }
        sdata.tx_items = items
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
        sdata = cast(SimpleData, self.data)
        if sdata.tx_items:
            return None

        if self.peer_state.psa:
            key_hdl = self.peer_state.psa.edhoc.get_key_handler()
        elif self.peer_state.edhoc:
            edhoc = cast(EdhocEntity, self.peer_state.edhoc.info.data)
            key_hdl = edhoc.get_key_handler()
        else:
            raise RuntimeError('no key handle available')

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

        sdata.tx_items = items
        return items

    def set_rx_items(self, items: Optional[dict]):
        sdata = cast(SimpleData, self.data)
        sdata.rx_items = items

    def state_changed(self):
        state = (self.act.last_step_tx, self.act.last_step_rx)

        if max(state) == 1:
            # step 1 has either been sent or received
            self._generate_ssa()

    def _generate_ssa(self):
        psa = self.peer_state.psa

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

        context = io.BytesIO()
        enc_context = cbor2.CBOREncoder(context)
        enc_context.encode(sai_i.value)
        enc_context.encode(sai_r.value)
        LOGGER.debug('Generated SSA context %s', context.getvalue().hex())
        prk_sa = psa.edhoc.edhoc_exporter(SAFE_EXPORTER_LABEL, context.getvalue(), psa.suite.app_hash_length)
        LOGGER.debug('Generated PRK_SA2 %s', prk_sa.hex())

        ssa = SecondarySecAssn(
            psa=psa,
            local_sai=local_sai,
            peer_eid=self.peer_state.peer_eid,
            peer_sai=peer_sai,
            keystores=KeyStoreSet(
                was_initiator=self.act.as_initiator,
                app_kdf=psa.keystores.app_kdf,
                prk_sa=prk_sa,
            ),
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

    own: Dict[int, ActivityState] = field(default_factory=dict)
    peer: Dict[int, ActivityState] = field(default_factory=dict)

    edhoc: Optional[ActivityState] = None
    ''' State for IA activity '''
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
class BaseContentKey:
    # TODO add time interval

    key: SymmetricKey
    ''' COSE key including base-IV '''

    op_count: int = 0
    ''' Counter for each operation '''
    bytes_count: int = 0
    ''' Counter for data volume to avoid over use '''

    def increment(self, plain_size: int):
        LOGGER.debug('Incrementing %s use size %d', self.key.kid.hex(), plain_size)
        self.op_count += 1
        self.bytes_count += plain_size


@dataclass
class TxContentKey(BaseContentKey):
    ''' Each TX Content Key for an SA '''

    def partial_iv(self) -> bytes:
        ''' Get a partial-iv byte string based on the op_count. '''
        # avoid zero-value PIV
        piv = self.op_count + 1
        return piv.to_bytes((piv.bit_length() + 7) // 8, 'big')


@dataclass
class RxContentKey(BaseContentKey):
    ''' Each RX Content Key for an SA '''


@dataclass
class BasePreKey:
    # TODO add time interval

    key: CoseKey
    ''' COSE key of agreed NIKE/KEM algorithm type '''


@dataclass
class KeyStoreSet:

    was_initiator: bool
    ''' True if the local entity was the initiator for this SA '''
    app_kdf: AbstractKDF
    ''' The KDF function to use for key derivation, determined by EDHOC suite. '''
    prk_sa: bytes
    ''' The PRK for this specific SA '''

    tx_keys: Dict[bytes, TxContentKey] = field(default_factory=dict)
    ''' TX Content Key store '''
    rx_keys: Dict[bytes, RxContentKey] = field(default_factory=dict)
    ''' RX Content Key store '''

    tx_prekeys: Dict[bytes, BasePreKey] = field(default_factory=dict)
    rx_prekeys: Dict[bytes, BasePreKey] = field(default_factory=dict)

    def safe_kdf(self, prk: bytes, context: List[object], length: int) -> bytes:
        info = io.BytesIO()
        enc_info = cbor2.CBOREncoder(info)
        for item in context:
            enc_info.encode(item)
        enc_info.encode(length)

        return self.app_kdf.expand(prk, info.getvalue(), length)


@dataclass
class PrimarySecAssn:
    ''' State of a security association from Section 3.3 '''
    local_sai: ConnectionId

    peer_eid: str
    peer_sai: ConnectionId

    edhoc: EdhocEntity
    suite: CipherSuite
    ''' Copy of the cipher suite info from EDHOC '''

    keystores: KeyStoreSet
    ''' Key stores for this SA '''

    def __str__(self) -> str:
        parts = [
            f'local_sai={self.local_sai.value.hex()}',
            f'peer_eid={self.peer_eid!r}',
            f'peer_sai={self.peer_sai.value.hex()}',
            f'app_aead={self.suite.app_aead.__name__}',
        ]
        return f'PrimarySecAssn({",".join(parts)})'

    def create_content_key(self, kid_ck: bytes, prk_ck: Optional[bytes], arn: bytes, txi: bool, is_tx: bool) -> SymmetricKey:
        ''' Create a new content key with no key ops yet. '''
        txi = bool(txi)

        if prk_ck is None:
            # no FS
            prk_ck = self.keystores.prk_sa

        sk = self.keystores.safe_kdf(prk_ck, [1, txi, kid_ck, arn], self.suite.app_key_length)
        iv = self.keystores.safe_kdf(prk_ck, [2, txi, kid_ck, arn], self.suite.app_iv_length)

        ops = [keyops.EncryptOp if is_tx else keyops.DecryptOp]
        return SymmetricKey(
            k=sk,
            optional_params={
                keyparam.KpKid: b'',
                keyparam.KpAlg: self.suite.app_aead,
                keyparam.KpKeyOps: ops,
                keyparam.KpBaseIV: iv,
            }
        )


@dataclass
class SecondarySecAssn:
    ''' State of a security association from Section 3.3 '''
    psa: PrimarySecAssn
    ''' Parent of this SA '''

    local_sai: ConnectionId
    ''' Local unique SAI '''
    peer_eid: str
    ''' Peer entity endpoint '''
    peer_sai: ConnectionId
    ''' Peer unique SAI '''

    keystores: KeyStoreSet
    ''' Key stores for this SA '''

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
                 authn_priv_key: Optional[CoseKey] = None,
                 id_cred: Optional[dict] = None,
                 cred_store: Optional[CredStore] = None,
                 ke_priv_key: Optional[List[CoseKey]] = None,
                 conn_id: Optional[bytes] = None):

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
        peer_state = self._peer_state(peer_eid)
        self._logger.debug('PDU RX from %s data %s', peer_eid, pdu.hex())
        dec_pdu = cbor2.CBORDecoder(io.BytesIO(pdu))

        # pdu contents
        version = dec_pdu.decode()
        if version != 1:
            self._logger.error('Cannot handle SAFE version %d', version)
            return True
        partial_iv = dec_pdu.decode()
        psa_kid = dec_pdu.decode()

        pri_sa_id = ConnectionId()
        pri_sa_id.decode(dec_pdu)

        if partial_iv is None and psa_kid is None:
            self._logger.debug('EDHOC reading at offset %s', dec_pdu.fp.tell())
            # expect only one EDHOC message in remainder of PDU
            seqdata = dec_pdu.fp.read()
            if not seqdata:
                raise ValueError('No EDHOC bytes present')

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

        elif isinstance(partial_iv, bytes) and isinstance(psa_kid, bytes):
            self._logger.debug('Got psa-kid %s partial-iv %s', psa_kid.hex(), partial_iv.hex())

            # an established primary SA with ciphertext
            psa = self._pri_sai[pri_sa_id.value]
            try:
                rx_ck = psa.keystores.rx_keys[psa_kid]
            except KeyError:
                raise KeyError(f'Unknown psa-kid {psa_kid.hex()}')

            ciphertext = dec_pdu.decode()
            self._logger.debug('Got ciphertext %s', ciphertext.hex())

            aad = io.BytesIO()
            enc_aad = cbor2.CBOREncoder(aad)
            pri_sa_id.encode(enc_aad)

            enc0 = Enc0Message(
                phdr={
                    headers.Algorithm: psa.suite.app_aead,
                },
                uhdr={
                    headers.PartialIV: partial_iv,
                },
                payload=ciphertext,
                external_aad=aad.getvalue(),
                key=rx_ck.key,
            )
            self._logger.debug('Decrypting with KID=%s', enc0.key.kid.hex())
            plain = enc0.decrypt()
            rx_ck.increment(len(plain))
            self._logger.debug('Generated plaintext %s', plain.hex())

            dec_plain = cbor2.CBORDecoder(io.BytesIO(plain))
            plain_len = len(plain)
            while dec_plain.fp.tell() < plain_len:
                self._recv_msg(peer_state, dec_plain.decode())

        else:
            # something invalid
            raise RuntimeError('Unexpected partial-iv or psa-kid')

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
        enc_pdu.encode(None)  # psa-kid

        step = act.next_step
        self._logger.debug('Sending IA for step %s', step)

        if step == 0:
            self._logger.debug('Generate EAD empty')
            ead = None  # no EAD sent in plaintext

            enc_pdu.encode(True)  # rx-sai
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
        enc_pdu.write(seqdata)

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

        # choose key
        tx_ck = psa.keystores.tx_keys[b'']
        psa_kid = tx_ck.key.kid
        partial_iv = tx_ck.partial_iv()
        self._logger.debug('Using psa-kid %s partial-iv %s', psa_kid.hex(), partial_iv.hex())

        buf = io.BytesIO()
        enc_pdu = cbor2.CBOREncoder(buf)
        enc_pdu.encode(1)  # version

        enc_pdu.encode(partial_iv)  # partial-iv
        enc_pdu.encode(psa_kid)  # psa-kid
        psa.peer_sai.encode(enc_pdu)  # peer connection ID

        buf_plain = io.BytesIO()
        enc_plain = cbor2.CBOREncoder(buf_plain)
        for msgdata in msgdata_list:
            enc_plain.encode(msgdata)
        plain = buf_plain.getvalue()
        self._logger.debug('Generated plaintext %s', plain.hex())

        aad = io.BytesIO()
        enc_aad = cbor2.CBOREncoder(aad)
        # FIXME bind to transport source EID?
        psa.peer_sai.encode(enc_aad)

        enc0 = Enc0Message(
            phdr={
                headers.Algorithm: psa.suite.app_aead,
            },
            uhdr={
                headers.PartialIV: partial_iv,
            },
            payload=plain,
            external_aad=aad.getvalue(),
            key=tx_ck.key,
        )
        self._logger.debug('Encrypting with KID=%s', enc0.key.kid.hex())
        ciphertext = enc0.encrypt()
        tx_ck.increment(len(plain))
        self._logger.debug('Generated ciphertext %s', ciphertext.hex())
        enc_pdu.encode(ciphertext)

        return buf.getvalue()

    def _peer_state(self, peer_eid: str) -> PeerState:
        if peer_eid not in self._act_peer:
            self._act_peer[peer_eid] = PeerState(peer_eid)
        return self._act_peer[peer_eid]

    def _queue_process_tx(self):
        ''' Queue a call to :fun:`_process_tx` in the event loop.
        '''
        self._logger.debug('Queue process TX')
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
