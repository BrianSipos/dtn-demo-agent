
from binascii import hexlify
import cbor2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448, ed25519, ed448
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from Crypto.Hash import KMAC128, KMAC256
from dataclasses import dataclass, field
import enum
import io
import logging
from pycose import algorithms
from pycose.keys import curves, keytype, CoseKey, EC2Key, OKPKey, SymmetricKey
from pycose.messages import Sign1Message, Enc0Message
from pycose import headers
import random
from typing import ClassVar, List, Optional, Type, TypeAlias, Union


LOGGER = logging.getLogger(__name__)


@enum.unique
class Method(enum.IntEnum):
    ''' Methods defined in Section 3.2 of RFC 9528 '''
    SIGN_SIGN = 0
    SIGN_DH = 1
    DH_SIGN = 2
    DH_DH = 3

    RESERVED_23 = 23


def pycose_iv_length(alg: algorithms._EncAlg):
    # FIXME cannot introspect, taken from IANA registry
    if issubclass(alg, algorithms._AesGcm):
        return 12
    elif issubclass(alg, (algorithms.AESCCM1664128, algorithms.AESCCM16128128)):
        return 13
    else:
        raise NotImplementedError(f'Not implemented for {alg}')


@dataclass
class CipherSuite:
    ''' Parameters for a single cipher suite '''
    value: int
    ''' The ciphersuite code point value '''

    edhoc_aead: algorithms.CoseAlgorithm
    ''' AEAD algorithm '''
    edhoc_hash: algorithms.CoseAlgorithm
    ''' Hash algorithm '''
    edhoc_mac_length: int
    ''' Specific MAC length in bytes '''
    edhoc_ke: curves.CoseCurve
    ''' Key Exchange algorithm '''
    edhoc_sign: algorithms.CoseAlgorithm
    ''' Signature algorithm '''

    app_aead: algorithms.CoseAlgorithm
    ''' AEAD algorithm for using applications '''
    app_hash: algorithms.CoseAlgorithm
    ''' Hash algorithm for using applications '''

    @property
    def edhoc_ecdh_key_length(self) -> int:
        return self.edhoc_ke.size

    @property
    def edhoc_key_length(self) -> int:
        return self.edhoc_aead.get_key_length()

    @property
    def edhoc_iv_length(self) -> int:
        return pycose_iv_length(self.edhoc_aead)

    @property
    def edhoc_hash_length(self) -> int:
        return self.edhoc_hash.hash_cls.digest_size

    @property
    def app_key_length(self) -> int:
        return self.app_aead.get_key_length()

    @property
    def app_iv_length(self) -> int:
        return pycose_iv_length(self.app_aead)

    @property
    def app_hash_length(self) -> int:
        return self.app_hash.hash_cls.digest_size


SUITES = [
    # 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA, AES‑CCM‑16‑64‑128, SHA-256
    CipherSuite(0, algorithms.AESCCM1664128, algorithms.Sha256, 8, curves.X25519,
                algorithms.EdDSA, algorithms.AESCCM1664128, algorithms.Sha256),
    # 1: AES-CCM-16-128-128, SHA‑256, 16, X25519, EdDSA, AES‑CCM‑16‑64‑128, SHA-256
    CipherSuite(1, algorithms.AESCCM16128128, algorithms.Sha256, 16, curves.X25519,
                algorithms.EdDSA, algorithms.AESCCM1664128, algorithms.Sha256),
    # 2: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES‑CCM‑16‑64‑128, SHA-256
    CipherSuite(2, algorithms.AESCCM1664128, algorithms.Sha256, 8, curves.P256,
                algorithms.Es256, algorithms.AESCCM1664128, algorithms.Sha256),
    # 3: AES-CCM-16-128-128, SHA‑256, 16, P-256, ES256, AES‑CCM‑16‑64‑128, SHA-256
    CipherSuite(3, algorithms.AESCCM16128128, algorithms.Sha256, 16, curves.P256,
                algorithms.Es256, algorithms.AESCCM1664128, algorithms.Sha256),
    # 4: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA, ChaCha20/Poly1305, SHA-256
    # 5: ChaCha20/Poly1305, SHA-256, 16, P-256, ES256, ChaCha20/⁠Poly1305, SHA-256
    # pycose missing chacha support
    # 6: A128GCM, SHA-256, 16, X25519, ES256, A128GCM, SHA-256
    CipherSuite(6, algorithms.A128GCM, algorithms.Sha256, 16, curves.X25519,
                algorithms.Es256, algorithms.A128GCM, algorithms.Sha256),
    # 24: A256GCM, SHA-384, 16, P-384, ES384, A256GCM, SHA-384
    CipherSuite(24, algorithms.A256GCM, algorithms.Sha384, 16, curves.P384,
                algorithms.Es384, algorithms.A256GCM, algorithms.Sha384),
    # 25: ChaCha20/Poly1305, SHAKE256, 16, X448, EdDSA, ChaCha20/Poly1305, SHAKE256
    # pycose missing chacha support
]
''' Known cipher suites registered with IANA '''
SUITES_BY_VALUE = {
    obj.value: obj
    for obj in SUITES
}
''' Indexed by value for lookup '''


@dataclass
class KeyHandler:
    ''' Key exchange key handling logic '''

    key_cls: Type[CoseKey]

    crv: Type[curves.CoseCurve]

    def generate_key(self) -> CoseKey:
        return self.key_cls.generate_key(crv=self.crv)

    def validate(self, key: CoseKey):
        if key.crv is not self.crv:
            raise ValueError(f'Required curve {self.crv} mismatch from key curve {key.crv}')

    def to_pub_data(self, key: CoseKey) -> bytes:
        # same duck type use for subtypes
        return bytes(key.x)

    def from_pub_data(self, data: bytes) -> CoseKey:
        # same duck type use for subtypes
        return self.key_cls(crv=self.crv, x=data)


_KEY_HANDLER_MAP = {
    keytype.KtyOKP: lambda crv: KeyHandler(key_cls=OKPKey, crv=crv),
    keytype.KtyEC2: lambda crv: KeyHandler(key_cls=EC2Key, crv=crv),
}


def cose_key(key) -> CoseKey:
    ''' Convert from native cryptography key to a CoseKey '''
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return EC2Key._from_cryptography_key(key)
    elif isinstance(key, (x25519.X25519PrivateKey, x25519.X25519PublicKey,
                          x448.X448PrivateKey, x448.X448PublicKey)):
        return OKPKey._from_cryptography_key(key)
    else:
        raise NotImplementedError(f'unhandled key type {type(key)} from {type(key).__bases__}')


@dataclass
class EadItem:
    ''' A single EAD item per Section 3.8 of RFC 9528 '''
    label: int
    value: Optional[bytes] = None

    def __repr__(self) -> str:
        parts = [
            f'label={self.label!r}',
            f'value={self.value.hex()}',
        ]
        return f'{type(self).__name__}({",".join(parts)})'


@dataclass
class EadList:
    ''' A set of EAD per Section 3.8 of RFC 9528 '''
    items: List[EadItem] = field(default_factory=list)

    def encode(self, enc: cbor2.CBOREncoder):
        ''' Encode to a CBOR item sequence '''
        for item in self.items:
            enc.encode(item.label)
            if item.value is not None:
                enc.encode(item.value)

    def decode(self, dec: cbor2.CBORDecoder):

        self.items = []

        at_end = False
        last_dec = None
        last_dec_valid = False
        while not at_end:
            if not last_dec_valid:
                try:
                    last_dec = dec.decode()
                except cbor2.CBORDecodeEOF:
                    break
            label = int(last_dec)

            value = None
            if not at_end:
                try:
                    last_dec = dec.decode()
                except cbor2.CBORDecodeEOF:
                    at_end = True

                if not at_end and isinstance(last_dec, bytes):
                    value = bytes(last_dec)
                    last_dec_valid = False
                else:
                    last_dec_valid = True

            self.items.append(EadItem(label, value))


def _bytes_compress(value: Union[bytes, bool]) -> Union[bytes, int]:
    if isinstance(value, bytes) and len(value) == 1:
        octet = value[0]
        if (octet <= 0x17) or (octet >= 0x20 and octet <= 0x37):
            # as integer form
            return cbor2.loads(value)

    return value


def _bytes_decompress(src: Union[bytes, int, bool]) -> Union[bytes, bool]:
    if isinstance(src, (bytes, bool)):
        return src
    else:
        return cbor2.dumps(src)


@dataclass
class ConnectionId:

    value: bytes = b''
    ''' Native simple value '''

    EncodedType: ClassVar[TypeAlias] = Union[bytes, int]
    ''' Encoded value type '''

    @staticmethod
    def from_item(item: EncodedType) -> 'ConnectionId':
        return ConnectionId(
            value=_bytes_decompress(item)
        )

    def encode(self, enc: cbor2.CBOREncoder):
        ''' Encode the value '''
        enc.encode(_bytes_compress(self.value))

    def decode(self, dec: cbor2.CBORDecoder):
        ''' Decode the value '''
        self.value = _bytes_decompress(dec.decode())


@dataclass
class IdCred:

    value: dict = field(default_factory=dict)
    ''' Native simple value '''

    EncodedType: ClassVar = Union[dict, bytes, int]
    ''' Encoded value type '''

    def encode(self, enc: cbor2.CBOREncoder):
        ''' Encode the value '''
        if len(self.value) == 1 and headers.KID.identifier in self.value:
            item = _bytes_compress(self.value[headers.KID.identifier])
        else:
            item = self.value
        enc.encode(item)

    def decode(self, dec: cbor2.CBORDecoder):
        ''' Decode the value '''
        item = dec.decode()
        if isinstance(item, (int, bytes)):
            self.value = {headers.KID.identifier: _bytes_decompress(item)}
        else:
            self.value = dict(item)


@dataclass
class CredItem:
    ''' Data to represent credentials and their associated public keys '''

    data: bytes
    ''' The pre-encoded CBOR item representing the credential '''
    pubkey: CoseKey
    ''' The pre-extracted COSE key from the credential '''


class CredStore:
    ''' An indexed collection of CredItem objects '''

    def __init__(self):
        self._items = dict()

    def _map(self, value):
        if isinstance(value, list):
            return tuple(value)
        return value

    def add(self, id_cred, item: CredItem):
        for label, value in id_cred.items():
            self._items[(label, self._map(value))] = item

    def find(self, id_cred: dict) -> Optional[CredItem]:
        if headers.X5chain.identifier in id_cred:
            # Direct public credential
            chain = id_cred[headers.X5chain.identifier]
            if isinstance(chain, bytes):
                chain = [chain]

            cred = chain[0]
            cert = x509.load_der_x509_certificate(chain[0])
            pubkey = cose_key(cert.public_key())
            return CredItem(data=cred, pubkey=pubkey)

        else:
            # Indirect lookup
            for label, value in id_cred.items():
                found = self._items.get((label, self._map(value)))
                if found:
                    return found

        raise KeyError(f'No credential matching {id_cred}')


def _collapse_list(val: List[int]) -> Union[List, int]:
    if len(val) == 1:
        return val[0]
    return val


def _expand_list(val: Union[List, int]) -> List[int]:
    if isinstance(val, List):
        return val
    return [val]


EcKeyType = Union[EC2Key, OKPKey]
''' Type for any elliptic curve COSE key object '''


def perform_ecdh(priv_key: EcKeyType, peer_key: EcKeyType) -> bytes:
    ''' Derive a shared secret from a pair of ECDH private and public keys.
    '''
    LOGGER.debug('ECDH with %s and %s', priv_key, peer_key)
    if not isinstance(priv_key, type(peer_key)):
        raise ValueError('Peer key must be the same type as our key')

    if isinstance(priv_key, EC2Key):
        d_value = int(hexlify(priv_key.d), 16)
        d = ec.derive_private_key(
            d_value, priv_key.crv.curve_obj, backend=default_backend())

        x_value = int(hexlify(peer_key.x), 16)
        y_value = int(hexlify(peer_key.y), 16)
        p = ec.EllipticCurvePublicNumbers(
            x_value, y_value, peer_key.crv.curve_obj)
        p = p.public_key(backend=default_backend())

        shared_key = d.exchange(ec.ECDH(), p)
    elif isinstance(priv_key, OKPKey):
        KEY_CLS = {
            curves.Ed25519: (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey),
            curves.Ed448: (ed448.Ed448PrivateKey, ed448.Ed448PublicKey),
            curves.X25519: (x25519.X25519PrivateKey, x25519.X25519PublicKey),
            curves.X448: (x448.X448PrivateKey, x448.X448PublicKey),
        }
        (priv_cls, pub_cls) = KEY_CLS[priv_key.crv]

        d = priv_cls.from_private_bytes(priv_key.d)
        p = pub_cls.from_public_bytes(peer_key.x)

        shared_key = d.exchange(p)
    else:
        raise NotImplementedError

    return shared_key


def bytes_xor(ina: bytes, inb: bytes) -> bytes:
    ''' Perform a bitwise XOR of two byte strings '''
    return bytes(a ^ b for a, b in zip(ina, inb))


class AbstractKDF:
    ''' Generic interface for performing EDHOC_KDF() function. '''

    def __call__(self, prk: bytes, info_label: int, context: bytes, length: int) -> bytes:
        ''' The EDHOC_KDF() function signature.
        This depends on the cipher suite used and its "EDHOC hash algorithm"
        or "application hash algorithm" used.
        '''
        info = io.BytesIO()
        enc_info = cbor2.CBOREncoder(info)
        enc_info.encode(info_label)
        enc_info.encode(context)
        enc_info.encode(length)

        return self.expand(prk, info.getvalue(), length)

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        ''' The EDHOC_Extract() interface '''
        raise NotImplementedError

    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        ''' The EDHOC_Expand() interface '''
        raise NotImplementedError


class HKDF(AbstractKDF):
    ''' Encapsulate the configuration of an HKDF '''

    def __init__(self, cls: Type[hashes.HashAlgorithm]):
        self._hash_cls = cls

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        ''' The EDHOC_Extract() to use when edhoc_hash is one of SHA2 '''
        ext = hmac.HMAC(
            key=salt,
            algorithm=self._hash_cls(),
            backend=default_backend()
        )
        ext.update(ikm)
        return ext.finalize()

    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        ''' The EDHOC_Expand() to use when edhoc_hash is one of SHA2 '''
        exp = HKDFExpand(
            algorithm=self._hash_cls(),
            length=length,
            info=info,
            backend=default_backend()
        )
        return exp.derive(prk)


class KMAC(AbstractKDF):
    ''' Encapsulate the configuration of a KMAC PRF '''

    _ALG_MAP = {
        hashes.SHAKE128: (KMAC128, 256),
        hashes.SHAKE256: (KMAC256, 512),
    }
    ''' MAC type and extract length for each valid hash algorithm '''

    def __init__(self, hash_cls: Type[hashes.HashAlgorithm]):
        self._mac_cls, self._ext_length = KMAC._ALG_MAP[hash_cls]

    def extract(self, salt: bytes, ikm: bytes) -> bytes:
        ''' The EDHOC_Extract() to use when edhoc_hash is one of SHAKE '''
        ext = self._mac_cls.new(
            key=salt,
            mac_len=self._ext_length
        )
        ext.update(ikm)
        return ext.digest()

    def expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        ''' The EDHOC_Expand() to use when edhoc_hash is one of SHAKE '''
        exp = self._mac_cls.new(
            key=prk,
            mac_len=length
        )
        exp.update(info)
        return exp.digest()


def _get_kdf(hash_cls: Type[hashes.HashAlgorithm]) -> AbstractKDF:
    ''' Derive a KDF function object from a specific hash class used by
    an EDHOC cipher suite.
    '''
    SHA2_HASH_ALGOS = {
        hashes.SHA224,
        hashes.SHA256,
        hashes.SHA384,
        hashes.SHA512,
    }
    KMAC_ALGOS = {
        hashes.SHAKE128,
        hashes.SHAKE256,
    }
    if hash_cls in SHA2_HASH_ALGOS:
        return HKDF(hash_cls)
    elif hash_cls in KMAC_ALGOS:
        return KMAC(hash_cls)
    else:
        raise NotImplementedError(f'Undefined use of hash class {hash_cls}')


class CommonState:
    ''' Common processing for either EDHOC endpoint.

    :param authn_priv_key: The local entity private key.
    :param cred_store: The credential store for all entities.
    :param id_cred: The local entity ID_CRED value.
    :param ke_priv_key: A manual ECDH key used only for debugging.
    '''

    def __init__(self,
                 authn_priv_key: EcKeyType,
                 cred_store: CredStore,
                 id_cred: dict,
                 as_initiator: bool,
                 ke_priv_key: Optional[EcKeyType] = None,
                 method: Optional[Method] = None,
                 conn_id: Optional[bytes] = None):
        self._logger = logging.getLogger(f'{__name__}.{type(self).__name__}')

        self.cred_store = cred_store
        self._as_init = bool(as_initiator)

        self._method = method
        self._init_auth_sign = None
        self._resp_auth_sign = None

        self._sel_suite = None
        self._key_hdl: KeyHandler = None
        self.edhoc_kdf: AbstractKDF = None
        self.app_kdf: AbstractKDF = None

        self._own_ke_key = ke_priv_key
        self._peer_ke_key = None

        self._hash_msg_1 = None
        self._th_2 = None
        self._prk_2e = None
        self._prk_3e2m = None
        self._plain_2 = None
        self._th_3 = None
        self._k_3 = None
        self._iv_3 = None
        self._prk_4e3m = None
        self._plain_3 = None
        self._th_4 = None
        self._k_4 = None
        self._iv_4 = None
        self._prk_out = None
        self._prk_exporter = None

        if conn_id is not None:
            self._own_conn_id = ConnectionId(bytes(conn_id))
        else:
            self._own_conn_id = ConnectionId(random.randbytes(4))
        self._logger.debug('Using C_x %s', self._own_conn_id.value.hex())
        self._peer_conn_id = ConnectionId()

        self._own_id_cred = IdCred(value=id_cred.copy())
        self._logger.debug('Using ID_CRED_x %s', self._own_id_cred.value)
        self._peer_id_cred = IdCred()

        # Cached credentials from cred_store
        self._own_cred = self.cred_store.find(self._own_id_cred.value)
        self._peer_cred = None

        self._own_authn_priv_key = authn_priv_key
        self._logger.debug('Using authentication key type %s',
                           type(self._own_authn_priv_key).__name__)

    def _set_sel_suite(self, method: Method, suite_id: int):
        self._method = method
        self._init_auth_sign = self._method in {Method.SIGN_SIGN, Method.SIGN_DH}
        self._resp_auth_sign = self._method in {Method.SIGN_SIGN, Method.DH_SIGN}

        self._sel_suite = SUITES_BY_VALUE[suite_id]
        self._key_hdl = _KEY_HANDLER_MAP[self._sel_suite.edhoc_ke.key_type](
            self._sel_suite.edhoc_ke
        )

        if self._own_ke_key is not None:
            self._key_hdl.validate(self._own_ke_key)
        else:
            self._own_ke_key = self._key_hdl.generate_key()

        self.edhoc_kdf = _get_kdf(self._sel_suite.edhoc_hash.hash_cls)
        self.app_kdf = _get_kdf(self._sel_suite.app_hash.hash_cls)

    def _edhoc_hash(self, data: bytes) -> bytes:
        return self._sel_suite.edhoc_hash.compute_hash(data)

    def _derive_secrets_2a(self):
        ''' Secrets from Section 5.3.2 and 4.1.1.1 of RFC 9528 '''
        g_y = self._key_hdl.to_pub_data(
            self._peer_ke_key if self._as_init else self._own_ke_key
        )

        tr2 = io.BytesIO()
        enc_tr2 = cbor2.CBOREncoder(tr2)
        enc_tr2.encode(g_y)
        enc_tr2.encode(self._hash_msg_1)
        self._logger.debug('Generated transcript_2 %s', tr2.getvalue().hex())

        self._th_2 = self._edhoc_hash(tr2.getvalue())
        self._logger.debug('Generated TH_2 %s', self._th_2.hex())

        g_xy = perform_ecdh(self._own_ke_key, self._peer_ke_key)
        self._logger.debug('Generated G_XY %s', g_xy.hex())
        self._prk_2e = self.edhoc_kdf.extract(salt=self._th_2, ikm=g_xy)
        self._logger.debug('Generated PRK_2e %s', self._prk_2e.hex())

    def _derive_secrets_2b(self):
        ''' Secrets from 5.3.2 and 4.1.1.2 of RFC 9528 after having CRED_R '''
        if self._resp_auth_sign:
            self._prk_3e2m = self._prk_2e
        else:
            salt_3e2m = self.edhoc_kdf(
                prk=self._prk_2e,
                info_label=1,
                context=self._th_2,
                length=self._sel_suite.edhoc_hash_length
            )
            self._logger.debug('Generated salt_3e2m %s', salt_3e2m.hex())

            if not self._as_init:
                g_rx = perform_ecdh(self._own_authn_priv_key, self._peer_ke_key)
            else:
                cred_r = self._peer_cred if self._as_init else self._own_cred
                g_rx = perform_ecdh(self._own_ke_key, cred_r.pubkey)
            self._logger.debug('Generated G_RX %s', g_rx.hex())
            self._prk_3e2m = self.edhoc_kdf.extract(salt=salt_3e2m, ikm=g_rx)
        self._logger.debug('Generated PRK_3e2m %s', self._prk_3e2m.hex())

    def _get_mac_2(self, ead: Optional[EadList]) -> bytes:
        ''' MAC_2 from Section 5.3.2 of RFC 9528 '''
        c_r = self._peer_conn_id if self._as_init else self._own_conn_id
        id_cred_r = self._peer_id_cred if self._as_init else self._own_id_cred
        cred_r = self._peer_cred if self._as_init else self._own_cred

        ctx_2 = io.BytesIO()
        enc_ctx_2 = cbor2.CBOREncoder(ctx_2)
        c_r.encode(enc_ctx_2)
        enc_ctx_2.encode(id_cred_r.value)  # non-compressed ID_CRED_R
        enc_ctx_2.encode(self._th_2)
        ctx_2.write(cred_r.data)  # pre-encoded
        if ead:
            ead.encode(enc_ctx_2)
        self._logger.debug('Generated context_2 %s', ctx_2.getvalue().hex())

        mac_length = self._sel_suite.edhoc_hash_length if self._resp_auth_sign else self._sel_suite.edhoc_mac_length
        mac_2 = self.edhoc_kdf(
            prk=self._prk_3e2m,
            info_label=2,
            context=ctx_2.getvalue(),
            length=mac_length
        )
        self._logger.debug('Generated MAC_2 %s', mac_2.hex())
        return mac_2

    def _get_aad_2(self, ead: Optional[EadList]) -> bytes:
        ''' external_aad from Section 5.3.2 of RFC 9528 '''
        cred_r = self._peer_cred if self._as_init else self._own_cred

        aad = io.BytesIO()
        if self._resp_auth_sign:
            enc_aad = cbor2.CBOREncoder(aad)
            enc_aad.encode(self._th_2)
            aad.write(cred_r.data)
            if ead:
                ead.encode(enc_aad)
            self._logger.debug('Generated signature AAD %s',
                               aad.getvalue().hex())

        return aad.getvalue()

    def _derive_secrets_3a(self):
        ''' Secrets from 5.4.2 of RFC 9528 '''
        cred_r = self._peer_cred if self._as_init else self._own_cred

        tr3 = io.BytesIO()
        enc_tr3 = cbor2.CBOREncoder(tr3)
        enc_tr3.encode(self._th_2)
        tr3.write(self._plain_2)  # already encoded sub-sequence
        tr3.write(cred_r.data)
        self._logger.debug('Generated transcript_3 %s', tr3.getvalue().hex())

        self._th_3 = self._edhoc_hash(tr3.getvalue())
        self._logger.debug('Generated TH_3 %s', self._th_3.hex())

        self._k_3 = self.edhoc_kdf(
            prk=self._prk_3e2m,
            info_label=3,
            context=self._th_3,
            length=self._sel_suite.edhoc_key_length
        )
        self._logger.debug('Generated K_3 %s', self._k_3.hex())

        self._iv_3 = self.edhoc_kdf(
            prk=self._prk_3e2m,
            info_label=4,
            context=self._th_3,
            length=self._sel_suite.edhoc_iv_length
        )
        self._logger.debug('Generated IV_3 %s', self._iv_3.hex())

    def _derive_secrets_3b(self):
        ''' Secrets from 5.4.2 of RFC 9528 after having CRED_I '''
        if self._init_auth_sign:
            self._prk_4e3m = self._prk_3e2m
        else:
            salt_4e3m = self.edhoc_kdf(
                prk=self._prk_3e2m,
                info_label=5,
                context=self._th_3,
                length=self._sel_suite.edhoc_hash_length
            )
            self._logger.debug('Generated salt_4e3m %s', salt_4e3m.hex())

            if self._as_init:
                g_iy = perform_ecdh(self._own_authn_priv_key, self._peer_ke_key)
            else:
                cred_i = self._own_cred if self._as_init else self._peer_cred
                g_iy = perform_ecdh(self._own_ke_key, cred_i.pubkey)
            self._logger.debug('Generated G_IY %s', g_iy.hex())
            self._prk_4e3m = self.edhoc_kdf.extract(salt=salt_4e3m, ikm=g_iy)
        self._logger.debug('Generated PRK_4e3m %s', self._prk_4e3m.hex())

    def _get_mac_3(self, ead: Optional[EadList]) -> bytes:
        ''' MAC_3 from Section 5.4.2 of RFC 9528 '''
        id_cred_i = self._own_id_cred if self._as_init else self._peer_id_cred
        cred_i = self._own_cred if self._as_init else self._peer_cred

        ctx_3 = io.BytesIO()
        enc_ctx_3 = cbor2.CBOREncoder(ctx_3)
        enc_ctx_3.encode(id_cred_i.value)  # non-compressed ID_CRED_I
        enc_ctx_3.encode(self._th_3)
        ctx_3.write(cred_i.data)
        if ead:
            ead.encode(enc_ctx_3)
        self._logger.debug('Generated context_3 %s', ctx_3.getvalue().hex())

        mac_length = self._sel_suite.edhoc_hash_length if self._init_auth_sign else self._sel_suite.edhoc_mac_length
        mac_3 = self.edhoc_kdf(
            prk=self._prk_4e3m,
            info_label=6,
            context=ctx_3.getvalue(),
            length=mac_length
        )
        self._logger.debug('Generated MAC_3 %s', mac_3.hex())
        return mac_3

    def _get_aad_3(self, ead: Optional[EadList]) -> bytes:
        ''' external_aad from Section 5.4.2 of RFC 9528 '''
        cred_i = self._own_cred if self._as_init else self._peer_cred

        aad = io.BytesIO()
        enc_aad = cbor2.CBOREncoder(aad)
        enc_aad.encode(self._th_3)
        aad.write(cred_i.data)
        if ead:
            ead.encode(enc_aad)
        self._logger.debug('Generated signature AAD %s',
                           aad.getvalue().hex())

        return aad.getvalue()

    def _derive_secrets_4(self):
        ''' Secrets from Section 5.4.2 of RFC 9528 '''
        cred_i = self._own_cred if self._as_init else self._peer_cred

        tr4 = io.BytesIO()
        enc_tr4 = cbor2.CBOREncoder(tr4)
        enc_tr4.encode(self._th_3)
        tr4.write(self._plain_3)  # already encoded sub-sequence
        tr4.write(cred_i.data)
        self._logger.debug('Generated transcript_4 %s', tr4.getvalue().hex())

        self._th_4 = self._edhoc_hash(tr4.getvalue())
        self._logger.debug('Generated TH_4 %s', self._th_4.hex())

        self._prk_out = self.edhoc_kdf(
            prk=self._prk_4e3m,
            info_label=7,
            context=self._th_4,
            length=self._sel_suite.edhoc_hash_length
        )
        self._logger.debug('Generated PRK_out %s', self._prk_out.hex())

        self._k_4 = self.edhoc_kdf(
            prk=self._prk_4e3m,
            info_label=8,
            context=self._th_4,
            length=self._sel_suite.edhoc_key_length
        )
        self._logger.debug('Generated K_4 %s', self._k_4.hex())

        self._iv_4 = self.edhoc_kdf(
            prk=self._prk_4e3m,
            info_label=9,
            context=self._th_4,
            length=self._sel_suite.edhoc_iv_length
        )
        self._logger.debug('Generated IV_4 %s', self._iv_4.hex())

        self._prk_exporter = self.edhoc_kdf(
            prk=self._prk_out,
            info_label=10,
            context=b'',
            length=self._sel_suite.edhoc_hash_length
        )
        self._logger.debug('Generated PRK_exporter %s',
                           self._prk_exporter.hex())

    def as_initiator(self) -> bool:
        return self._as_init

    def get_own_conn_id(self) -> ConnectionId:
        return self._own_conn_id

    def get_peer_conn_id(self) -> ConnectionId:
        return self._peer_conn_id

    def get_cipher_suite(self) -> CipherSuite:
        return self._sel_suite

    def get_key_handler(self) -> KeyHandler:
        return self._key_hdl

    def get_prk_exporter(self) -> bytes:
        return self._prk_exporter

    def edhoc_exporter(self, info_label: int, context: bytes, length: int) -> bytes:
        ''' Provide an application interface to the final exporter behavior
        defined in Section 4.2 of RFC 9528.
        '''
        return self.edhoc_kdf(self._prk_exporter, info_label, context, length)


CipherSuitesType = List[Union[CipherSuite, int]]


def _normalize_suites(suites: CipherSuitesType) -> List[CipherSuite]:
    res = []
    for val in suites:
        if isinstance(val, CipherSuite):
            res.append(val)
        else:
            res.append(SUITES_BY_VALUE[val])
    return res


class EdhocInitiator(CommonState):
    ''' Logic for the initiator side of an EDHOC conversation. '''

    def __init__(self, method: Method, suites: CipherSuitesType, **kwargs):
        kwargs['as_initiator'] = True
        super().__init__(**kwargs)

        suites = _normalize_suites(suites)
        self._suite_ids = list([suite.value for suite in suites])
        self._set_sel_suite(method, self._suite_ids[-1])

    def get_message_1(self, ead: Optional[EadList] = None) -> bytes:
        ''' From Section 5.2.1 of RFC 9528 '''
        buf = io.BytesIO()
        enc = cbor2.CBOREncoder(buf)

        enc.encode(int(self._method))
        enc.encode(_collapse_list(self._suite_ids))
        enc.encode(self._key_hdl.to_pub_data(self._own_ke_key))
        self._own_conn_id.encode(enc)
        if ead:
            ead.encode(enc)

        self._hash_msg_1 = self._edhoc_hash(buf.getvalue())
        self._logger.debug('H(message_1) %s', self._hash_msg_1.hex())
        return buf.getvalue()

    def process_message_2(self, msg: bytes) -> EadList:
        self._logger.debug('Got message_2 data %s', msg.hex())
        dec = cbor2.CBORDecoder(io.BytesIO(msg))
        # message is a single bstr
        buf = io.BytesIO(dec.decode())

        key_size = self._sel_suite.edhoc_ke.size
        self._peer_ke_key = self._key_hdl.from_pub_data(buf.read(key_size))

        self._derive_secrets_2a()

        ciphertext_2 = buf.read()

        keystream_2 = self.edhoc_kdf(
            prk=self._prk_2e,
            info_label=0,
            context=self._th_2,
            length=len(ciphertext_2)
        )
        self._plain_2 = bytes_xor(ciphertext_2, keystream_2)
        self._logger.debug('Decrypted PLAINTEXT_2 %s', self._plain_2.hex())

        dec_plain_2 = cbor2.CBORDecoder(io.BytesIO(self._plain_2))
        self._peer_conn_id.decode(dec_plain_2)
        self._logger.debug('Got C_R %s', self._peer_conn_id.value.hex())
        self._peer_id_cred.decode(dec_plain_2)
        self._logger.debug('Got ID_CRED_R %s', self._peer_id_cred.value)
        sign_or_mac_2 = dec_plain_2.decode()
        self._logger.debug('Got Signature_or_MAC_2 %s',
                           sign_or_mac_2.hex())
        ead = EadList()
        ead.decode(dec_plain_2)
        self._logger.debug('Got EAD_2 %s', ead)

        self._peer_cred = self.cred_store.find(self._peer_id_cred.value)
        self._derive_secrets_2b()

        mac_2 = self._get_mac_2(ead=ead)
        if self._resp_auth_sign:
            aad_2 = self._get_aad_2(ead=ead)
            sign1 = Sign1Message(
                phdr=self._peer_id_cred.value,
                uhdr={
                    headers.Algorithm: self._sel_suite.edhoc_sign,
                },
                payload=mac_2,
                external_aad=aad_2,
                key=self._peer_cred.pubkey,
            )
            self._logger.debug('Verifying with phdr %s uhdr %s key %s',
                               sign1.phdr, sign1.uhdr, sign1.key)
            sign1.signature = sign_or_mac_2
            if sign1.verify_signature():
                self._logger.info('Verified Signature_2')
            else:
                raise ValueError('Signature_2 verify failed')
        else:
            if sign_or_mac_2 == mac_2:
                self._logger.info('Verified MAC_2')
            else:
                raise ValueError('MAC_2 mismatch')

        return ead

    def get_message_3(self, ead: Optional[EadList] = None) -> bytes:
        self._derive_secrets_3a()
        self._derive_secrets_3b()
        mac_3 = self._get_mac_3(ead)

        if self._init_auth_sign:
            aad_3 = self._get_aad_3(ead)
            sign1 = Sign1Message(
                phdr=self._own_id_cred.value,
                uhdr={
                    headers.Algorithm: self._sel_suite.edhoc_sign,
                },
                payload=mac_3,
                external_aad=aad_3,
                key=self._own_authn_priv_key,
            )
            self._logger.debug('Signing with phdr %s uhdr %s key %s',
                               sign1.phdr, sign1.uhdr, sign1.key)
            sign_or_mac_3 = sign1.compute_signature()
        else:
            sign_or_mac_3 = mac_3
        self._logger.debug('Generated Signature_or_MAC_3 %s',
                           sign_or_mac_3.hex())

        plain_3 = io.BytesIO()
        enc = cbor2.CBOREncoder(plain_3)
        self._own_id_cred.encode(enc)
        enc.encode(sign_or_mac_3)
        self._logger.debug('Using EAD_3 %s', ead)
        if ead:
            ead.encode(enc)
        self._plain_3 = plain_3.getvalue()
        self._logger.debug('Created PLAINTEXT_3 %s',
                           self._plain_3.hex())

        enc0 = Enc0Message(
            phdr={},
            uhdr={
                headers.Algorithm: self._sel_suite.edhoc_aead,
                headers.IV: self._iv_3,
            },
            payload=self._plain_3,
            external_aad=self._th_3,
            key=SymmetricKey(k=self._k_3),
        )
        self._logger.debug('Encrypting with key K=%s',
                           enc0.key.k.hex())
        ciphertext_3 = enc0.encrypt()
        self._logger.debug('Generated ciphertext_3 %s',
                           ciphertext_3.hex())

        self._derive_secrets_4()

        # message is a single bstr
        return cbor2.dumps(ciphertext_3)

    def process_message_4(self, msg: bytes) -> EadList:
        self._logger.debug('Got message_4 data %s', msg.hex())
        # message is a single bstr with no structure
        ciphertext_4 = cbor2.loads(msg)

        enc0 = Enc0Message(
            phdr={},
            uhdr={
                headers.Algorithm: self._sel_suite.edhoc_aead,
                headers.IV: self._iv_4,
            },
            payload=ciphertext_4,
            external_aad=self._th_4,
            key=SymmetricKey(k=self._k_4),
        )
        self._logger.debug('Decrypting with key K=%s',
                           enc0.key.k.hex())
        plain_4 = enc0.decrypt()
        self._logger.debug('Decrypted PLAINTEXT_4 %s', plain_4.hex())

        dec_plain_4 = cbor2.CBORDecoder(io.BytesIO(plain_4))
        ead = EadList()
        ead.decode(dec_plain_4)
        self._logger.debug('Got EAD_4 %s', ead)

        return ead


class EdhocResponder(CommonState):
    ''' Logic for the responder side of an EDHOC conversation. '''

    def __init__(self, valid_methods=List[Method], valid_suites=CipherSuitesType, **kwargs):
        kwargs['as_initiator'] = False
        super().__init__(**kwargs)

        self._valid_methods = set(valid_methods)
        self._method = None
        self._valid_suites = _normalize_suites(valid_suites)
        self._valid_suite_ids = set([
            suite.value for suite in self._valid_suites
        ])

    def process_message_1(self, msg: bytes) -> EadList:
        self._logger.debug('Got message_1 data %s', msg.hex())
        buf = io.BytesIO(msg)
        dec = cbor2.CBORDecoder(buf)

        # First extract message contents
        method = Method(int(dec.decode()))
        if method not in self._valid_methods:
            raise ValueError(f'message_1 has invalid method {method}')

        suites = _expand_list(dec.decode())
        used_suite_id = int(suites[-1])
        if used_suite_id not in self._valid_suite_ids:
            raise ValueError(f'Suite {used_suite_id} is not acceptable'
                             + f' from {self._valid_suite_ids}')
        self._set_sel_suite(method, used_suite_id)

        self._peer_ke_key = self._key_hdl.from_pub_data(dec.decode())
        self._peer_conn_id.decode(dec)
        self._logger.debug('Got C_I %s', self._peer_conn_id.value.hex())

        ead = EadList()
        ead.decode(dec)

        self._hash_msg_1 = self._edhoc_hash(msg)
        self._logger.debug('H(message_1) %s', self._hash_msg_1.hex())

        # Then construct own counterparts
        self._derive_secrets_2a()
        self._derive_secrets_2b()

        return ead

    def get_message_2(self, ead: Optional[EadList] = None) -> bytes:
        mac_2 = self._get_mac_2(ead=ead)

        if self._resp_auth_sign:
            aad_2 = self._get_aad_2(ead=ead)
            sign1 = Sign1Message(
                phdr=self._own_id_cred.value,
                uhdr={
                    headers.Algorithm: self._sel_suite.edhoc_sign,
                },
                payload=mac_2,
                external_aad=aad_2,
                key=self._own_authn_priv_key,
            )
            self._logger.debug('Signing with phdr %s uhdr %s key %s',
                               sign1.phdr, sign1.uhdr, sign1.key)
            sign_or_mac_2 = sign1.compute_signature()
        else:
            sign_or_mac_2 = mac_2
        self._logger.debug('Generated Signature_or_MAC_2 %s',
                           sign_or_mac_2.hex())

        plain_2 = io.BytesIO()
        enc = cbor2.CBOREncoder(plain_2)
        self._logger.debug('Sending C_R %s', self._own_conn_id.value.hex())
        self._own_conn_id.encode(enc)
        self._own_id_cred.encode(enc)
        enc.encode(sign_or_mac_2)
        self._logger.debug('Using EAD_2 %s', ead)
        if ead:
            ead.encode(enc)
        self._plain_2 = plain_2.getvalue()
        self._logger.debug('Created PLAINTEXT_2 %s',
                           self._plain_2.hex())

        keystream_2 = self.edhoc_kdf(
            prk=self._prk_2e,
            info_label=0,
            context=self._th_2,
            length=len(self._plain_2)
        )
        ciphertext_2 = bytes_xor(self._plain_2, keystream_2)

        data = self._key_hdl.to_pub_data(self._own_ke_key) + ciphertext_2
        # message is a single bstr
        return cbor2.dumps(data)

    def process_message_3(self, msg: bytes) -> EadList:
        self._logger.debug('Got message_3 data %s', msg.hex())
        # message is a single bstr
        ciphertext_3 = cbor2.loads(msg)

        self._derive_secrets_3a()
        enc0 = Enc0Message(
            phdr={},
            uhdr={
                headers.Algorithm: self._sel_suite.edhoc_aead,
                headers.IV: self._iv_3,
            },
            payload=ciphertext_3,
            external_aad=self._th_3,
            key=SymmetricKey(k=self._k_3),
        )
        self._logger.debug('Decrypting with key K=%s',
                           enc0.key.k.hex())
        self._plain_3 = enc0.decrypt()
        self._logger.debug('Decrypted PLAINTEXT_3 %s', self._plain_3.hex())

        dec_plain_3 = cbor2.CBORDecoder(io.BytesIO(self._plain_3))
        self._peer_id_cred.decode(dec_plain_3)
        self._logger.debug('Got ID_CRED_I %s', self._peer_id_cred.value)
        sign_or_mac_3 = dec_plain_3.decode()
        self._logger.debug('Got Signature_or_MAC_3 %s',
                           sign_or_mac_3.hex())
        ead = EadList()
        ead.decode(dec_plain_3)
        self._logger.debug('Got EAD_3 %s', ead)

        self._peer_cred = self.cred_store.find(self._peer_id_cred.value)
        self._derive_secrets_3b()

        mac_3 = self._get_mac_3(ead)
        if self._init_auth_sign:
            aad_3 = self._get_aad_3(ead)
            sign1 = Sign1Message(
                phdr=self._peer_id_cred.value,
                uhdr={
                    headers.Algorithm: self._sel_suite.edhoc_sign,
                },
                payload=mac_3,
                external_aad=aad_3,
                key=self._peer_cred.pubkey,
            )
            self._logger.debug('Verifying with phdr %s uhdr %s key %s',
                               sign1.phdr, sign1.uhdr, sign1.key)
            sign1.signature = sign_or_mac_3
            if sign1.verify_signature():
                self._logger.info('Verified Signature_3')
            else:
                raise ValueError('Signature_3 verify failed')
        else:
            if sign_or_mac_3 == mac_3:
                self._logger.info('Verified MAC_3')
            else:
                raise ValueError('MAC_3 mismatch')

        self._derive_secrets_4()

        return ead

    def get_message_4(self, ead: Optional[EadList] = None) -> bytes:
        plain_4 = io.BytesIO()
        enc = cbor2.CBOREncoder(plain_4)
        self._logger.debug('Using EAD_4 %s', ead)
        if ead:
            ead.encode(enc)
        plain_4.getvalue()
        self._logger.debug('Created PLAINTEXT_4 %s',
                           plain_4.getvalue().hex())

        enc0 = Enc0Message(
            phdr={},
            uhdr={
                headers.Algorithm: self._sel_suite.edhoc_aead,
                headers.IV: self._iv_4,
            },
            payload=plain_4.getvalue(),
            external_aad=self._th_4,
            key=SymmetricKey(k=self._k_4),
        )
        self._logger.debug('Encrypting with key K=%s',
                           enc0.key.k.hex())
        ciphertext_4 = enc0.encrypt()
        self._logger.debug('Generated ciphertext_4 %s',
                           ciphertext_4.hex())

        # message is a single bstr
        return cbor2.dumps(ciphertext_4)
