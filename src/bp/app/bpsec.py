''' Application layer adaptors.
'''
from abc import ABC, abstractmethod
import cbor2
import copy
from dataclasses import dataclass, field
import datetime
import enum
import logging
import re
import traceback
from typing import Callable, Dict, List, Literal, Optional, Tuple, Union
from certvalidator import CertificateValidator, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pycose.messages import (
    CoseMessage, Mac0Message, MacMessage, Sign1Message, SignMessage,
    Enc0Message, EncMessage
)
from pycose.messages.recipient import CoseRecipient, KeyWrap
from pycose.messages.signer import CoseSignature
from pycose import algorithms, headers
from pycose.keys import (
    curves, keyparam, keyops, CoseKey, EC2Key, RSAKey, SymmetricKey
)
from pycose.exceptions import CoseUnsupportedCurve
from pycose.extensions.x509 import X5T, X5Chain
from pycose.algorithms import CoseAlgorithm

from scapy_cbor.util import encode_diagnostic
import tcpcl.session
from bp.config import Config
from bp.encoding import (
    DtnTimeField,
    PrimaryBlock, CanonicalBlock, StatusReport,
    BlockIntegrityBlock, BlockConfidentialityBlock, AbstractSecurityBlock,
    TypeValuePair, TargetResultList,
)
from bp.util import ChainStep, BundleContainer
from bp.crypto import (OID_ON_EID, load_pem_key, load_pem_chain, encode_der_cert)
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)

# IANA allocated context ID
BPSEC_COSE_CONTEXT_ID = 3


class AbstractContext(ABC):
    ''' Base context interface class.
    '''

    @abstractmethod
    def load_config(self, config: Config):
        raise NotImplementedError()

    @abstractmethod
    def apply_bib(self, ctr: BundleContainer) -> None:
        ''' Attempt to apply a BIB to a bundle.

        :param ctr: The entire bundle container.
        '''
        raise NotImplementedError()

    @abstractmethod
    def verify_bib(self, ctr: BundleContainer, bib: CanonicalBlock) -> Optional[int]:
        ''' Verify or accept a BIB for this context.

        :param ctr: The entire bundle container.
        :param bib: The specific BIB to verify.
        :return: A non-None status value if failed.
        '''
        raise NotImplementedError()

    @abstractmethod
    def apply_bcb(self, ctr: BundleContainer) -> None:
        ''' Attempt to apply a BIB to a bundle.

        :param ctr: The entire bundle container.
        '''
        raise NotImplementedError()

    @abstractmethod
    def verify_bcb(self, ctr: BundleContainer, bcb: CanonicalBlock) -> Optional[int]:
        ''' Verify or accept a BCB for this context.

        :param ctr: The entire bundle container.
        :param bcb: The specific BCB to verify.
        :return: A non-None status value if failed.
        '''
        raise NotImplementedError()


SecurityOperationType = Literal['bib', 'bcb']


@dataclass
class SecOperation:
    ''' Options for an individual security operation to process.
    '''
    sec_type: SecurityOperationType
    ''' Type of operation to apply '''
    role: Literal['source', 'verifier', 'acceptor']
    ''' Role for the operation '''

    tgt_blk_num: Optional[int] = None
    ''' The existing target block number.
    When used as a template, this is None.
    '''

    priv_key_id: Optional[bytes] = None
    ''' When role is source: the KID to use for this operation '''
    content_alg: Optional[algorithms.CoseAlgorithm] = None
    ''' Authorized layer 0 algorithm to source or validate '''
    content_key: Optional[bytes] = None
    ''' Optional fixed layer 0 content key.
    Leave as None for random content key when wrapping. 
    '''
    content_iv: List[bytes] = field(default_factory=list)
    ''' Sequence of content IV for encryption.
    Leave empty to use random or when not encrypting.
    '''

    priv_key: Optional[CoseKey] = None
    ''' Derived reference to a key '''
    x5chain: Optional[List[bytes]] = None
    ''' Derived DER certificate chain '''


@dataclass
class SecAssociation:
    ''' A single security association with endpoint pattern matching and
    resulting security operation details including symmetric key.
    '''

    src_pat: re.Pattern
    dst_pat: re.Pattern

    tgt_blk_types: List[int]
    ''' Naive list of block types to target '''

    templates: List[SecOperation] = field(default_factory=list)
    ''' Template security operation to expand based on :py:attr:`target_types` '''

    def is_match(self, ctr: BundleContainer, sec_type: SecurityOperationType) -> List[SecOperation]:
        ''' Check for a match on a bundle '''
        src_match = self.src_pat.fullmatch(ctr.bundle.primary.source)
        dst_match = self.dst_pat.fullmatch(ctr.bundle.primary.destination)
        LOGGER.debug('SA match on src %s %s dst %s %s', ctr.bundle.primary.source,
                     src_match, ctr.bundle.primary.destination, dst_match)
        if src_match is None or dst_match is None:
            return []

        target_block_nums = sorted([
            blk.block_num
            for blk in ctr.bundle.blocks
            if blk.type_code in self.tgt_blk_types
        ])
        if not target_block_nums:
            LOGGER.warning('No target blocks have matching type %s', self.tgt_blk_types)
            return []

        result = []
        for sop in self.templates:
            if sop.sec_type != sec_type:
                continue

            # clone SecOp for each valid target
            for blk_num in target_block_nums:
                sop = copy.copy(sop)
                sop.tgt_blk_num = blk_num
                result.append(sop)

        return result


class CertificateStore:
    ''' Logic for managing certificate bags. '''

    def __init__(self):
        # Map from DER to decoded Certificate
        self._certs_by_der: Dict[bytes, x509.Certificate] = dict()
        # Map from subject key identifier digest to Certificate
        self._certs_by_ski: Dict[bytes, x509.Certificate] = dict()

    def add_untrusted_cert(self, data: bytes):
        if data in self._certs_by_der:
            return

        cert = x509.load_der_x509_certificate(data, default_backend())
        self._certs_by_der[data] = cert

        ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        self._certs_by_ski[ski] = cert

    def find_chain(self, alg_id: int, want_tprint: bytes) -> Tuple[bytes]:
        ''' Find a chain corresponding to a specific end-entity thumbprint.

        :return: The chain of DER data starting at the end-entity up to any CA.
        '''
        alg = CoseAlgorithm.from_id(alg_id)
        LOGGER.debug('CertificateStore.find_chain searching for %s:%s', alg_id, want_tprint)

        cur_cert = None
        chain = []
        for data, cert in self._certs_by_der.items():
            tprint = alg.compute_hash(data)
            if tprint == want_tprint:
                cur_cert = cert
                chain.append(data)

        if not cur_cert:
            raise RuntimeError(f'No EE certificate found with thumbprint {want_tprint}')
        LOGGER.debug('CertificateStore.find_chain got EE %s', cert)

        while True:
            try:
                current_aki = cur_cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
            except x509.ExtensionNotFound:
                raise RuntimeError(f'Certificate does not contain an AuthorityKeyIdentifier extension')
            parent_ski = current_aki.key_identifier

            try:
                parent_cert = self._certs_by_ski[parent_ski]
            except KeyError:
                raise RuntimeError(f'No parent certificate with SubjectKeyIdentifier {parent_ski}')
            LOGGER.debug('CertificateStore.find_chain got parent %s', parent_cert)

            if parent_cert == cur_cert:
                break
            cur_cert = parent_cert
            chain.append(encode_der_cert(cur_cert))

        LOGGER.debug('CertificateStore.find_chain got size %d for %s:%s', len(chain), alg_id, want_tprint)
        return tuple(chain)


@dataclass
class CoseSecOpCtx:
    ''' Collection of external data needed to process one security operation
    in the COSE Context.
    '''
    ctr: BundleContainer
    sec_blk: CanonicalBlock

    ssrc_enc: Optional[bytes] = None
    ''' Encoded security source from the security block '''
    aad_scope: Optional[Dict[int, int]] = None
    ''' Decoded AAD Scope parameter '''
    addl_protected: Optional[bytes] = None
    ''' Encoded Additional Protected parameter '''
    addl_headers: Optional[Dict] = None
    ''' All additional headers combined together and de-duplicated '''
    addl_parsed: Optional[Dict] = None
    ''' All additional headers parsed by :py:mod:`pycose`. '''

    tgt_blk: Optional[CanonicalBlock] = None
    ''' Target block for specific operations, which can be modified '''

    def check_secblk(self) -> bool:
        ''' Initial consistency check of :py:attr:`sec_blk`
        '''
        type_ids = [param.type_code for param in self.sec_blk.payload.parameters]
        if len(set(type_ids)) != len(type_ids):
            LOGGER.error('Duplicate parameter IDs')
            return False

        for tgt_ix, target_results in enumerate(self.sec_blk.payload.results):
            type_ids = [res.type_code for res in target_results.results]
            if len(set(type_ids)) != len(type_ids):
                LOGGER.error('Duplicate result IDs for index %d', tgt_ix)
                return False

        return True

    def extract_secblk(self) -> None:
        ''' Extract derived fields from :py:attr:`sec_blk`
        '''

        # Encoded security source EID
        ssrc_fld, ssrc_val = self.sec_blk.payload.getfield_and_val('source')
        self.ssrc_enc = cbor2.dumps(ssrc_fld.i2m(self.sec_blk.payload, ssrc_val))

        self.addl_protected = b''
        addl_unprotected = b''
        self.aad_scope = {0: 1, -1: 1, -2: 1}
        for param in self.sec_blk.payload.parameters:
            if param.type_code == 3:
                self.addl_protected = bytes(param.value)
            elif param.type_code == 4:
                addl_unprotected = bytes(param.value)
            elif param.type_code == 5:
                self.aad_scope = dict(param.value)

        addl_protected_map = cbor2.loads(self.addl_protected) if self.addl_protected else {}
        addl_unprotected_map = cbor2.loads(addl_unprotected) if addl_unprotected else {}
        dupe_keys = set(addl_protected_map.keys()).intersection(set(addl_unprotected_map.keys()))
        if dupe_keys:
            raise ValueError(f'Duplicate keys in additional headers: {dupe_keys}')
        self.addl_headers = dict(addl_protected_map)
        self.addl_headers.update(addl_unprotected_map)

        # use additional headers as defaults in highest layers
        self.addl_parsed = CoseMessage._parse_header(self.addl_headers, allow_unknown_attributes=False)

    def get_external_aad(self) -> bytes:
        ''' Generate External AAD from a bundle container per Section 2.5.1 of draft-ietf-bpsec-cose
        '''
        # roundabout way of forcing sorted map
        aad_scope_enc = cbor2.dumps(self.aad_scope, canonical=True)
        aad_scope = cbor2.loads(aad_scope_enc)

        aad_data = self.ssrc_enc + aad_scope_enc

        # processing order by block number in CBOR sort logic
        for blk_num, flags in aad_scope.items():
            if blk_num in (0, -2, self.sec_blk.block_num) and flags & CoseContext.AadScopeFlag.BTSD:
                LOGGER.error(f'Invalid AAD Scope flags for block {blk_num}')

            if blk_num == -1:
                blk = self.tgt_blk
            elif blk_num == -2:
                # security block is not yet part of the bundle
                blk = self.sec_blk
            elif blk_num == 0:
                blk = self.ctr.bundle.primary
            else:
                blk = self.ctr.block_num(blk_num)
            is_primary = isinstance(blk, PrimaryBlock)

            if is_primary:
                if flags & CoseContext.AadScopeFlag.METADATA:
                    blk.update_crc()
                    aad_data += bytes(blk)

            else:
                if flags & CoseContext.AadScopeFlag.METADATA:
                    # block metadata not in array framing
                    aad_data += b''.join(cbor2.dumps(item) for item in blk.build()[:3])

                if flags & CoseContext.AadScopeFlag.BTSD:
                    aad_data += cbor2.dumps(bytes(blk.btsd))

        aad_data += cbor2.dumps(self.addl_protected)

        LOGGER.debug('External AAD encoded %s', aad_data.hex())
        return aad_data

    def decode_msg(self, result: TypeValuePair) -> CoseMessage:
        ''' Decode a COSE message froma  result value and condition it
        for this context.
        This relies on :py:attr:`tgt_blk` and other optional fields to be set.
        '''
        msg_cls: CoseMessage = CoseMessage._COSE_MSG_ID[result.type_code]

        # replace detached payload
        msg_enc = bytes(result.getfieldval('value'))
        msg_dec = cbor2.loads(msg_enc)
        LOGGER.debug('Received COSE message\n%s', encode_diagnostic(msg_dec))
        msg_dec[2] = self.tgt_blk.getfieldval('btsd')

        msg_obj = msg_cls.from_cose_obj(msg_dec, allow_unknown_attributes=False)
        msg_obj.external_aad = self.get_external_aad()

        return msg_obj


class CoseContext(AbstractContext):

    @enum.unique
    class AadScopeFlag(enum.IntFlag):
        METADATA = 0x01
        BTSD = 0x02

    def __init__(self):
        super().__init__()

        self._config: Optional[Config] = None
        self._ca_certs = []
        self._cert_chain = []

        self.asym_key_store: Dict[bytes, CoseKey] = dict()
        self.sym_key_store: Dict[bytes, SymmetricKey] = dict()
        self.cert_store = CertificateStore()

        # security associations for policy
        self.sec_assoc: List[SecAssociation] = list()

    def load_config(self, config: Config):
        self._config = config

        if config.verify_ca_file:
            with open(config.verify_ca_file, 'rb') as infile:
                self._ca_certs = load_pem_chain(infile)
            for cert in self._ca_certs:
                self.cert_store.add_untrusted_cert(encode_der_cert(cert))

        if config.sign_cert_file:
            with open(config.sign_cert_file, 'rb') as infile:
                self._cert_chain = load_pem_chain(infile)

        if config.sign_key_file:
            with open(config.sign_key_file, 'rb') as infile:
                pkey = load_pem_key(infile)

            try:
                cose_key = self.extract_cose_key(pkey)
            except Exception as err:
                LOGGER.error('Cannot handle private key: %s', repr(err))
                raise

            cose_key.kid = b'PEM'
            cose_key.key_ops = [keyops.SignOp]
            self.asym_key_store[cose_key.kid] = cose_key

            # Sign self-sourced payload only
            if self._config.node_id.startswith('ipn:'):
                own_pat = re.escape(self._config.node_id.removesuffix('.0') + '.') + '.*'
            elif self._config.node_id.startswith('dtn:'):
                own_pat = re.escape(self._config.node_id.removesuffix('/') + '/') + '.*'
            LOGGER.debug('Signing from source pattern %s', own_pat)
            self.sec_assoc.append(SecAssociation(
                src_pat=re.compile(own_pat),
                dst_pat=re.compile('.*'),
                tgt_blk_types=[1],
                templates=[
                    SecOperation(
                        sec_type='bib',
                        role='source',
                        priv_key_id=cose_key.kid,
                    )
                ],
            ))

    @staticmethod
    def extract_cose_key(keyobj):
        ''' Get a COSE version of the local private key.
        :param keyobj: The cryptography key object.
        :return: The associated COSE key.
        :rtype: :py:class:`CoseKey`
        '''
        if isinstance(keyobj, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            if hasattr(keyobj, 'private_numbers'):
                priv_nums = keyobj.private_numbers()
                pub_nums = keyobj.public_key().public_numbers()
            else:
                priv_nums = None
                pub_nums = keyobj.public_numbers()

            kwargs = dict()
            if pub_nums:

                def convert(name, attr=None):
                    val = getattr(pub_nums, attr or name)
                    kwargs[name] = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")

                convert('n')
                convert('e')
            if priv_nums:

                def convert(name, attr=None):
                    val = getattr(priv_nums, attr or name)
                    kwargs[name] = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")

                convert('d')
                convert('p')
                convert('q')
                convert('dp', 'dmp1')
                convert('dq', 'dmq1')
                convert('qinv', 'iqmp')

            cose_key = RSAKey(**kwargs)
            cose_key.alg = algorithms.Ps512

        elif isinstance(keyobj, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            CURVE_CLS_MAP = {
                ec.SECP256R1: curves.P256,
                ec.SECP384R1: curves.P384,
                ec.SECP521R1: curves.P521,
            }
            CURVE_ALG_MAP = {
                ec.SECP256R1: algorithms.Es256,
                ec.SECP384R1: algorithms.Es384,
                ec.SECP521R1: algorithms.Es512,
            }

            try:
                curve_cls = CURVE_CLS_MAP[type(keyobj.curve)]
            except KeyError:
                raise CoseUnsupportedCurve('Cannot match curve for {}'.format(repr(keyobj)))
            LOGGER.debug('Found COSE curve %s', curve_cls)

            try:
                alg_cls = CURVE_ALG_MAP[type(keyobj.curve)]
            except KeyError:
                raise CoseUnsupportedCurve('Cannot match algorithm for {}'.format(repr(keyobj)))
            LOGGER.debug('Found COSE algorithm %s', alg_cls)

            if hasattr(keyobj, 'private_numbers'):
                priv_nums = keyobj.private_numbers()
                pub_nums = keyobj.public_key().public_numbers()
            else:
                priv_nums = None
                pub_nums = keyobj.public_numbers()

            kwargs = dict(
                crv=curve_cls,
                optional_params={
                    keyparam.KpAlg: alg_cls,
                },
            )

            if pub_nums:
                x_coor = pub_nums.x
                y_coor = pub_nums.y
                kwargs.update(dict(
                    x=x_coor.to_bytes((x_coor.bit_length() + 7) // 8, byteorder="big"),
                    y=y_coor.to_bytes((y_coor.bit_length() + 7) // 8, byteorder="big")
                ))
            if priv_nums:
                d_value = priv_nums.private_value
                kwargs.update(dict(
                    d=d_value.to_bytes((d_value.bit_length() + 7) // 8, byteorder="big"),
                ))

            cose_key = EC2Key(**kwargs)

        else:
            raise TypeError('Cannot handle key {}'.format(repr(keyobj)))

        return cose_key

    def validate_chain_func(self, time_at: datetime.datetime) -> Callable[[Tuple[bytes]], None]:
        ''' Get a function to validate a certificate chain.

        :param time_at: The time to validate at.
        :return: A callable which takes an x5chain of certificates and either
            throws an Exception not not if valid.
        '''
        val_ctx = ValidationContext(
            trust_roots=[
                encode_der_cert(cert)
                for cert in self._ca_certs
            ],
            other_certs=[
                encode_der_cert(cert)
                for cert in self._cert_chain
            ],
            moment=time_at,
        )

        def validate(chain: Tuple[bytes]):
            val = CertificateValidator(
                end_entity_cert=chain[0],
                intermediate_certs=chain[1:],
                validation_context=val_ctx
            )
            val.validate_usage(
                key_usage={'digital_signature'},
                extended_key_usage={'1.3.6.1.5.5.7.3.35'},
                extended_optional=False
            )

        return validate

    def apply_bib(self, ctr: BundleContainer) -> None:
        secop_lists = [assoc.is_match(ctr, 'bib') for assoc in self.sec_assoc]
        secops: List[SecOperation] = [item for sublist in secop_lists for item in sublist]
        if not secops:
            LOGGER.warning('No BIB operations')
            return

        # Pre-populate derived attributes of all operations
        common_x5chain = None
        for sop in secops:
            if sop.priv_key_id in self.sym_key_store:
                sop.priv_key = self.sym_key_store[sop.priv_key_id]
                sop.x5chain = None
            elif sop.priv_key_id in self.asym_key_store:
                # any asymmetric key associated with a cert
                sop.priv_key = self.asym_key_store[sop.priv_key_id]
                sop.x5chain = []
                for cert in self._cert_chain:
                    sop.x5chain.append(encode_der_cert(cert))
                # FIXME: make this logic correct for multiple SOPs
                common_x5chain = sop.x5chain
            else:
                LOGGER.error(f'No private key with KID {sop.priv_key_id}')
                return

        addl_protected_map = {}
        addl_unprotected_map = {}
        aad_scope = {0: 1, -1: 1}  # primary and target metadata

        # A little switcharoo to avoid cached overload_fields on `data`
        bib = CanonicalBlock(
            type_code=BlockIntegrityBlock._overload_fields[CanonicalBlock]['type_code'],
            block_num=ctr.get_block_num(),
        )
        bib_data = BlockIntegrityBlock(
            targets=[sop.tgt_blk_num for sop in secops],
            context_id=BPSEC_COSE_CONTEXT_ID,
            context_flags=(
                AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
            ),
            source=self._config.node_id,
            parameters=[
                TypeValuePair(type_code=5, value=aad_scope),
            ],
        )
        # Encoded security source EID
        ssrc_fld, ssrc_val = bib_data.getfield_and_val('source')
        ssrc_enc = cbor2.dumps(ssrc_fld.i2m(bib_data, ssrc_val))

        # identity de-duplicated in additional headers
        if common_x5chain:
            if self._config.integrity_include_chain:
                addl_unprotected_map[headers.X5chain.identifier] = X5Chain(common_x5chain).encode()
            else:
                addl_unprotected_map[headers.X5t.identifier] = X5T.from_certificate(algorithms.Sha256, common_x5chain[0]).encode()

        # Inject optional additional headers
        addl_protected = cbor2.dumps(addl_protected_map) if addl_protected_map else b''
        if addl_protected:
            bib_data.parameters.append(
                TypeValuePair(type_code=3, value=addl_protected)
            )
        addl_unprotected = cbor2.dumps(addl_unprotected_map) if addl_unprotected_map else b''
        if addl_unprotected:
            bib_data.parameters.append(
                TypeValuePair(type_code=4, value=addl_unprotected)
            )

        secopctx = CoseSecOpCtx(ctr=ctr, sec_blk=bib, ssrc_enc=ssrc_enc,
                                aad_scope=aad_scope, addl_protected=addl_protected)

        # Message for each target with one result per op/target
        target_result = []
        for sop in secops:
            tgt_blk = ctr.block_num(sop.tgt_blk_num)
            tgt_blk.ensure_block_type_specific_data()
            target_plaintext = tgt_blk.getfieldval('btsd')

            secopctx.tgt_blk = tgt_blk
            ext_aad_enc = secopctx.get_external_aad()
            LOGGER.debug('Integrity protecting target %d AAD %s payload %s',
                         sop.tgt_blk_num, encode_diagnostic(ext_aad_enc),
                         encode_diagnostic(target_plaintext))

            if isinstance(sop.priv_key, SymmetricKey):
                if keyops.MacCreateOp in sop.priv_key.key_ops:
                    # direct MAC
                    msg_obj = Mac0Message(
                        phdr={
                            headers.Algorithm: sop.priv_key.alg,
                        },
                        uhdr={
                            headers.KID: sop.priv_key.kid,
                        },
                        payload=target_plaintext,
                        # Non-encoded parameters
                        external_aad=ext_aad_enc,
                        key=sop.priv_key
                    )
                    LOGGER.debug('MAC with COSE key %s', repr(sop.priv_key))
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    msg_dec[2] = None

                elif keyops.WrapOp in sop.priv_key.key_ops:
                    recip = KeyWrap(
                        phdr=dict(),
                        uhdr={
                            headers.Algorithm: sop.priv_key.alg,
                            headers.KID: sop.priv_key.kid,
                        },
                        # Non-encoded parameters
                        key=sop.priv_key
                    )
                    if sop.content_key:
                        recip.payload = sop.content_key

                    msg_obj = MacMessage(
                        phdr={
                            headers.Algorithm: sop.content_alg,
                        },
                        uhdr=dict(),
                        payload=target_plaintext,
                        recipients=[recip],
                        # Non-encoded parameters
                        external_aad=ext_aad_enc
                    )
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    LOGGER.debug('Used content key %s', msg_obj.key.k.hex())
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    msg_dec[2] = None

                else:
                    raise ValueError(f'Cannot MAC with key having {sop.priv_key.key_ops}')

            else:
                phdr = {
                    headers.Algorithm: sop.priv_key.alg,
                }
                uhdr = dict()

                if keyops.SignOp in sop.priv_key.key_ops:
                    # Direct signing
                    msg_obj = Sign1Message(
                        phdr=phdr,
                        uhdr=uhdr,
                        payload=target_plaintext,
                        # Non-encoded parameters
                        external_aad=ext_aad_enc,
                        key=sop.priv_key
                    )
                    LOGGER.debug('Signing with COSE key %s', repr(sop.priv_key))
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    msg_dec[2] = None

                else:
                    raise ValueError(f'Cannot sign with key having {sop.priv_key.key_ops}')

            msg_enc = cbor2.dumps(msg_dec)
            LOGGER.debug('Sending COSE message %s', encode_diagnostic(msg_dec))

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
        ctr.add_block(bib)

    def verify_bib(self, ctr: BundleContainer, bib: CanonicalBlock) -> Optional[int]:
        ''' Verify all targets in a single BIB based on local policy config.

        :return: An error code, or None if successful.
        '''
        secop = CoseSecOpCtx(ctr=ctr, sec_blk=bib)
        if not secop.check_secblk():
            return StatusReport.ReasonCode.FAILED_SEC
        secop.extract_secblk()

        failure = None
        accept_ix = []
        for (tgt_ix, tgt_blk_num) in enumerate(bib.payload.targets):
            tgt_blk = ctr.block_num(tgt_blk_num)
            result_list = bib.payload.results[tgt_ix].results
            if len(result_list) != 1:
                LOGGER.error('Result array in BIB num %d does not have exactly one result', bib.block_num)
                failure = StatusReport.ReasonCode.FAILED_SEC
            else:
                result = result_list[0]

                secop.tgt_blk = tgt_blk
                one_failure = self.verify_bib_target(secop, result)
                if one_failure is not None:
                    failure = one_failure
                elif self._config.accept_after_verify:
                    LOGGER.debug('Accepting target block num %d after verification', tgt_blk_num)
                    accept_ix.append(tgt_ix)

        for tgt_ix in sorted(accept_ix, reverse=True):
            bib.payload.targets.pop(tgt_ix)
            bib.payload.results.pop(tgt_ix)
        if not bib.payload.targets:
            LOGGER.debug('Removing empty BIB num %d', bib.block_num)
            ctr.remove_block(bib)

        return failure

    def verify_bib_target(self, secop: CoseSecOpCtx, result: TypeValuePair) -> Optional[int]:
        ''' Verify a single BIB security operation on a single target.
        '''
        valid = False
        try:
            msg_obj = secop.decode_msg(result)

            if isinstance(msg_obj, Mac0Message):
                valid = self._verify_bib_mac0(secop, msg_obj)

            elif isinstance(msg_obj, MacMessage):
                # Any one must be valid, but not all
                for r_ix, recip in enumerate(msg_obj.recipients):
                    one_valid = self._verify_bib_mac(secop, msg_obj, recip)
                    if not one_valid:
                        LOGGER.warning('Failed to verify COSE_Mac recipient %s with key k=%s', r_ix, msg_obj.key)
                    valid |= one_valid
                LOGGER.debug('Used content key %s', msg_obj.key.k.hex())

            elif isinstance(msg_obj, Sign1Message):
                valid = self._verify_bib_sign1(secop, msg_obj)

            elif isinstance(msg_obj, SignMessage):
                # Any one must be valid, but not all
                for s_ix, signer in enumerate(msg_obj.signers):
                    one_valid = self._verify_bib_sign(secop, msg_obj, signer)
                    if not one_valid:
                        LOGGER.warning('Failed to verify COSE_Sign signer %s with key k=%s', s_ix, msg_obj.key)
                    valid |= one_valid

            else:
                raise TypeError(f'Unhandled message in {type(msg_obj)}')

        except Exception as err:
            LOGGER.error('Exception during verify of BIB num %d, target block num %d: %s', secop.sec_blk.block_num, secop.tgt_blk.block_num, err)
            LOGGER.debug('%s', traceback.format_exc())
            valid = False

        if valid:
            LOGGER.info('Verified BIB num %d, target block num %d', secop.sec_blk.block_num, secop.tgt_blk.block_num)
            return None
        else:
            LOGGER.error('Failed to verify BIB num %d, target block num %d', secop.sec_blk.block_num, secop.tgt_blk.block_num)
            return StatusReport.ReasonCode.FAILED_SEC

    def _verify_bib_mac0(self, secop: CoseSecOpCtx, msg_obj: Mac0Message) -> bool:
        ''' Verify a single result with a COSE_Mac0 '''
        for (key, val) in secop.addl_parsed.items():
            msg_obj.uhdr.setdefault(key, val)

        try:
            msg_obj.key = self._get_cose_key(secop.ctr, msg_obj, secop.sec_blk.payload.source)
            return msg_obj.verify_tag()
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Mac0: %s', err)
            LOGGER.debug('%s', traceback.format_exc())
            return False

    def _verify_bib_mac(self, secop: CoseSecOpCtx, msg_obj: MacMessage, recip: CoseRecipient) -> bool:
        ''' Verify a single result with a COSE_Mac '''
        for (key, val) in secop.addl_parsed.items():
            recip.uhdr.setdefault(key, val)

        try:
            recip.key = self._get_cose_key(secop.ctr, recip, secop.sec_blk.payload.source)
            return msg_obj.verify_tag(recip)
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Mac recipient %s: %s', recip, err)
            LOGGER.debug('%s', traceback.format_exc())
            return False

    def _verify_bib_sign1(self, secop: CoseSecOpCtx, msg_obj: Sign1Message) -> bool:
        ''' Verify a single result with a COSE_Sign1 '''
        for (key, val) in secop.addl_parsed.items():
            msg_obj.uhdr.setdefault(key, val)

        try:
            msg_obj.key = self._get_cose_key(secop.ctr, msg_obj, secop.sec_blk.payload.source)
            return msg_obj.verify_signature()
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Sign1: %s', err)
            LOGGER.debug('%s', traceback.format_exc())
            return False

    def _verify_bib_sign(self, secop: CoseSecOpCtx, msg_obj: SignMessage, signer: CoseSignature) -> bool:
        ''' Verify a single result with a COSE_Mac '''
        for (key, val) in secop.addl_parsed.items():
            signer.uhdr.setdefault(key, val)

        try:
            signer.key = self._get_cose_key(secop.ctr, signer, secop.sec_blk.payload.source)
            return msg_obj.verify_signature(signer)
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Sign signer %s: %s', signer, err)
            LOGGER.debug('%s', traceback.format_exc())
            return False

    def apply_bcb(self, ctr: BundleContainer) -> None:
        secop_lists = [assoc.is_match(ctr, 'bcb') for assoc in self.sec_assoc]
        secops: List[SecOperation] = [item for sublist in secop_lists for item in sublist]
        if not secops:
            LOGGER.warning('No BCB operations')
            return

        # Pre-populate derived attributes of all operations
        for sop in secops:
            if sop.priv_key_id in self.sym_key_store:
                sop.priv_key = self.sym_key_store[sop.priv_key_id]
            elif sop.priv_key_id in self.asym_key_store:
                # any asymmetric key associated with a cert
                sop.priv_key = self.asym_key_store[sop.priv_key_id]
            else:
                LOGGER.error(f'No private key with KID {sop.priv_key_id}')
                return

        addl_protected_map = {}
        addl_unprotected_map = {}
        aad_scope = {0: 1, -1: 1}  # primary and target metadata

        # A little switcharoo to avoid cached overload_fields on `data`
        bcb = CanonicalBlock(
            type_code=BlockConfidentialityBlock._overload_fields[CanonicalBlock]['type_code'],
            block_num=ctr.get_block_num(),
            block_flags=CanonicalBlock.Flag.REPLICATE_IN_FRAGMENT,
        )
        bcb_data = BlockConfidentialityBlock(
            targets=[sop.tgt_blk_num for sop in secops],
            context_id=BPSEC_COSE_CONTEXT_ID,
            context_flags=(
                AbstractSecurityBlock.Flag.PARAMETERS_PRESENT
            ),
            source=self._config.node_id,
            parameters=[
                TypeValuePair(type_code=5, value=aad_scope),
            ],
        )
        # Encoded security source EID
        ssrc_fld, ssrc_val = bcb_data.getfield_and_val('source')
        ssrc_enc = cbor2.dumps(ssrc_fld.i2m(bcb_data, ssrc_val))

        # Inject optional additional headers
        addl_protected = cbor2.dumps(addl_protected_map) if addl_protected_map else b''
        if addl_protected:
            bcb_data.parameters.append(
                TypeValuePair(type_code=3, value=addl_protected)
            )
        addl_unprotected = cbor2.dumps(addl_unprotected_map) if addl_unprotected_map else b''
        if addl_unprotected:
            bcb_data.parameters.append(
                TypeValuePair(type_code=4, value=addl_unprotected)
            )

        secop = CoseSecOpCtx(ctr=ctr, sec_blk=bcb, ssrc_enc=ssrc_enc,
                             aad_scope=aad_scope, addl_protected=addl_protected)

        # Message for each target with one result per op/target
        target_result = []
        for sop in secops:
            tgt_blk = ctr.block_num(sop.tgt_blk_num)
            tgt_blk.ensure_block_type_specific_data()
            target_plaintext = tgt_blk.getfieldval('btsd')

            secop.tgt_blk = tgt_blk
            ext_aad_enc = secop.get_external_aad()
            LOGGER.debug('Integrity protecting target %d AAD %s payload %s',
                         sop.tgt_blk_num, encode_diagnostic(ext_aad_enc),
                         encode_diagnostic(target_plaintext))

            if isinstance(sop.priv_key, SymmetricKey):
                if keyops.EncryptOp in sop.priv_key.key_ops:
                    # direct key
                    msg_obj = Enc0Message(
                        phdr={
                            headers.Algorithm: sop.priv_key.alg,
                        },
                        uhdr={
                            headers.KID: sop.priv_key.kid,
                            headers.IV: sop.content_iv.pop(0),
                        },
                        payload=target_plaintext,
                        # Non-encoded parameters
                        external_aad=ext_aad_enc,
                        key=sop.priv_key
                    )
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    tgt_blk.setfieldval('btsd', msg_dec[2])
                    msg_dec[2] = None

                elif keyops.WrapOp in sop.priv_key.key_ops:
                    recip = KeyWrap(
                        phdr=dict(),
                        uhdr={
                            headers.Algorithm: sop.priv_key.alg,
                            headers.KID: sop.priv_key.kid,
                        },
                        # Non-encoded parameters
                        key=sop.priv_key
                    )
                    if sop.content_key:
                        recip.payload = sop.content_key

                    msg_obj = EncMessage(
                        phdr={
                            headers.Algorithm: sop.content_alg,
                        },
                        uhdr={
                            headers.IV: sop.content_iv.pop(0),
                        },
                        payload=target_plaintext,
                        recipients=[recip],
                        # Non-encoded parameters
                        external_aad=ext_aad_enc
                    )
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    LOGGER.debug('Used content key %s', msg_obj.key.k.hex())
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    tgt_blk.setfieldval('btsd', msg_dec[2])
                    msg_dec[2] = None

                else:
                    raise ValueError(f'Cannot MAC with key having {sop.priv_key.key_ops}')

            else:
                phdr = {
                    headers.Algorithm: sop.priv_key.alg,
                }
                uhdr = dict()

                if keyops.SignOp in sop.priv_key.key_ops:
                    # Direct signing
                    msg_obj = Sign1Message(
                        phdr=phdr,
                        uhdr=uhdr,
                        payload=target_plaintext,
                        # Non-encoded parameters
                        external_aad=ext_aad_enc,
                        key=sop.priv_key
                    )
                    LOGGER.debug('Signing with COSE key %s', repr(sop.priv_key))
                    msg_enc = msg_obj.encode(
                        tag=False
                    )
                    # detach payload
                    msg_dec = cbor2.loads(msg_enc)
                    msg_dec[2] = None

                else:
                    raise ValueError(f'Cannot sign with key having {sop.priv_key.key_ops}')

            msg_enc = cbor2.dumps(msg_dec)
            LOGGER.debug('Sending COSE message %s', encode_diagnostic(msg_dec))

            target_result.append(
                TypeValuePair(
                    type_code=msg_obj.cbor_tag,
                    value=msg_enc
                )
            )

        # One result per target
        bcb_data.setfieldval('results', [
            TargetResultList(results=[result])
            for result in target_result
        ])
        bcb.add_payload(bcb_data)
        ctr.add_block(bcb)

    def verify_bcb(self, ctr: BundleContainer, bcb: CanonicalBlock) -> Optional[int]:
        ''' Verify all targets in a single BCB based on local policy config.

        :return: An error code, or None if successful.
        '''
        secop = CoseSecOpCtx(ctr=ctr, sec_blk=bcb)
        if not secop.check_secblk():
            return StatusReport.ReasonCode.FAILED_SEC
        secop.extract_secblk()

        failure = None
        accept_ix = []
        for (tgt_ix, tgt_blk_num) in enumerate(bcb.payload.targets):
            tgt_blk = ctr.block_num(tgt_blk_num)
            result_list = bcb.payload.results[tgt_ix].results
            if len(result_list) != 1:
                LOGGER.error('Result array in BCB num %d does not have exactly one result', bcb.block_num)
                failure = StatusReport.ReasonCode.FAILED_SEC
            else:
                result = result_list[0]

                secop.tgt_blk = tgt_blk
                one_failure = self.verify_bcb_target(secop, result)
                if one_failure is not None:
                    failure = one_failure
                elif self._config.accept_after_verify:
                    LOGGER.debug('Accepting target block num %d after verification', tgt_blk_num)
                    accept_ix.append(tgt_ix)

        for tgt_ix in sorted(accept_ix, reverse=True):
            bcb.payload.targets.pop(tgt_ix)
            bcb.payload.results.pop(tgt_ix)
        if not bcb.payload.targets:
            LOGGER.debug('Removing empty BCB num %d', bcb.block_num)
            ctr.remove_block(bcb)

        return failure

    def verify_bcb_target(self, secop: CoseSecOpCtx, result: TypeValuePair) -> Optional[int]:
        ''' Verify a single BCB security operation on a single target.
        '''
        plaintext = None
        try:
            msg_obj = secop.decode_msg(result)

            if isinstance(msg_obj, Enc0Message):
                plaintext = self._verify_bcb_enc0(secop, msg_obj)

            elif isinstance(msg_obj, EncMessage):
                # Any one must be valid, but not all
                for r_ix, recip in enumerate(msg_obj.recipients):
                    plaintext = self._verify_bcb_enc(secop, msg_obj, recip)
                    if plaintext is None:
                        LOGGER.warning('Failed to verify COSE_Enc recipient %s with key k=%s', r_ix, msg_obj.key)
                    else:
                        # stop on first success
                        break

            else:
                raise TypeError(f'Unhandled message in {type(msg_obj)}')

        except Exception as err:
            LOGGER.error('Exception during verify of BCB num %d, target block num %d: %s', secop.sec_blk.block_num, secop.tgt_blk.block_num, err)
            LOGGER.debug('%s', traceback.format_exc())
            plaintext = None

        if plaintext is not None:
            LOGGER.info('Verified BCB num %d, target block num %d', secop.sec_blk.block_num, secop.tgt_blk.block_num)
            if self._config.accept_after_verify:
                secop.tgt_blk.setfieldval('btsd', plaintext)
            return None
        else:
            LOGGER.error('Failed to verify BCB num %d, target block num %d', secop.sec_blk.block_num, secop.tgt_blk.block_num)
            return StatusReport.ReasonCode.FAILED_SEC

    def _verify_bcb_enc0(self, secop: CoseSecOpCtx, msg_obj: Enc0Message) -> Optional[bytes]:
        ''' Verify a single result with a COSE_Enc0 '''
        for (key, val) in secop.addl_parsed.items():
            msg_obj.uhdr.setdefault(key, val)

        try:
            msg_obj.key = self._get_cose_key(secop.ctr, msg_obj, secop.sec_blk.payload.source)
            plaintext = msg_obj.decrypt()
            LOGGER.debug('Got plaintext %s', plaintext.hex())
            return plaintext
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Enc0: %s', err)
            LOGGER.debug('%s', traceback.format_exc())
            return None

    def _verify_bcb_enc(self, secop: CoseSecOpCtx, msg_obj: EncMessage, recip: CoseRecipient) -> Optional[bytes]:
        ''' Verify a single result with a COSE_Mac '''
        for (key, val) in secop.addl_parsed.items():
            recip.uhdr.setdefault(key, val)

        try:
            recip.key = self._get_cose_key(secop.ctr, recip, secop.sec_blk.payload.source)
            # ignore the plaintext
            plaintext = msg_obj.decrypt(recip)
            LOGGER.debug('Got plaintext %s', plaintext.hex())
            return plaintext
        except Exception as err:
            LOGGER.error('Failed to verify COSE_Enc recipient %s: %s', recip, err)
            LOGGER.debug('%s', traceback.format_exc())
            return None

    def _get_cose_key(self, ctr: BundleContainer, hdr_src: Union[CoseMessage, CoseRecipient, CoseSignature],
                      secsrc_eid: str) -> CoseKey:
        ''' Get a local COSE key associated with a specific COSE message and security source EID '''
        kid_item = hdr_src.get_attr(headers.KID)
        if kid_item:
            LOGGER.debug('Trying key based on KID %s with store containing %s', kid_item, self.sym_key_store.keys())
            if kid_item in self.sym_key_store:
                return self.sym_key_store.get(kid_item)
            LOGGER.error('Given kid parameter %s but no key found, falling through', kid_item)

        x5t_item = hdr_src.get_attr(headers.X5t)
        x5chain_item = hdr_src.get_attr(headers.X5chain)
        if x5t_item or x5chain_item:
            LOGGER.debug('Trying key based on x5t %s and x5chain %s', x5t_item, x5chain_item)
            # Look up cert chain to validate signature
            x5t = X5T.decode(x5t_item) if x5t_item else None

            if isinstance(x5chain_item, bytes):
                x5chain = [x5chain_item]
            else:
                x5chain = x5chain_item
            LOGGER.info('Validating X5t %s and X5chain length %d', x5t.encode() if x5t else None, len(x5chain) if x5chain else 0)

            bundle_at = DtnTimeField.dtntime_to_datetime(
                ctr.bundle.primary.create_ts.getfieldval('dtntime')
            )
            val_func = self.validate_chain_func(bundle_at)
            LOGGER.debug('Validating certificates at time %s', bundle_at)

            found_chain = None
            if x5t is None and x5chain:
                # Only one possible end-entity cert
                LOGGER.info('No X5T in header, assuming single chain')
                found_chain = x5chain
            else:
                LOGGER.debug('Attempting to find cert chain matching %s', x5t.encode())
                if x5chain and x5t.matches(x5chain[0]):
                    found_chain = x5chain
                else:
                    try:
                        found_chain = self.cert_store.find_chain(x5t.alg.identifier, x5t.thumbprint)
                    except Exception as err:
                        LOGGER.debug('No cert_store chain found matching %s: %s', x5t.encode(), err)

            if not found_chain:
                raise RuntimeError('Failed to find cert chain')

            LOGGER.debug('Validating chain with %d certs against %d CAs', len(found_chain), len(self._ca_certs))
            try:
                val_func(found_chain)
            except Exception as err:
                LOGGER.debug('%s', traceback.format_exc())
                raise RuntimeError(f'Failed to verify cert chain: {err}') from err

            # Ensure validated ones are present for next time
            for data in found_chain:
                self.cert_store.add_untrusted_cert(data)

            end_cert = x509.load_der_x509_certificate(found_chain[0], default_backend())
            authn_nodeid = tcpcl.session.match_id(secsrc_eid, end_cert, OID_ON_EID, LOGGER, 'NODE-ID')
            if authn_nodeid:
                return self.extract_cose_key(end_cert.public_key())
            # Continue on to verification
            LOGGER.error('Failed to authenticate peer identity "%s", falling through', secsrc_eid)

        raise RuntimeError('No parameter for key identity found')


@app('bpsec')
class Bpsec(AbstractApplication):
    ''' Bundle Protocol security.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config: Optional[Config] = None
        self._contexts: Dict[int, AbstractContext] = {
            BPSEC_COSE_CONTEXT_ID: CoseContext(),
        }

    def get_context(self, ctx_id) -> AbstractContext:
        ''' Get the handler for a specific context id.

        :param ctx_id: The ID to search for.
        :return: The context handler.
        :raise KeyError: If the context has no handler.
        '''
        return self._contexts[ctx_id]

    def load_config(self, config):
        self._config = config

        for ctx in self._contexts.values():
            ctx.load_config(config)

    def add_chains(self, rx_chain: List[ChainStep], tx_chain: List[ChainStep]):
        rx_chain.append(ChainStep(
            order=19,
            name='BPSec accept confidentiality',
            action=self._verify_bcb
        ))
        rx_chain.append(ChainStep(
            order=20,
            name='BPSec verify integrity',
            action=self._verify_bib
        ))

        tx_chain.append(ChainStep(
            order=10,
            name='BPSec apply integrity',
            action=self._apply_bib
        ))
        tx_chain.append(ChainStep(
            order=11,
            name='BPSec apply confidentiality',
            action=self._apply_bcb
        ))

    def _apply_bib(self, ctr: BundleContainer):
        ''' If configured add a BIB.
        The container must be reloaded beforehand.
        '''

        # No configuration here yet
        for ctx in self._contexts.values():
            ctx.apply_bib(ctr)

    def _apply_bcb(self, ctr: BundleContainer):
        ''' If configured add a BCB.
        The container must be reloaded beforehand.
        '''

        # No configuration here yet
        for ctx in self._contexts.values():
            ctx.apply_bcb(ctr)

    def _verify_bcb(self, ctr):
        ''' Check for and verify an BCBs.
        '''
        if 'deliver' not in ctr.actions:
            return

        # Report status reason
        failure = []

        confidential_blocks = ctr.block_type(BlockConfidentialityBlock)
        for bcb in confidential_blocks:
            LOGGER.debug('Verifying BCB in %d with context %s, targets %s',
                         bcb.block_num, bcb.payload.context_id, bcb.payload.targets)

            ctx = self._contexts.get(bcb.payload.context_id)
            if ctx is None:
                LOGGER.warning('Ignoring BCB with unknown security context ID %s', bcb.payload.context_id)
                result = StatusReport.ReasonCode.UNKNOWN_SEC
            else:
                try:
                    result = ctx.verify_bcb(ctr, bcb)
                except Exception as err:
                    result = f'Failed to verify BCB in block num {bcb.block_num} with context {bcb.payload.context_id}: {err}'

            if result is not None:
                failure.append(result)

        if failure:
            LOGGER.warning('Deleting bundle with BCB failure codes %s', failure)
            del ctr.actions['deliver']
            ctr.record_action('delete', max(failure))
            return True

        return None

    def _verify_bib(self, ctr: BundleContainer) -> bool:
        ''' Check for and verify any BIBs.
        '''
        if 'deliver' not in ctr.actions:
            return

        # Report status reason
        failure = []

        integ_blocks = ctr.block_type(BlockIntegrityBlock)
        for bib in integ_blocks:
            LOGGER.debug('Verifying BIB in %d with context %s, targets %s',
                         bib.block_num, bib.payload.context_id, bib.payload.targets)

            ctx = self._contexts.get(bib.payload.context_id)
            if ctx is None:
                LOGGER.warning('Ignoring BIB with unknown security context ID %s', bib.payload.context_id)
                result = StatusReport.ReasonCode.UNKNOWN_SEC
            else:
                try:
                    result = ctx.verify_bib(ctr, bib)
                except Exception as err:
                    result = f'Failed to verify BIB in block num {bib.block_num} with context {bib.payload.context_id}: {err}'
            if result is not None:
                failure.append(result)

        if failure:
            LOGGER.warning('Deleting bundle with BIB failure codes %s', failure)
            if 'deliver' in ctr.actions:
                del ctr.actions['deliver']
            ctr.record_action('delete', max(failure))
            return True

        return None
