''' Application layer adaptors.
'''
from abc import ABC, abstractmethod
import cbor2
import datetime
import enum
import logging
from typing import Tuple
from certvalidator import CertificateValidator, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pycose.messages import CoseMessage, Sign1Message
from pycose import algorithms, headers
from pycose.keys import curves, keyparam, EC2Key, RSAKey, CoseKey
from pycose.exceptions import CoseUnsupportedCurve
from pycose.extensions.x509 import X5T, X5Chain
from pycose.algorithms import CoseAlgorithm

from scapy_cbor.util import encode_diagnostic
import tcpcl.session
from bp.encoding import (
    DtnTimeField, Timestamp,
    AbstractBlock, PrimaryBlock, CanonicalBlock, StatusReport,
    BlockIntegrityBlock, BlockConfidentalityBlock, AbstractSecurityBlock,
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
    def load_config(self, config):
        raise NotImplementedError()

    @abstractmethod
    def apply_bib(self, ctr):
        ''' Attempt to apply a BIB to a bundle.

        :param ctr: The entire bundle container.
        :type ctr: :py:cls:`BundleContainer`
        '''
        raise NotImplementedError()

    @abstractmethod
    def verify_bib(self, ctr, bib):
        ''' Verify a BIB for this context.

        :param ctr: The entire bundle container.
        :type ctr: :py:cls:`BundleContainer`
        :param bib: The specific BIB to verify.
        :type bib: :py:cls:`CanonicalBlock`
        :return: A non-None status value if failed.
        '''
        raise NotImplementedError()


class CertificateStore:
    ''' Logic for managing certificate bags. '''

    def __init__(self):
        # Map from DER to decoded Certificate
        self._certs_by_der = dict()
        # self._certs_tprint = dict()
        self._certs_by_ski = dict()

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
        return chain


class CoseContext(AbstractContext):

    @enum.unique
    class AadScopeFlag(enum.IntFlag):
        METADATA = 0x01
        BTSD = 0x02

    def __init__(self):
        super().__init__()

        self._config = None
        self._ca_certs = []
        self._cert_chain = []
        self._priv_key = None
        self.cert_store = CertificateStore()

    def load_config(self, config):
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
                self._priv_key = load_pem_key(infile)

    @staticmethod
    def get_bpsec_cose_aad(ctr: BundleContainer, target, secblk: CanonicalBlock, aad_scope: dict, addl_protected: bytes) -> bytes:
        ''' Extract AAD from a bundle container per Section 2.5.1 of draft-ietf-bpsec-cose
        '''
        aad_list = []
        aad_list.append(aad_scope)

        # processing order by block number
        for blk_num, flags in sorted(aad_scope.items()):

            if blk_num in (0, -2, secblk.block_num) and flags & CoseContext.AadScopeFlag.BTSD:
                LOGGER.error(f'Invalid AAD Scope flags for block {blk_num}')

            if blk_num == -1:
                blk = target
            elif blk_num == -2 or blk_num == secblk.block_num:
                # security block is not yet part of the bundle
                blk = secblk
            elif blk_num == 0:
                blk = ctr.bundle.primary
            else:
                blk = ctr.block_num(blk_num)
            is_primary = isinstance(blk, PrimaryBlock)

            if is_primary:
                if flags & CoseContext.AadScopeFlag.METADATA:
                    blk.update_crc()
                    aad_list.append(blk.build())

            else:
                if flags & CoseContext.AadScopeFlag.METADATA:
                    # block metadata not in array framing
                    aad_list += blk.build()[:3]
                if flags & CoseContext.AadScopeFlag.BTSD:
                    aad_list.append(blk.btsd)

        aad_list.append(addl_protected)

        LOGGER.debug('AAD-structure %s', aad_list)
        return b''.join(cbor2.dumps(item) for item in aad_list)

    @staticmethod
    def extract_cose_key(keyobj):
        ''' Get a COSE version of the local private key.
        :param keyobj: The cryptography key object.
        :return: The associated COSE key.
        :rtype: :py:cls:`CoseKey`
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
            cose_key.alg = algorithms.Ps256

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

    def validate_chain_func(self, time_at: datetime.datetime) -> callable:
        ''' Get a function to validate a certificate chain.

        :param time_at: The time to validate at.
        :return: A callable which takes an x5chain of certificates
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

        def validate(chain):
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

    def apply_bib(self, ctr):
        if not self._priv_key:
            LOGGER.warning('No private key')
            return

        addl_protected_map = {}
        addl_unprotected_map = {}
        aad_scope = {0: 1, 1: 1}  # primary and target metadata

        target_block_nums = [
            blk.block_num
            for blk in ctr.bundle.blocks
            if blk.type_code in self._config.integrity_for_blocks
        ]
        if not target_block_nums:
            LOGGER.warning('No target blocks have matching type')
            return

        x5chain = []
        for cert in self._cert_chain:
            x5chain.append(encode_der_cert(cert))

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

        # identity in additional headers
        if self._config.integrity_include_chain:
            addl_unprotected_map[headers.X5chain.identifier] = X5Chain(x5chain).encode()
        else:
            addl_unprotected_map[headers.X5t.identifier] = X5T.from_certificate(algorithms.Sha256, x5chain[0]).encode()

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

        try:
            cose_key = self.extract_cose_key(self._priv_key)
        except Exception as err:
            LOGGER.error('Cannot handle private key: %s', repr(err))
            return

        phdr = {
            headers.Algorithm: cose_key.alg,
        }
        uhdr = {}

        # Sign each target with one result per
        target_result = []
        for blk_num in bib_data.getfieldval('targets'):
            target_blk = ctr.block_num(blk_num)
            target_blk.ensure_block_type_specific_data()
            target_plaintext = target_blk.getfieldval('btsd')

            ext_aad_enc = CoseContext.get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope, addl_protected)
            # LOGGER.debug('Signing target %d AAD %s payload %s',
            #              blk_num, encode_diagnostic(ext_aad_enc),
            #              encode_diagnostic(target_plaintext))
            msg_obj = Sign1Message(
                phdr=phdr,
                uhdr=uhdr,
                payload=target_plaintext,
                # Non-encoded parameters
                external_aad=ext_aad_enc,
                key=cose_key
            )
            LOGGER.debug('Signing with COSE key %s', repr(cose_key))
            msg_enc = msg_obj.encode(
                tag=False
            )
            # detach payload
            msg_dec = cbor2.loads(msg_enc)
            msg_dec[2] = None
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

    def verify_bib(self, ctr, bib):
        addl_protected = b''
        addl_unprotected = b''
        aad_scope = {0: 1, -1: 1, -2: 1}
        for param in bib.payload.parameters:
            if param.type_code == 3:
                addl_protected = bytes(param.value)
            elif param.type_code == 4:
                addl_unprotected = bytes(param.value)
            elif param.type_code == 5:
                aad_scope = dict(param.value)

        addl_protected_map = cbor2.loads(addl_protected) if addl_protected else {}
        addl_unprotected_map = cbor2.loads(addl_unprotected) if addl_unprotected else {}
        dupe_keys = set(addl_protected_map.keys()).intersection(set(addl_unprotected_map.keys()))
        if dupe_keys:
            LOGGER.warning('Duplicate keys in additional headers: %s', dupe_keys)
            return StatusReport.ReasonCode.FAILED_SEC
        addl_headers = dict(addl_protected_map)
        addl_headers.update(addl_unprotected_map)

        bundle_at = DtnTimeField.dtntime_to_datetime(
            ctr.bundle.primary.create_ts.getfieldval('dtntime')
        )
        val_func = self.validate_chain_func(bundle_at)
        LOGGER.debug('Validating certificates at time %s', bundle_at)

        failure = None
        for (ix, blk_num) in enumerate(bib.payload.targets):
            target_blk = ctr.block_num(blk_num)
            for result in bib.payload.results[ix].results:
                msg_cls = CoseMessage._COSE_MSG_ID[result.type_code]

                # replace detached payload
                msg_enc = bytes(result.getfieldval('value'))
                msg_dec = cbor2.loads(msg_enc)
                LOGGER.debug('Received COSE message\n%s', encode_diagnostic(msg_dec))
                msg_dec[2] = target_blk.getfieldval('btsd')

                msg_obj = msg_cls.from_cose_obj(msg_dec, allow_unknown_attributes=False)
                msg_obj.external_aad = CoseContext.get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope, addl_protected)
                # use additional headers as defaults
                for (key, val) in msg_cls._parse_header(addl_headers, allow_unknown_attributes=False).items():
                    msg_obj.uhdr.setdefault(key, val)

                x5t_item = msg_obj.get_attr(headers.X5t)
                x5t = X5T.decode(x5t_item) if x5t_item else None

                x5chain_item = msg_obj.get_attr(headers.X5chain)
                if isinstance(x5chain_item, bytes):
                    x5chain = [x5chain_item]
                else:
                    x5chain = x5chain_item
                LOGGER.info('Validating X5t %s and X5chain length %d', x5t.encode() if x5t else None, len(x5chain) if x5chain else 0)

                found_chain = None
                if x5t is None and x5chain:
                    # Only one possible end-entity cert
                    LOGGER.warning('No X5T in header, assuming single chain')
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
                    LOGGER.error('Failed to find cert chain for block num %d', blk_num)
                    failure = StatusReport.ReasonCode.FAILED_SEC
                    continue

                LOGGER.debug('Validating chain with %d certs against %d CAs', len(found_chain), len(self._ca_certs))
                try:
                    val_func(found_chain)
                except Exception as err:
                    LOGGER.error('Failed to verify chain on block num %d: %s', blk_num, err)
                    failure = StatusReport.ReasonCode.FAILED_SEC
                    continue

                # Ensure validated ones are present for next time
                for data in found_chain:
                    self.cert_store.add_untrusted_cert(data)

                peer_nodeid = bib.payload.source
                end_cert = x509.load_der_x509_certificate(found_chain[0], default_backend())
                authn_nodeid = tcpcl.session.match_id(peer_nodeid, end_cert, OID_ON_EID, LOGGER, 'NODE-ID')
                if not authn_nodeid:
                    LOGGER.error('Failed to authenticate peer "%s" on block num %d', peer_nodeid, blk_num)
                    failure = StatusReport.ReasonCode.FAILED_SEC
                    # Continue on to verification

                try:
                    msg_obj.key = self.extract_cose_key(end_cert.public_key())
                    valid = msg_obj.verify_signature()
                except Exception as err:
                    valid = False
                    LOGGER.error('Failed to verify signature on block num %d: %s', blk_num, err)
                    failure = StatusReport.ReasonCode.FAILED_SEC

                if valid:
                    LOGGER.info('Verified BIB target block num %d', blk_num)
                else:
                    LOGGER.error('Failed to verify BIB target block num %d', blk_num)

        return failure

    def verify_bcb(self, ctr, bcb):
        raise NotImplementedError('no BCB handling')


@app('bpsec')
class Bpsec(AbstractApplication):
    ''' Bundle Protocol security.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._config = None
        self._contexts = {
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

    def add_chains(self, rx_chain, tx_chain):
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

    def _apply_bib(self, ctr):
        ''' If configured add a BIB.
        The container must be reloaded beforehand.
        '''

        # No configuration here yet
        for ctx in self._contexts.values():
            ctx.apply_bib(ctr)

    def _verify_bcb(self, ctr):
        ''' Check for and verify an BCBs.
        '''
        if 'deliver' not in ctr.actions:
            return

        # Report status reason
        failure = []

        confidential_blocks = ctr.block_type(BlockConfidentalityBlock)
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

    def _verify_bib(self, ctr):
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
