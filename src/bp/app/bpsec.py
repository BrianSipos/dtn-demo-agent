''' Application layer adaptors.
'''
from abc import ABC, abstractmethod
import cbor2
import logging
from certvalidator import CertificateValidator, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cose.messages import CoseMessage, Sign1Message
from cose import algorithms, headers
from cose.keys import curves, keyparam, EC2Key
try:
    from cose.keys import RSAKey
except ImportError:
    pass
from cose.exceptions import CoseUnsupportedCurve
from cose.extensions.x509 import X5T, X5Chain

from scapy_cbor.util import encode_diagnostic
import tcpcl.session
from bp.encoding import (
    DtnTimeField, Timestamp,
    AbstractBlock, PrimaryBlock, CanonicalBlock, StatusReport,
    BlockIntegrityBlock, AbstractSecurityBlock, TypeValuePair, TargetResultList,
)
from bp.util import ChainStep
from bp.app.base import app, AbstractApplication

LOGGER = logging.getLogger(__name__)

#: Dummy context ID value
BPSEC_COSE_CONTEXT_ID = 99


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


class CoseContext(AbstractContext):

    def __init__(self):
        super().__init__()

        self._config = None
        self._ca_certs = []
        self._cert_chain = []
        self._priv_key = None

    def load_config(self, config):
        self._config = config

        if config.verify_ca_file:
            with open(config.verify_ca_file, 'rb') as infile:
                self._ca_certs = load_pem_list(infile)

        if config.sign_cert_file:
            with open(config.sign_cert_file, 'rb') as infile:
                self._cert_chain = load_pem_list(infile)

        if config.sign_key_file:
            with open(config.sign_key_file, 'rb') as infile:
                self._priv_key = serialization.load_pem_private_key(infile.read(), None, default_backend())

    @staticmethod
    def get_bpsec_cose_aad(ctr, target, secblk, aad_scope, addl_protected):
        ''' Extract AAD from a bundle container.
        '''
        aad_struct = [
            ctr.bundle.primary.build() if aad_scope & 0x1 else None,
            target.build()[:3] if aad_scope & 0x2 else None,
            secblk.build()[:3] if aad_scope & 0x4 else None,
            addl_protected
        ]
        LOGGER.debug('AAD-structure %s', aad_struct)
        return cbor2.dumps(aad_struct)

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

    def apply_bib(self, ctr):
        if not self._priv_key:
            LOGGER.warning('No private key')
            return

        addl_protected_map = {}
        addl_unprotected = {}
        aad_scope = 0x3

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
            x5chain.append(cert.public_bytes(serialization.Encoding.DER))
        if self._config.integrity_include_chain:
            addl_protected_map[headers.X5chain.identifier] = X5Chain(x5chain).encode()

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
        # Inject optional additional headers
        addl_protected = cbor2.dumps(addl_protected_map) if addl_protected_map else b''
        if addl_protected:
            bib_data.parameters.append(
                TypeValuePair(type_code=3, value=addl_protected)
            )
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
        uhdr = {
            headers.X5t: X5T.from_certificate(algorithms.Sha256, x5chain[0]).encode(),
        }

        # Sign each target with one result per
        target_result = []
        for blk_num in bib_data.getfieldval('targets'):
            target_blk = ctr.block_num(blk_num)
            target_blk.ensure_block_type_specific_data()
            target_plaintext = target_blk.getfieldval('btsd')

            ext_aad_enc = CoseContext.get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope, addl_protected)
            LOGGER.debug('Signing target %d AAD %s payload %s',
                         blk_num, encode_diagnostic(ext_aad_enc),
                         encode_diagnostic(target_plaintext))
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
        addl_unprotected = {}
        aad_scope = 0x7
        for param in bib.payload.parameters:
            if param.type_code == 3:
                addl_protected = bytes(param.value)
            elif param.type_code == 4:
                addl_unprotected = dict(param.value)
            elif param.type_code == 5:
                aad_scope = int(param.value)

        addl_protected_map = cbor2.loads(addl_protected) if addl_protected else {}
        dupe_keys = set(addl_protected_map.keys()).intersection(set(addl_unprotected.keys()))
        if dupe_keys:
            LOGGER.warning('Duplicate keys in additional headers: %s', dupe_keys)
            return StatusReport.ReasonCode.FAILED_SEC
        addl_headers = dict(addl_protected_map)
        addl_headers.update(addl_unprotected)

        bundle_at = DtnTimeField.dtntime_to_datetime(
            ctr.bundle.primary.create_ts.getfieldval('dtntime')
        )
        val_ctx = ValidationContext(
            trust_roots=[
                cert.public_bytes(serialization.Encoding.DER)
                for cert in self._ca_certs
            ],
            other_certs=[
                cert.public_bytes(serialization.Encoding.DER)
                for cert in self._cert_chain
            ],
            moment=bundle_at,
        )
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

                msg_obj = msg_cls.from_cose_obj(msg_dec)
                msg_obj.external_aad = CoseContext.get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope, addl_protected)
                # use additional headers as defaults
                for (key, val) in msg_cls._parse_header(addl_headers).items():
                    msg_obj.uhdr.setdefault(key, val)
                LOGGER.info('full uhdr %s', msg_obj.uhdr)

                x5t_item = msg_obj.get_attr(headers.X5t)
                x5t = X5T.decode(x5t_item) if x5t_item else None

                x5chain_item = msg_obj.get_attr(headers.X5chain)
                if isinstance(x5chain_item, bytes):
                    x5chain = [x5chain_item]
                else:
                    x5chain = x5chain_item
                LOGGER.info('Validating X5t %s and X5chain length %d', x5t.encode() if x5t else None, len(x5chain) if x5chain else 0)

                if x5t is None and x5chain:
                    # Only one possible end-entity cert
                    LOGGER.warning('No X5T in header, assuming single chain')
                    found_chain = x5chain
                else:
                    try:
                        found_chain = x5chain if x5t.matches(x5chain[0]) else None
                        if not found_chain:
                            raise RuntimeError('No chain matcing end-entity cert for {}'.format(x5t.encode()))
                        LOGGER.debug('Found chain matcing end-entity cert for %s', x5t.encode())
                    except Exception as err:
                        LOGGER.error('Failed to find cert chain for block num %d: %s', blk_num, err)
                        failure = StatusReport.ReasonCode.FAILED_SEC
                        continue

                LOGGER.debug('Validating chain with %d certs against %d CAs', len(found_chain), len(self._ca_certs))
                try:
                    val = CertificateValidator(
                        end_entity_cert=found_chain[0],
                        intermediate_certs=found_chain[1:],
                        validation_context=val_ctx
                    )
                    val.validate_usage(
                        key_usage={'digital_signature'},
                        extended_key_usage={'1.3.6.1.5.5.7.3.35'},
                        extended_optional=True
                    )
                except Exception as err:
                    LOGGER.error('Failed to verify chain on block num %d: %s', blk_num, err)
                    failure = StatusReport.ReasonCode.FAILED_SEC
                    continue

                peer_nodeid = bib.payload.source
                end_cert = x509.load_der_x509_certificate(found_chain[0], default_backend())
                authn_nodeid = tcpcl.session.match_id(peer_nodeid, end_cert, x509.UniformResourceIdentifier, LOGGER, 'NODE-ID')
                if not authn_nodeid:
                    LOGGER.error('Failed to authenticate peer "%s" on block num %d', peer_nodeid, blk_num)
                    failure = StatusReport.ReasonCode.FAILED_SEC
                    # Continue on to verification

                try:
                    msg_obj.key = self.extract_cose_key(end_cert.public_key())
                    msg_obj.verify_signature()
                    LOGGER.info('Verified signature on block num %d', blk_num)
                except Exception as err:
                    LOGGER.error('Failed to verify signature on block num %d: %s', blk_num, err)
                    failure = StatusReport.ReasonCode.FAILED_SEC

        return failure


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

    def load_config(self, config):
        self._config = config

        for ctx in self._contexts.values():
            ctx.load_config(config)

    def add_chains(self, rx_chain, tx_chain):
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
                LOGGER.warning('Ignoring BIB with unknnown security context ID %s', bib.payload.context_id)
                result = StatusReport.ReasonCode.UNKNOWN_SEC
            else:
                result = ctx.verify_bib(ctr, bib)

            if result is not None:
                failure.append(result)

        if failure:
            LOGGER.warning('Deleting bundle with BIB failure codes %s', failure)
            del ctr.actions['deliver']
            ctr.record_action('delete', max(failure))
            return True

        return
