''' Application layer adaptors.
'''
import cbor2
import logging
from certvalidator import CertificateValidator, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cose import headers
from cose.messages import Sign1Message
from cose import algorithms, curves
from cose.keys import (EC2Key, RSAKey)
from cose.exceptions import CoseIllegalCurve
from cose.extensions.x509 import X5T

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


@app('bpsec')
class Bpsec(AbstractApplication):
    ''' Bundle Protocol security.
    '''

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

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

    def _extract_cose_key(self, keyobj):
        ''' Get a COSE version of the local private key.
        :param keyobj: The cryptography key object.
        :return: The associated COSE key.
        :rtype: :py:cls:`CoseKey`
        '''
        if isinstance(keyobj, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            cose_key = RSAKey.from_cryptograpy_key_obj(keyobj)
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
                raise CoseIllegalCurve('Cannot match curve for {}'.format(repr(keyobj)))
            LOGGER.debug('Found COSE curve %s', curve_cls)

            try:
                alg_cls = CURVE_ALG_MAP[type(keyobj.curve)]
            except KeyError:
                raise CoseIllegalCurve('Cannot match algorithm for {}'.format(repr(keyobj)))
            LOGGER.debug('Found COSE algorithm %s', alg_cls)

            if hasattr(keyobj, 'private_numbers'):
                priv_nums = keyobj.private_numbers()
                pub_nums = keyobj.public_key().public_numbers()
            else:
                priv_nums = None
                pub_nums = keyobj.public_numbers()

            kwargs = {}
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

            cose_key = EC2Key(
                alg=alg_cls,
                curve=curve_cls,
                **kwargs
            )

        else:
            raise TypeError('Cannot handle key {}'.format(repr(keyobj)))

        return cose_key

    def _apply_bib(self, ctr):
        ''' If configured add a BIB.
        The container must be reloaded beforehand.
        '''
        if not self._priv_key:
            LOGGER.warning('No private key')
            return

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

        try:
            cose_key = self._extract_cose_key(self._priv_key)
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

            ext_aad_enc = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)
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

    def _verify_bib(self, ctr):
        ''' Check for and verify any BIBs.
        '''
        if 'deliver' not in ctr.actions:
            return

        # Report status reason
        failure = None

        integ_blocks = ctr.block_type(BlockIntegrityBlock)
        for bib in integ_blocks:
            LOGGER.debug('Verifying BIB in %d with context %s, targets %s',
                         bib.block_num, bib.payload.context_id, bib.payload.targets)
            if bib.payload.context_id == BPSEC_COSE_CONTEXT_ID:
                from cose.messages import CoseMessage

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
                    other_certs=[
                        cert.public_bytes(serialization.Encoding.DER)
                        for cert in self._cert_chain
                    ],
                    moment=bundle_at,
                )

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
                        msg_obj.external_aad = get_bpsec_cose_aad(ctr, target_blk, bib, aad_scope)

                        LOGGER.debug('Validating certificate at time %s', bundle_at)

                        try:
                            x5t = X5T.decode(msg_obj.uhdr[headers.X5t])
                        except KeyError:
                            x5t = None

                        if x5t is None and len(der_chains) == 1:
                            # Only one possible end-entity cert
                            LOGGER.warning('No X5T in header, assuming single chain')
                            found_chains = der_chains
                        else:
                            try:
                                found_chains = [
                                    chain for chain in der_chains
                                    if x5t.matches(chain[0])
                                ]
                                LOGGER.debug('Found %d chains matcing end-entity cert for %s', len(found_chains), encode_diagnostic(x5t.encode()))
                                if not found_chains:
                                    raise RuntimeError('No chain matcing end-entity cert for {}'.format(x5t.encode()))
                                if len(found_chains) > 1:
                                    raise RuntimeError('Multiple chains matcing end-entity cert for {}'.format(x5t.encode()))
                            except Exception as err:
                                LOGGER.error('Failed to find cert chain for block num %d: %s', blk_num, err)
                                failure = StatusReport.ReasonCode.FAILED_SEC
                                continue

                        try:
                            chain = found_chains[0]
                            LOGGER.debug('Validating chain with %d certs against %d CAs', len(chain), len(self._ca_certs))
                            val = CertificateValidator(
                                end_entity_cert=chain[0],
                                intermediate_certs=chain[1:],
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
                        end_cert = x509.load_der_x509_certificate(chain[0], default_backend())
                        authn_nodeid = tcpcl.session.match_id(peer_nodeid, end_cert, x509.UniformResourceIdentifier, LOGGER, 'NODE-ID')
                        if not authn_nodeid:
                            LOGGER.error('Failed to authenticate peer "%s" on block num %d', peer_nodeid, blk_num)
                            failure = StatusReport.ReasonCode.FAILED_SEC
                            # Continue on to verification

                        try:
                            msg_obj.key = self._extract_cose_key(end_cert.public_key())
                            msg_obj.verify_signature()
                            LOGGER.info('Verified signature on block num %d', blk_num)
                        except Exception as err:
                            LOGGER.error('Failed to verify signature on block num %d: %s', blk_num, err)
                            failure = StatusReport.ReasonCode.FAILED_SEC

        if failure is not None:
            del ctr.actions['deliver']
            ctr.record_action('delete', failure)
        return failure is not None
