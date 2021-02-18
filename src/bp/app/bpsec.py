''' Application layer adaptors.
'''
import cbor2
import logging
from certvalidator import CertificateValidator, ValidationContext
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from scapy_cbor.util import encode_diagnostic
import tcpcl.session
from bp.encoding import (
    DtnTimeField, Timestamp,
    Bundle, AbstractBlock, PrimaryBlock, CanonicalBlock,
    BlockIntegrityBlock, AbstractSecurityBlock, TypeValuePair, TargetResultList,
)
from bp.util import BundleContainer, ChainStep
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


@app('/org/ietf/dtn/bp/bpsec')
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
            order=-10,
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

    def _verify_bib(self, ctr):
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
