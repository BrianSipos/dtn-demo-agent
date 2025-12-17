''' Test the module :py:mod:`bp.app.bpsec`.
'''
import datetime
import logging
import os
import re
import unittest
import asn1
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from pycose.keys import SymmetricKey
from bp.encoding.blocks import PrimaryBlock, CanonicalBlock
from bp.encoding.bundle import Bundle
from bp.util import BundleContainer
from bp.encoding.bpsec import (TargetResultList, TypeValuePair,
                               BlockIntegrityBlock, BlockConfidentalityBlock)
from bp.config import Config
from bp.agent import Agent
from bp.app.bpsec import SecAssociation, CoseContext, BPSEC_COSE_CONTEXT_ID

LOGGER = logging.getLogger()
SELFDIR = os.path.dirname(os.path.abspath(__file__))


class TestBpsecCoseSign(unittest.TestCase):

    @classmethod
    def setUpClass(cls)->None:
        super().setUpClass()

        from dbus.mainloop.glib import DBusGMainLoop
        # Must run before connection or real main loop is constructed
        cls.eloop = DBusGMainLoop(set_as_default=True)

    @classmethod
    def tearDownClass(cls)->None:
        cls.eloop = None

        super().tearDownClass()

    def setUp(self):
        super().setUp()

        config = Config()
        config.node_id = 'dtn://node/'
        self._bp = Agent(config)
        self._app = self._bp._app['bpsec']
        self.assertIsNotNone(self._app)

        self._ctx: CoseContext = self._app._contexts[BPSEC_COSE_CONTEXT_ID]
        self.assertIsNotNone(self._ctx)

    def _dummy_ca_cert(self, ca_key):
        ca_name = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'CA'),
        ])
        nowtime = datetime.datetime.now(datetime.timezone.utc)
        cert = x509.CertificateBuilder().subject_name(
            ca_name
        ).issuer_name(
            ca_name
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            nowtime
        ).not_valid_after(
            nowtime + datetime.timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())
        return cert

    def _dummy_end_cert(self, ca_key, ca_cert, end_key):
        nowtime = datetime.datetime.now(datetime.timezone.utc)
        eid_enc = asn1.Encoder()
        eid_enc.start()
        eid_enc.write(self._app._config.node_id.encode('ascii'), asn1.Numbers.IA5String)
        sans = [
            x509.OtherName(
                x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.8.11'),  # id-on-bundleEID
                eid_enc.output()
            )
        ]
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'end-entity'),
            ])
        ).issuer_name(
            ca_cert.issuer
        ).public_key(
            end_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            nowtime
        ).not_valid_after(
            nowtime + datetime.timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName(sans),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ObjectIdentifier('1.3.6.1.5.5.7.3.35')  # id-kp-bundleSecurity
            ]),
            critical=False,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(end_key.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        ).sign(ca_key, hashes.SHA256(), backend=default_backend())
        return cert

    def _dummy_ctr(self):
        ''' Generate a dummy bundle container.
        '''
        ctr = BundleContainer()
        ctr.bundle.primary = PrimaryBlock(
            destination="dtn://other/svc",
        )
        ctr.add_block(CanonicalBlock(
            type_code=1,
            btsd=b'hi',
        ))
        self._bp._apply_primary(ctr)
        return ctr

    def test_apply_bib_ec2(self):
        ca_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        ca_cert = self._dummy_ca_cert(ca_key)
        end_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())  # Curve for COSE ES256
        end_cert = self._dummy_end_cert(ca_key, ca_cert, end_key)

        self._ctx._ca_certs = [ca_cert]
        self._ctx._cert_chain = [end_cert]
        self._ctx._priv_key = end_key

        ctr = self._dummy_ctr()
        self._app._apply_bib(ctr)

        bib_set = ctr.block_type(BlockIntegrityBlock)
        self.assertEqual(1, len(bib_set))
        bib = bib_set[0]
        self.assertEqual([1], bib.payload.targets)
        self.assertEqual(BPSEC_COSE_CONTEXT_ID, bib.payload.context_id)

        result = self._ctx.verify_bib(ctr, bib)
        self.assertIsNone(result)

    def test_apply_bib_rsa(self):
        ca_key = rsa.generate_private_key(0x10001, 1024, backend=default_backend())
        ca_cert = self._dummy_ca_cert(ca_key)
        end_key = rsa.generate_private_key(0x10001, 1024, backend=default_backend())
        end_cert = self._dummy_end_cert(ca_key, ca_cert, end_key)

        self._ctx._ca_certs = [ca_cert]
        self._ctx._cert_chain = [end_cert]
        self._ctx._priv_key = end_key

        ctr = self._dummy_ctr()
        self._ctx.apply_bib(ctr)

        bib_set = ctr.block_type(BlockIntegrityBlock)
        self.assertEqual(1, len(bib_set))
        bib = bib_set[0]
        self.assertEqual([1], bib.payload.targets)
        self.assertEqual(BPSEC_COSE_CONTEXT_ID, bib.payload.context_id)

        result = self._ctx.verify_bib(ctr, bib)
        self.assertIsNone(result)

    def test_verify_bib_symmetric(self):
        with open(os.path.join(SELFDIR, 'data', 'key-ExampleA.5.cbor'), 'rb') as infile:
            cosekey = SymmetricKey.decode(infile.read())

        self._ctx.sym_key_store.clear()
        self._ctx.sym_key_store[cosekey.kid] = cosekey

        with open(os.path.join(SELFDIR, 'data', 'integrity.cbor'), 'rb') as infile:
            ctr = BundleContainer(bundle=Bundle(infile.read()))
            self.assertSetEqual(set(), ctr.bundle.check_all_crc())
        LOGGER.info('got %s', repr(ctr.bundle))

        bib_set = ctr.block_type(BlockIntegrityBlock)
        self.assertSetEqual({5}, set(bib.block_num for bib in bib_set))
        bib = bib_set[0]
        self.assertEqual(BPSEC_COSE_CONTEXT_ID, bib.payload.context_id)
        result = self._ctx.verify_bib(ctr, bib)
        self.assertIsNone(result)

    def test_verify_bcb_symmetric(self):
        with open(os.path.join(SELFDIR, 'data', 'key-ExampleA.5.cbor'), 'rb') as infile:
            cosekey = SymmetricKey.decode(infile.read())

        self._ctx.sym_key_store.clear()
        self._ctx.sym_key_store[cosekey.kid] = cosekey

        with open(os.path.join(SELFDIR, 'data', 'confidentiality.cbor'), 'rb') as infile:
            ctr = BundleContainer(bundle=Bundle(infile.read()))
            self.assertSetEqual(set(), ctr.bundle.check_all_crc())
        LOGGER.info('got %s', repr(ctr.bundle))

        bib_set = ctr.block_type(BlockConfidentalityBlock)
        self.assertSetEqual({5}, set(bib.block_num for bib in bib_set))
        bib = bib_set[0]
        self.assertEqual(BPSEC_COSE_CONTEXT_ID, bib.payload.context_id)
        result = self._ctx.verify_bcb(ctr, bib)
        self.assertIsNone(result)
