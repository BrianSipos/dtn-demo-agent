''' Test the module :py:mod:`bp.blocks`.
'''
import datetime
import unittest
import asn1
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from bp.encoding.fields import (EidField)
from bp.encoding.blocks import PrimaryBlock, CanonicalBlock
from bp.util import BundleContainer
from bp.encoding.bpsec import (TargetResultList, TypeValuePair,
                               BlockIntegrityBlock)
from bp.config import Config
from bp.agent import Agent
from bp.app.bpsec import Bpsec, BPSEC_COSE_CONTEXT_ID


class TestBpsecCoseSign(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        from dbus.mainloop.glib import DBusGMainLoop
        # Must run before connection or real main loop is constructed
        DBusGMainLoop(set_as_default=True)

    def setUp(self):
        super().setUp()

        config = Config()
        config.node_id = 'dtn://node/'
        self._bp = Agent(config)
        self._app = self._bp._app['bpsec']

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
        ca_key = ec.generate_private_key(ec.SECP256R1, backend=default_backend())
        ca_cert = self._dummy_ca_cert(ca_key)
        end_key = ec.generate_private_key(ec.SECP256R1, backend=default_backend())  # Curve for COSE ES256
        end_cert = self._dummy_end_cert(ca_key, ca_cert, end_key)

        ctx = self._app._contexts[BPSEC_COSE_CONTEXT_ID]
        ctx._ca_certs = [ca_cert]
        ctx._cert_chain = [end_cert]
        ctx._priv_key = end_key

        ctr = self._dummy_ctr()
        self._app._apply_bib(ctr)

        bibs = ctr.block_type(BlockIntegrityBlock)
        self.assertNotEqual([], bibs)
        bib = bibs[0]
        self.assertEqual([1], bib.payload.targets)

        ctr.record_action('deliver')
        self.assertFalse(self._app._verify_bib(ctr))
        self.assertEqual({'deliver'}, ctr.actions.keys())

    def test_apply_bib_rsa(self):
        ca_key = rsa.generate_private_key(0x10001, 1024, backend=default_backend())
        ca_cert = self._dummy_ca_cert(ca_key)
        end_key = rsa.generate_private_key(0x10001, 1024, backend=default_backend())
        end_cert = self._dummy_end_cert(ca_key, ca_cert, end_key)

        ctx = self._app._contexts[BPSEC_COSE_CONTEXT_ID]
        ctx._ca_certs = [ca_cert]
        ctx._cert_chain = [end_cert]
        ctx._priv_key = end_key

        ctr = self._dummy_ctr()
        self._app._apply_bib(ctr)

        bibs = ctr.block_type(BlockIntegrityBlock)
        self.assertNotEqual([], bibs)
        bib = bibs[0]
        self.assertEqual([1], bib.payload.targets)

        ctr.record_action('deliver')
        self.assertFalse(self._app._verify_bib(ctr))
        self.assertEqual({'deliver'}, ctr.actions.keys())
