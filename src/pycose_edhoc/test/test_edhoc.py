''' Test the package :py:mod:`pycose_edhoc`.
'''
from binascii import unhexlify
import cbor2
import io
import logging
import unittest
from cryptography import x509
from pycose import algorithms
from pycose.keys import curves, keyparam, CoseKey, EC2Key, OKPKey
from typing import Tuple

from pycose_edhoc import (
    _bytes_compress,
    Method, CipherSuite, SUITES_BY_VALUE, EdhocInitiator, EdhocResponder,
    EadList, EadItem, CredStore, CredItem
)


LOGGER = logging.getLogger(__name__)


def seq_decoder(data: bytes):
    with io.BytesIO(data) as buf:
        dec = cbor2.CBORDecoder(buf)
        while True:
            try:
                yield dec.decode()
            except cbor2.CBORDecodeEOF:
                # cannot detect pre-EOF so will not catch not-well-formed data
                break


class TestUtils(unittest.TestCase):
    def test_bytes_compress(self):
        self.assertEqual(b'hi', _bytes_compress(b'hi'))
        self.assertEqual(3, _bytes_compress(b'\x03'))
        self.assertEqual(-14, _bytes_compress(b'\x2d'))


class TestEdhoc(unittest.TestCase):

    def _get_thumbprint(self, data: bytes) -> Tuple[int, bytes]:
        alg = algorithms.Sha256Trunc64

        return [
            alg.identifier,
            alg.compute_hash(data)
        ]

    def _check_msg1(self, msg, method: Method, suite: CipherSuite, conn_id: bytes):
        LOGGER.debug('Got msg data: %s', msg.hex())
        self.assertIsInstance(msg, bytes)
        items = list(seq_decoder(msg))
        LOGGER.debug('Got msg items: %s', items)
        self.assertIsInstance(items, list)
        self.assertLessEqual(4, len(items))

        self.assertEqual(method, items[0])
        # self.assertEqual(suite.value, items[1])
        self.assertIsInstance(items[2], bytes)
        self.assertEqual(suite.edhoc_ecdh_key_length, len(items[2]))
        self.assertEqual(conn_id, items[3])

    def _check_msg234(self, msg):
        LOGGER.debug('Got msg data: %s', msg.hex())
        self.assertIsInstance(msg, bytes)
        items = list(seq_decoder(msg))
        LOGGER.debug('Got msg items: %s', items)
        self.assertIsInstance(items, list)
        self.assertEqual(1, len(items))
        self.assertIsInstance(items[0], bytes)

    def test_method0_suite0_rfc9529(self):
        method = Method.SIGN_SIGN
        suite = SUITES_BY_VALUE[0]

        # Keys and expected messages from Section 2 of RFC 9529
        init_authn_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.Ed25519,
            keyparam.OKPKpD: unhexlify(
                '4c5b25878f507c6b9dae68fbd4fd3ff997533db0af00b25d324ea28e6c213bc8'
            ),
            keyparam.OKPKpX: unhexlify(
                'ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e'
            ),
        })
        init_authn_pub = OKPKey(
            crv=init_authn_priv.crv,
            x=init_authn_priv.x,
        )
        init_ke_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                '892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03'
            ),
            keyparam.OKPKpX: unhexlify(
                '31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04'
            ),
        })
        init_cred = CredItem(
            data=cbor2.dumps(unhexlify('3081ee3081a1a003020102020462319ea0300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323430305a170d3239313233313233303030305a30223120301e06035504030c174544484f4320496e69746961746f722045643235353139302a300506032b6570032100ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e300506032b6570034100521241d8b3a770996bcfc9b9ead4e7e0a1c0db353a3bdf2910b39275ae48b756015981850d27db6734e37f67212267dd05eeff27b9e7a813fa574b72a00b430b')),
            pubkey=init_authn_pub,
        )
        init_id_cred = {34: self._get_thumbprint(cbor2.loads(init_cred.data))}
        self.assertEqual([-15, unhexlify('c24ab2fd7643c79f')], init_id_cred[34])

        resp_authn_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.Ed25519,
            keyparam.OKPKpD: unhexlify(
                'ef140ff900b0ab03f0c08d879cbbd4b31ea71e6e7ee7ffcb7e7955777a332799'
            ),
            keyparam.OKPKpX: unhexlify(
                'a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359'
            ),
        })
        resp_authn_pub = OKPKey(
            crv=resp_authn_priv.crv,
            x=resp_authn_priv.x,
        )
        resp_ke_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                'e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8'
            ),
            keyparam.OKPKpX: unhexlify(
                'dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c'
            ),
        })
        resp_cred = CredItem(
            data=cbor2.dumps(unhexlify('3081ee3081a1a003020102020462319ec4300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323433365a170d3239313233313233303030305a30223120301e06035504030c174544484f4320526573706f6e6465722045643235353139302a300506032b6570032100a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359300506032b6570034100b723bc01eab0928e8b2b6c98de19cc3823d46e7d6987b032478fecfaf14537a1af14cc8be829c6b73044101837eb4abc949565d86dce51cfae52ab82c152cb02')),
            pubkey=resp_authn_pub,
        )
        resp_id_cred = {34: self._get_thumbprint(cbor2.loads(resp_cred.data))}
        self.assertEqual([-15, unhexlify('79f2a41b510c1f9b')], resp_id_cred[34])

        cred_store = CredStore()
        cred_store.add(init_id_cred, init_cred)
        cred_store.add(resp_id_cred, resp_cred)

        init = EdhocInitiator(
            authn_priv_key=init_authn_priv,
            ke_priv_key=init_ke_priv,
            method=method,
            suites=[suite],
            conn_id=b'\x2d',
            cred_store=cred_store,
            id_cred=init_id_cred,
        )
        resp = EdhocResponder(
            authn_priv_key=resp_authn_priv,
            ke_priv_key=resp_ke_priv,
            valid_methods=[method],
            valid_suites=[suite],
            conn_id=b'\x18',
            cred_store=cred_store,
            id_cred=resp_id_cred,
        )

        msg = init.get_message_1()
        self._check_msg1(msg, method, suite, -14)
        self.assertEqual(
            '0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d',
            msg.hex()
        )
        ead_out = resp.process_message_1(msg)
        self.assertEqual([], ead_out.items)

        msg = resp.get_message_2()
        self._check_msg234(msg)
        self.assertEqual(
            '5872dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1cbc26dd270fe9c02c44ce3934794b1cc62ba22f05459f8d358c8d12275ac42c5f96ded5f13cc9084e5b201889a45e5a60a5562dc118619c3daa2fd9f4c9f4d6edad109dd4edf95962aafbaf9ab3f4a1f6b98f',
            msg.hex()
        )
        ead_out = init.process_message_2(msg)
        self.assertEqual([], ead_out.items)

        msg = init.get_message_3()
        self._check_msg234(msg)
        self.assertEqual(
            '585825c345884aaaeb22c527f9b1d2b6787207e0163c69b62a0d43928150427203c31674e4514ea6e383b566eb29763efeb0afa518776ae1c65f856d84bf32af3a7836970466dcb71f76745d39d3025e7703e0c032ebad51947c',
            msg.hex()
        )
        ead_out = resp.process_message_3(msg)
        self.assertEqual([], ead_out.items)

        msg = resp.get_message_4()
        self._check_msg234(msg)
        self.assertEqual(
            '484f0edee366e5c883',
            msg.hex()
        )
        ead_out = init.process_message_4(msg)
        self.assertEqual([], ead_out.items)

        # internal final derived value
        expect_prk_exporter = '2aaec8fc4ab3bc3295def6b551051a2fa561424db301fa84f642f5578a6df51a'
        self.assertEqual(
            expect_prk_exporter,
            init.get_prk_exporter().hex()
        )
        self.assertEqual(
            expect_prk_exporter,
            resp.get_prk_exporter().hex()
        )

        # application side PRK
        self.assertEqual(
            '1e1c6beac3a8a1cac435de7e2f9ae7ff',
            init.edhoc_exporter(0, b'', 16).hex()
        )

    def test_method3_suite2_rfc9529(self):
        method = Method.DH_DH
        suite = SUITES_BY_VALUE[2]

        # Keys and expected messages from Section 3 of RFC 9529
        init_authn_priv = EC2Key.from_dict({
            keyparam.EC2KpCurve: curves.P256,
            keyparam.EC2KpD: unhexlify(
                'fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b'
            ),
            keyparam.EC2KpX: unhexlify(
                'ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6'
            ),
            keyparam.EC2KpY: unhexlify(
                '6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8'
            ),
        })
        init_authn_pub = EC2Key(
            crv=init_authn_priv.crv,
            x=init_authn_priv.x,
            y=init_authn_priv.y,
        )
        init_ke_priv = EC2Key.from_dict({
            keyparam.EC2KpCurve: curves.P256,
            keyparam.EC2KpD: unhexlify(
                '368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525'
            ),
            keyparam.EC2KpX: unhexlify(
                '8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6'
            ),
            keyparam.EC2KpY: unhexlify(
                '51e8af6c6edb781601ad1d9c5fa8bf7aa15716c7c06a5d038503c614ff80c9b3'
            ),
        })
        init_cred = CredItem(
            data=unhexlify('a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8'),
            pubkey=init_authn_pub
        )
        init_id_cred = {4: unhexlify('2b')}

        resp_authn_priv = EC2Key.from_dict({
            keyparam.EC2KpCurve: curves.P256,
            keyparam.EC2KpD: unhexlify(
                '72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac'
            ),
            keyparam.EC2KpX: unhexlify(
                'bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0'
            ),
            keyparam.EC2KpY: unhexlify(
                '4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072'
            ),
        })
        resp_authn_pub = EC2Key(
            crv=resp_authn_priv.crv,
            x=resp_authn_priv.x,
            y=resp_authn_priv.y,
        )
        resp_ke_priv = EC2Key.from_dict({
            keyparam.EC2KpCurve: curves.P256,
            keyparam.EC2KpD: unhexlify(
                'e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418'
            ),
            keyparam.EC2KpX: unhexlify(
                '419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5'
            ),
            keyparam.EC2KpY: unhexlify(
                '5e4f0dd8a3da0baa16b9d3ad56a0c1860a940af85914915e25019b402417e99d'
            ),
        })
        resp_cred = CredItem(
            data=unhexlify('a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072'),
            pubkey=resp_authn_pub
        )
        resp_id_cred = {4: unhexlify('32')}

        cred_store = CredStore()
        cred_store.add(init_id_cred, init_cred)
        cred_store.add(resp_id_cred, resp_cred)

        init = EdhocInitiator(
            authn_priv_key=init_authn_priv,
            ke_priv_key=init_ke_priv,
            method=method,
            suites=[6, 2],
            conn_id=b'\x37',
            cred_store=cred_store,
            id_cred=init_id_cred,
        )
        resp = EdhocResponder(
            authn_priv_key=resp_authn_priv,
            ke_priv_key=resp_ke_priv,
            valid_methods=[method],
            valid_suites=[2],
            conn_id=b'\x27',
            cred_store=cred_store,
            id_cred=resp_id_cred,
        )

        msg = init.get_message_1()
        self._check_msg1(msg, method, suite, -24)
        self.assertEqual(
            '0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637',
            msg.hex()
        )
        ead_out = resp.process_message_1(msg)
        self.assertEqual([], ead_out.items)

        msg = resp.get_message_2()
        self._check_msg234(msg)
        self.assertEqual(
            '582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd',
            msg.hex()
        )
        ead_out = init.process_message_2(msg)
        self.assertEqual([], ead_out.items)

        msg = init.get_message_3()
        self._check_msg234(msg)
        self.assertEqual(
            '52e562097bc417dd5919485ac7891ffd90a9fc',
            msg.hex()
        )
        ead_out = resp.process_message_3(msg)
        self.assertEqual([], ead_out.items)

        msg = resp.get_message_4()
        self._check_msg234(msg)
        self.assertEqual(
            '4828c966b7ca304f83',
            msg.hex()
        )
        ead_out = init.process_message_4(msg)
        self.assertEqual([], ead_out.items)

        # internal final derived value
        expect_prk_exporter = 'e14d06699cee248c5a04bf9227bbcd4ce394de7dcb56db43555474171e6446db'
        self.assertEqual(
            expect_prk_exporter,
            init.get_prk_exporter().hex()
        )
        self.assertEqual(
            expect_prk_exporter,
            resp.get_prk_exporter().hex()
        )

        # application side PRK
        self.assertEqual(
            'f9868f6a3aca78a05d1485b35030b162',
            init.edhoc_exporter(0, b'', 16).hex()
        )

    def _generate_keys(self, method: Method, suite: CipherSuite, as_initiator: bool) -> Tuple[CoseKey, CoseKey]:
        SIGN_OKP = {
            algorithms.EdDSA: curves.Ed25519,
        }
        SIGN_EC2 = {
            algorithms.Es256: curves.P256,
            algorithms.Es384: curves.P384,
        }
        KE_OKP = {
            curves.X25519,
            curves.X448,
        }
        KE_EC2 = {
            curves.P256,
            curves.P384,
        }

        if as_initiator:
            sign_methods = {Method.SIGN_SIGN, Method.SIGN_DH}
        else:
            sign_methods = {Method.SIGN_SIGN, Method.DH_SIGN}

        if method in sign_methods:
            # signature authentication
            if suite.edhoc_sign in SIGN_OKP:
                curve = SIGN_OKP[suite.edhoc_sign]
                priv = OKPKey.generate_key(curve)
                pub = OKPKey(
                    crv=priv.crv,
                    x=priv.x,
                )
            elif suite.edhoc_sign in SIGN_EC2:
                curve = SIGN_EC2[suite.edhoc_sign]
                priv = EC2Key.generate_key(curve)
                pub = EC2Key(
                    crv=priv.crv,
                    x=priv.x,
                    y=priv.y,
                )
            else:
                raise NotImplementedError(f'signature type {suite.edhoc_sign}')

        else:
            # DH authentication
            if suite.edhoc_ke in KE_OKP:
                priv = OKPKey.generate_key(suite.edhoc_ke)
                pub = OKPKey(
                    crv=priv.crv,
                    x=priv.x,
                )
            elif suite.edhoc_ke in KE_EC2:
                priv = EC2Key.generate_key(suite.edhoc_ke)
                pub = EC2Key(
                    crv=priv.crv,
                    x=priv.x,
                    y=priv.y,
                )
            else:
                raise NotImplementedError(f'key exchange type {suite.edhoc_ke}')

        return (priv, pub)

    def test_methods_suites_seq_normal(self):
        for method in Method:
            for value, suite in SUITES_BY_VALUE.items():
                with self.subTest(method=method, suite=value):

                    init_priv, init_pub = self._generate_keys(method, suite, True)
                    init_id_cred = {34: [-15, unhexlify('deadbeef')]}
                    resp_priv, resp_pub = self._generate_keys(method, suite, False)
                    resp_id_cred = {34: [-15, unhexlify('0badf00d')]}

                    cred_store = CredStore()
                    cred_store.add(init_id_cred, CredItem(
                        data=cbor2.dumps(b'hello'),
                        pubkey=init_pub
                    ))
                    cred_store.add(resp_id_cred, CredItem(
                        data=cbor2.dumps(b'there'),
                        pubkey=resp_pub
                    ))

                    init = EdhocInitiator(
                        authn_priv_key=init_priv,
                        method=method,
                        suites=[suite],
                        conn_id=b'hihi',
                        cred_store=cred_store,
                        id_cred=init_id_cred,
                    )
                    resp = EdhocResponder(
                        authn_priv_key=resp_priv,
                        valid_methods=[method],
                        valid_suites=[suite],
                        conn_id=b'hoho',
                        cred_store=cred_store,
                        id_cred=resp_id_cred,
                    )

                    msg = init.get_message_1()
                    self._check_msg1(msg, method, suite, b'hihi')
                    resp.process_message_1(msg)

                    ead_in = EadList(items=[EadItem(65535, b'hello')])
                    msg = resp.get_message_2(ead_in)
                    self._check_msg234(msg)
                    ead_out = init.process_message_2(msg)
                    self.assertEqual(ead_in, ead_out)

                    ead_in = EadList(items=[EadItem(65534, b'hi')])
                    msg = init.get_message_3(ead_in)
                    self._check_msg234(msg)
                    ead_out = resp.process_message_3(msg)
                    self.assertEqual(ead_in, ead_out)

                    self.assertEqual(
                        init.get_prk_exporter().hex(),
                        resp.get_prk_exporter().hex()
                    )
