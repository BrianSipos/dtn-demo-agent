''' Test the package :py:mod:`pycose_edhoc`.
'''
from binascii import unhexlify
import cbor2
from dataclasses import dataclass
from gi.repository import GLib
import logging
import unittest
from pycose import algorithms
from pycose.keys import curves, keyparam, CoseKey, EC2Key, OKPKey
import queue
import random
from typing import Tuple

from pycose_edhoc import (
    Method, CipherSuite, SUITES_BY_VALUE,
    CredStore, CredItem
)
from bp.safe_info import (
    SafeEntity
)


LOGGER = logging.getLogger(__name__)


@dataclass
class Transfer:
    ''' A queued and logged PDU transfer '''
    src: str
    dst: str
    pdu: bytes


class TestBpSafe(unittest.TestCase):

    def setUp(self):
        self._eloop = GLib.MainLoop()
        self._endpoints = {}
        self._pdu_ix = 0
        # log, in order, of all seen :py:cls:`Transfer`
        self._log = queue.Queue()

        random.seed(b'TestBpSafe')

    def tearDown(self):
        self._send = {}
        self._eloop = None

    def _get_thumbprint(self, data: bytes) -> Tuple[int, bytes]:
        alg = algorithms.Sha256Trunc64

        return [
            alg.identifier,
            alg.compute_hash(data)
        ]

    def _add_endpoint(self, eid: str, safe: SafeEntity):
        self.assertFalse(eid in self._endpoints)
        self._endpoints[eid] = safe

        safe.own_eid = eid
        safe.send_pdu = lambda pdu, dst: self._send_pdu(pdu=pdu, src=eid, dst=dst)

    def _send_pdu(self, pdu: bytes, src: str, dst: str):
        xfer = Transfer(src=src, dst=dst, pdu=pdu)
        self._pdu_ix += 1
        LOGGER.info('PDU #%d src %s dst %s data %s', self._pdu_ix,
                    xfer.src, xfer.dst, xfer.pdu.hex())

        self._log.put(xfer)
        self._eloop.quit()
        # actual delivery
        self._endpoints[dst].recv_pdu(xfer.pdu, xfer.src)

    def _wait_xfer(self, timeout=1) -> bytes:
        GLib.timeout_add_seconds(timeout, lambda: self._eloop.quit())
        self._eloop.run()
        return self._log.get(False)

    def test_method0_suite24_with_ead(self):
        self.skipTest('need to troubleshoot CI')
        method = Method.SIGN_SIGN
        suite = SUITES_BY_VALUE[6]

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
        init_ke_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                '892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03'
            ),
            keyparam.OKPKpX: unhexlify(
                '31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04'
            ),
        })
        init_ke_priv_sa2 = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                '892ec28e5cb6669108470539500b705e60d008d347c5817ee9f3327c8a87bb03'
            ),
            keyparam.OKPKpX: unhexlify(
                '31f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f04'
            ),
        })
        # TBD replace
        init_cred = CredItem(
            data=cbor2.dumps(unhexlify('3081ee3081a1a003020102020462319ea0300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323430305a170d3239313233313233303030305a30223120301e06035504030c174544484f4320496e69746961746f722045643235353139302a300506032b6570032100ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f23d8cc20b73085141e300506032b6570034100521241d8b3a770996bcfc9b9ead4e7e0a1c0db353a3bdf2910b39275ae48b756015981850d27db6734e37f67212267dd05eeff27b9e7a813fa574b72a00b430b')),
            pubkey=init_authn_pub,
        )
        init_id_cred = {34: self._get_thumbprint(cbor2.loads(init_cred.data))}

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
        resp_ke_priv = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                'e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8'
            ),
            keyparam.OKPKpX: unhexlify(
                'dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c'
            ),
        })
        resp_ke_priv_sa2 = OKPKey.from_dict({
            keyparam.OKPKpCurve: curves.X25519,
            keyparam.OKPKpD: unhexlify(
                'e69c23fbf81bc435942446837fe827bf206c8fa10a39db47449e5a813421e1e8'
            ),
            keyparam.OKPKpX: unhexlify(
                'dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c'
            ),
        })
        # TBD replace
        resp_cred = CredItem(
            data=cbor2.dumps(unhexlify('3081ee3081a1a003020102020462319ec4300506032b6570301d311b301906035504030c124544484f4320526f6f742045643235353139301e170d3232303331363038323433365a170d3239313233313233303030305a30223120301e06035504030c174544484f4320526573706f6e6465722045643235353139302a300506032b6570032100a1db47b95184854ad12a0c1a354e418aace33aa0f2c662c00b3ac55de92f9359300506032b6570034100b723bc01eab0928e8b2b6c98de19cc3823d46e7d6987b032478fecfaf14537a1af14cc8be829c6b73044101837eb4abc949565d86dce51cfae52ab82c152cb02')),
            pubkey=resp_authn_pub,
        )
        resp_id_cred = {34: self._get_thumbprint(cbor2.loads(resp_cred.data))}

        cred_store = CredStore()
        cred_store.add(init_id_cred, init_cred)
        cred_store.add(resp_id_cred, resp_cred)

        safe1 = SafeEntity(
            send_pdu=None,  # set in _add_endpoint
            method=method,
            suite=suite,
            authn_priv_key=init_authn_priv,
            ke_priv_key=[init_ke_priv, init_ke_priv_sa2],
            conn_id=b'\x2d',
            cred_store=cred_store,
            id_cred=init_id_cred,
        )
        self._add_endpoint('urn:safe1', safe1)
        safe2 = SafeEntity(
            send_pdu=None,  # set in _add_endpoint
            method=method,
            suite=suite,
            authn_priv_key=resp_authn_priv,
            ke_priv_key=[resp_ke_priv, resp_ke_priv_sa2],
            conn_id=b'\x18',
            cred_store=cred_store,
            id_cred=resp_id_cred,
        )
        self._add_endpoint('urn:safe2', safe2)

        safe1.start('urn:safe2')

        # expected sequence
        for _ix in range(5):
            xfer = self._wait_xfer()

        # no more transfers
        with self.assertRaises(queue.Empty):
            self._wait_xfer(timeout=0.2)

        psas1 = safe1.get_primary_sas()
        psas2 = safe2.get_primary_sas()
        self.assertEqual(len(psas1), len(psas2))
        for sa1, sa2 in zip(psas1, psas2):
            self.assertEqual(sa1.local_sai, sa2.peer_sai)
            self.assertEqual(sa1.peer_sai, sa2.local_sai)

            self.assertEqual(sa1.prk_sa1, sa2.prk_sa1)
            self._compare_cose_keys(sa1.tx_use.key, sa2.rx_use.key)
            self._compare_cose_keys(sa1.rx_use.key, sa2.tx_use.key)

            # only one post-IA PDU
            self.assertEqual(1, sa1.tx_use.op_count)
            self.assertEqual(3, sa1.tx_use.bytes_count)
            self.assertEqual(0, sa1.rx_use.op_count)
            self.assertEqual(0, sa1.rx_use.bytes_count)
            self.assertEqual(0, sa2.tx_use.op_count)
            self.assertEqual(0, sa2.tx_use.bytes_count)
            self.assertEqual(1, sa2.rx_use.op_count)
            self.assertEqual(3, sa2.rx_use.bytes_count)

        ssas1 = safe1.get_secondary_sas()
        ssas2 = safe2.get_secondary_sas()
        self.assertEqual(len(ssas1), len(ssas2))
        for sa1, sa2 in zip(ssas1, ssas2):
            self.assertEqual(sa1.local_sai, sa2.peer_sai)
            self.assertEqual(sa1.peer_sai, sa2.local_sai)

            self._compare_cose_keys(sa1.tx_use.key, sa2.rx_use.key)
            self._compare_cose_keys(sa1.rx_use.key, sa2.tx_use.key)

            self.assertEqual(0, sa1.tx_use.op_count)
            self.assertEqual(0, sa1.rx_use.op_count)
            self.assertEqual(0, sa2.tx_use.op_count)
            self.assertEqual(0, sa2.rx_use.op_count)

    def _compare_cose_keys(self, key1: CoseKey, key2: CoseKey):
        self.assertEqual(key1.kty, key2.kty)
        self.assertEqual(key1.kid, key2.kid)
        self.assertEqual(key1.k, key2.k)
        self.assertEqual(key1.alg, key2.alg)
        self.assertEqual(key1.base_iv, key2.base_iv)
        self.assertNotEqual(key1.key_ops, key2.key_ops)
