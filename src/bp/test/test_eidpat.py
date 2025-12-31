import unittest
from bp.eidpat import (
    EidPattern, EidRepr, UnknownSchemeError
)


class TestPatternText(unittest.TestCase):

    def test_any_scheme(self):
        pat = EidPattern()
        pat.from_text('*:**')
        self.assertIsNone(pat.items)

    def test_empty(self):
        pat = EidPattern()
        pat.from_text('')
        self.assertListEqual([], pat.items)

    def test_onepart_ipn_anyssp(self):
        pat = EidPattern()
        pat.from_text('ipn:**')
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_anyssp(self):
        pat = EidPattern()
        pat.from_text('2:**')
        self.assertEqual(1, len(pat.items))

    def test_onepart_ipn_all2_single(self):
        pat = EidPattern()
        pat.from_text('ipn:0.0')
        self.assertEqual(1, len(pat.items))

    def test_onepart_ipn_all3_single(self):
        pat = EidPattern()
        pat.from_text('ipn:0.0.0')
        self.assertEqual(1, len(pat.items))

    def test_onepart_ipn_all_wild(self):
        pat = EidPattern()
        pat.from_text('ipn:*.*.*')
        self.assertEqual(1, len(pat.items))

    def test_twopart_ipn_anyssp(self):
        pat = EidPattern()
        pat.from_text('ipn:**|2:**')
        self.assertEqual(2, len(pat.items))

    def test_twopart_ipn_dtn_anyssp(self):
        pat = EidPattern()
        pat.from_text('ipn:**|dtn:**')
        self.assertEqual(2, len(pat.items))

    def test_error_malformed(self):
        pat = EidPattern()

        CASES = [
            'hi',
            '|',
            'hi|',
        ]
        for text in CASES:
            with self.subTest(text):
                with self.assertRaises(ValueError):
                    pat.from_text(text)

    def test_error_unknown(self):
        pat = EidPattern()

        CASES = [
            '65536:hi',
            'unknown:hi',
        ]
        for text in CASES:
            with self.subTest(text):
                with self.assertRaises(UnknownSchemeError):
                    pat.from_text(text)


class TestPatternCbor(unittest.TestCase):

    def test_any_scheme(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('F5'))
        self.assertIsNone(pat.items)

    def test_empty(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('80'))
        self.assertListEqual([], pat.items)

    def test_onepart_ipn_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('816369706E'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('8102'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_all2_single(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('818202820000'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_all3_single(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('81820283000000'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_all_wild(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('81820283F5F5F5'))
        self.assertEqual(1, len(pat.items))

    def test_twopart_2_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('826369706E02'))
        self.assertEqual(2, len(pat.items))

    def test_twopart_2_1_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('820201'))
        self.assertEqual(2, len(pat.items))

    def test_error_malformed(self):
        pat = EidPattern()

        CASES = [
            'hi',
            '|',
            'hi|',
        ]
        for text in CASES:
            with self.subTest(text):
                with self.assertRaises(ValueError):
                    pat.from_text(text)


class TestRoundtrips(unittest.TestCase):
    # No state checks, just decode and re-encode

    CASES = [
        ('', '80'),
        ('*:**', 'F5'),
        ('asdf:**', '816461736466'),
        ('ipn:**', '8102'),
        ('ipn:0.0.0', '81820283000000'),
        ('ipn:0.1.2', '81820283000102'),
        ('ipn:1.2', '818202820102'),
        ('ipn:0.*.*', '8182028300F5F5'),
        ('ipn:0.[1-10,50-100].*', '818202830084010918261832F5'),
        ('ipn:0.[1-10].[50+]', '8182028300820109811832'),
    ]

    def test_roundtrip_text(self):
        for orig_text, _ in self.CASES:
            with self.subTest(orig_text):
                pat = EidPattern()
                pat.from_text(orig_text)
                out_text = pat.to_text()
                self.assertEqual(orig_text, out_text)

    def test_roundtrip_cbor(self):
        for _, orig_hex in self.CASES:
            with self.subTest(orig_hex):
                if not orig_hex:
                    self.skipTest('missing')
                pat = EidPattern()
                pat.from_cbor(bytes.fromhex(orig_hex))
                out_hex = pat.to_cbor().hex().upper()
                self.assertEqual(orig_hex, out_hex)

    def test_text_cbor(self):
        for orig_text, expect_hex in self.CASES:
            with self.subTest(orig_text):
                if not expect_hex:
                    self.skipTest('missing')
                pat = EidPattern()
                pat.from_text(orig_text)
                out_hex = pat.to_cbor().hex().upper()
                self.assertEqual(expect_hex, out_hex)

    def test_cbor_text(self):
        for expect_text, orig_hex in self.CASES:
            with self.subTest(orig_hex):
                if not orig_hex:
                    self.skipTest('missing')
                pat = EidPattern()
                pat.from_cbor(bytes.fromhex(orig_hex))
                out_text = pat.to_text()
                self.assertEqual(expect_text, out_text)


class TestPatternMatch(unittest.TestCase):

    def test_any_scheme(self):
        pat = EidPattern()
        pat.from_text('*:**')

        CASES = [
            (EidRepr('dtn', 'none'), True),
            (EidRepr(1, 0), True),
            (EidRepr('ipn', [0, 0, 0]), True),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), True),
            (EidRepr('ipn', [1, 0]), True),
            (EidRepr('ipn', [2**64, 2**64]), True),
            (EidRepr(2, [0, 0, 0]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(eid):
                self.assertEqual(expect, pat.is_match(eid))

    def test_empty(self):
        pat = EidPattern()
        pat.from_text('')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), False),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [1, 0]), False),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 0, 0]), False),
        ]
        for eid, expect in CASES:
            with self.subTest(eid):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_anyssp(self):
        pat = EidPattern()
        pat.from_text('ipn:**')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), True),
            (EidRepr('ipn', [0, 1, 0]), True),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), True),
            (EidRepr('ipn', [1, 0]), True),
            (EidRepr('ipn', [2**64, 2**64]), True),
            (EidRepr(2, [0, 0, 0]), True),  # Special case
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn2_anyssp(self):
        pat = EidPattern()
        pat.from_text('ipn:**|2:**')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), True),
            (EidRepr('ipn', [0, 1, 0]), True),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), True),
            (EidRepr('ipn', [1, 0]), True),
            (EidRepr('ipn', [2**64, 2**64]), True),
            (EidRepr(2, [0, 0, 0]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_3elem_all_single(self):
        pat = EidPattern()
        pat.from_text('ipn:0.0.0')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), True),
            (EidRepr('ipn', [0, 1, 0]), False),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [1, 0]), False),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 0, 0]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_3elem_wildcard(self):
        pat = EidPattern()
        pat.from_text('ipn:0.1.*')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), False),
            (EidRepr('ipn', [0, 1, 0]), True),
            (EidRepr('ipn', [0, 1, 100]), True),
            (EidRepr('ipn', [0, 1, 2**64]), True),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [1, 0]), True),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 1, 0]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_2elem_wildcard(self):
        pat = EidPattern()
        pat.from_text('ipn:1.*')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), False),
            (EidRepr('ipn', [0, 1, 0]), True),
            (EidRepr('ipn', [0, 1, 100]), True),
            (EidRepr('ipn', [0, 1, 2**64]), True),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [1, 0]), True),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 1, 0]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_3elem_ranges(self):
        pat = EidPattern()
        pat.from_text('ipn:0.[1-10].[50+]')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), False),
            (EidRepr('ipn', [0, 1, 0]), False),
            (EidRepr('ipn', [0, 1, 50]), True),
            (EidRepr('ipn', [0, 10, 2**64]), True),
            (EidRepr('ipn', [0, 11, 2**64]), False),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [1, 0]), False),
            (EidRepr('ipn', [1, 50]), True),
            (EidRepr('ipn', [1, 2**64]), True),
            (EidRepr('ipn', [10, 2**64]), True),
            (EidRepr('ipn', [11, 2**64]), False),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 1, 0]), False),
            (EidRepr(2, [0, 1, 50]), True),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))
