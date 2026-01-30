import unittest
from bp.eidpat import (
    EidPattern, EidRepr, UnknownSchemeError
)


class TestPatternText(unittest.TestCase):

    def test_any_scheme(self):
        pat = EidPattern()
        pat.from_text('*:**')
        self.assertEqual(1, len(pat.items))
        self.assertSetEqual({'*'}, set(pat.items[0].schemes.keys()))

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

    def test_onepart_ipn_2_anyssp(self):
        pat = EidPattern()
        pat.from_text('[ipn,2]:**')
        self.assertEqual(1, len(pat.items))

    def test_onepart_ipn_dtn_anyssp(self):
        pat = EidPattern()
        pat.from_text('[ipn,dtn]:**')
        self.assertEqual(1, len(pat.items))

    def test_error_invalid(self):
        pat = EidPattern()

        CASES = [
            'hi',
            '|',
            'hi|',
            'ipn:*.*.[',
            'ipn:*.*.[]',
            'ipn:*.*.[,3]',
            'ipn:*.*.[+]',
            # out-of-domain values
            'ipn:4294967296.4294967295.18446744073709551615',
            'ipn:4294967295.4294967296.18446744073709551615',
            'ipn:4294967295.4294967295.18446744073709551616',
            'ipn:18446744073709551616.18446744073709551615',
            'ipn:18446744073709551615.18446744073709551616',
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
        self.assertEqual(1, len(pat.items))
        self.assertSetEqual({'*'}, set(pat.items[0].schemes.keys()))

    def test_empty(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('80'))
        self.assertListEqual([], pat.items)

    def test_onepart_ipn_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('8182F66369706E'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('8182F602'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_all3_single(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('81820283000000'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_all_wild(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('81820283F5F5F5'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_ipn_2_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('8183F66369706E02'))
        self.assertEqual(1, len(pat.items))

    def test_onepart_2_1_anyssp(self):
        pat = EidPattern()
        pat.from_cbor(bytes.fromhex('8183F60201'))
        self.assertEqual(1, len(pat.items))

    def test_error_malformed(self):
        pat = EidPattern()

        CASES = [
            '',
        ]
        for in_hex in CASES:
            with self.subTest(in_hex):
                with self.assertRaises(ValueError):
                    pat.from_cbor(bytes.fromhex(in_hex))


class TestRoundtrips(unittest.TestCase):
    # No state checks, just decode and re-encode with canonical forms

    CASES = [
        ('', '80'),
        ('*:**', 'F5'),
        ('asdf:**', '8182F66461736466'),
        ('ipn:**', '8182F602'),
        ('ipn:0.0.0', '81820283000000'),
        ('ipn:0.1.2', '81820283000102'),
        ('ipn:0.*.*', '8182028300F5F5'),
        ('ipn:0.*.[10]', '8182028300F5820A00'),  # not simplified
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


class TestNormalCanonical(unittest.TestCase):
    # No state checks, just decode and re-encode

    def test_text_range(self):
        CASES = [
            # scheme-independent normalization
            ('*:**|ipn:**|2:**', '*:**'),  # redundant items removed
            ('ipn:**|dtn:**', '[ipn,dtn]:**'),  # redundant item coalesced
            ('[ipn,2]:**', 'ipn:**'),  # redundant any-SSP scheme elided
            ('ipn:0.0.0|2:0.1.2|ipn:**', 'ipn:**'),  # redundant scheme-specific items
            # IPN scheme normalization
            ('ipn:*.*.[10,10]', 'ipn:*.*.[10]'),  # duplicate elided
            ('ipn:*.*.[10,11,12]', 'ipn:*.*.[10-12]'),  # adjacency coalesced
            ('ipn:*.*.[10-45,40-50]', 'ipn:*.*.[10-50]'),  # finite overlap
            ('ipn:*.*.[10+,40-50]', 'ipn:*.*.[10+]'),  # infinite overlap
            ('ipn:[10-4294967296].*.0', 'ipn:[10+].*.0'),  # clamped domain maximum
            ('ipn:0.[10-4294967296].0', 'ipn:0.[10+].0'),  # clamped domain maximum
            ('ipn:*.*.[10-18446744073709551616]', 'ipn:*.*.[10+]'),  # clamped domain maximum
            # scheme-independent canonicalization
            ('ipn:0.0.0|dtn:**', 'dtn:**|ipn:0.0.0'),  # any-SSP in front
            # IPN scheme canonicalization
            ('ipn:*.*.[10-10]', 'ipn:*.*.[10]'),  # singleton elided
            ('ipn:*.*.[20-10]', 'ipn:*.*.[10-20]'),  # bounds ordering
            ('ipn:*.*.[10-20,1-5]', 'ipn:*.*.[1-5,10-20]'),  # interval ordering
            ('ipn:[10-4294967295].*.0', 'ipn:[10+].*.0'),  # domain maximum
            ('ipn:0.[10-4294967295].0', 'ipn:0.[10+].0'),  # domain maximum
            ('ipn:*.*.[10-18446744073709551615]', 'ipn:*.*.[10+]'),  # domain maximum
            ('ipn:0.[4294967295].0', 'ipn:0.[4294967295].0'),  # not special value
            # FIXME ('ipn:0.!.0', 'ipn:0.4294967295.0'),  # special value
            ('ipn:977000.4294967295.0', 'ipn:977000.4294967295.0'),  # not special value
            ('ipn:!.0', 'ipn:0.4294967295.0'),  # special encoding
            ('ipn:4196183048192100.0', 'ipn:977000.100.0'),  # two-element normalization
            ('ipn:18446744073709551615.0', 'ipn:4294967295.4294967295.0'),
        ]
        for orig_text, expect_text in CASES:
            with self.subTest(orig_text):
                pat = EidPattern()
                pat.from_text(orig_text)
                out_text = pat.to_text()
                self.assertEqual(expect_text, out_text)

    def test_cbor_range(self):
        CASES = [
            # canonicalization
            ('81820283820A1AFFFFFFFFF5F5', '81820283810AF5F5'),  # domain maximum
            ('8182028300820A1AFFFFFFFFF5', '8182028300810AF5'),  # domain maximum
            ('8182028300F5820A1BFFFFFFFFFFFFFFFF', '8182028300F5810A'),  # domain maximum
        ]
        for orig_hex, expect_hex in CASES:
            with self.subTest(orig_hex):
                pat = EidPattern()
                pat.from_cbor(bytes.fromhex(orig_hex))
                out_hex = pat.to_cbor().hex().upper()
                self.assertEqual(expect_hex, out_hex)


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
            (EidRepr(2, [0, 0, 0]), True),  # known pattern scheme
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
            (EidRepr('ipn', [0, 0]), True),
            (EidRepr('ipn', [1, 0]), False),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 0, 0]), True),
            (EidRepr(2, [0, 1, 0]), False),
        ]
        for eid, expect in CASES:
            with self.subTest(str(eid)):
                self.assertEqual(expect, pat.is_match(eid))

    def test_onepart_ipn_2elem_all_single(self):
        pat = EidPattern()
        pat.from_text('ipn:0.0')

        CASES = [
            (EidRepr('dtn', 'none'), False),
            (EidRepr(1, 0), False),
            (EidRepr('ipn', [0, 0, 0]), True),
            (EidRepr('ipn', [0, 1, 0]), False),
            (EidRepr('ipn', [2**32, 2**32, 2**64]), False),
            (EidRepr('ipn', [0, 0]), True),
            (EidRepr('ipn', [1, 0]), False),
            (EidRepr('ipn', [2**64, 2**64]), False),
            (EidRepr(2, [0, 0, 0]), True),
            (EidRepr(2, [0, 1, 0]), False),
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
