"""Strict decoding and constant-time comparison tests."""

import unittest

from pyhookverify import HookVerifyError, ct_equal, decode_base64, decode_hex, parse_timestamp


class HexTests(unittest.TestCase):
    def test_valid_lower(self):
        self.assertEqual(decode_hex("00ff10"), b"\x00\xff\x10")

    def test_valid_upper(self):
        self.assertEqual(decode_hex("00FF10"), b"\x00\xff\x10")

    def test_odd_length_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            decode_hex("abc")
        self.assertEqual(cm.exception.code, "invalid_encoding")

    def test_empty_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex("")

    def test_0x_prefix_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex("0xff")

    def test_whitespace_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex("aa bb")

    def test_trailing_newline_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex("aabb\n")

    def test_non_string_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex(b"aabb")

    def test_unicode_hexlike_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_hex("ааbb")

    def test_field_name_in_error(self):
        with self.assertRaises(HookVerifyError) as cm:
            decode_hex("zz", "signature")
        self.assertIn("signature", cm.exception.message)


class Base64Tests(unittest.TestCase):
    def test_valid_padded(self):
        self.assertEqual(decode_base64("Zg=="), b"f")

    def test_valid_no_padding_needed(self):
        self.assertEqual(decode_base64("Zm9v"), b"foo")

    def test_valid_two_pads(self):
        self.assertEqual(decode_base64("Zm8="), b"fo")

    def test_unpadded_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            decode_base64("Zg")
        self.assertEqual(cm.exception.code, "invalid_encoding")

    def test_extra_padding_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("Zg===")

    def test_noncanonical_padding_bits_rejected(self):
        # 'Zh==' has nonzero slack bits and decodes to the same byte as 'Zg=='.
        with self.assertRaises(HookVerifyError) as cm:
            decode_base64("Zh==")
        self.assertIn("padding bits", cm.exception.message)

    def test_noncanonical_two_pad_bits_rejected(self):
        # 'aa==' has nonzero slack bits; re-encoding the decoded byte yields
        # a different final character, so the canonical check must reject it.
        with self.assertRaises(HookVerifyError) as cm:
            decode_base64("aa==")
        self.assertIn("padding bits", cm.exception.message)

    def test_urlsafe_alphabet_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("a-b_")

    def test_whitespace_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("Zm8 =")

    def test_embedded_newline_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("Zm8=\n")

    def test_empty_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("")

    def test_trailing_garbage_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64("Zm8=!!")

    def test_non_string_rejected(self):
        with self.assertRaises(HookVerifyError):
            decode_base64(b"Zg==")


class TimestampTests(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_timestamp("1700000000"), 1700000000)

    def test_zero(self):
        self.assertEqual(parse_timestamp("0"), 0)

    def test_negative_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            parse_timestamp("-1")
        self.assertEqual(cm.exception.code, "invalid_timestamp")

    def test_plus_sign_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("+123")

    def test_float_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("1.5")

    def test_exponent_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("1e9")

    def test_hex_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("0x10")

    def test_unicode_digits_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("１２３")

    def test_empty_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("")

    def test_huge_rejected(self):
        with self.assertRaises(HookVerifyError):
            parse_timestamp("9" * 30)

    def test_digit_run_longer_than_cpython_int_limit_rejected(self):
        # CPython 3.11+ raises ValueError from int() past 4300 digits unless the
        # length is checked first; the error must stay a HookVerifyError on every
        # supported interpreter.
        with self.assertRaises(HookVerifyError) as cm:
            parse_timestamp("9" * 5000)
        self.assertEqual(cm.exception.code, "invalid_timestamp")

    def test_max_int64_accepted(self):
        self.assertEqual(parse_timestamp("9223372036854775807"), 2 ** 63 - 1)

    def test_above_max_int64_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            parse_timestamp("9223372036854775808")
        self.assertEqual(cm.exception.code, "invalid_timestamp")


class ConstantTimeTests(unittest.TestCase):
    def test_equal(self):
        self.assertTrue(ct_equal(b"abc", b"abc"))

    def test_different_same_length(self):
        self.assertFalse(ct_equal(b"abc", b"abd"))

    def test_different_length(self):
        self.assertFalse(ct_equal(b"abc", b"abcd"))

    def test_empty_equal(self):
        self.assertTrue(ct_equal(b"", b""))

    def test_bytes_only(self):
        self.assertFalse(ct_equal("abc", "abc"))
        self.assertFalse(ct_equal(bytearray(b"abc"), b"abc"))


if __name__ == "__main__":
    unittest.main()
