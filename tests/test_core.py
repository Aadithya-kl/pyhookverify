"""Core verifier configuration, rotation, body types, timestamp, and cap tests."""

import base64
import hashlib
import hmac
import unittest

from pyhookverify import (
    MAX_CANDIDATE_SIGNATURES,
    HookVerifyError,
    MemoryReplayStore,
    NullReplayStore,
    VerificationResult,
    WebhookVerifier,
)

NOW = 1700000000.0
SECRET = "current-secret"


def sha256_hex(secret, payload):
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def github_header(secret, body):
    return {"X-Hub-Signature-256": "sha256=" + sha256_hex(secret, body)}


class ConfigurationTests(unittest.TestCase):
    def test_string_secrets_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier("secret", "github")
        self.assertEqual(cm.exception.code, "invalid_config")

    def test_empty_secrets_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier([], "github")
        self.assertEqual(cm.exception.code, "invalid_config")

    def test_empty_secret_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier([""], "github")
        self.assertEqual(cm.exception.code, "invalid_secret")

    def test_whitespace_secret_rejected(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["   "], "github")

    def test_tab_secret_rejected(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["\t\n"], "github")

    def test_non_string_secret_rejected(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier([123], "github")

    def test_bytes_secret_rejected(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier([b"secret"], "github")

    def test_unknown_provider_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier(["s"], "unknown-provider")
        self.assertEqual(cm.exception.code, "unknown_provider")

    def test_bad_tolerance_type(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", tolerance_seconds=1.5)

    def test_negative_tolerance(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", tolerance_seconds=-1)

    def test_huge_tolerance(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", tolerance_seconds=100000)

    def test_zero_tolerance(self):
        verifier = WebhookVerifier(["s"], "github", tolerance_seconds=0)
        self.assertEqual(verifier.tolerance_seconds, 0)

    def test_bad_clock(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", clock=42)

    def test_bad_replay_store(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier(["s"], "github", replay_store=object())
        self.assertEqual(cm.exception.code, "invalid_config")

    def test_bad_candidate_cap(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", max_candidate_signatures=0)

    def test_candidate_cap_above_max(self):
        with self.assertRaises(HookVerifyError):
            WebhookVerifier(["s"], "github", max_candidate_signatures=33)

    def test_default_cap(self):
        self.assertEqual(MAX_CANDIDATE_SIGNATURES, 32)

    def test_injectable_clock(self):
        ticks = [0.0, 1.0, 2.0]
        verifier = WebhookVerifier(["s"], "github", clock=lambda: ticks.pop(0))
        self.assertEqual(verifier._now(), 0.0)
        self.assertEqual(verifier._now(), 1.0)
        self.assertEqual(verifier._now(), 2.0)


class BodyTypeTests(unittest.TestCase):
    def verifier(self):
        return WebhookVerifier([SECRET], "github", clock=lambda: NOW)

    def test_bytes_accepted(self):
        body = b"abc"
        result = self.verifier().verify(github_header(SECRET, body), body)
        self.assertEqual(result.provider, "github")

    def test_bytearray_accepted(self):
        body = b"abc"
        result = self.verifier().verify(github_header(SECRET, body), bytearray(body))
        self.assertEqual(result.provider, "github")

    def test_memoryview_accepted(self):
        body = b"abc"
        result = self.verifier().verify(github_header(SECRET, body), memoryview(body))
        self.assertEqual(result.provider, "github")

    def test_dict_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, {"key": "value"})
        self.assertEqual(cm.exception.code, "invalid_body")

    def test_list_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, [1, 2, 3])
        self.assertEqual(cm.exception.code, "invalid_body")

    def test_int_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, 123)
        self.assertEqual(cm.exception.code, "invalid_body")

    def test_string_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, '{"a":1}')
        self.assertEqual(cm.exception.code, "invalid_body")

    def test_none_rejected(self):
        with self.assertRaises(HookVerifyError):
            self.verifier().verify({}, None)

    def test_headers_non_mapping_rejected(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify("X-Hub-Signature-256: abc", b"abc")
        self.assertEqual(cm.exception.code, "invalid_headers")

    def test_body_checked_before_headers(self):
        with self.assertRaises(HookVerifyError) as cm:
            self.verifier().verify({}, {"a": 1})
        self.assertEqual(cm.exception.code, "invalid_body")


class RotationTests(unittest.TestCase):
    def test_second_secret_matches(self):
        body = b"rotation-body"
        verifier = WebhookVerifier(["old", "new"], "github", clock=lambda: NOW)
        result = verifier.verify(github_header("new", body), body)
        self.assertEqual(result.secret_index, 1)

    def test_first_secret_matches(self):
        body = b"rotation-body"
        verifier = WebhookVerifier(["old", "new"], "github", clock=lambda: NOW)
        result = verifier.verify(github_header("old", body), body)
        self.assertEqual(result.secret_index, 0)

    def test_none_match(self):
        body = b"rotation-body"
        verifier = WebhookVerifier(["old", "new"], "github", clock=lambda: NOW)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify(github_header("retired", body), body)
        self.assertEqual(cm.exception.code, "invalid_signature")

    def test_result_fields(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        result = verifier.verify(github_header(SECRET, body), body)
        self.assertIsInstance(result, VerificationResult)
        self.assertIsNone(result.timestamp)
        self.assertEqual(len(result.signature), 64)
        self.assertEqual(
            set(result.as_dict()), {"provider", "secret_index", "timestamp", "signature"}
        )

    def test_verify_request_alias(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        result = verifier.verify_request(github_header(SECRET, body), body)
        self.assertEqual(result.provider, "github")

    def test_error_str_has_code(self):
        with self.assertRaises(HookVerifyError) as cm:
            WebhookVerifier([], "github")
        self.assertIn("invalid_config", str(cm.exception))
        self.assertIn("invalid_config", repr(cm.exception))


class ReplayDefenseTests(unittest.TestCase):
    def test_second_verify_rejected(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        headers = github_header(SECRET, body)
        verifier.verify(headers, body)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify(headers, body)
        self.assertEqual(cm.exception.code, "replay")

    def test_bad_signature_does_not_poison_store(self):
        body = b"abc"
        store = NullReplayStore()
        verifier = WebhookVerifier([SECRET], "github", replay_store=store, clock=lambda: NOW)
        with self.assertRaises(HookVerifyError):
            verifier.verify({"X-Hub-Signature-256": "sha256=" + "00" * 32}, body)
        self.assertEqual(len(store), 0)

    def test_wrong_secret_does_not_poison_store(self):
        body = b"abc"
        store = NullReplayStore()
        verifier = WebhookVerifier([SECRET], "github", replay_store=store, clock=lambda: NOW)
        with self.assertRaises(HookVerifyError):
            verifier.verify(github_header("wrong", body), body)
        self.assertEqual(len(store), 0)

    def test_malformed_header_does_not_poison_store(self):
        store = NullReplayStore()
        verifier = WebhookVerifier([SECRET], "stripe", replay_store=store, clock=lambda: NOW)
        with self.assertRaises(HookVerifyError):
            verifier.verify({"Stripe-Signature": "garbage"}, b"abc")
        self.assertEqual(len(store), 0)

    def test_stale_request_does_not_poison_store(self):
        body = b"abc"
        store = NullReplayStore()
        verifier = WebhookVerifier([SECRET], "stripe", replay_store=store, clock=lambda: NOW)
        timestamp = int(NOW) - 400
        payload = str(timestamp).encode() + b".abc"
        header = "t=%d,v1=%s" % (timestamp, sha256_hex(SECRET, payload))
        with self.assertRaises(HookVerifyError):
            verifier.verify({"Stripe-Signature": header}, body)
        self.assertEqual(len(store), 0)

    def test_multi_v1_subset_replay_rejected(self):
        """A header with two valid v1 signatures must consume both keys."""
        body = b"abc"
        timestamp = int(NOW)
        payload = str(timestamp).encode() + b"." + body
        sig_a = sha256_hex(SECRET, payload)
        sig_b = sha256_hex("rotated-secret", payload)
        header_all = "t=%d,v1=%s,v1=%s" % (timestamp, sig_a, sig_b)
        header_subset = "t=%d,v1=%s" % (timestamp, sig_a)

        store = MemoryReplayStore(clock=lambda: NOW)
        verifier = WebhookVerifier(
            [SECRET, "rotated-secret"], "stripe", replay_store=store, clock=lambda: NOW
        )
        verifier.verify({"Stripe-Signature": header_all}, body)
        # Both candidate keys must have been consumed.
        self.assertEqual(len(store), 2)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"Stripe-Signature": header_subset}, body)
        self.assertEqual(cm.exception.code, "replay")

    def test_multi_v1_reversed_subset_rejected(self):
        body = b"abc"
        timestamp = int(NOW)
        payload = str(timestamp).encode() + b"." + body
        sig_a = sha256_hex(SECRET, payload)
        sig_b = sha256_hex("rotated-secret", payload)
        store = MemoryReplayStore(clock=lambda: NOW)
        verifier = WebhookVerifier(
            [SECRET, "rotated-secret"], "stripe", replay_store=store, clock=lambda: NOW
        )
        verifier.verify(
            {"Stripe-Signature": "t=%d,v1=%s,v1=%s" % (timestamp, sig_b, sig_a)}, body
        )
        with self.assertRaises(HookVerifyError):
            verifier.verify(
                {"Stripe-Signature": "t=%d,v1=%s" % (timestamp, sig_b)}, body
            )

    def test_svix_multi_v1_subset_rejected(self):
        body = b"abc"
        timestamp = int(NOW)
        payload = b"msg.1700000000.abc"

        def b64(secret):
            return base64.b64encode(hmac.new(secret.encode(), payload, hashlib.sha256).digest()).decode()

        sig_a = b64(SECRET)
        sig_b = b64("rotated")
        store = MemoryReplayStore(clock=lambda: NOW)
        verifier = WebhookVerifier(
            ["whsec_" + SECRET, "whsec_rotated"], "svix", replay_store=store, clock=lambda: NOW
        )
        headers = {
            "webhook-id": "msg",
            "webhook-timestamp": "1700000000",
            "webhook-signature": "v1,%s v1,%s" % (sig_a, sig_b),
        }
        verifier.verify(headers, body)
        self.assertEqual(len(store), 2)
        headers["webhook-signature"] = "v1," + sig_b
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify(headers, body)
        self.assertEqual(cm.exception.code, "replay")

    def test_invalid_candidate_in_multi_header_not_consumed(self):
        body = b"abc"
        timestamp = int(NOW)
        payload = str(timestamp).encode() + b"." + body
        sig_a = sha256_hex(SECRET, payload)
        store = NullReplayStore()
        verifier = WebhookVerifier([SECRET], "stripe", replay_store=store, clock=lambda: NOW)
        header = "t=%d,v1=%s,v1=zz" % (timestamp, sig_a)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"Stripe-Signature": header}, body)
        self.assertEqual(cm.exception.code, "invalid_encoding")
        self.assertEqual(len(store), 0)

    def test_shared_store_blocks_cross_verifier_replay(self):
        body = b"abc"
        store = MemoryReplayStore(clock=lambda: NOW)
        first = WebhookVerifier([SECRET], "github", replay_store=store, clock=lambda: NOW)
        second = WebhookVerifier([SECRET], "github", replay_store=store, clock=lambda: NOW)
        headers = github_header(SECRET, body)
        first.verify(headers, body)
        with self.assertRaises(HookVerifyError):
            second.verify(headers, body)

    def test_ttl_expiry_allows_reverify_with_shared_clock(self):
        body = b"abc"
        clock = [100.0]
        store = MemoryReplayStore(ttl_seconds=10, clock=lambda: clock[0])
        verifier = WebhookVerifier(
            [SECRET], "github", replay_store=store, clock=lambda: clock[0]
        )
        headers = github_header(SECRET, body)
        verifier.verify(headers, body)
        clock[0] = 111.0
        result = verifier.verify(headers, body)
        self.assertEqual(result.provider, "github")


class CandidateCapTests(unittest.TestCase):
    def test_32_candidates_accepted(self):
        body = b"abc"
        timestamp = int(NOW)
        payload = str(timestamp).encode() + b"." + body
        valid = sha256_hex(SECRET, payload)
        invalid = "00" * 32
        sigs = ",".join(["v1=" + valid] + ["v1=" + invalid] * 31)
        verifier = WebhookVerifier([SECRET], "stripe", clock=lambda: NOW)
        result = verifier.verify({"Stripe-Signature": "t=%d,%s" % (timestamp, sigs)}, body)
        self.assertEqual(result.secret_index, 0)

    def test_33_candidates_rejected(self):
        body = b"abc"
        timestamp = int(NOW)
        sigs = ",".join(["v1=" + "00" * 32] * 33)
        verifier = WebhookVerifier([SECRET], "stripe", clock=lambda: NOW)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"Stripe-Signature": "t=%d,%s" % (timestamp, sigs)}, body)
        self.assertEqual(cm.exception.code, "too_many_signatures")

    def test_custom_lower_cap(self):
        body = b"abc"
        timestamp = int(NOW)
        sigs = ",".join(["v1=" + "00" * 32] * 3)
        verifier = WebhookVerifier(
            [SECRET], "stripe", clock=lambda: NOW, max_candidate_signatures=2
        )
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"Stripe-Signature": "t=%d,%s" % (timestamp, sigs)}, body)
        self.assertEqual(cm.exception.code, "too_many_signatures")


class HeaderNormalizationTests(unittest.TestCase):
    def test_list_header_single_value(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        result = verifier.verify(
            {"x-hub-signature-256": ["sha256=" + sha256_hex(SECRET, body)]}, body
        )
        self.assertEqual(result.provider, "github")

    def test_tuple_header_single_value(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        result = verifier.verify(
            {"X-HUB-SIGNATURE-256": ("sha256=" + sha256_hex(SECRET, body),)}, body
        )
        self.assertEqual(result.provider, "github")

    def test_empty_list_header_rejected(self):
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"X-Hub-Signature-256": []}, b"abc")
        self.assertEqual(cm.exception.code, "missing_header")

    def test_empty_string_header_rejected(self):
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        with self.assertRaises(HookVerifyError) as cm:
            verifier.verify({"X-Hub-Signature-256": "   "}, b"abc")
        self.assertEqual(cm.exception.code, "missing_header")

    def test_non_string_header_value_rejected(self):
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        with self.assertRaises(HookVerifyError):
            verifier.verify({"X-Hub-Signature-256": 12345}, b"abc")

    def test_unrelated_duplicate_header_ignored(self):
        body = b"abc"
        verifier = WebhookVerifier([SECRET], "github", clock=lambda: NOW)
        result = verifier.verify(
            {
                "X-Hub-Signature-256": "sha256=" + sha256_hex(SECRET, body),
                "Content-Type": ["application/json", "charset=utf-8"],
            },
            body,
        )
        self.assertEqual(result.provider, "github")


if __name__ == "__main__":
    unittest.main()
