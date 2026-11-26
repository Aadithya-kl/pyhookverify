# Security Policy

## Supported versions

Security fixes are applied to the latest released version. Report issues against the current main branch.

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue. Include:

* the affected version and Python version
* a minimal reproducing webhook request and headers
* the impact you observed
* a suggested fix, if you have one

Please do not publish exploit details until a fix is available. You should receive an acknowledgement within seven days.

## Scope

In scope:

* signature verification bypasses
* replay-protection bypasses, including multi-signature and key-rotation cases
* non-constant-time comparison paths
* malformed hex, base64, or timestamp inputs accepted when they should be rejected
* memory-exhaustion issues in the replay store or signature parsing

Out of scope:

* attacks requiring possession of a valid shared secret
* payload-level authorization or business logic in consuming applications
* vulnerabilities in third-party web frameworks or TLS configurations
* denial of service from network volume alone

## Design commitments

* Verification uses `hmac.compare_digest` on equal-length decoded bytes only.
* Replay keys are written only after a signature matches a configured secret.
* All six built-in providers verify HMAC-SHA256 over exact raw body bytes.
* Candidate signatures are capped at 32 per request.
* The default replay store has a TTL and a hard entry cap.
* No runtime dependencies are used; the package imports only the standard library.
