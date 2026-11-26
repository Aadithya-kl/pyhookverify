# Good first issues

Each item below is scoped for a focused pull request. Include tests and docs updates where noted.

## Providers

1. **Discord webhook signatures.** Add a `discord` provider using the Ed25519 `X-Signature-Ed25519` and `X-Signature-Timestamp` headers. Note that this requires adding signature verification beyond HMAC; propose an API before implementing.
2. **PayPal webhook signatures.** Implement PayPal `PAYPAL-TRANSMISSION-ID`, `PAYPAL-TRANSMISSION-TIME`, `PAYPAL-TRANSMISSION-SIG`, and `PAYPAL-CERT-URL` verification with certificate pinning options.
3. **Twilio webhook signatures.** Add a `twilio` provider using `X-Twilio-Signature` with the URL plus sorted POST parameters signing string. Accept a configurable request URL.
4. **SendGrid webhook signatures.** Add a `sendgrid` provider using `X-Twilio-Webhook-Signature` and ECDSA, with a clear statement about non-HMAC requirements.
5. **Vercel webhook signatures.** Add a `vercel` provider using `x-vercel-signature` with SHA1 fallback and `x-vercel-id` replay key.
6. **JWT-based webhook providers.** Explore a generic `jwt` provider that verifies HS256 tokens and exposes claims as headers, without adding dependencies.
7. **Provider alias table.** Add aliases such as `standard-webhooks` for `svix` and document them in the README.
8. **Configurable digest algorithms.** Allow sha512 providers with an explicit algorithm parameter while keeping the default sha256.

## Frameworks

9. **FastAPI dependency injection.** Ship a `pyhookverify.fastapi` helper exposing a dependency that returns a verified `VerificationResult`. Keep FastAPI optional.
10. **Django middleware.** Add middleware that verifies configured routes and attaches the result to `request.hookverify`.
11. **Flask before_request helper.** Provide a decorator factory that verifies the raw body and aborts with 401 on `HookVerifyError`.
12. **Starlette middleware.** Provide ASGI middleware that reads the body without consuming it for downstream handlers.
13. **AWS Lambda adapter.** Add a function that accepts API Gateway event headers and a base64 body flag, verifying without double-decoding.

## Core and tests

14. **Persistent replay store.** Implement a file-backed or SQLite-backed store implementing `ReplayStore` with atomic check-and-store semantics and documented cleanup behavior.
15. **Fuzz tests for decoders.** Add deterministic property-style tests over random hex and base64 strings, asserting that accepted values re-encode canonically and rejected values raise `invalid_encoding`.
