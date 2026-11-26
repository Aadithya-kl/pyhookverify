# Contributing

Thanks for helping improve pyhookverify.

## Basics

* Python 3.9 or newer is required. Use only the standard library in runtime code.
* Run the suite before opening a pull request:

  ```bash
  PYTHONPATH=src python3 -m unittest discover -s tests
  ```

* Add deterministic tests for every behavior change. No network calls, no live webhook endpoints, no wall-clock dependence (inject a clock).
* Keep error codes stable. Adding a new code is fine; renaming one is a breaking change.
* Do not add runtime dependencies. Dev tooling is intentionally minimal.
* Use plain ASCII punctuation. Avoid smart dashes and curly quotes in docs and code.

## Pull request checklist

1. Tests pass locally on your Python version.
2. New providers include canonical signing-format tests and a negative test.
3. Replay-related changes include a pre-auth poisoning test and a multi-signature replay test.
4. README code examples remain copy-paste runnable.
5. Commit messages describe the behavior change, not the file list.

## Adding a provider

Providers implement a parser returning `(timestamp, candidates, signing_payload)`. Register it with `register_provider(Provider(name, parser))`. See `GOOD_FIRST_ISSUES.md` for concrete provider and framework tasks.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open public issues for exploitable bugs.
