# Contributing

Contributions are welcome for reproducible defects, compatibility, documentation,
tests, and bounded capabilities. Describe the affected version and expected
behavior, and use synthetic fixtures for reproduction.

Install the development dependencies as documented in [README.md](README.md).
Run the focused tests for your change and the release checks before submission:

```bash
python scripts/check_repository_hygiene.py
python scripts/verify_release.py
```

The release verifier runs the test suite, typing, registry/scenario checks,
stdio/HTTP protocol smoke, wheel inspection, and installed-wheel smoke without
contacting a FortiPAM appliance. Device acceptance scripts require a separately
configured, authorized environment and are not part of the offline test run.

Do not submit credentials, tokens, private keys, device addresses, customer data,
raw responses, or proprietary vendor material. Preserve fixed operation boundaries,
redaction, authorization, state-drift rejection, and closed-by-default execution.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
