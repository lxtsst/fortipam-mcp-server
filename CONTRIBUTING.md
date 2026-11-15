# Contributing

Contributions are welcome for reproducible defects, compatibility, documentation,
tests, and bounded capabilities. Describe the affected version and expected
behavior, and use synthetic fixtures for reproduction.

After cloning the repository, create a dedicated environment with Python 3.11
or 3.12. Install all dependencies needed by the offline test suite:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --constraint deploy/docker/runtime-constraints.txt hatchling==1.32.0 -e '.[dev,bulk-import]'
```

Run focused tests for your change, then the full release checks before submission.
The full suite contains over 23,000 cases and can take substantially longer than
the user smoke checks:

```bash
.venv/bin/python scripts/check_repository_hygiene.py
.venv/bin/python scripts/verify_release.py
```

The release verifier runs the test suite, typing, registry/scenario checks,
stdio/HTTP protocol smoke, wheel inspection, and installed-wheel smoke without
contacting a FortiPAM appliance. macOS native-isolation tests require
`/usr/bin/sandbox-exec`; CI runs them separately with standalone CPython 3.11.16.
Linux skips those platform-specific cases. The GitHub workflow partitions the
full suite across four shards for each Python version. Device acceptance scripts require a separately
configured, authorized environment and are not part of the offline test run.

Do not submit credentials, tokens, private keys, device addresses, customer data,
raw responses, or proprietary vendor material. Preserve fixed operation boundaries,
redaction, authorization, state-drift rejection, and closed-by-default execution.
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
