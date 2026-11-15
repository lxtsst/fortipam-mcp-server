# Docker Packaging

The Dockerfile installs a verified wheel and dependency wheelhouse. It verifies
their SHA-256 manifest and records the application-wheel digest in an OCI label.
It does not include credentials or a shared appliance configuration.

This optional build targets Linux x86-64 with Python 3.12. It is not a published
container image or a cross-platform deployment certification. Use the Python
installation in the main README for the verified source installation path.

From the tagged source, with the contributor dependencies installed:

```bash
SOURCE_DATE_EPOCH=1735689600 .venv/bin/python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
PYTHON_COMMAND=.venv/bin/python bash deploy/docker/download_wheelhouse.sh
(cd deploy/docker/wheelhouse && shasum -a 256 -c ../wheelhouse-manifest.sha256)
APP_WHEEL_SHA256="$(shasum -a 256 dist/fortipam_mcp_server-4.0.0b109-py3-none-any.whl | cut -d ' ' -f 1)"
docker build --platform linux/amd64 --network=none \
  --build-arg APP_WHEEL_SHA256="${APP_WHEEL_SHA256}" \
  --tag fortipam-mcp-server:4.0.0b109 .
```

The downloader uses the exact versions and hashes in the manifest, including
transitive dependencies. The pinned base image must already be available locally
for an offline build. Do not replace expected hashes to bypass a mismatch. A
maintainer changing package contents (including README metadata) must rebuild,
review and update the application entry, then rerun the release checks.

The image starts `fortipam-mcp-http` as a non-root user. Configure explicit memory
limits, a read-only root filesystem, a loopback backend, protected secret mounts,
and only the writable state directories required by the chosen profile. Place
remote access behind verified HTTPS and OAuth. Keep each deployment's state,
credentials, and recovery backup separate.

Container runtime and target-appliance qualification are deployment-specific.
Passing source tests or building an image does not establish that qualification.
See [deployment](../../docs/DEPLOYMENT.md) and
[security](../../docs/SECURITY_MODEL.md).
