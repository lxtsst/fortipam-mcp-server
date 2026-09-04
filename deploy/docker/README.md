# Docker deployment

Build the deterministic wheel first, then build the image using the exact wheel SHA-256:

```bash
SOURCE_DATE_EPOCH=1700000000 python -m build --wheel --no-isolation
APP_WHEEL_SHA256="$(shasum -a 256 dist/fortipam_mcp_server-3.1.3-py3-none-any.whl | awk '{print $1}')"
docker build \
  --build-arg APP_WHEEL_SHA256="${APP_WHEEL_SHA256}" \
  --tag fortipam-mcp-server:3.1.3 .
```

The image runs as a non-root user. Use a read-only root filesystem, drop all capabilities, mount credentials as read-only secrets, and expose the service only through an HTTPS reverse proxy when remote access is required.

The default runtime profile is read-only. The optional `lab-simulated` profile writes only isolated local fixtures and must not be treated as FortiPAM write support.

Runtime dependency hashes are pinned in `runtime-constraints.txt` and `wheelhouse-manifest.sha256`. Use `download_wheelhouse.sh` only on a trusted build host and verify the generated wheelhouse before transferring it to an offline build environment.
