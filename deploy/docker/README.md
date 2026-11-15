# Docker Packaging

The Dockerfile installs a verified wheel and dependency wheelhouse. It verifies
their SHA-256 manifest and records the application-wheel digest in an OCI label.
It does not include credentials or a shared appliance configuration.

Build the application wheel from this source, refresh its entry in
`wheelhouse-manifest.sha256`, then prepare the dependency wheelhouse with
`download_wheelhouse.sh`. Supply the application digest as `APP_WHEEL_SHA256`.
Use a base image that matches the pinned Dockerfile digest and target platform.
The build uses local wheels and supports `--network=none` once those inputs exist.

The image starts `fortipam-mcp-http` as a non-root user. Configure explicit memory
limits, a read-only root filesystem, a loopback backend, protected secret mounts,
and only the writable state directories required by the chosen profile. Place
remote access behind verified HTTPS and OAuth. Keep each deployment's state,
credentials, and recovery backup separate.

Container runtime and target-appliance qualification are deployment-specific.
Passing source tests or building an image does not establish that qualification.
See [deployment](../../docs/DEPLOYMENT.md) and
[security](../../docs/SECURITY_MODEL.md).
