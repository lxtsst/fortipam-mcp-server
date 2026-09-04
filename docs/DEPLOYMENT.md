# Deployment

Use a dedicated least-privilege FortiPAM API identity for read-only calls and a separate SSH public-key identity when CLI diagnostics are enabled. Keep credentials outside the repository in owner-only environment files or secret mounts.

Local stdio is the simplest deployment. Streamable HTTP without authentication is loopback-only. Any remote deployment must terminate HTTPS and use OAuth with an audience bound to the MCP resource.

The Docker assets run as a non-root user and are designed for a read-only root filesystem with dropped capabilities. Review [`deploy/docker/README.md`](../deploy/docker/README.md) before building an image.

The `lab-simulated` profile writes only local fixtures. It is not proof of FortiPAM write compatibility or production qualification.

