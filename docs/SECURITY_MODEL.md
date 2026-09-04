# Security Model

The project intentionally does not expose:

- arbitrary HTTP methods, URLs, headers, bodies, or API paths;
- arbitrary SSH, shell, SQL, or SDK execution;
- Secret plaintext retrieval, password verification, or credential checkout;
- session launch, recording download, or unrestricted device administration.

Configuration, catalog entries, Skills, and metadata cannot expand runtime authority. Credentials and protected material must remain outside model context, MCP arguments and results, logs, fixtures, and Git.

Synthetic and local tests do not establish production suitability. Operators remain responsible for TLS, identity, network, role, backup, upgrade, and rollback controls in their own environment.
