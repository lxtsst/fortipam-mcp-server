# Architecture

The server exposes curated MCP tools rather than a generic REST, SSH, shell, or SDK proxy.

Core boundaries:

1. fixed API routes and CLI commands are defined in code;
2. caller input is schema-constrained and cannot select arbitrary endpoints or commands;
3. responses are recursively redacted and reduced to operational evidence;
4. the default runtime profile is read-only;
5. local diagnostic and simulation state is kept separate from FortiPAM device state;
6. controlled-operation metadata does not by itself authorize or dispatch a device change.

The package supports stdio and Streamable HTTP transports. HTTP can use local OAuth for a single-operator deployment or validate tokens from an external authorization server.

