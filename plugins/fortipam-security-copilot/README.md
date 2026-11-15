# FortiPAM Security Copilot Plugin

This optional plugin contains FortiPAM diagnostic and administrative workflow
Skills plus a sanitized remote MCP definition. Basic capability discovery also
uses client-neutral MCP Resources and Prompts.

The tracked `.mcp.json` is an example. Create a personal copy with
`scripts/install_local_codex_plugin.py` and configure your own authorized HTTPS
endpoint outside the repository. The installer accepts the endpoint on standard
input and supports separate `/fpamcp-v3` and `/fpamcp-v4` paths and plugin identities.
Run its `--help` command for available options.

Never add tokens, passwords, private addresses, CA files, or local paths to the
tracked plugin. The MCP client discovers OAuth from the configured server.
Skills guide a workflow; they do not grant permissions or enable tools.
Use the actual server-advertised profile and tool schemas as runtime authority.
Controlled workflows require explicit server-side bindings and authorization.
