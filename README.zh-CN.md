# FortiPAM Security Copilot MCP Server

[English](README.md)

一个独立开发的 FortiPAM MCP Server，通过固定、最小化、可审计的能力，帮助 AI 客户端进行只读状态检查、运维诊断和受控的本地模拟工作流。

> 本项目不是 Fortinet 官方产品，也不受 Fortinet 背书。Fortinet 和 FortiPAM 是其各自权利人的商标。

## 主要能力

- 默认只读的 FortiPAM API 与受限 SSH 诊断能力；
- 固定路由、输入约束、递归脱敏和最小化输出；
- stdio 与 Streamable HTTP 两种 MCP 传输；
- 本地 OAuth 或外部 OAuth 资源服务器模式；
- 可选的 `lab-simulated` 配置，仅修改隔离的本地 Fixture，不修改 FortiPAM；
- 配套的 FortiPAM 运维 Skills、场景目录和自动化测试。

## 安装与验证

要求 Python 3.11 或 3.12。

```bash
git clone https://github.com/lxtsst/fortipam-mcp-server.git
cd fortipam-mcp-server
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python scripts/verify_release.py
```

启动 stdio Server：

```bash
.venv/bin/fortipam-mcp-server
```

本地启动 Streamable HTTP：

```bash
FORTIPAM_MCP_HTTP_AUTH_MODE=none .venv/bin/fortipam-mcp-http
```

未认证 HTTP 模式只能绑定 loopback。远程部署必须使用 HTTPS 和适当的 OAuth 配置。

## 配置

仓库只提供脱敏示例：

- [`.env.example`](.env.example)
- [`config/fortipam.example.json`](config/fortipam.example.json)
- [`deploy/docker/fortipam-http.example.env`](deploy/docker/fortipam-http.example.env)

真实凭据、Token、SSH 私钥、设备地址和客户数据不得提交到 Git。部署方式和安全边界见 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) 与 [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md)。

## 项目结构

- `src/fortipam_mcp/`：MCP Server 实现；
- `plugins/fortipam-security-copilot/`：Codex Plugin 与 FortiPAM Skills；
- `registry/`、`schemas/`：受控动作和管理元数据；
- `tests/`、`evals/`：自动化测试与场景评估；
- `deploy/docker/`：Docker 部署材料。

## 安全报告与 License

安全问题请按 [`SECURITY.md`](SECURITY.md) 私下报告，不要在公开 Issue 中粘贴敏感信息。项目采用 [MIT License](LICENSE)。
