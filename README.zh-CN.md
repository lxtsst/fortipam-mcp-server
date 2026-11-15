# FortiPAM Security Copilot MCP Server

[English](README.md)

面向 FortiPAM 状态检查、运维排障、管理规划和显式启用受控工作流的独立自托管 MCP Server。

**当前版本：4.0.0b109（Beta）**。这是预发布版本，不代表生产环境认证。
[下载当前 V4 源码](https://github.com/lxtsst/fortipam-mcp-server/releases/tag/v4.0.0-beta.109)。
由于 V4 是预发布版本，GitHub 可能仍将旧 [v3.1.3](https://github.com/lxtsst/fortipam-mcp-server/releases/tag/v3.1.3)
标为 Latest；V3 不包含 V4 能力。

本项目不是 Fortinet 官方产品，也未获得 Fortinet 背书。
Fortinet 和 FortiPAM 是 Fortinet, Inc. 的商标。

## 主要能力

- 默认提供只读 API 状态检查和固定 SSH 诊断。
- 提供离线 API 检索、运维场景及管理规划。
- 区分 `readonly`、`lab-simulated`、`v4-plan-only` 和 `v4-controlled` Profile。
- 支持 stdio、Streamable HTTP、本地 OAuth 和外部 OAuth Resource Server。
- 已支持的受控工作流采用版本化动作契约、状态漂移检查、有限执行、最小化读回和本地防篡改审计。
- 提供客户端通用的 MCP Resources、Prompts 和可选 FortiPAM 工作流 Skills。

默认 Profile 暴露 28 个只读／离线 Tool。经过认证的 HTTP `v4-plan-only` Profile
暴露 97 个 Tool，不能执行设备变更。`v4-controlled` 仅注册显式绑定且逐项启用的动作；
所有执行 Gate 默认关闭。

## 试用只读示例

[运行离线 MCP 示例](docs/READ_ONLY_EXAMPLE.md)：无需设备或凭据，通过真实 MCP 调用
查询两个 API 操作的风险分类，并获取 FortiAnalyzer 日志投递排查建议。
示例包含预期结果，也说明了配置自有授权设备后如何进行固定状态读取。

## 安装与验证

在 macOS 或 Linux 上使用 Python 3.11 或 3.12，并创建独立环境。
以下仅安装运行依赖，不安装开发测试或可选工作流依赖：

```bash
git clone https://github.com/lxtsst/fortipam-mcp-server.git
cd fortipam-mcp-server
git checkout v4.0.0-beta.109
python3 -m venv .venv
.venv/bin/python -m pip install --constraint deploy/docker/runtime-constraints.txt .
.venv/bin/python -m pip check
.venv/bin/fortipam-mcp-smoke
.venv/bin/fortipam-mcp-http-smoke
```

这些离线检查验证 MCP 初始化、28 个 Tool、5 个 Resource、7 个 Prompt；
HTTP 检查还验证未认证请求被拒绝。检查不连接 FortiPAM 设备。
完整开发与发布检查见[贡献说明](CONTRIBUTING.md)。

项目通过 GitHub 源码 Release 分发。上述命令在本地构建并安装 Python 包，
不依赖已发布的 PyPI 包或 GHCR 镜像。可选工作流插件与 Server 独立编号。

启动默认 stdio Server：

```bash
.venv/bin/fortipam-mcp-server
```

stdio 会等待 MCP 客户端连接，不是交互式终端。支持本地 stdio 的客户端
应将启动命令设为 `.venv/bin/fortipam-mcp-server` 的**绝对路径**，无需参数。

仅在 loopback 启动 HTTP：

```bash
FORTIPAM_MCP_HTTP_AUTH_MODE=none .venv/bin/fortipam-mcp-http
```

支持 HTTP 的 MCP 客户端连接 `http://127.0.0.1:8000/mcp`。
可选插件中的 HTTPS 地址是占位示例，必须替换为自己的部署地址。

远程 HTTP 必须配置 HTTPS 和适当的 OAuth。详见
[部署说明](docs/DEPLOYMENT.md)、[Profile 与兼容限制](docs/COMPATIBILITY.md)及
[安全模型](docs/SECURITY_MODEL.md)。

## 配置

参考 [.env.example](.env.example) 和 [配置示例](config/fortipam.example.json)。
真实配置放在被 Git 忽略、仅文件所有者可访问的本地文件中。
部署者需自行提供有权管理的 FortiPAM 地址、CA 信任、API 身份及单独需要的 SSH 身份。
不得提交凭据、Token、私钥、设备地址、客户数据或原始设备响应。

## 已知限制

动作可用性取决于 Profile、显式绑定、产品版本、身份和所需状态。
源码或目录中存在一个模块，不代表该工作流已可调用或适用于当前部署。
服务账号 Target 创建／恢复存在未确定结果，相关执行保持隔离，更新入口未注册。
HA、批量导入、Terraform、外部身份／MFA，以及依赖原生客户端或硬件的场景仍有未验证范围。
操作结果不确定时，必须先核对状态，不得直接重试。

## 贡献与许可

请参阅 [贡献说明](CONTRIBUTING.md) 和 [安全报告](SECURITY.md)。
源码采用 [MIT License](LICENSE)，不因此授予第三方 API 归档或厂商文档的再分发权利。
仓库提供实现、有限元数据、合成测试和脱敏示例，不提供共享凭据或托管 FortiPAM 服务。
另见[隐私说明](PRIVACY.md)和[使用条件](TERMS.md)。
