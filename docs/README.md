# Nyx 文档导航

> 文档按功能归类。最新状态始终看 `docs/STATUS.md`(单一事实源)。

## 根目录(操作手册)

| 文件 | 用途 |
|---|---|
| `README.md` | 项目快速入门 — 构建、运行、三终端启动 |
| `CLAUDE.md` | AI agent 工作指南 — 架构、构建命令、代码约定 |
| `CAPABILITIES.md` | 完整能力清单 — 按代码核对的特性矩阵 |
| `PROJECT.md` | 项目愿景和范围 |

## docs/

| 文件/目录 | 用途 |
|---|---|
| `STATUS.md` | **权威状态文档** — 经代码核对的单一事实源 |
| `audits/` | 安全审计报告 + 代码审计(按日期归档) |
| `bypass/` | EDR 绕过模块设计 + 能力报告 + IOC 审计 |
| `design/` | 架构设计文档 — 传输层、加密、内核、T-REX、愿景报告 |
| `research/` | 外部研究资料 — 学术论文、C2 竞品分析、内核 EDR 手册、UI 研究 |
| `testing/` | 测试与验证策略 — Windows 开发指南、真机验证清单、开发交接 |
| `trex/` | T-REX EDR 侦察引擎 — 设计、传输加密、气隙方案 |
| `windows-api/` | Windows API 参考 — VEH、CONTEXT、NTSTATUS 等 |
| `superpowers/specs/` | 功能设计规格(spec-1 ~ 最新) |
| `superpowers/plans/` | 实现计划(UI 重设计、bypass 模块等) |
| `archive/` | 历史文档 — 早期审计、P1/P2 开发计划(参考用) |

## 快速链接

- **传输层设计**: `docs/superpowers/specs/2026-07-14-transport-dispatcher-design.md`
- **C2 竞品对比**: `docs/research/commercial_c2_security_research.md`
- **Windows 构建指南**: `docs/testing/WINDOWS_DEV.md`
- **最新审计**: `docs/audits/CODE_AUDIT_2026-07-10.md`
