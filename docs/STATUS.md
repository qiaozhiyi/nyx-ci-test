# Nyx 当前状态

**更新日期：** 2026-08-03  
**用途：** 本文件是项目能力状态和整改进度的入口；遇到旧报告或 README 表述冲突时，以当前代码、CI 结果和本文件链接的审计记录为准。

## 能力状态口径

| 状态 | 含义 |
|---|---|
| 已交付 | 在受支持环境中通过端到端验证，限制已文档化 |
| 受限交付 | 可用，但存在明确的平台、功能或运维限制 |
| 实验性 | 仅局部测试或研究验证；不得视为稳定发布能力 |
| 规划中 | 尚未进入受支持工作流 |

## 当前总体结论

| 领域 | 当前状态 | 依据 |
|---|---|---|
| 协议与服务端基础 | 已交付 | [`AUTHORITATIVE_FACTS_2026-07-18.md`](audits/AUTHORITATIVE_FACTS_2026-07-18.md) §1;2026-07-31 修复冲刺:contributory X25519 拒绝低阶点(`protocol/src/crypto.rs:222-248,302-319,370-386`)、encode 侧 `MAX_CT_LEN` 上限、`FileOp::Ls` wire tag 5、kill-date 严格校验(`server/src/implant_gen.rs:258-268`)、任务分批 ≤ 上限、Slack HMAC key fail-closed boot(`server/src/extc2_relay.rs:381-413`) |
| 存储、传输与 Windows 端 | 受限交付 | 同上;2026-07-31 修复冲刺:`mask_secret` char 化(`store/src/model.rs:73-82`)、token 消费原子 fail-closed、session_store schema 迁移(`send_counter`/`last_recv`);**2026-08-03 接线波次:全部 4 个 extc2 中继( Slack/LLM/Discord/MCP)接入 boot-time `TransportStack`(`extc2_relay.rs`),alias 路由删除;DoH 权威 DNS 应答器(`dns_responder.rs`:RFC 8484 JSON `/dns-query` + UDP/53 wire,`NYX_DOH_DOMAIN`/`NYX_DOH_UDP_ADDR`);SMB/TCP pivot 父监听器(`smb_listener.rs` Windows-only + `tcp_pivot.rs`),implant `SmbPipe`/`Tcp` 门禁翻转(配置缺省时 SetChannel 拒)**;**loader 反射加载真实 layer-2 已接线并经**真机验证**(2026-08-02:pic-loader + `loader-probe-exe` CreateThread 探针,DllMain marker 证实,免费 GitHub 托管 windows-latest runner;CI Gate 5 Unicorn 仿真探针守护回归) |
| UI 与操作体验 | 受限交付 | 基础界面可用;2026-08-03 接线波次补齐 **协作上下文 v1**(会话归属/移交 `POST /api/session/owner` + 操作员名册 `GET /api/operators` + SessionTable owner 选择器,store schema v4)与 **报告闭环**(`GET /api/report` markdown 快照 + 设置页导出);设置页启用(Dock 按钮 + profile 展示);拓扑去掉 MOCK 演示数据改诚实空态;死 placeholder CSS 删除;2026-07-31:任务历史按 session 隔离(App 级 store)、结果带 `session_id`、pending 任务过期 |
| 研究性实现 | 实验性 | 未接线、stub 或缺少端到端验证的实现不作为稳定能力宣传;TLS 指纹 emitter 已接线(`nyx-agent-dev --features impersonation` + `NYX_IMERSONATE` 消费 `build_impersonating_client`,CI Gate 7 编译 + 线上 JA3 验证) |
| 发布工程 | 整改中 | 见下方工程计划与 CI 门禁 |

## 进行中的整改

1. [工程化整改计划（2026 Q3）](design/NYX_REMEDIATION_PROGRAM_2026Q3.md)
2. [维护性审计（2026-07-23）](audits/ANTI_HUMAN_AUDIT_2026-07-23.md)
3. [长期路线图](design/ROADMAP_2026-2027.md)
4. **修复冲刺（2026-07-31，已合入当前分支 `refactor/ah-audit-followups`）** — 协议 / 存储 / 内核 daemon / nyx-loader / implant / bof-runner / agent-dev / server / UI / scripting-rhai / config-macros / transport / offsets 共 13 个工作包;验证:workspace check + test 全绿(`nyx-server` 72、`nyx-transport` 109、`nyx-protocol` 49、`nyx-store` 28)。明细见 [CHANGELOG [Unreleased]](../CHANGELOG.md#unreleased)。
5. **Loader 波次（2026-08-02，已提交）** — 真实 Layer-2 反射加载接线(pic-loader no_std PIC)+ **真机验证 PASS**(`crates/loader-probe-exe` CreateThread 探针,DllMain marker 证实)+ Unicorn 仿真探针(CI Gate 5)+ Qiling 无头 selftest 门禁(CI Gate 6)+ 发布管线迁移到 GitHub 托管 runner(selftest 门禁带 notice 跳过)。
6. **Zero-leftover sweep（2026-08-02，已提交）** — 注入 / 键录 / 内核中继 / 服务端 GC / 传输 / 偏移单一来源 / 模式扫描 / 文档 8 个工作包;本文件与 README / CHANGELOG / 基准评测文档同步更新。
7. **全量接线波次（2026-08-03，待提交）** — 关闭全部文档化"未接线"项:4 通道 extc2 中继、DoH 权威 DNS 应答器、SMB/TCP pivot 父监听 + implant 门禁翻转、agent-dev 全 profile 消费 + DoH 信道 + SOCKS relay + impersonation 消费、协作上下文与报告闭环(服务端 + UI)。验证:workspace check + test 全绿(server 72+4+13 e2e、transport 111+8、store 29、agent-dev 22);新增 e2e 覆盖 DoH 全 beacon 循环、TCP pivot 交易、SOCKS 全链、协作 API、DNS wire; **SMB listener 运行时验证闭环**:Windows-only 命名管道 e2e(`server/tests/smb_pipe_e2e.rs`,真实 CreateFileW 往返)在 CI Gate 3 windows-latest 原生执行;6 个独立 crate 构建验证全覆盖(Gate 4: kernelsdk/evasionsdk/minidump/offset-resolver/kernel-cli;Gate 6: implant-win selftest + **生产 DLL 双构建**)。

## 近期发布门禁

- Rust 工作区与独立包的格式、静态检查和测试；
- UI 的锁文件依赖安装与生产构建；
- 对 GitHub 托管 runner 与真实环境(真机 P4-P5、loader 真机探针)的明确结果记录;
- 发布内容与已知限制同步进入发行说明。

## 文档生命周期

- 本文件与 `docs/design/NYX_REMEDIATION_PROGRAM_2026Q3.md`：当前执行口径。
- `docs/audits/`：审计时点快照，需以日期和后续变更判断时效。
- `docs/testing/`：验证策略与环境结果。
- `docs/research/`：研究材料，不代表产品承诺。
