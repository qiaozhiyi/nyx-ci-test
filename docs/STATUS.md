# Nyx 当前状态

**更新日期：** 2026-08-08  
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
7. **全量接线波次（2026-08-03，已提交：1826a35 `feat(wiring)`、282007f `fix(smb-listener)`）** — 关闭全部文档化"未接线"项:4 通道 extc2 中继、DoH 权威 DNS 应答器、SMB/TCP pivot 父监听 + implant 门禁翻转、agent-dev 全 profile 消费 + DoH 信道 + SOCKS relay + impersonation 消费、协作上下文与报告闭环(服务端 + UI)。验证:workspace check + test 全绿(server 72+4+13 e2e、transport 111+8、store 29、agent-dev 22);新增 e2e 覆盖 DoH 全 beacon 循环、TCP pivot 交易、SOCKS 全链、协作 API、DNS wire; **SMB listener 运行时验证闭环 + 竞态修复**:Windows-only 命名管道 e2e(`server/tests/smb_pipe_e2e.rs`,真实 CreateFileW 往返 ×2 轮含 re-arm)在 wine 真 Win32 语义下验证通过,并发现/修复 `DisconnectNamedPipe` 丢弃未读 reply 的竞态(`smb_listener.rs` 写后 drain 等待,`PeekNamedPipe` 轮询);测试在 CI Gate 3 windows-latest 原生执行;6 个独立 crate 构建验证全覆盖(Gate 4: kernelsdk/evasionsdk/minidump/offset-resolver/kernel-cli;Gate 6: implant-win selftest + **生产 DLL 双构建**)。
8. **v0.4.0 专项（2026-08-04 设计已批准，spec [2026-08-04-v040-beacon-isolation-crate-split-design.md](superpowers/specs/2026-08-04-v040-beacon-isolation-crate-split-design.md)）** — **WP-A 巨函数拆分已完成**：140 个 >50 行非测试函数全部拆至 <50 行（transport/server/implant-win 三 crate，零行为变更）；含 15 路并行执行 + 15 簇对抗评审 + 终验门禁：全量复扫 0、fmt/clippy `-D warnings`/workspace test 全绿、implant-win 双 feature + nyx_diag 交叉检查 Finished。**WP-B1 VEH 任务守卫已实现**（`task_guard.rs`：链尾 VEH 捕获任务致命故障 → `Response::Err("task crashed: 0x…")` 哨兵，崩溃恢复 + 复位自测 `nyx_selftest_task_guard`，已接入 Qiling 矩阵——rootfs 无 VEH 导出 → skip 标志退出码 0x9；门禁：双 feature 构建 0 告警、fmt 干净、Qiling 矩阵 5/5 PASS）。**WP-B2 任务路径 panic 站点清零已完成（2026-08-08）**：beacon 3× unreachable→Err 哨兵、context panic-free、bof run_entry_addr 上界检查（唯一真实越界，144 处索引全量审计）、coff/fs/trex/screenshot/tp 加固。**WP-C crate 拆分已完成（2026-08-08）**：断环三刀 + 4 rlib + 1 cdylib 壳落地（`crates/implant-core`/`implant-evasion`/`implant-net`/`implant-tasks` + 壳），pub 提升 13 项人工核对、no_mangle 面壳侧保活三重实证、5 路对抗评审零中高危；server_pub 烘焙随 config 下沉 core（spec 条目已修订）；CI Gate 4 纳入 4 个新 standalone crate（AH-13，check+fmt 硬门、clippy report-only 记录既有 lint 债）。明细见 [CHANGELOG [Unreleased]](../CHANGELOG.md#unreleased)。剩余：**B3 BOF 子进程模式**（依赖已就绪的 core crate，设计已批准、待实施）。

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
