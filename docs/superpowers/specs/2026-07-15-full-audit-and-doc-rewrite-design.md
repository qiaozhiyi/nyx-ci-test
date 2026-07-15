# 全量代码审计 + 对外文档重写 设计

- **日期**: 2026-07-15
- **状态**: 已批准路径 A(审计先行,文档随后)
- **背景**: 现有 38 份审计文档(四轮:07-03/07-05/07-08/07-10)覆盖全 crate,但 `docs/STATUS.md`(自称唯一真相源)在 Foliage APC、SPOOF_SWAP、MiniFilter 三条上与代码实情不符。README/CAPABILITIES/CLAUDE 间存在 LOC 数(69K/77K/88K)、测试数(88/119/142/326)、selftest 数(53/54)、gate 默认值等多处漂移。需以代码为唯一依据重新核对,并重写全套对外文档。

## 1. 目标

1. **审计**:从源码重新逐 crate 核对每个能力/开关/状态的真实性,不信任现有审计结论。产出独立审计报告 `docs/audits/CODE_TRUTH_2026-07-15.md`,每条结论附 `file:line` 证据。
2. **文档**:以审计报告为唯一事实源,重写 5 份对外文档,保证互相一致且可追溯到代码。
3. **旧文档**:保留全部 38 份旧审计 + archive 不动,在 `docs/README.md` 索引中标注被 2026-07-15 取代的关系。

## 2. 审计子系统切分(5 路并行)

每路审计 agent 的统一输出契约(写入各自 section,最终汇总):

```
### [crate 名]
| 能力/开关/模块 | 代码实情 | 证据 file:line | 旧文档声明 | 偏差 |
```

代码实情取值:`✅完成并接线` / `🟡部分` / `🔴死代码/废弃` / `默认ON` / `默认OFF` / `🔴损坏`。

### 路线 1 — implant-win(30,848 LOC, 63 文件)
核心 PIC 植入体。覆盖:beacon/entry/kits/sleep/fluctuation/mem/ntalloc/heap/transport/channels/inject/bof/fs/hashdump/keylog/screenshot/recon/pivot/unhook/blind_hwbp/trex/selftests + build.rs。
重点核对:
- Foliage APC 是否死代码(已知:四函数 `#[allow(dead_code)]` + FATAL 注释,实际走 Fluctuation)
- Fluctuation sleep mask 实情 + heap mask 是否保持 ON
- SPOOF_SWAP 完成度(已知:#CP 修复缝 doc-only,f 未在伪造栈执行)
- 9 通道 dispatcher 实接线状态
- 28 个 implant 命令实现状态
- 所有 `NYX_*` runtime gate 的真实默认值与读取点
- selftests.rs 54 个导出的实际覆盖

### 路线 2 — operator-kernelsdk + operator-kernel-cli + offset-resolver(11,311 LOC)
内核层 kit。覆盖:BYOVD/etw_deception/DKOM/minifilter(telemetry)/persistence/netsec/offsets/kernel_base/pattern_scan + CLI + PDB 工具。
重点核对:
- MiniFilter unlink 算法 + flt_globals_kva 解析 + PDB 工具是否端到端接通(已知:基本完成)
- 4 个 BYOVD driver pack 真实可用性(07-10 审计称 3/4 silently broken)
- ETW-TI deception 完成度
- DKOM/PsActiveProcessHead/通知例程回调摘除实情
- PatchGuard 窗口:2-real/1-skeleton 还是旧文档的"3 no-op"
- offset-resolver PDB 下载 + RVA 解析真实现

### 路线 3 — server + protocol + rest + store(7,918 LOC)
团队服务器 + 协议。覆盖:server/lib.rs(beacon listener/session registry/task queue/control API/implant_gen)+ protocol(crypto/framing/msg)+ rest + store(SQLite creds)。
重点核对:
- wire protocol crypto 层(X25519+ChaCha20-Poly1305)实现完整性
- SessionInfo 字段 + 28 Commands + 7 Responses 实际编码路径
- HTTP 路由表 + operator auth 模型
- implant generation(NYX_TEMPLATE)流程实情
- SQLite schema + ACID
- 已知 HIGH:SOCKS5 auth bypass、HTTP-policy gap on /connect(虽属 client-cli,但 server 侧策略要对齐)

### 路线 4 — client-cli + client-ui(20,150 LOC)
操作端。覆盖:client-cli(TUI 4413 行 / rest 3334 / socks / input / render / panes)+ client-ui(Makepad GUI 6337 行)。
重点核对:
- 60+ TUI 命令实际实现状态
- SOCKS5 proxy 实情(已知 HIGH:auth bypass at handshake.rs:72-84)
- /connect HTTP policy gap(已知 at rest.rs:513-517)
- Makepad GUI 启动/连接/会话功能完成度
- 两种客户端的 REST 对齐

### 路线 5 — 支撑 crate 集(~14,000 LOC)
transport(3792)+ profile(1733)+ evasion(261)+ implant-evasionsdk(2028)+ coff(365)+ bof-runner(421)+ nyx-loader(448)+ nyx-mutate(634)+ config(153)+ config-macros(192)+ scripting(237)+ scripting-rhai(166)+ parse(544)+ agent-dev(1181)+ minidump-assembler(469)+ pe(134, dead)。
重点核对:
- 9 通道 transport 层各自完成度(已知:WinHTTP TLS beacon 坏在 WinHttpSetOption 时机)
- JA3/JA4 + HTTP/2 指纹 emitter seam 实情
- malleable C2 profile 解析 + c2lint
- COFF/BOF loader + 重定位(已知 HIGH:BOF section-memory leak at bof.rs:720-815)
- nyx-mutate 变异引擎(NOP/指令替换/寄存器轮转/密钥随机化)实接线
- config-macros 编译期随机化 + 加密
- `pe` crate 确认 dead(零依赖)
- 各 crate 的 NYX_* env 读取点与默认值

## 3. 审计报告结构

`docs/audits/CODE_TRUTH_2026-07-15.md`:
- 头部:日期、分支、commit、方法说明("以代码为唯一依据,不引用旧审计结论")、LOC/测试数实测值(`wc -l` / `cargo test` 统计)
- §0 全局事实表:LOC 实测、crate 数、测试数实测、selftest 导出数实测、NYX_* env 完整清单
- §1–§5:对应 5 路审计,每路一个章节,内含逐 crate 的能力状态表
- §6 偏差汇总:所有"代码实情 ≠ 旧文档声明"的条目集中列出(这是文档重写的事实依据)
- §7 活跃缺陷沿用:从 07-10 审计继承的 20 HIGH / 50 MED / ~59 LOW 清单(标注哪些已被本次核对修正)

## 4. 文档重写(审计完成后)

5 份文档,以审计报告为唯一事实源。重写顺序:STATUS 先行(作为其他文档的事实源)→ 其余 4 份可并行。

### 4.1 `docs/STATUS.md` — 唯一真相状态表
- 保持"single source of truth"声明
- §0 实测全局数据(LOC/测试/selftest/env)——用审计 §0 的实测值,删除所有漂移数字
- §1 完成度总表——以审计逐 crate 结论重算
- §2 能力清单——每条标注代码实情(✅/🟡/🔴/默认ON/OFF)+ file:line
- §3 gate 默认值表——以代码读取点为准,纠正历史"默认 OFF"误称
- §4 易误读条目澄清(Foliage=废/SPOOF=部分/MiniFilter=完成 等)
- §5 已知缺口 G1–G7——以代码核对结果重写(哪些真缺、哪些已由替代技术覆盖)
- §6 活跃缺陷表——沿用审计 §7
- 引用 `CODE_TRUTH_2026-07-15.md` 作为证据来源

### 4.2 `README.md`(根)— 开发者上手指南
- 功能概览(精简,指向 STATUS/CAPABILITIES)
- 项目结构(实测 LOC/crate 数)
- 环境要求 + 快速上手(server/dev-implant/Win-PIC/TUI/GUI)
- 服务器环境变量表(以审计 §0 env 清单为准)
- TUI 命令速查(以审计 client-cli 结论为准)
- 内核层操作 + 偏移自动解析
- 构建与测试(实测命令)
- 已知限制(以审计 §6 偏差为准)
- Roadmap + 免责声明

### 4.3 `CAPABILITIES.md` — 能力矩阵
- 9 章结构保留
- 每个能力条目以代码核对结果重生成(完成度 + file:line)
- 删除与 STATUS 重复的状态叙述,改为引用 STATUS 对应章节

### 4.4 `CLAUDE.md` — AI 开发指南
- 架构总览 + crate 角色(以实测为准)
- build/conventions(以审计 build.rs + NYX_* env 结论为准)
- 更新 gate 默认值、Foliage/SPOOF/MiniFilter 三条澄清
- 指向 STATUS 为状态唯一源

### 4.5 `docs/README.md` — 文档索引
- 列出所有 docs 子目录及用途
- **标注取代关系**:07-03/07-05/07-08 审计标注"已被 2026-07-15 CODE_TRUTH 取代,仅作历史参考";07-10 标注"安全发现仍有效,状态结论以 07-15 为准";archive 标注"历史/非权威"
- 指向 STATUS 为状态唯一源

## 5. 执行顺序

1. **阶段一(并行)**:5 路 agent 只读审计 → 汇总成 `CODE_TRUTH_2026-07-15.md`。不改任何代码。
2. **阶段二(串行先行)**:基于审计报告重写 `STATUS.md`。
3. **阶段三(并行)**:基于 STATUS + 审计报告重写 README/CAPABILITIES/CLAUDE/docs-README。
4. **阶段四**:一致性校验——5 份文档间数字/状态/gate 值交叉核对,确保零漂移。

## 6. 不做的事

- 不修改任何 `.rs` 源码(纯文档任务)
- 不删除/移动旧审计文档(只标注)
- 不重写 docs/design、docs/research、docs/trex、docs/testing、docs/windows-api(这些是设计/研究参考,非对外状态文档)
- 不重写 `ECC技能命令完全参考手册.md`(独立关注点)
- 不动 `.claude/agents/`(运行时配置)

## 7. 验收标准

- `CODE_TRUTH_2026-07-15.md` 覆盖全部 25 个活跃 crate,每条结论有 file:line
- 5 份重写文档间 LOC/测试数/selftest 数/gate 默认值零漂移
- Foliage/SPOOF/MiniFilter/TLS beacon 四条在所有文档中口径一致
- `docs/README.md` 明确标注每份旧审计的取代关系
- STATUS.md 不再包含与代码矛盾的声明
