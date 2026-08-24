# EDR 量化记录矩阵 —— "技术 × EDR × 告警量" 记录框架

> **目的:** 把 ARM64 VM 演练从"Defender 检出 / 未检出"的二元结论升级为
> **每种 evasion/注入技术 × 每个 EDR × 告警量** 的量化记录，支撑
> `docs/research/frontier_gap_analysis_2026-08-21.md` §2 P0 行
> （"多 EDR 量化验证缺失"），并作为 Q3 整改 L4 层（受支持环境回归）在
> EDR 维度的证据载体。
> **本轮交付:** schema + 记录模板 + 采集脚本（`scripts/edr_matrix_record.sh`）。
> 真 EDR 矩阵实测需要 VM 环境，属后续执行；本文档中 Nyx 自有数据一律标 **待实测**，
> 不含任何虚构数据。

---

## 1. 记录 schema

**一条记录 = 一次"技术 × EDR"实测**（同一技术在同一 EDR 上重复实测 = 多条记录，按日期区分）。

| # | 字段 | 类型 | 说明 |
|---|---|---|---|
| 1 | `date` | YYYY-MM-DD | 实测日期 |
| 2 | `technique` | 枚举 | Nyx 技术名：`module_stomp` / `threadless` / `pool_party` / `fls_callback` / `fluctuation` / `hwbp_blind` / `indirect_syscall`（新增技术追加枚举） |
| 3 | `edr_name` | 字符串 | EDR/AV 名称，如 `Microsoft Defender` |
| 4 | `edr_version` | 字符串 | EDR 版本。Defender 取 `Get-MpComputerStatus` 的 `AMProductVersion`；脚本自动采集 |
| 5 | `delivery_context` | 枚举 | 投递上下文：`dll-sideload` / `exe` / `other`（注明） |
| 6 | `samples` | 整数 | 样本数（重复执行次数） |
| 7 | `successes` | 整数 | 成功数（技术动作完成且载荷执行/回连） |
| 8 | `success_rate` | 百分比 | = successes / samples，脚本自动计算 |
| 9 | `alerts` | 整数 | 告警数 = 实测前后 `Get-MpThreatDetection` + `Get-MpThreat` 计数差值 |
| 10 | `env_limit` | 枚举 | 环境限制，**强制字段**，见 §2 |
| 11 | `evidence` | 路径/URL | 证据链接：相对路径指向回收的日志/CSV，如 `.agents/orchestrator/win_run_20260810_*/selftest_run.log` |

### 1.1 CSV 形态（机器可读，追加式）

文件默认位于 `.agents/orchestrator/edr_matrix.csv`，列定义（首行表头）：

```csv
date,technique,edr_name,edr_version,delivery_context,samples,successes,success_rate,alerts,env_limit,evidence
```

空值规则：未采集的字段留空，**不得**填 0 冒充实测（0 告警必须是真实测出的 0）。

### 1.2 Markdown 表形态（报告引用用）

```markdown
| 日期 | 技术 | EDR（版本） | 投递上下文 | 样本数 | 成功率 | 告警数 | 环境限制 | 证据 |
|---|---|---|---|---|---|---|---|---|
```

## 2. 强制口径：环境限制字段与 L4 层

`env_limit` 枚举值：

| 值 | 含义 |
|---|---|
| `无` | 真 x64 或全功能环境，无已知降级 |
| `Prism 仿真降级` | ARM64 VM x64 仿真下运行：间接 syscall gadget 路径被 Prism 拒（0xC000026F）→ 直调降级；fluctuation 降级为纯 sleep |
| `无 CET` | 仿真/当前环境不存在 CET shadow stack，CET 相关结论不成立 |
| `EDR 未装` | 目标 EDR 未安装，本条不构成对该 EDR 的实测 |
| `Defender 已关闭` | 第二遍对照（实时保护关），仅用于区分功能 bug 与检测拦截 |
| `环境阻塞-其他` | 注明具体阻塞原因 |

**口径（引用 `docs/design/NYX_REMEDIATION_PROGRAM_2026Q3.md` §3.1 :44 原文）：**
"测试环境限制必须在结果中显式记录……'环境阻塞'不能误记为产品测试失败或测试通过。"
落实为本矩阵的两条规则：

- 每条记录 **必须** 填 `env_limit`，即使是 `无`；留空视同违规。
- 环境阻塞/降级下的实测结果只证明该环境下的表现，**不得外推**为真 x64 / 有 CET 环境的
  结论；跨环境外推需要对应环境自己的记录行。

**与 L4 层的关系：** L4（受支持环境回归，稳定版发布必须通过，同文件 :42）目前缺少
EDR 维度的量化证据——现有演练只有 Defender 二元结论。本矩阵是 L4 在 EDR 维度的
记录格式：稳定版发布前，首版矩阵（§3）中每项技术至少应有一行 `env_limit=无`
或显式标注降级的实测记录。

## 3. 首版矩阵：Nyx 技术 × Microsoft Defender（待实测）

目标环境：ARM64 VM（Parallels Win11 24H2, build 26100）+ Defender 实时保护 ON。
**全部为占位行，无一经过本框架实测。**

| 状态 | 技术 | EDR | 投递上下文 | 成功率 | 告警数 | 预期环境限制 |
|---|---|---|---|---|---|---|
| 待实测 | module_stomp | Microsoft Defender | exe | — | — | Prism 仿真降级 |
| 待实测 | threadless | Microsoft Defender | exe | — | — | Prism 仿真降级 |
| 待实测 | pool_party | Microsoft Defender | exe | — | — | Prism 仿真降级（另需构建期 `NYX_POOL_PARTY_ON=1`） |
| 待实测 | fls_callback | Microsoft Defender | exe | — | — | Prism 仿真降级 |
| 待实测 | fluctuation | Microsoft Defender | exe | — | — | Prism 仿真降级（仿真下退化为纯 sleep，测的是降级路径） |
| 待实测 | hwbp_blind | Microsoft Defender | exe | — | — | Prism 仿真降级 + 无 CET |
| 待实测 | indirect_syscall | Microsoft Defender | exe | — | — | Prism 仿真降级（gadget 路径被拒 → 直调降级，测的是降级路径） |

> 后续每新增一个 EDR（真 x64 主机 + 第三方 EDR），整表按 EDR 维度复制一套行。
> 2026-08-10 演练的既有结论（Defender 全程 0 检出）是**全链路聚合**结果，不可拆算到
> 单技术，故不回填本表；其口径说明见 `vm-arm64-verify-2026-08-10.md` §10。

## 4. 外部基线参照（非 Nyx 实测）

> ⚠️ **以下为外部数据**：AutoBypass（arXiv 2608.01639）Table 11/12，
> 5 个 AV/EDR 聚合、其自有样本集与投递链，**非 Nyx 实测，环境与技术实现均不同**。
> 仅作数量级参照（哪种技术天然高告警），不得与 §3 的 Nyx 行直接比大小。

### 4.1 技术 × 成功率 / 告警量（AutoBypass Table 11）

| 技术（AutoBypass 命名） | 成功率 | 告警数 | 与 Nyx 的近似对照 |
|---|---|---|---|
| module_overload | 74.3% | 9 | ≈ module_stomp 族（实现不同） |
| remote_thread_hijack | 62.1% | 18 | —（Nyx 无对应） |
| fls_callback | 60.0% | 14 | 同名技术（WP-A 已实装，inject method 3） |
| threadless | 56.5% | 56 | 同名技术（inject method 1） |
| ekko_sleep | 55.2% | 67 | ≈ fluctuation 族（睡眠混淆） |
| etw_patch | 54.2% | 173 | 字节补丁路线 —— Nyx 以 hwbp_blind（patchless）替代的依据之一 |
| unhook_ntdll | 51.4% | 139 | LiveUnhook 类 —— Nyx 维持 opt-in 不默认启用的依据 |
| hells_gate | 49.1% | 90 | ≈ indirect_syscall 族 |

### 4.2 投递上下文（AutoBypass Table 12）

| 投递上下文 | 成功率 |
|---|---|
| DLL sideload | 52.3% |
| 独立 EXE | 37.4% |

→ 本矩阵 `delivery_context` 字段单独立项的原因：同一技术在不同投递上下文下
检测面不同，记录时必须分开成行。

## 5. 每种技术的实测操作方法

触发方式有两类：**selftest 导出**（自包含、可脚本化，优先）与
**operator 命令**（真 C2 会话里驱动，测的是完整链路）。inject method 编号表见
`crates/implant-tasks/src/inject.rs` `do_inject`（:1397 起）：

- method 0 = Pool Party（构建期 `NYX_POOL_PARTY_ON=1` 门控 + 必须 `pid≠0`；失败自动降级 method 2 并带 WARN 前缀）
- method 1 = threadless HWBP（仅牺牲进程路径，`pid=0`）
- method 2 = module stomp（`pid=0` 牺牲进程）/ classic remote thread（`pid≠0` 现有进程变体）
- method 3 = FLS callback（2026-08-21 新增，`pid≠0` 现有进程或 RUNNING 牺牲进程）

| 技术 | selftest 导出 | operator 命令 | 实测要点 |
|---|---|---|---|
| module_stomp | `nyx_selftest_inject_armed`（真 stomp 全路径） | `inject 0 <hex> 2`；`inject <pid> <hex> 2` 走现有进程变体 | 目标进程必须 x64（仿真进程），不可注入 ARM64 原生进程 |
| threadless | 无专用导出（`nyx_selftest_inject` 只建牺牲进程不注入） | `inject 0 <hex> 1` | 仅牺牲进程路径；必须真 C2 会话驱动 |
| pool_party | `nyx_selftest_inject_pool`（导出内强制 gate ON；不在 `win_selftest_all.ps1` 期望码表内，按 best-effort 记录） | `inject <pid> <hex> 0`（需构建期 gate + pid≠0） | 响应含 `WARN: Pool Party` 前缀 = 已降级 method 2，本条应记为 pool_party 失败而非成功 |
| fls_callback | `nyx_selftest_inject_fls`（RUNNING notepad 牺牲进程 + 1 字节 ret 探针） | `inject <pid> <hex> 3` 或 `inject 0 <hex> 3` | 牺牲进程必须 RUNNING（suspended 无 kernel32 映射） |
| fluctuation | 无独立导出；经真 C2 beacon 正常 sleep 路径触发（evasion 入口 `nyx_entry`） | `sleep <秒>` 后观察 beacon 存活与告警 | ARM64 仿真下降级为纯 sleep，`env_limit` 必须标 `Prism 仿真降级` |
| hwbp_blind | `nyx_selftest_hwbp_blind`（diag 标记路径，出口码 0xFF=全过） | evasion 入口 bootstrap 自动执行（`blind_etw_hwbp` / `blind_amsi_hwbp`） | patchless，无字节补丁；对照外部 etw_patch 173 告警 |
| indirect_syscall | `nyx_selftest_syscall_rt`（间接 trampoline 实调 NtClose） | evasion 入口下任意走 syscall 的任务 | 仿真下 gadget 路径被 Prism 拒（0xC000026F）→ 直调降级；测得的是降级路径，如实记录 |

**单导出触发命令**（DLL 已 `win_remote_run.sh build` 上传到 `C:\nyx` 后）：

```bash
ssh <vm> "rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_inject_fls" ; echo "exit=$?"
```

## 6. 采集脚本用法

`scripts/edr_matrix_record.sh`：在目标 Windows 机（VM 或服务器）上按"前置快照 →
触发技术 → 后置快照"采集 `Get-MpThreatDetection` / `Get-MpThreat` 计数差值，
按 §1.1 schema 追加一行到本地 CSV（默认 `.agents/orchestrator/edr_matrix.csv`）。
**hosted-runner 版（2026-08-24）**：`scripts/edr_matrix_hosted.ps1` 由
`.github/workflows/windows-hosted-verify.yml` 的 `edr-matrix` job 调用——runner 即
目标机（原生 x64，无 Prism 降级），Defender 实时保护由 job 反开，触发改走
nyx-bof-isolated-probe 控制台线束（rundll32 在 Session 0 不可用）。CSV 为 artifact
保留 90 天；回填本文件 §3 时从最近成功 run 取数，evidence 列即 run URL。

```bash
# selftest 导出驱动（自动算告警差值）：
WIN_HOST=win ./scripts/edr_matrix_record.sh record \
    --technique fls_callback --edr "Microsoft Defender" \
    --context exe --export nyx_selftest_inject_fls \
    --samples 1 --successes 1 --env-limit "Prism 仿真降级" \
    --evidence .agents/orchestrator/win_run_latest/selftest_run.log

# operator 手动驱动（告警数人工观察后回填）：
WIN_HOST=win ./scripts/edr_matrix_record.sh record \
    --technique fluctuation --edr "Microsoft Defender" \
    --context exe --no-trigger --alerts 0 \
    --samples 1 --successes 1 --env-limit "Prism 仿真降级"
```

详细参数见脚本文末用法注释。Defender 版本号由脚本经 `Get-MpComputerStatus`
自动采集，无需手填。
