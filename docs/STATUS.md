# Nyx 当前状态

**更新日期：** 2026-08-16  
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
8. **v0.4.0 专项（2026-08-04 设计已批准，spec [2026-08-04-v040-beacon-isolation-crate-split-design.md](superpowers/specs/2026-08-04-v040-beacon-isolation-crate-split-design.md)）** — **WP-A 巨函数拆分已完成**：140 个 >50 行非测试函数全部拆至 <50 行（transport/server/implant-win 三 crate，零行为变更）；含 15 路并行执行 + 15 簇对抗评审 + 终验门禁：全量复扫 0、fmt/clippy `-D warnings`/workspace test 全绿、implant-win 双 feature + nyx_diag 交叉检查 Finished。**WP-B1 VEH 任务守卫已实现**（`task_guard.rs`：链尾 VEH 捕获任务致命故障 → `Response::Err("task crashed: 0x…")` 哨兵，崩溃恢复 + 复位自测 `nyx_selftest_task_guard`，已接入 Qiling 矩阵——rootfs 无 VEH 导出 → skip 标志退出码 0x9；门禁：双 feature 构建 0 告警、fmt 干净、Qiling 矩阵 5/5 PASS）。**WP-B2 任务路径 panic 站点清零已完成（2026-08-08）**：beacon 3× unreachable→Err 哨兵、context panic-free、bof run_entry_addr 上界检查（唯一真实越界，144 处索引全量审计）、coff/fs/trex/screenshot/tp 加固。**WP-C crate 拆分已完成（2026-08-08）**：断环三刀 + 4 rlib + 1 cdylib 壳落地（`crates/implant-core`/`implant-evasion`/`implant-net`/`implant-tasks` + 壳），pub 提升 13 项人工核对、no_mangle 面壳侧保活三重实证、5 路对抗评审零中高危；server_pub 烘焙随 config 下沉 core（spec 条目已修订）；CI Gate 4 纳入 4 个新 standalone crate（AH-13，check+fmt 硬门、clippy report-only 记录既有 lint 债）。**B3 BOF 子进程隔离已完成（2026-08-08，受限交付）**：新 standalone crate `crates/bof-host`（no_std cdylib → PIC blob `bof-host.bin` 14646 字节、入口 `nyx_bof_host_entry` @ offset 0、0 基址重定位；COFF 加载核心自 bof.rs 抽取，BeaconPrintf→继承 stdout 管道，ExitProcess 码约定；无写静态：stateless HeapAlloc 分配器 + match 式 shim 表 + TEB ArbitraryUserPointer 参数暂存；`BeaconGetSpawnTo` 返回只读 "cmd.exe"（static 数组；mergeable 常量触发 LLVM anchor thunk，共享 dumper 已支持 lea 取址跟随））；`regen.sh` + 复用 pic-loader dumper（entry 参数化）生成 bin 并提交入库；共享 decoder 放宽 LEA disp32 常量豁免 + lea 取址 BFS 跟随（anchor thunk 可达），pic-loader regen 无回归。协议 `Command::Bof.isolate` wire 尾部可选标志字节（新旧双向兼容 4 测试），server batch packer 强制 isolate BOF 独占帧尾（单测 3 场景）；implant 侧 `bof_isolated`（牺牲进程变体：继承 stdout 管道 + 挂起 CreateProcessW + section 投递 + 主线程 hijack），交错回收（PeekNamedPipe 100ms 切片边等边排空、60s 总预算 kill、EOF 排空 → BofOutput、退出码/崩溃/超时 → Err、1 MiB 输出上限超限排空丢弃、RAII 防泄漏），pre-launch 失败 WARN 回退内联。自测 `nyx_selftest_bof_isolated`（bof_print.o 管道回收 + 新 fixture `bof_crash.o` null 写崩溃断言 + CreateProcessW 缺失 → skip 0x9）；**Qiling 矩阵 6/6 PASS（本地真实验证）**；真机验证自动化：windows-ci 新增 `nyx-bof-isolated-probe`（console 进程，hosted runner 可跑，期望 exit 7；wine 根因实证：其 syscall 分派基于 RIP 反查 stub、不认 eax/SSN，间接 syscall 无法在 wine 全链验证）。**AH-13 clippy 债清理已完成（2026-08-08）**：core/evasion/net/win 四 crate 机械清理（transmute 注解、`?` 转换、迭代器转换等，零行为变更）+ rustdoc #Safety 补齐 + implant-win build.rs kernel-offsets 烘焙移除（自始无消费方，偏移单一来源为 evasionsdk 运行时表，spec §5 修订注记 + 历史文档引用已同步）。明细见 [CHANGELOG [Unreleased]](../CHANGELOG.md#unreleased)。

9. **ARM64 VM 全链路实证 + 生成管线根因修复（2026-08-10/11，已在 main）** — Parallels Win11 ARM64（build 26100，Prism x64 仿真，中文系统，Defender 实时保护 ON）全链路演练：generate-implant → beacon 回家 → 用户层任务面（shell/文件/截屏/剪贴板/keylog/portscan/BOF 内联+隔离/hashdump/getuid/trex）全绿、0 检出（[报告](testing/vm-arm64-verify-2026-08-10.md)）。根因修复：fat LTO 常量折叠吞 `.nyx_cfg` 补丁（b94a158，此前 generate-implant 产出全为回连 127.0.0.1 的死 implant，已实证回连）、Prism 间接 syscall 仿真探测 + 直调降级（87d8ade）、getuid 三个 x64 ABI bug；shell OEM/GBK→UTF-8 转码 + 内建 cd/pwd（dc9094c）、fileop 相对路径跟随 beacon CWD（23cf714）、GUI 交互 10 项修复（e2f9fe9）、BOF/upload 原生文件选择器 + 结果内存治理（ae9def4）、「文件」Dock 页（de06636）。已知残留：**全 evasion 入口 `nyx_entry` 仿真崩溃已修复（2026-08-13，c2525de）**——真凶经 E1 二分实证为 HookChain IAT 重定向安装的间接 syscall stub 在仿真下触发 0xC000026F（与 `syscalls::Runtime::direct` 同机制）；仿真下 HookChain 整体跳过、HWBP 降级 byte-patch（WoA WoW64 不投递调试寄存器，llvm/llvm-project#80665）、RSP swap 不武装；生成 implant 全 evasion 入口实证回家 + shell 任务回环（Win11 build 26200，Defender ON）；内核层（HVCI/PatchGuard/驱动，2026-08-13 零成本路径实证）：**驱动无关内核评估已免费常跑**——`nyx-kernel assess --user` 硬门（NtQuery 真内核数据）在 hosted windows-latest 上 PASS；**BYOVD RTCore64 在全部免费 hosted 镜像上被实证拦截**（windows-2022 镜像 20260802.262 上 `NtLoadDriver` 返回 0xC0000034——WDAC CI 策略直接执行 blocklist，注册表开关未设仍生效；`windows-byovd-hosted.yml` 已改为尝试加载 + loaded 状态门禁硬 gate + 诚实 skip）；**免费驱动层路径候选 = WDTKernel.sys（Dell，WHQL 签名，LOLDrivers `LoadsDespiteHVCI: TRUE`，不在 blocklist）**——kernelsdk 已有 `byovd_drivers/wdtkernel.rs` 实现（phys-only：MmMapIoSpace 物理读写，需 VA→PA 组合），下一工作包：Update Catalog 取二进制 + CLI phys 模式接线 + CI 真机验证；**HVCI 开状态矩阵暂无零成本环境**（GitHub 标准 runner 无嵌套虚拟化，嵌套 virt 属付费大规格）——有环境时用 `scripts/kernel-lab/`（Trusted Launch 包已备，pay-as-you-go）。

10. **内核/睡眠混淆四问题专项修复（2026-08-14，已提交 0d4a202）** — (1) **Foliage APC 死代码清零**：执行器早于 841ffc5 删除，本轮删残留模型（evasionsdk `foliage.rs`/`apc.rs`）+ 废弃入口 + 失效注释，`kits.rs` 误名 `Foliage`→`Fluctuation`，存活路径 beacon→`kits::sleep`→`fluctuation::sleep` 不变（evasionsdk 47 测试绿）；(2) **PatchGuard 占位偏移离线证伪**：三个 ntkrnlmp.pdb（19041.1023/22621.1778/26100.1742）实证 `_KPRCB+0x190` = `LastExceptionToRip`（非指针），0x190 占位确定性证伪（证据在 `offsets.rs` 注释），allow-list 门仍 OFF，真值需 live-kernel dump，Peekaboo 仍是出货路径；(3) **WFP kit 实装**：pid→image-path→`FwpmGetAppIdFromFileName0`→单条件 `ALE_APP_ID` block filter（SDK 全布局修正，零条件 filter 不可能构造，P0-9 钉测试），tier 已接线（`wfp=true`），**2026-08-16 ARM64 VM 端到端已验**（`wfp-selftest` baseline→blocked→restored 全过；真机抓到并修复两个 mock 盲区 bug：`FWP_E_NULL_DISPLAY_NAME` + 默认会话 filter 持久化残留，见第 12 条）；(4) **WDT 免费验证链**：CR3 扫描抽 `cr3_scan.rs` 并修块边界漏针 bug（+8 mock-phys 测试，159 全绿），`check_byovd_blocklist.py` 离线门本机 PASS（WDT 不在微软 blocklist / RTCore64 阳性对照），CI 新增 `blocklist-gate` + `byovd-wdt`（windows-2022 免费 runner，SHA256 钉 + loaded 硬门）。明细见 [CHANGELOG [Unreleased]](../CHANGELOG.md#unreleased)。

11. **BYOVD 驱动包换血（2026-08-16）** — **删除**：RTCore64（CI 实测全部 hosted 镜像 WDAC 拦截，`NtLoadDriver` 0xC0000034）与 iqvw64e（2023 年起在名单）整文件移除，`raw_rw` 改为 trait 必需方法；**默认驱动**：Shield（clean，VA 任意 memcpy）；**新增第二条 clean phys 路径 ALSysIO64**（CPUID CPU-Z，LOLDrivers `4d365dd0`）：对 v2.0.8.0/v2.1.0.0 两个样本静态逆向 dispatch（jump-table 直接解码，非猜测）实证 v2.0.x 的 `0x9C402618/0x9C40261C` 物理读写臂存在、**v2.1.0.0 已删除**（落 STATUS_NOT_IMPLEMENTED 默认臂）——CI 钉死 v2.0.8.0 SHA256 `7196187f…`；`win::alsys` 复用 CR3 扫描 + MZ 验证骨架（`wdt::bootstrap_phys_with` 泛化），CLI `--alsysio` 臂，`KernelBootstrap::Alsys` 变体；blocklist-gate 新增 A5（名 + 双 SHA256 缺席）/B3（LOLDrivers 钉样本在场），`windows-byovd-hosted.yml` 新增 `byovd-alsysio` job（真机加载 + assess 硬门）。kernelsdk 168 host 测试全绿 + windows target 0 警告。HVCI-on 矩阵按决策放弃（无零成本环境）。

12. **WFP kit ARM64 VM 端到端验证 + 两个真机 bug 修复（2026-08-16）** — Parallels Win11 ARM64（26100，Prism x64 仿真，SYSTEM 通道）跑 `nyx-kernel wfp-selftest`：**baseline→blocked→restored 全过、无残留**。e2e 抓到两个 mock 测试盲区 bug 并已修复：(1) `FwpmFilterAdd0` 拒绝 `displayData.name=NULL` 的 filter（`FWP_E_NULL_DISPLAY_NAME` 0x80320023）——filter 现带静态名 "NyxWfpKit"；(2) `FwpmEngineOpen0` 传默认会话导致 filter **持久化残留**（guard drop 后仍 blocked，重启才清除）——会话改为 `FWPM_SESSION_FLAG_DYNAMIC`（新增 `FwpmSession0` SDK 布局 + 偏移钉测试 `wfp_session0_layout_matches_sdk`），关会话即清 filter，无残留契约成立。kernelsdk 169 测试全绿。

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
