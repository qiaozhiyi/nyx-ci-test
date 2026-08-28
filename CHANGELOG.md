# Changelog

All notable changes to the Nyx C2 framework are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0` is treated as a pre-release internal state that was never officially tagged;
`0.2.0` is the first shipped release. Entries cite the originating commit short-SHA so
operators can `git show` the exact change. Evidence is authoritative over prose — when
this file and the code disagree, the code wins.

## [Unreleased]

2026-08-28 hosted-fix（CRT3 sleeper + WFP 出站 + probe `--hold-tp`；Pool Party 证据待下次 nyx-ci-test）：

- **Pool Party**：hosted 已绿。Windows CI [33141408224](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33141408224) `inject_pool` 出口 3 PASS；Hosted Verify [33141405429](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33141405429) 矩阵 **pool_party 100.0%**（8/8 技术 100%、0 告警）；Win BYOVD [33141406810](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33141406810) 含 WFP 全绿。通过码是 0x3（spawn+ok），不是 0x7。
- **WFP**：hosted `blocked=false` 是 loopback 分类（IS_LOOPBACK / RECV_ACCEPT PERMIT），不是缺 filter。`wfp-selftest` 现测出站 `1.1.1.1:443`（回退 `8.8.8.8`/`9.9.9.9`；无出口记 `env_limit` 退出 6）。Win BYOVD [33136778239](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33136778239) 已绿。

2026-08-28 Windows 用户态收口（文档口径，不编造 CI 数字）：

- **探针覆盖（已有 hosted 证据）**：nyx-ci-test `windows-closeout` — Hosted Verify [33135025777](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33135025777) 与 Windows CI [33135028358](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33135028358) 全绿。`vad`/`inject_threadless`/`fluctuation` 出口 7；`cfgstage` 未补丁 `0x41`；`inject_pool` Windows CI 为 0x9 env-skip，矩阵 pool_party 仍 0.0%（WARN 降级）。Win BYOVD [33135027007](https://github.com/qiaozhiyi/nyx-ci-test/actions/runs/33135027007) 的 wfp-selftest 仍 `blocked=false`（operator kit，非 implant）。
- **PIC `bof-host` inject 刻意 Unresolved**：`BeaconInjectProcess`/`BeaconInjectTemporaryProcess` 保持带名 Unresolved——牺牲子进程无 kernel32；ntdll `NtCreateThreadEx` 会破无写静态/PIC dumper。std `bof-runner` 已有 RW→RX。这是文档化限制，不是未修 bug。
- **永久环境阻塞（不排期）**：CET 物理机、HVCI-on 嵌套虚拟化、CrowdStrike/SentinelOne 企业盘、NDR 长驻流量、Defender 实时保护在 GitHub Server 2025 hosted（矩阵行保持 `env_limit=Defender 已关闭`，功能结果不是检测结果）。
- **MDE / 第三方 EDR**：可选限时试验，不是合入门禁。
- **下一产品轨道**：Linux implant（见 `docs/design/LINUX_IMPLANT_ENTRY.md`）。Windows 用户态 C2 受限交付收口，待本收口 hosted 证据。

2026-08-28 多 agent 收口波次（leftover 合入 + BOF inject + UDRL + Sleepmask 9/9 + 内核窗 GUI + 多态 L1/L3；测试走 `qiaozhiyi/nyx-ci-test`）：

- **leftover 合入**：`profiles/stealth.profile`（padding + bursty，未设 `NYX_PROFILE` 不加载）；既有进程注入 `inject_existing_stage_alloc` RW→RX（VAD R3 漏点）；HookChain stub 页不再 RWX 分配。
- **CI**：`fls.rs` 非 selftest 构建下 `resolved` 未使用触发 `-D warnings`（nyx-ci-test standalone crate tests 红因）；现始终消费该变量。
- **BOF inject 族**：`BeaconInjectProcess` / `BeaconInjectTemporaryProcess` 在 `bof-runner` 实装为 RW alloc → write → RX protect → `CreateRemoteThread`。protect 失败释放远程页且不建线程。`bof-host` PIC **刻意**带名 Unresolved（牺牲子进程未映射 kernel32；见上方收口条目）。host sequencer 单测锁顺序；wine64 live-fire `0xC3` 进挂起 `cmd.exe`。
- **UDRL**：pic-loader 映射改为 RW，导入后、DllMain 前擦 DOS+NT+节表，再按 Characteristics 收口（W+X 塌成 RX，无 RWX 稳态）。`VirtualProtect` PEB-walk + djb2（`0x8B9EBDCD`），解析失败返回 3、protect 失败返回 15。`pic-loader.bin` regen 6512B、0 源重定位。
- **SleepmaskKit 9/9**：`LiveSleepmask` 委托 `fluctuation::sleep`；默认 `EvasionStack` 仍 Floors；生产路径仍 `kits.rs`（不双睡）。
- **内核窗 GUI**：设置页 Open/Close + 可选 PID；`send_command` 对 inject/hashdump 尽最大努力 `phase=open`（404/网络错误仍下发任务，502 出 notice 仍下发）。无 implant 信令，无发明 undo。
- **多态 L1/L3**：`NYX_BUILD_SEED` → `scripts/poly_seed.sh` / `nyx-config::poly` 轮换 `opt-level`∈{3,s,z} 与 `codegen-units`∈{16,1}，**永不设置 LTO**（fat LTO 根因 b94a158）。L3 为 `#[used]` `.rdata` splitmix64 blob；unset 省略。新组合须过 `nyx_selftest_cfgstage`。
- **EDR 矩阵 §3.0**：回填 nyx-ci-test hosted verify run 32680867069（原生 x64，`env_limit=Defender 已关闭`）。

2026-08-28 用户态 stealth Malleable profile：

- **`profiles/stealth.profile`**：checked-in 操作员模板，含 `sleeptime`/`jitter`、`padding_min/max`（64–512，≤4096）、`timing_baseline "bursty"`、可 invert 的 http-post `base64; print;` 信封、真实浏览器 UA 池（默认 Chrome/131，非 `Mozilla/4.0 Nyx`）。`c2lint` 0 Error / 0 Warning。`NYX_PROFILE=profiles/stealth.profile` 同时给 server 与 agent-dev；**未设 env 不自动加载**（默认 `padding_max==0` wire 不变）。`nyx-profile` 测试 `lint(parse(stealth.profile))` 无 Error 且 envelope invert。

2026-08-28 既有进程注入 RW→RX（method 2 + pid≠0，VAD R3 漏点）：

- **`inject_existing_stage_alloc`**：`NtAllocateVirtualMemory` 改为 `stealth::payload_alloc_protect()`（0x04 RW），写完后 `nt_protect_virtual_memory_process` → `stealth::desired_final_protect()`（0x20 RX）。protect 失败关句柄并 Err，不以 RWX 稳态 `CreateRemoteThread`。HookChain stub 页 `VirtualAlloc` 由 0x40 改为 0x20（写窗口仍短暂 RWX→还原 RX；`lockdown_stub_page` 收 RX）。stomp 的 IMAGE `.text` RX→RWX→RX 窗口保留。

2026-08-28 implant 内存/注入 stealth（VAD R1–R3 + Pool Party 0x5）：

- **R3 RWX→RX**：`threadless_inject_alloc` 与 Pool Party stub/section 视图改为 alloc/map RW → 写 → `NtProtectVirtualMemory` / 目标视图 `PAGE_EXECUTE_READ`（0x20）。protect 失败则 Err，不以 RWX 为稳态。FLS 路径未改。
- **R2 stomp 掩护 DLL 池**：`xpsservices.dll` → `colorui.dll` → `dpx.dll` → `cryptui.dll`（均微软签名、System32、冷门；排除 mshtml）。按 LoadLibrary 成功且远程 `.text` vsize ≥ payload 选用；全部失败返回最后一条 COVER_LOAD_FAIL / COVER_TOO_SMALL。
- **R1 VAD 自检**：新模块 `vad.rs`（VirtualQuery 枚举 + Image/Mapped/Private 分类 + PEB/`K32GetMappedFileNameW` 背靠名）。导出 `nyx_selftest_vad`（bit0 走查 / bit1 Image RX / bit2 scratch RX 释放无残留）。补齐 `nyx_selftest_inject_threadless`（安全前缀，1 字节 `ret`，不 RIP 劫持）与 `nyx_selftest_fluctuation`（scratch 页 NOACCESS→RX，不翻 implant `.text`）。
- **Pool Party 0x5**：hosted 出口 0x5 是自测 bitmask（spawn + WARN 降级），不是产品伪造成功。根因：(1) `SYSTEM_HANDLE_INFORMATION_EX` Handles[] 在 x64 从 **0x10** 起（Reserved @0x08），旧解析 0x08 得到 0 candidates；(2) 未部署 sleeper 时 notepad 可能没有 worker factory / OpenProcess GLE=5。修复句柄表偏移并在无 worker factory / OpenProcess 失败时置 **bit3 skip（0x9）**，与 0x5 WARN-fail 区分。不把 0x9 记为成功。

2026-08-28 流量元数据整形收尾 + L4 per-implant 时序（WP-C leftover + `NYX_POLYMORPHISM_DESIGN.md` L4）：

- **malleable.rs `jitter_ms` 透传**：`MalleableProfile` 增 `jitter_base_ms`，从 CS profile 的 `sleeptime`/`jitter`/`timing_baseline` 映射（`cs_timing_to_jitter`）；缺 timing 时 `jitter_ms()==0`（默认 cadence 不变）；有 jitter/`timing_baseline` 时非零。预构建 profile 的 `jitter_base_ms=0` + 非零 pct 仍走历史 100ms ± pct。nyx-profile 仅 test 依赖，默认构建不启用 impersonation。
- **PIC implant `timing_baseline=bursty`**：`implant-net/build.rs` 烘焙 `TIMING_BASELINE_BURSTY`（无 profile 为 false）；`bursty_delay(cycle, base)` 对齐 agent-dev `BURST_LEN=4`（秒级：in-burst = max(1, base/8)，quiet gap = base）。beacon `sleep_jitter` 在 bursty 时先选 base 再套 jitter_pct；`base==0` 仍 no-op；cycle 用 AtomicU32。
- **L4 per-implant 覆盖**：`.nyx_cfg` spec-1 尾后一字节 u8（0 继承 bake / 1 uniform / 2 bursty）；缺字节 = 0。`GenerateRequest.timing_baseline` 未知值 HTTP 400；旧请求无字段 serde 默认 0。UI 生成表单 + invoke.ts 同 `fallback_bitmap` 模式。这是元数据整形，不声称 NDR bypass。

2026-08-28 内核时间窗 T2 第一增量（operator 发起，非 implant 信令；蓝图 [`docs/bypass/EDR_BLINDNESS_UPGRADE_2026-07.md`](docs/bypass/EDR_BLINDNESS_UPGRADE_2026-07.md) §0.3 T2）：

- **`POST /api/kernel/window`**（Admin-only，与既有 `/api/kernel/*` 同鉴权，仅 `NYX_KERNEL_DAEMON` 设时注册）：body `{ "phase": "open"|"close", "pid": optional u32 }`。open 失败即停（502 + `failed_step`，不继续后续 kit）：daemon `blind-etw` → `neutralize` method=`freeze`（既有 neutralize 路由语义，**不调用 kill**）→ `detach-minifilter`。WFP **不在**默认窗（AppId filter 过响）。close 逆序尽最大努力；当前三个 kit 均无 kernelsdk restore（ETW-TI 无 unblind、MiniFilter unlink 自环无 relink、freeze 无解冻），返回 per-step `restored: false, reason: "no undo op"`，不谎报 `ok: true`，不发明内核写。**植入体任务不会自动暂停**，操作员须自行排序 inject/hashdump。
- **CLI / daemon**：`nyx-kernel window-open [pid]`、`window-close`、`window --phase open|close`；`--serve` JSON `{"op":"window-open","pid":N}` / `{"op":"window-close"}`，复用既有 kit 函数，无重复 IOCTL。
- **测试**：server `window_plan` 顺序 + fail-closed fold（含 `ok:false` 视为失败、fold 不拉后续 kit）；CLI host 单测 plan/close JSON。不需真驱动。无 kernel GUI，跳过 UI。

2026-08-28 WFP kit hosted Server 2025 `blocked=false`：

- **根因（代码）**：`FwpmFilter0` 把 `sublayer_key` 置 `GUID_NULL`（默认 UNIVERSAL 子层）且 `weight_type=FWP_EMPTY` 自动权重（`netsec.rs` `block_outbound_app_id`）。hosted Server 2025 默认子层有高权重 loopback PERMIT（AppContainerLoopback / `IsLoopback`），可压过 AppId BLOCK；自测只连 `127.0.0.1`，于是 filter 已装仍 `blocked=false`。同 build 26100 的 ARM64 VM 无该 PERMIT 仲裁所以通过。另：`silence_edr` 在无 admin / BFE 停时也 JSON 写 `blocked=false`，把环境限制记成产品失败。
- **修复**：DYNAMIC 会话不变、filter 仍名 "NyxWfpKit"。新增自有子层（`NyxWfpSub`，weight `0xFFFF`）+ filter `FWP_UINT8` 权重 15，BLOCK 不再与 UNIVERSAL loopback PERMIT 同层仲裁。`FwpmEngineOpen0`/`FwpmFilterAdd0`/`FwpmSubLayerAdd0` 的 5/1058/1722/1753 等 DWORD/HRESULT 归 `env_limit:`；`wfp-selftest` 遇 env_limit 打 `note=env_limit:…` 退出 6（workflow skip，不当 `blocked=false` 产品失败），filter 已装但未拦仍 exit 3，并打印 session_flags / AppId blob 长度 / idle 镜像 vs 探针副本 `path_match`。kernelsdk 增 skip-vs-fail + 路径归一化宿主测试。**hosted Server 2025 复跑仍待确认 loopback 现可 `blocked=true`。**

2026-08-24（续）hosted 波次首跑实证 + 八项修复（ci-test 公共镜像，run 32680867069/…60770/…60771/…60772）：

- **首跑实证（零成本）**：(1) **WP-H sideload 真 loader 双阶段 PASS**（windows-latest：named 转发 + DllMain 触发 marker；ordinal-only `orddll_orig.#1` 转发解析返回 42）——WP-H 最大遗留关闭。(2) **WP-A FLS 真机 PASS 双确认**：windows-ci B4 硬门（exit 7）+ edr-matrix 行 100%。(3) **EDR 矩阵首版实测 5 行**：module_stomp/hwbp_blind/indirect_syscall/fls_callback 全 100%、0 告警；**pool_party 0.0%——exit 0x5（WARN 降级 method 2），原生 x64 Server 2025 上 pool party 未跑通**，首个真实平台差异数据点；Defender 实时保护在 Server 2025 镜像不可开（AMService on / RTP off，Set-MpPreference 无效），5 行如实记 `env_limit=Defender 已关闭`——功能结果，非检测结果。(4) **deviceguard-probe：windows-2022 与 windows-latest 均 VBS=2 运行但 HVCI=False**——免费层无 HVCI-on 环境实锤，HVCI 矩阵维持环境阻塞（现有决策不变，证据补齐）。
- **八项修复**：(a) cargo fmt 三处（08-21 波次未过 fmt 门）；(b) clippy `collapsible_if`（session_store.rs v3→v4 迁移臂）；(c) **kernelsdk 危险测试修复**：`edr_neutralizer_kill_finds_eprocess` 的 Windows 臂对硬编码 pid 100 做真 `OpenProcess(PROCESS_TERMINATE)`——CI runner 上 access denied（失败形态），本机若可开则**真的会杀宿主进程**；改走 K2 `kill_with` 缝注入 stub（断言目标本就是 pid→EPROCESS 链表遍历）；(d) blocklist-gate **A5 精确化**：政策 10.0.29545.0 实锤含 `ALSysIO.sys`（≤2.0.10.x，hash 01af9b2e…，32 位名兄弟条目，08-16 离线断言漏检）但**不含**出货的 `ALSysIO64.sys` v2.0.8.0（文件名+哈希均异）——名称检查收紧为 `alsysio64` 精确匹配，兄弟条目降为 ::warning 级 family watch；顺带修复 A1/A5 `[+] ABSENT` 无条件打印（失败时日志仍显示绿色假象）；(e) ci.yml Qiling job 补 nightly `rustfmt`/`clippy` 组件（macos 镜像不再默认携带）；(f) JA3 live 两步加 3 次重试（peet.ws 连接抖动，本地实测 200 可达）；(g) WFP selftest 增 live 诊断（guard 存活期 dump 过滤器表 + 探针镜像路径——动态会话退出即清，workflow 级 post-mortem 看不到）；(h) **fallback_bitmap server 下发闭环**：GenerateRequest 增 `primary_channel`(0-8 校验 400)/`fallback_bitmap`，`build_implant_config` 无条件写 spec-1 尾段（空通道参数串，implant 解码与缺省等价），UI 生成表单两字段 + invoke.ts 类型；3 个新 wire 测试（尾段携带/缺省语义/越界拒绝）。验证：server 85+4+13 / store 41 / kernelsdk 184 host / clippy `-D warnings` / fmt / UI build 全绿，kernelsdk+kernel-cli windows-gnu target check 0 告警。
- **待回**：WFP kit hosted Server 2025 x64 首跑 `blocked=false` 已按 2026-08-28 条目修 skip-vs-fail + 子层权重，**复跑仍待确认** `blocked=true`。MDE 评估实验室/第三方 EDR 注册实测仍按调研文档 §3 另行推进。

2026-08-24 零成本 hosted 验证波次（依据 [免费测试资源调研](docs/testing/free-test-resources-2026-08-21.md) §4 落地建议 1/2/4；私有仓免费额度，Windows 2x 倍率，手动 + 周一定时触发控制消耗）：

- **新 workflow `.github/workflows/windows-hosted-verify.yml`**（三 job，均为证据生产而非 PR 门禁；PR 门禁仍在 windows-ci.yml）：(1) `deviceguard-probe`：windows-2022/windows-latest 双镜像探测 VBS/HVCI 实际状态（Win32_DeviceGuard），回答"哪个免费镜像能做 HVCI-on 矩阵"，信息性不挂门。(2) `edr-matrix`：**WP-B 首版矩阵实测自动化**——Defender 实时保护反开（Server 2025 镜像默认关，p4-p5-validate.yml:29；开不起来则行如实记 `env_limit=Defender 已关闭`，schema 枚举原值，edr-quant-matrix.md §2），5 个 hosted 可跑技术（module_stomp 0xF / pool_party 0x7 / fls_callback 0x7 / hwbp_blind 0xFF / indirect_syscall 0x3，掩码见 win_selftest_all.ps1 注释）经 bof-isolated-probe 控制台线束逐个触发，`Get-MpThreatDetection` 前后差值计告警，每技术一行 CSV（schema 逐列对齐 §1.1，success_rate %.1f%%），artifact 保留 90 天。threadless/fluctuation 无 selftest 导出行（需真 C2 会话，§5 口径），保持待实测。hosted runner 是**原生 x64**——矩阵行 `env_limit=无`，不受 Prism 降级约束。(3) `sideload-runtime`：**WP-H 投递链真 loader 实测**——两阶段：named（host_version.exe 静态导入 version.dll → 代理 16 导出全转发 version_orig + DllMain 触发线程加载 fixture implant，断言 marker `C:\nyx_probe_fixture_loaded.txt`）+ ordinal（orddll.dll 单导出 ordinal 1 NONAME → 代理 `"_ord_1" = "orddll_orig.#1"` 转发 → host_ord.exe GetProcAddress(#1) 必须返回 42）。失败时回收 Defender 遥测 + 完整 deploy 目录。
- **新脚本 `scripts/edr_matrix_hosted.ps1`**：`edr_matrix_record.sh` 的 runner 内直跑版（runner 即目标机，无 ssh/rundll32；探针线束 Session 0 安全），行格式与 bash 版逐字节兼容（同表头、同 csvq 引号规则、同负差值警告口径）；退出 3 = 前置缺失，技术失败只记行不挂步（失败也是矩阵数据）。
- **新 fixture `tools/sideload-proxy/fixture/`**：`host_version.c`（静态导入 version.dll，转发调用必须返回真值）/`ordlib.c`+`ordlib.def`（NONAME ordinal 导出）/`host_ord.c`（GetProcAddress(#1) 验证序数转发运行时解析）。
- **WP-E 收尾：server extc2 出站 live JA3 入 CI**：ci.yml impersonation job 新增一步跑 `blocking_probe_*` ignored 测试（`transport/src/blocking.rs`，BlockingImpersonatingClient = `NYX_EXTC2_IMPERSONATE` 实际消费的客户端），tls.peet.ws 实测 chrome/firefox 指纹可区分——Gate 7 先例复用，"live JA3 端到端"遗留项关闭。
- **本地预验证（wine64 + mingw-w64，2026-08-24）**：sideload 两阶段全链冒烟 PASS——named 阶段转发调用返回真值 + implant marker 落盘（需 `WINEDLLOVERRIDES=version=n`，wine builtin 优先于应用目录的 wine 特有行为，真 Windows version.dll 非 KnownDLL 不受影响）；ordinal 阶段 `ordinal #1 -> 42` + marker 落盘。中间证伪并排除一个假警报：无 override 时"宿主正常返回但无 marker"是 wine builtin 加载顺序所致，非生成器缺陷（最小 DllMain 探针证明 mingw CRT 正确调用代理 DllMain、CreateThread 触发链无问题）。
- **遗留**：FLS 真机门禁（windows-ci.yml B4，已在本工作区）随下次 push 首跑；EDR 矩阵首轮实测数据待 workflow 首跑回填 `edr-quant-matrix.md` §3 占位行；MDE 评估实验室/第三方免费 EDR 行（OpenEDR/LimaCharlie）按调研文档 §3 另行注册实测。

2026-08-21（续2）前沿对标差距改进八工作包（依据 [前沿对标差距分析报告](docs/research/frontier_gap_analysis_2026-08-21.md)，覆盖其 §2 差距矩阵 P0–P3 全部 8 行）：

- **WP-A FLS 回调注入原语（P0，`inject method 3`）**：新模块 `implant-tasks/src/fls.rs`（`fls_callback_inject` + `FLS_INJECT_ENABLED` 门禁默认 ON + `RemoteAlloc` zero-leftover guard）。**勘察后偏离原始设计并有硬证据**：PEB `FlsCallback@0x320`/`FlsHighIndex@0x350` 自 Win10 1903 起被移除（Vergilius 逐版本 dump，偏移以带出处常量 + 钉值单测保留但活路径不用）；实装版本无关路径 = `CreateRemoteThread(FlsAlloc, shellcode)` 注册 + 36 字节 stub 远程线程 `FlsSetValue` 后 `ret` 进线程退出 rundown 触发回调（ReactOS `BaseRundownFls` 证实数据门控）。内存纪律 RW→WPM→RX 全程无 RWX。接线：`inject.rs` do_inject method 3（新增 `create_sacrificial_running` + `wait_remote_kernel32`）、protocol doc、server 审计日志 `method_name` 字段、UI 注释、implant-win re-export、`nyx_selftest_inject_fls` + win_selftest_all.ps1 期望码。验证：implant-tasks wine64 25 全绿（含 stub 字节精确编码）、protocol/server 全绿、三 crate 双 target check 0 警告。遗留：真机/VM 未实测（FlsAlloc 远程线程 + rundown 触发链路、wine 的 FLS rundown 完整性）。
- **WP-B EDR 量化矩阵框架（P0）**：新文档 `docs/testing/edr-quant-matrix.md`（11 列 schema：`date, technique, edr_name, edr_version, delivery_context, samples, successes, success_rate, alerts, env_limit, evidence`；env_limit 强制枚举落实 remediation program :44 "环境阻塞不得误记"口径；首版矩阵 7 技术 × Defender 全标"待实测"，AutoBypass Table 11/12 单列并显著标注外部数据）；新脚本 `scripts/edr_matrix_record.sh`（单技术粒度告警差值采集：前置/后置 `Get-MpThreatDetection` 快照 + `--no-trigger` 回填模式，输出 `.agents/orchestrator/edr_matrix.csv`）；vm-arm64-verify/vm-route-a-guide 登记口径。验证：`bash -n` + stub ssh 冒烟两模式。遗留：真 EDR 实测需 VM 环境。
- **WP-C 流量元数据整形 + c2lint（P1，依据 arXiv 2506.08922 元数据级检测）**：profile 新维度 `padding_min`/`padding_max`（envelope `shape_body` transform 后追加自定界 padding：`encode(frame)||pad||len2`，len2=两个 base64url 字符、n≤4095、填充字节取 URL-safe 字母表使任意 terminator 位置合法；`pad_strip` 先于 decode；`padding_max==0` 时 wire 与旧 profile 逐字节一致）与 `timing_baseline`（`uniform`/`bursty`，agent-dev `bursty_sleep` 突发节奏；implant `sleep_jitter` 刻意不动）。c2lint 新检查：padding 非数字/min>max Error、>4096 Note、timing_baseline 未知 Error、元数据维度全缺 Warning。implant 侧 `implant-net/build.rs` 烘焙 `post_client_padding()`/`post_server_padding()` + transport.rs pad_append/pad_strip（xorshift32，照 sleep_jitter 模式）；server invert 路径 strip_padding。验证：profile 55 / agent-dev 29 / transport 135 / server 92 全绿，clippy 0 告警，implant-net 双 profile 烘焙 check 通过。遗留：`malleable.rs` jitter_ms 透传未做（需改 9 处构造，超最小改动）。
- **WP-D LiveUnhook opt-in 制度化（P1 收尾）**：`unhook.rs` Safety 注释改"默认不启用；如启用须 bootstrap 单线程期且先于 BlindKit"；`evasion_glue.rs` LiveUnhook 文档注释写入决策依据（AutoBypass Table 11：unhook 51.4% 成功率/139 告警全表次高，与 patchless blind 默认路线冲突）。无行为变更。
- **WP-E TLS emitter 接 server 出站（P1）**：新模块 `transport/src/blocking.rs` `BlockingImpersonatingClient`（own current-thread runtime + `block_on`，照 agent-dev BeaconLink 模式，feature `impersonation` 门控）；slack/discord/llm/mcp 四 channel 加 `with_impersonation(profile)` builder seam（默认 ureq 路径逐字节不变）；`BrowserProfile: FromStr`；server `NYX_EXTC2_IMPERSONATE=chrome|firefox|safari|edge`（非法值 fail-closed 拒 boot）+ `nyx-server --features impersonation` feature 转发（hermetic：默认构建 `cargo tree` 0 命中 wreq/boring）。STATUS:22 "已接线"表述修正。验证：transport 默认 136 / impersonation 142 全绿，server 默认/impersonation 双绿（boring-sys2 本机可编译），clippy 0 新告警。遗留：live JA3 端到端（CI Gate 7 先例可复用）。
- **WP-F VAD 一致性离线分析（P2，纯文档）**：`docs/research/vad-consistency-analysis.md`。核心结论：module_stomp 在 RX-INT 下暴露最高（.text 哈希 IOC + RWX 翻转历史，RX 还原零缓解）；threadless/pool_party 的 RWX 是**常驻**（inject.rs:1234、tp.rs:703 后无降权调用）；Pool Party 的 MEM_MAPPED+可执行+无文件名正是 manual mapping 典型指纹；Fluctuation 不覆盖 VAD 元数据启发式。实装建议 R1-R6（Top3：注入后 VAD 自检工具、threadless/pool_party RWX→RX 降权、stomp 目标多元化）。
- **WP-G 载荷多态生成（P2，设计 + 第一增量）**：勘察定论——生成管线是"预编译模板 + 生成期补丁"（`implant_gen.rs` 内存克隆模板覆写 1024 字节 `.nyx_cfg`，无编译动作）。设计文档 `docs/design/NYX_POLYMORPHISM_DESIGN.md`（L1 编译参数轮换/L2 常量随机化/L3 代码重排/L4 行为化分层 + 成本收益证据 + 路线图；L1 风险显式引用 2026-08-10 fat LTO 根因，轮换须以 `nyx_selftest_cfgstage` 为门禁；诚实边界引用 2511.21764 EDR 76% 上限）。第一增量落 `implant_gen.rs`：`.nyx_cfg` 段尾死区全零填充改 `OsRng` 随机（消除固定偏移 0x00 签名锚点）+ 随机 PE overlay [128,4224) 字节（模板未签名、不自读镜像，对补丁定位零影响）。3 个新单测（两种子哈希必异、功能等价、overlay 区间），server 82+4+13 全绿。
- **WP-H sideloading 投递链配套（P3，依据 Table 12 sideload 52.3% vs exe 37.4%）**：文档 `docs/design/SIDELOADING_DELIVERY.md`（宿主选择四条件、投递链四步、检测面×5 带缓解、Table 12 标注外部数据）；新工具 `tools/sideload-proxy/`（独立 workspace 仿 srdi 先例，零外部依赖）：自含 PE 导出解析（具名/ordinal-only/转发识别/地址表洞；否决 goblin 因其静默丢 ordinal-only）→ 生成代理 crate 骨架（GNU ld `.def` 转发条目 `"Name" = "real.Name" @ord`，真转发不经代理代码故触发点为 DllMain：起线程→延时→LoadLibraryW 同目录 implant，loader-lock opsec 注释在内）。验证：7/7 测试绿、clippy 0 告警、**mingw 交叉编译实测**（真实 DLL 输入 → 生成 crate 构建通过 → objdump 核对导出表一致）。遗留：VM 投递链实测、ordinal-only 转发运行时行为未实测。

2026-08-21（续）两个本地工作包（无需真机/服务器）：

- **fallback_bitmap 运行时消费接通**：`Config.fallback_bitmap`（wire spec-1 既有 u8 字段）此前零消费，现已接入 implant failover 路径。语义：bitmap=0 完全保持静态链 `Https→DohDns→Dns→Tcp→SmbPipe`（逐通道断言与旧行为一致，向后兼容硬约束）；非零时按 `DEFAULT_FALLBACK_CHAIN` 位置过滤、保持链序（位位置不含顺序信息，{Smb,Tcp} 解析为 Tcp→SmbPipe）；链外位 5-7 忽略（ExtC2 与 Https 同 egress 无兜底语义，DiscordApi(8) u8 不可编码），仅含链外位 = 禁用自动 failover；bitmap 不 gate operator 显式 SetChannel。改动：implant-net `next_fallback_with_bitmap` + 3 测试；implant-tasks `beacon_send_frame` 接线 `cfg.fallback_bitmap` + failover 接线测试（死端口触发，bitmap=0/bit2/0xE0 三场景）；implant-core config.rs/build.rs 注释修正。wine64：net 39 / tasks 21 全绿。遗留：server 侧尚无界面下发非零 bitmap（build.rs 配置键解析已存在）。
- **evasionsdk 剩余 trait 补 live impl（5/9 → 8/9）**：`LiveSyscalls`（SyscallProvider：幂等 init + NtAllocateVirtualMemory SSN 活性校验，Prism 直调降级诚实语义）、`LiveUnhook`（新底层原语 implant-core `unhook::restore_ntdll_text`：KnownDlls SEC_IMAGE 映射（降级磁盘 ntdll）→ .text 边界比对（版本不一致拒写）→ diff==0 不写不 VirtualProtect 幂等无 IOC → RWX 窗口整体写回并还原保护；**硬约束：必须先于 BlindKit**，否则覆盖自家 EtwEventWrite/NtTraceEvent 补丁）、`LiveAntiDebug`（PEB BeingDebugged + ProcessDebugPort OR，有意不含 uptime 启发式）。SleepmaskKit 在 SDK seam 保持 Floors（真 Fluctuation 仍在 implant-tasks kits.rs 后，迁移待定）。验证：evasionsdk host 47 绿；implant-core wine 10 绿（含模拟 inline hook 修复测试）；implant-evasion wine 56 绿；implant-win nightly check 双 feature 0 警告。遗留：三个新 impl 与既有 5 个一样是独立选用，未接入 entry.rs bootstrap（LiveUnhook 进 bootstrap 须排在 blind 前，属集成决策）。

2026-08-21 七路并行工作包（内核收尾 + 已知限制清理）：

- **K1 内核 VA→PA host 可测化 + CLI 自检臂**：`VaKernelRw` 适配器（含 `PhysWrite` trait）从 `cfg(windows)` 的 `win/va_rw.rs` 上移 crate-root `pagewalk.rs`（host 可编译可测），`win/va_rw.rs` 退化为 re-export 壳（wdt/alsys/CLI 导入路径不变）；pagewalk 测试增至 15 个（1GB 大页、PFN >4GiB 不截断、分级 NotPresent、跨 2MB 大页 kread/kwrite 往返、IOCTL 失败契约）。CLI `--wdt`/`--alsysio` bootstrap 成功后新增 VA→PA 自检臂（经适配器读 ntoskrnl 基址验 MZ，失败则卸载驱动 exit(3)）。kernelsdk 184 host 测试全绿 + windows-msvc check 无警告。
- **K2 EdrNeutralizer::kill 测试闭环**：该能力实为 0d4a202 已实装（strip PPL/签名级别 → 用户态 TerminateProcess → 失败回滚保护字节），旧"仅 resolve"记录过时。本轮拆出 `kill_with` 可测试性缝，成功路径测试不再 Windows-only；新增 5 个 mock KernelRw host 测试（成功保持 strip / 终止失败回滚 / 回滚失败诚实报"ALIVE with PPL stripped" / 非规范地址拒写 / trait 委派）。
- **I1 proxy_veh 死代码删除**：调查实证两条路径均无消费价值（Mode A gadget 扫描结果全 workspace 零消费、架构上无法服务 HWBP #DB 流程；Mode B section-backed handler 的规避前提在其针对的扫描模型下不成立且 NtProtect restore 已被审计标记），整文件删除留 tombstone 模块文档（-820 行），`blind_hwbp::init_countermeasures` 变 no-op（bootstrap 省一次 .text gadget 扫描）。wine64 53 测试全绿，implant-win 下游 re-export 不破。
- **I2 BOF token/spawn API 扩面**：bof-runner 实装 `BeaconUseToken`（ImpersonateLoggedOnUser）/`BeaconRevertToken`（RevertToSelf，按 CS beacon.h 真实名）/`BeaconSpawnTemporaryProcess`（CreateProcessA CREATE_SUSPENDED，STARTUPINFOA cb=104 修正）/`BeaconCleanupProcess`——`BeaconGetSpawnTo` 返回值自此真实；inject 族保持带名 unresolved 报错并注释理由。bof-host（no_std PIC）用 ntdll `NtSetInformationThread` 原语实装 UseToken/RevertToken（stateless，符合无写静态约束），SpawnTemporaryProcess 不可行保持带名报错；`bof-host.bin` 已 regen（23504→23888 字节，dumper 0 重定位）。wine64 54 单测 + live-fire e2e（真实 spawn cmd.exe、token 回环）全绿。
- **I3 fallback 链扩展**：`DEFAULT_FALLBACK_CHAIN` 由 `Https→DohDns→Dns` 扩为 `Https→DohDns→Dns→Tcp→SmbPipe`——9 通道 implant 侧全部有真实 sender，Tcp/SmbPipe 未配置时 fail-fast 廉价跳过；4 个 ExtC2 刻意不入链（与 Https 同 server_host，无兜底语义），理由写入链文档注释。新增链完整性 + ExtC2 fail-fast 测试，wine64 36 测试全绿。**行为变化**：bake 了 tcp/smb 配置的部署在三层互联网通道全失败后现在会自动切 pivot 通道。
- **S1 SQLite 迁移框架补全**：三个 store（CredStore v1 / SessionStore v4 / ImplantStore v1）统一启动时版本戳校验——戳高于当前版本 fail-closed 报 `SchemaTooNew`（旧二进制不再静默打开新库）；session_store v3/v4 迁移 arm 改逐列幂等（PRAGMA table_info 判定），可恢复单事务化之前撕裂的库。6 个新测试（含半迁移恢复、撕裂前数据保留），41 全绿。
- **G1 GUI 盲点核查**：image/channel/file 真实渲染、ProcessTable.tsx、fetch_profile 接线、Three.js 按需加载四项经代码核实均已在此前波次落地（主 bundle 实测 305KB，three 独立异步 chunk），无需改动——已知限制表相应条目本轮关闭。

2026-08-16（续3）WFP kit ARM64 VM 端到端验证通过 + 两个真机 bug 修复：

- **e2e 实证**：Parallels Win11 ARM64（build 26100，Prism x64 仿真，
  SYSTEM 通道）`nyx-kernel wfp-selftest` → `{"baseline":true,"blocked":
  true,"restored":true,"filters":1,"note":"ok"}`，loopback 按预期被
  单条件 AppId block filter 拦截、guard drop 后恢复、**零残留**。
  WFP kit 状态从"实装待验"升为"真机已验"。
- **bug 1（FWP_E_NULL_DISPLAY_NAME 0x80320023）**：真机 `FwpmFilterAdd0`
  拒绝 `displayData.name=NULL` 的 filter——mock 测试无法暴露。filter
  现携带静态名 "NyxWfpKit"（static 生命周期天然满足借用契约）。
- **bug 2（filter 持久化残留）**：`FwpmEngineOpen0` 传 NULL（默认会话）
  时 filter 是持久对象，`FwpmEngineClose0` 不回收——首次 e2e 的
  residue 阶段保持 blocked，需重启清除。会话改开
  `FWPM_SESSION_FLAG_DYNAMIC`（新增 `FwpmSession0` 72 字节 SDK 布局 +
  `wfp_session0_layout_matches_sdk` 偏移钉测试），动态会话独占其
  filter：关会话/进程死亡即清除，guard 文档承诺的无残留契约自此成立。
- kernelsdk 169 host 测试全绿 + windows-msvc check 0 警告。

2026-08-16（续2）BYOVD 第二条 clean phys 路径 — ALSysIO64：

- **选型与实证**：CPUID CPU-Z `ALSysIO64.sys`（LOLDrivers `4d365dd0`，
  KDU `alcpu` provider）不在 MS blocklist（A5 离线断言）。对 LOLDrivers
  两个样本做 dispatch jump-table 直接解码：v2.0.8.0 的 case 0x18/0x1C
  指向 `MmMapIoSpace` 物理读写臂（in `{pa:u64,size:u32}`，单
  METHOD_BUFFERED 缓冲区），**v2.1.0.0 的 0x18/0x1C 已落入
  STATUS_NOT_IMPLEMENTED 默认臂**——IOCTL 号有效版本区间收窄为
  v2.0.x，CI 钉死 v2.0.8.0 SHA256 `7196187f…`（不符即红）。
- **代码**：`byovd_drivers/alsysio.rs`（`VulnDriverIoctl` +
  `supports_va=false` + `phys_read/phys_write` + 5 单测）；
  `win/alsys.rs`（`AlsysPhys` + `open_alsys` + `bootstrap_alsys`，复用
  泛化后的 `wdt::bootstrap_phys_with` 骨架：load → open → CR3 扫描 →
  MZ 验证 → `VaKernelRw`）；`KernelBootstrap::Alsys` 变体 + CLI
  `--alsysio`/`--alsysio-svc` 臂；`NYX_BYOVD=alsysio` 可选；
  scenarios 选择器候选表更新（phys-only 正确跳过语义）。
- **门**：`check_byovd_blocklist.py` 新增 A5（名 + 双版本 SHA256 缺席）
  /B3（LOLDrivers 钉样本在场）；`windows-byovd-hosted.yml` 新增
  `byovd-alsysio` job（windows-2022 真机加载 + assess `Assessed` 硬门）。
- **验证**：kernelsdk 168 host 测试全绿；`x86_64-pc-windows-msvc`
  target check 0 error 0 warning；A5/B3 断言逻辑已用 live 抓取数据
  本地预演通过。

2026-08-16（续）HVCI-on 验证矩阵放弃：

- **决策**：放弃 HVCI-on 真机/云上验证矩阵。依据：出货 BYOVD 驱动
  （WDTKernel / Shield）均不在微软 Vulnerable Driver Blocklist 上，
  HVCI 姿态不再阻塞任何出货路径；HVCI-on 只对"加载 blocklisted Nday"
  有意义，而该场景已由 DMA / driverless CVE / KslD 覆盖。
  代码的 HVCI 感知（`KrwError::HvciCodePage` 数据写降级契约、assess
  HVCI/VBS 位检测）保留——目标机仍可能开 HVCI，行为契约不变；放弃
  的只是"我们自己在 HVCI-on 环境下做验证"的基础设施。
- **删除**：`scripts/kernel-lab/run_hvci_matrix.sh`（HVCI 编排器）；
  `verify_kernel_env.ps1` 不再以 VBS+HVCI 运行为退出码门（纯姿态报告，
  `matrix_ready` 字段移除）；`bootstrap_kernel_lab.ps1` 改为启用
  test-signing（peekaboo-probe 测试签名驱动），不再启用 VBS/HVCI；
  `run_kernel_matrix.ps1`/`deploy_azure_lab.sh` 注释同步为普通 x64
  lab 语境（PG live dump / WFP e2e / 驱动功能验证）。

2026-08-16 BYOVD 驱动包清理（删除 blocklisted 驱动，默认换 Shield）：

- **删除 RTCore64 与 iqvw64e**：两者均已实锤在微软 Vulnerable Driver
  Blocklist 上——CI 实测 RTCore64 在全部 hosted 镜像被 WDAC CI 策略拦截
  （`NtLoadDriver` 0xC0000034，2026-08-13）；iqvw64e 自 2023 年起在名单。
  `byovd.rs` 中两个 struct/impl、`byovd_drivers/rtc64.rs` /
  `byovd_drivers/iqvw64e.rs` 整文件删除；`VulnDriverIoctl::raw_rw` 从
  RTCore64 逐字节循环默认实现改为 trait 必需方法（无消费者残留），
  `addr_offset` / `pack` / `RwPacket` 等只服务旧默认路径的接口一并清除。
- **默认驱动换 Shield**：`win::bootstrap_byovd` 硬编码默认从 RtCore64 改为
  `Box::new(Shield)`（clean，VA 任意 memcpy，单双向 IOCTL）；
  `default_driver()` 的 `NYX_BYOVD` 取值收敛为 `wdtkernel|shield`。
  存活加载链 = KslD → WDT phys / Shield VA，默认 Shield。
- **配套同步**：kernelsdk mock 场景测试改为 Shield + WdtKernel 覆盖
  （selector 跳过 absent 设备语义保留）；`cfg-write` 改走 Shield 设备；
  `windows-byovd-hosted.yml` 删除 RTCore64 `byovd` job（保留
  `blocklist-gate` + `byovd-wdt`，loaded 硬门与诚实 skip 语义不变）；
  `check_byovd_blocklist.py` 保留 RTCore64 阳性对照并新增 iqvw64e 阳性
  对照 + shield.sys 三变体缺席断言；`p4-p5-validate.yml` 与
  `scripts/kernel-lab/` 改为 Shield/WDT 语境。验证：kernelsdk 163 host
  测试全绿，blocklist 脚本本机 PASS。

2026-08-15 生产接缝落地（PeekabooProbe 客户端 + 探针驱动 + ETW 伪造 kit 接线 + store 迁移事务化）：

- **PeekabooProbe 生产接缝**：`win/peekaboo.rs` 实现 `persistence::PeekabooProbe` 的首个生产 impl——`PeekabooProbeClient` 走 `\\.\PeekabooProbe` METHOD_BUFFERED IOCTL 契约（HANDSHAKE/STATUS/TRACK/UNTRACK 四码，固定小端布局）；配套 `tools/peekaboo-probe/peekaboo_probe.c` 签名探针驱动源码（`PsSetCreateProcessNotifyRoutineEx` 回调在被跟踪进程终止时于内核态执行 Peekaboo 修复，`nt!PspProcessDelete` 一致性检查之前）。TRACK 直接消费 window 隐藏时用的 `EPROCESS+ActiveProcessLinks` KVA，偏移零重复。pack/parse + 客户端为纯跨平台代码（host 单测 + `scenarios.rs` mock transport 集成测试）；仅 CreateFileW/DeviceIoControl 传输与 `driver_load` 加载器 cfg(windows)。效果：`select_pg_window_with_probe` tier 1（offset-free `PeekabooWindow`）在生产可达，不再只有 MockPeekabooProbe 测试缝。驱动签名+部署仍需 operator 侧（EV 证书/WDK 构建）。
- **ETW 伪造 kit 接线**：`EtwDeceiver` 实现 `EtwForgeKit` trait，`win::assemble_tier` 装入 `KernelTier::etw_forge`（与其他 kit 同 object-safe 缝模式）；`NtTraceEvent` 注入本身仍 operator 侧。
- **store schema 迁移事务化**：`store.rs`/`session_store.rs`/`implant_store.rs` 的迁移 arm + 版本戳包进单个事务——此前崩溃/SIGKILL 落在两个 arm 之间会留下半迁移的旧版本 DB，下次 `open()` 重跑首个 arm 撞 duplicate-column 永久打不开；回滚保持迁移前状态，下次干净重试。

2026-08-14 内核/睡眠混淆四问题专项修复（Foliage 死代码清零 + PG 偏移离线证伪 + WFP 实装 + WDT 免费验证链）：

- **Foliage APC 死代码残留清零**：执行器本体已于 841ffc5（2026-07-15）删除，本轮清掉残留——evasionsdk 纯模型 `foliage.rs`/`apc.rs` 整文件删除（零非 test 消费者）、`sleep.rs` 废弃入口 `sleep()` 及失效 gating 注释约 100 行删除；`kits.rs` 误导性命名 `struct Foliage`（实为 Fluctuation kit）改名 `Fluctuation`；keylog/entry/selftests/mem/implant-core 等失效注释同步为现状。存活睡眠路径不变：beacon → `kits::sleep` → `fluctuation::sleep`（PAGE_NOACCESS 翻转）。验证：4 个 implant standalone crate 交叉 check 干净、evasionsdk 47 host 测试全绿。
- **PatchGuard 占位偏移离线证伪**：微软符号服务器取 19041.1023/22621.1778/26100.1742 三个 ntkrnlmp.pdb，`dump_kpcr_members` 实证三 build 上 `_KPRCB+0x190` 均为 `ProcessorState.SpecialRegisters.LastExceptionToRip`（saved RIP 槽，非指针）——`prcb_pg_thread_offset=0x190` 占位确定性证伪（证据含 PDB 版本+GUID，写入 `offsets.rs` 注释）；`verified:false` allow-list 门与测试钉不动，真值仍需 live-kernel KPCR dump（17763/26200 未 dump，诚实标注）；PeekabooWindow 仍为出货的 offset-free PG 路径。
- **WFP kit 实装（不再永返 Err）**：`netsec.rs` 实现 pid→image-path（OpenProcess+QueryFullProcessImageNameW）→ `FwpmGetAppIdFromFileName0` → 单条件 `FWPM_CONDITION_ALE_APP_ID`（FWP_MATCH_EQUAL）block filter；旧 96 字节"简化 FWPM_FILTER0"修正为 SDK 全布局（200 字节），layer GUID 与 `FWP_ACTION_BLOCK=0x1001` 按 SDK 纠正；AppId blob RAII 保证 `FwpmFilterAdd0` 返回后才释放；解析失败诚实 Err，无任何路径可装零条件 filter（P0-9 回归钉测试）；`assemble_tier` 接入 `wfp: Some(UserModeEdrSilencer)`。Windows lab 端到端验证待做。
- **WDT BYOVD 免费验证链**：CR3 扫描纯逻辑抽出 `cr3_scan.rs`（host 可测），修复 1 MiB 块边界漏针 bug（6 字节 tail 重叠携带，含跨块回归测试）+ 末位 off-by-one；新增 8 个 mock-phys 单元测试（kernelsdk 159 全绿）；新增 `scripts/check_byovd_blocklist.py` 离线 blocklist 回归门（微软官方 VulnerableDriverBlockList：WDTKernel 缺席 / RTCore64 在场阳性对照；LOLDrivers 交叉引用 `LoadsDespiteHVCI=TRUE`——本机实测 PASS）；`windows-byovd-hosted.yml` 新增 `blocklist-gate`（ubuntu-latest）+ `byovd-wdt`（windows-2022，LOLDrivers LFS 取样 + SHA256 钉 + loaded 状态硬门 + `assess --wdt` JSON 断言）两个 job——免费验证除 HVCI-on 姿态外全链路；HVCI-on 真机矩阵仍无零成本环境，留 `scripts/kernel-lab/` Azure spot 一次性会话。

2026-08-13（续）内核层零成本路径实证：

- **`windows-byovd-hosted.yml` 实测修正**（4a5888a + 31cb1e2）：windows-latest
  已迁 Server 2025（WDAC CI 策略 Enforced 拦 RTCore64）；钉回 windows-2022
  后实测 CI 策略同样 Enforced（`CodeIntegrityPolicyEnforcementStatus=2`）且
  blocklist 直接经 WDAC 生效（注册表 `VulnerableDriverBlocklistEnable` 未设
  仍拦）——`NtLoadDriver` 返回 0xC0000034。probe 改为「仅 HVCI 运行中或
  blocklist 注册表=1 才 skip，否则尝试加载由 NTSTATUS 裁决」；新增 loaded
  状态门禁 hard gate + 诚实 skip 通知。
- **免费驱动层路径候选已锁定**：WDTKernel.sys（Dell，WHQL 签名，LOLDrivers
  `LoadsDespiteHVCI: TRUE`，不在 blocklist），kernelsdk 已含
  `byovd_drivers/wdtkernel.rs`（phys-only IOCTL 协议）。下一工作包：Update
  Catalog 取样 + CLI phys 模式（VA→PA 组合）+ CI 真机验证。
- **驱动无关内核评估免费常跑**：`assess --user` 硬门在 hosted runner 上
  PASS（真内核模块表 + CI 状态）。

2026-08-13 Prism 全 evasion 入口崩溃修复 + 内核云上验证路径：

- **`nyx_entry` 仿真崩溃根因修复**（c2525de）：E1 二分实证真凶为 HookChain
  ——其 IAT 重定向安装的持久间接 syscall stub（`mov eax,SSN; jmp gadget`）
  正是仿真器拒绝分派的模式（0xC000026F，与 `syscalls::Runtime::direct` 同
  机制），首个经重定向导入的 Win32 调用即在 L0_loop_start 后杀进程。仿真
  下（`is_x64_emulated_on_arm64()`）：HookChain 整体跳过（bootstrap +
  `hookchain::apply` 双层门禁）、HWBP 拒绝武装并直落 byte-patch 盲化
  （WoA WoW64 不投递调试寄存器，llvm/llvm-project#80665；bootstrap +
  `blind_hwbp::add_hwbp` 双层门禁）、RSP swap 永不武装。真 x64 零行为变更。
  验证（Parallels Win11 ARM64 build 26200，Defender 实时保护 ON）：修复前
  EXITCODE=0xC000026F；修复后生成 implant 经 `/api/generate-implant` 全
  evasion 入口实证回家（SYSTEM 会话），shell 任务回环正确。
- **内核层验证环境路径**：`scripts/kernel-lab/`（Azure Trusted Launch
  Gen2 VM 一键部署 `deploy_azure_lab.sh` + VM 内 VBS/HVCI 引导
  `bootstrap_kernel_lab.ps1` + 姿态验证 `verify_kernel_env.ps1`）。HVCI/
  PatchGuard/驱动矩阵待 `az login` 后跑首个云上实例（本机 Apple Silicon
  只能跑 ARM64 Windows 内核，x64 kernelsdk 工作无解，故走云）。
- **状态更正**：v0.4.0 专项（WP-A/B1/B2/C/B3）此前已全部落地（2026-08-08），
  STATUS 第 8 条已载；本轮仅同步残留问题口径。

2026-08-10/11 ARM64 VM 全链路实证 + 生成管线根因修复 + 任务面/GUI 修复波次 —
Parallels Win11 ARM64（build 26100，Prism x64 仿真，中文系统，Defender 实时
保护 ON）完成 team server → generate-implant → beacon 回家 → 用户层任务面
全演练，全绿、0 检出（报告 `docs/testing/vm-arm64-verify-2026-08-10.md`）：

- **generate-implant 死 implant 根因修复**（b94a158）：fat LTO 把
  `NYX_CFG_PLACEHOLDER` 读取常量折叠，服务器对 `.nyx_cfg` 段的链接后补丁被
  吞——此前 generate-implant 产出的植入体**全部回连编译期默认 127.0.0.1**。
  `black_box` 修复 + `nyx_selftest_cfgstage` 诊断导出；同 commit 修复 getuid
  三个 x64 ABI bug（`GetTokenInformation` class u8→u32、`LookupAccountSidW`
  peUse 输出宽度、SID 指针指向已弹栈帧）。
- **Prism 仿真间接 syscall 降级**（87d8ade）：ARM64 Windows x64 仿真层拒绝
  非 ntdll stub 位点的间接 syscall（0xC000026F）；新增
  `is_x64_emulated_on_arm64()` 探测，仿真下 syscall4/5/6/11 直调 ntdll、
  fluctuation 降级纯 sleep。已知残留：全 evasion 入口 `nyx_entry` 仿真下仍
  崩（noevasion 正常，真 x64 无此问题）。
- **shell 中文输出 + 内建 cd/pwd**（dc9094c）：shell 输出 OEM/GBK→UTF-8
  转码（中文 Windows cmd 不再乱码）；新增内建 cd/pwd（beacon 进程级持久
  CWD，复合命令仍走 cmd）。
- **fileop 相对路径修复**（23cf714）：`ls .`、`ls ..`、相对子目录经
  GetFullPathNameW 预解析并跟随 beacon CWD；此前 `\??\.` 直接 0xC0000034。
- **GUI 交互层 10 项修复**（e2f9fe9）：默认选死 beacon、跨会话 task_id 撞
  车、drain 失败吞错、网络抖动踢人清史改横幅自动重试、截图重复解码卡死、
  假超时阈值 120s→180s 等。
- **GUI 文件选择器 + 结果内存治理**（ae9def4）：BOF/upload 原生文件选择器
  （tauri-plugin-dialog + Rust `read_file_hex`）；结果内存上限每会话 300 任
  务块 / 64MB data_hex（超出剥最旧）；u8 校验、exit 确认。
- **GUI「文件」Dock 页**（de06636）：远程文件浏览器（路径导航/双击进目录/
  下载/上传）。

2026-08-09 B3 真机（windows-latest 24H2）全链打通 — 前一天"受限交付"的
B3 隔离路径在真机上一轮 15 连失败，本轮以证据驱动逐层定位，修掉 6 个
互相掩盖的 bug，windows-ci 全绿（run 31310348731：probe `BOF-PRINT-OK`
管道回传 + `nyx_selftest_bof_isolated` exit 7=0b0111 + injection-chain +
syscall_rt 全 PASS）：

- **根因（最后一个）dumper lea 常量截断**（6254153）：PIC dumper 按指令
  操作数宽度拷贝 RIP 相对引用的常量，`lea` 的宽度是 8 字节指针而非字面量
  长度——所有 >8B 字符串字面量被截断（`"cmd.exe\0"` 恰好 8B 才一直没暴露）。
  bof-host 的 djb2 因此对 `"nttermin"+相邻垃圾` 求哈希，真机上**全部**
  ntdll 导出解析静默失败。修复：lea 引用常量统一扩展拷贝 128B（图像尾截
  断保护）；pic-loader.bin 重生成字节级一致（无回归）。死尸证据：func
  取证槽 len=18、前缀 `"nttermin"` 正确、target_hash 0xaa264e9e ≠ 正确值
  0xffb4438f。
- `NtAllocateVirtualMemory` 适配器少传 ZeroBits（6 参写成 5 参），后续实
  参整体左移，每次分区分配必败（33b9926）。
- 进程堆改读 `PEB+0x30`：`RtlGetProcessHeap` 在 24H2 ntdll 导出表**不存
  在**（probe 导出矩阵实证 MISSING；此前每次分配即 alloc-error 死）
  （7e0f8e4）。
- 返回地址扫描命中首个 MZ/PE 即返回，不再继续下探（越过映像基址读未映
  射页 → 子进程 0xc0000005，run 31308772386）（7e0f8e4）。
- export-walk 以 BLINK(+0x8) 而非 FLINK(+0x0) 前进——首条目（exe）之后
  即回表头，永远找不到 ntdll（41927a0）。
- bof-host 移除按名称的 Ldr 走查：24H2 上 populated Ldr 列表中旧偏移处
  的 (len,buf) 字段不可信，走查野指针解引用直接 AV（run 31308540437 死
  尸 stamp=0xC9+stage=2+0xc0000005）；ntdll-only 解析走 父基址 → 导出特
  征走查 → 返回地址扫描 三级回退（7af1ace）。
- 证据通道（nyx-ci-test probe + bof-host 内建）：死尸 stamp/8+11 槽 diag
  记录经**本地 section 视图**读取（子进程死亡后仍可读，这是全部定位的
  关键）；probe 管道写端可继承修复（此前子进程 stdout 是死句柄，所有
  `[bof-host]` 诊断静默丢失）；导出存在性矩阵 + 父进程侧解析副本对照。

2026-08-08 B3 BOF 子进程隔离（受限交付，spec 2026-08-04-v040 §4-B3 完成）—
operator 显式选择 `Command::Bof.isolate` 时，BOF 在牺牲子进程（bof-host）中
执行而非 beacon 内联：崩溃杀子进程、beacon 存活上报 `Response::Err`。

- **新 standalone crate `crates/bof-host`**：no_std cdylib → PIC blob
  `bof-host.bin`（14646 字节，入口 `nyx_bof_host_entry` @ offset 0，0 基址
  重定位）。COFF 加载核心（parse/alloc/relocate/flip/call）自 `bof.rs` 抽取
  移植；`BeaconPrintf`/`BeaconOutput` 写继承 stdout 管道；`ExitProcess(status)`
  结束（0 干净 / 1 加载器错误 / 其他 = BOF 自身退出或崩溃）。无写静态
  （stateless `HeapAlloc` 分配器 + match 式 shim 表 + TEB ArbitraryUserPointer
  参数暂存）；`BeaconGetSpawnTo` 返回只读 "cmd.exe"（static 数组，无写静态；
  mergeable 常量触发 LLVM anchor thunk，共享 dumper 已支持 lea 取址跟随）。
  管线：`regen.sh`（nightly + x86_64-pc-windows-gnu + `-Zbuild-std`）
  + 复用 pic-loader dumper（`nyx-bof-host-dumper`，entry 参数化）→ bin 提交
  入库（crate 级 .gitignore 取反）。共享 decoder 放宽 LEA disp32 常量豁免
  （lea 不访存，disp 是常量偏移非指针）；pic-loader regen 无回归。
- **协议**：`Command::Bof.isolate`（wire 尾部可选标志字节，新旧双向兼容测试
  4 个，旧组合按内联执行）；server `JsonCommand.isolate`（serde default）+ 
  batch packer 强制 invariant：isolate BOF 独占帧尾（flush 后单任务帧，单测
  3 场景：孤立/前置/后置）。
- **implant**：`bof_isolated`（`create_sacrificial_isolated` 变体：
  CreatePipe 继承 stdout + STARTF_USESTDHANDLES + 挂起 CreateProcessW +
  tp.rs section 投递 `[blob+payload]` + 主线程 hijack Rip=base、
  Rcx=base+blob.len()）；**交错回收**（PeekNamedPipe 100ms 切片边等边排空，
  60s 总预算 → TerminateProcess，EOF 排空 → `BofOutput`，退出码/崩溃/超时 →
  `Response::Err`，1 MiB 输出上限（超限继续排空丢弃，child 不阻塞），
  SacrificialProcess/PipeRead RAII 每路径防泄漏）；pre-launch 失败 WARN
  前缀回退内联（BOF 未运行，不双重执行）。
- **自测**：`nyx_selftest_bof_isolated`（bof_print.o 管道回收
  "BOF-PRINT-OK" + 新 fixture `bof_crash.o`（mingw gcc -c，null 页写崩溃）
  断言崩溃经 Err 通道 + beacon 存活；CreateProcessW 不可解析时置 skip 标志
  exit 0x9）。Qiling 矩阵 6/6 PASS（本地真实验证，macOS 复刻 Gate 6）；
  真机 `windows-ci` 期望 0b0111。
- **已知限制（受限交付）**：`BeaconGetSpawnTo` 返回只读 "cmd.exe"（bof.rs 为可写
  buffer——写入即 child 内 AV，由 B3 隔离吸收）；Qiling stub rootfs 无
  CreateProcessW → 矩阵跳过（exit 0x9）；wine 的 syscall 分派基于 RIP 反查 stub
  （不认 eax/SSN），implant 间接 syscall 在 wine 下不可全链验证（根因实证：
  direct=STATUS_SUCCESS vs indirect=STATUS_INVALID_SYSTEM_SERVICE）——**真机验证
  自动化**：windows-ci 新增 `nyx-bof-isolated-probe`（console 进程，hosted
  runner 可跑，期望 exit 7 = 0b0111，每次 push 即真机验证）。

2026-08-08 AH-13 clippy 债清理（WP-C 后续）— implant-core/evasion/net/win 四
crate 机械清理：transmute turbofish 注解、`?` 转换、迭代器转换、
`is_multiple_of`、c-string 字面量、match guard、`.dll`/`.exe` 分支合并等
（CI-pinned stable 1.96.0 构造全可用，零行为变更）；rustdoc missing-#Safety
补齐；implant-win build.rs kernel-offsets 烘焙（`bake_offsets`/`NYX_OFFSETS`）
移除——HEAD 与工作树均无 `include!` 消费方，偏移单一来源为
evasionsdk 运行时表（spec §5 实施修订同步；历史文档引用已更新）。

2026-08-08 WP-C 完成 + WP-B2 清零 — implant-win 拆分为 **4 rlib + 1 cdylib 壳**
（spec 2026-08-04-v040 §5）：`nyx-implant-core`（heap/cell/fmt/resolve/ntalloc/
unhook/stack/version/syscalls/context/hostinfo/config/diag 13 模块，含
bake_config + bake_server_pub 烘焙随迁）← `nyx-implant-evasion`（16 模块）
← `nyx-implant-net`（envelopes/transport/channels/*，bake_envelopes 随迁，
生成代码 heap 路径改 `nyx_implant_core::`）← `nyx-implant-tasks`（beacon/bof/
inject/trex/selftests 等 24 文件）← 壳 `nyx-implant-win`（lib.rs 全局唯一项
+ entry + dllmain + re-export 桥）。断环三刀前置落地：`sleep_seconds` 下沉
evasion 侧 sleep.rs（断 fluctuation→beacon）、`ModuleStomper` 移 inject.rs
（断 evasion_glue→inject）、`csprng_fill`/`diag_mark` 抽 core 侧 diag.rs
（断 mem/channels→entry）；唯一 DAG 硬违规 config→server_pub 以烘焙+include
整体下沉 core 消解（spec "server_pub 只能留壳" 条目已修订）。pub 提升 13 项
逐个人工核对（core 7 / evasion 5 / tasks 1）；no_mangle 面（15 Beacon* shim、
NYX_CFG_PLACEHOLDER、~53 selftest 导出、hwbp_veh_handler）壳侧 pub use 保活，
strings + Qiling + objdump 导出表三重实证。WP-B2 任务路径 panic 站点清零：
beacon 3× unreachable→Response::Err 误路由哨兵、context 6 读写助手 panic-free、
bof run_entry_addr section_number 上界检查（恶意 BOF 可越界杀 beacon 的真实洞）、
coff crate 3 处 unwrap/unreachable 改错误返回、fs rename 长度检查下沉、
trex/screenshot/tp 加固；144 处索引点全量审计（唯一必修即 bof 上界）。
验证：五 crate fmt 干净、base/selftest/nyx_diag 三配置交叉编译 0 告警、
Qiling 矩阵 5/5 PASS 且 bitmask 不变、生产 DLL 导出表不变（selftest 导出
feature 门控正确消失）、根 workspace check/test 全绿；5 路对抗评审零
critical/high/medium。CI Gate 4 新增 4 个 standalone crate 的
check + fmt（硬）+ clippy（report-only，~300 条拆分前既有 lint 记为
AH-13 遗留债）。已知偏差：implant-win/config.toml 改指针文件（烘焙读
implant-core 副本）；kernel_offsets 烘焙自始无消费方（HEAD 既有，未动）。

2026-08-06 WP-B1: beacon 任务隔离第一块落地 — `implant-win` 新增 VEH 任务守卫
（`task_guard.rs`，spec 2026-08-04-v040 §WP-B1）。`beacon_dispatch_tasks` /
`beacon_oneshot_run_tasks` 的每次 `execute()` 包一层链尾 VEH（First=0）：只放行
AV / ILLEGAL_INSTRUCTION / STACK_OVERFLOW 三类致命故障，命中后从 `RtlCaptureContext`
快照恢复、返回 `Response::Err("task crashed: 0x…")` 哨兵，beacon 进程不坠；
与 `blind_hwbp` 的 First=1 #DB 处理器无冲突（#DB 硬放行）。自测
`nyx_selftest_task_guard`：round-trip / 崩溃恢复 / 复位三 bit，环境无 VEH 时置
skip 标志（0x9）——Qiling 矩阵已接入，5/5 PASS。同批告警清零：implant-win
selftest 构建 21 条 + default 构建 4 条 dead-code 全部修复（Foliage 残留 import、
`static_mut_refs` 4+2 处改 `&raw`、`register_veh_once` 死参数、`BeaconInit.kp`
死字段、NtQuery fn-type 参数命名、selftest-only 助手补 cfg 门控），双 feature
构建 0 告警、fmt 干净。`.gitignore` 补 `__pycache__/`。

2026-08-05 WP-A: AH-2 巨函数拆分完成 — 冻结清单 140 个 >50 行非测试函数全部拆至
<50 行（transport 6 / server 27 / implant-win 107），纯 extract-method、零行为变更；
执行：Task 0-57 全部完成；质量：15 簇对抗评审（34 条 low 接受/记录，1 条 medium +
2 条 low 修复：write_panic_diag unsafe 上下文恢复（nyx_diag 构建）、do_download
句柄每路径恰关一次、into_command fmt 稳定化）；终验：复扫 0、fmt/clippy/test 全绿、
implant-win base+selftest+nyx_diag 三配置交叉检查 Finished。

2026-08-03 wW: full wiring sweep — every documented "未接线" item closed.
Committed (2026-08-03) — SHAs `1826a35` (feat(wiring))、`282007f`
(fix(smb-listener)).

### Added

- **External-C2 relays complete (wW).** `/extc2/llm` and `/extc2/discord` were
  plain-beacon aliases; now real relays. New `DiscordTransport`
  (`crates/transport/src/discord_api.rs` — bot messages, 2000-char content cap
  → 1400-byte max frame, HMAC frame integrity per CRITICAL-22) joined the
  shared boot-time `TransportStack` alongside Slack/LLM/MCP. Env contracts,
  all fail-closed: `NYX_EXTC2_LLM_KEY` + `NYX_EXTC2_LLM_MODEL` +
  `NYX_EXTC2_LLM_SESSION_KEY`; `NYX_EXTC2_DISCORD_TOKEN` +
  `NYX_EXTC2_DISCORD_CHANNEL` + `NYX_EXTC2_DISCORD_HMAC_KEY`
  (`crates/server/src/extc2_relay.rs`). The `extc2_alias_handler` is deleted —
  no plain-beacon alias routes remain.
- **Authoritative DNS responder (DoH channel server half, wW).**
  `crates/server/src/dns_responder.rs`: RFC 8484 JSON `POST /dns-query` route +
  UDP/53 wire responder (`NYX_DOH_DOMAIN` enables, `NYX_DOH_UDP_ADDR`
  configures), serving `c{seq}-{i}.{b64}.{domain}` chunk uploads,
  `task.{domain}` reply polls (TTL + serve-count bounded), and `health.{domain}`
  A canaries. Chunks reassemble through `parse_frame` → `handle_frame` — the
  same funnel as `/beacon`. Hand-rolled DNS wire format (compression pointers
  handled, hop-capped).
- **Raw pivot channels wired end-to-end (wW).** `Channel::SmbPipe`/`Tcp` were
  gated `is_implemented() == false` (implant-channels-2/3: no parent side). The
  team server now hosts both parents: `crates/server/src/tcp_pivot.rs`
  (reverse_tcp listener, `NYX_TCP_PIVOT_ADDR`) and
  `crates/server/src/smb_listener.rs` (Windows-only named-pipe server,
  `NYX_SMB_PIPE_NAME`). Implant gates flipped: dispatch arms call the real
  `smb::send_recv`/`tcp::send_recv`; `SetChannel` now rejects only
  *unconfigured* endpoints (pipe name / `tcp_peer_host`+`tcp_peer_port`, both
  added to the config blob with backward-compatible tail layers in
  `config.rs`/`config_placeholder.rs`/`build.rs`).
- **Dev agent is a full beacon now (wW).** `agent-dev/src/pivot.rs` — std port
  of the implant's relay channel table (Connect/Socks CONNECT+BIND/
  ChannelData/ChannelClose/pump, thread-local table, per-cycle pump in the
  beacon loop). SOCKS relay now works end-to-end on the dev host:
  operator → server → agent → socket → back. `BeaconLink` abstraction gives the
  agent the DoH channel (`NYX_CHANNEL=doh` via `DohDnsTransport` against the
  server's `/dns-query`) and the FULL two-sided Malleable profile shaping
  (client envelope on send — steps/headers/UA/URI — server envelope on recv),
  matching the PIC implant.
- **TLS fingerprint emitter consumed (wW).** `nyx-agent-dev` gains the
  `impersonation` feature (`NYX_IMERSONATE=chrome|firefox|safari|edge`) using
  `nyx-transport::fingerprint::build_impersonating_client` (BoringSSL wreq)
  driven by an embedded Tokio runtime; live JA3 validation passes. CI gate 7
  (`impersonation` job in `.github/workflows/ci.yml`) compiles both crates with
  the feature and runs the live `validate_ja3_live` probe on hosted runners.
- **Collaboration context + reporting loop (M3 v1, wW).** Session ownership:
  `owner` column (store schema v4 migration), `Session.owner`,
  `POST /api/session/owner` (audited, viewer-denied), owner surfaced in
  `SessionView` and restored on restart; beacon-path upserts never clobber it.
  `GET /api/operators` (roster for the picker). `GET /api/report` — markdown
  engagement snapshot (sessions/creds-by-kind/audit tail). UI: Settings page
  (connection + loaded profile + report export), owner chip + transfer select
  in SessionTable, topology honest empty state (MOCK_NODES demo data removed),
  dead placeholder CSS deleted, Dock settings button enabled.
- **E2E coverage for every new path:** DoH full beacon loop (agent over
  `DohDnsTransport` → task → shell output), TCP pivot reverse_tcp transaction,
  SOCKS relay full chain (connect → channeldata → echoed bytes), DoH HTTP
  chunk upload + task poll, collaboration API (owner/roster/report), DNS wire
  roundtrips incl. compression pointers.
- **SMB listener real-Windows runtime verification (wW).** New Windows-only
  e2e `crates/server/tests/smb_pipe_e2e.rs` (`#![cfg(windows)]`): boots the
  named-pipe parent exactly as the server does (`NYX_SMB_PIPE_NAME`), drives
  two consecutive child-side transactions with `CreateFileW`-equivalent
  `std::fs::File` opens — `[4B LE len][sealed check-in frame]` in, sealed
  reply out — and asserts the reply opens with the session key, the session
  lands in the registry, and the listener re-arms for a second session.
  Verified locally under wine (real Win32 named-pipe semantics) and runs
  natively in CI Gate 3 on hosted windows-latest, closing the "runtime
  validation pending hosted Windows CI" caveat. Gate 6 additionally builds
  the production (default-features) implant DLL — selftest exports are
  feature-gated out, so the exact shipped layout is now gated too —
  completing build verification for all 6 standalone crates (the other 5
  were already in the `standalone` job).
- **fix(smb-listener): drain the reply before re-arming the pipe (wW).**
  `serve_transaction` wrote the sealed reply and returned immediately; the
  spawn loop then called `DisconnectNamedPipe`, which discards any data the
  child has not yet read from the pipe buffer — racing the child's reply
  read and dropping the reply tail (`ERROR_PIPE_NOT_CONNECTED` mid-reply).
  Latent on real Windows, reproduced deterministically under wine. The
  listener now waits until the child has consumed the reply
  (`PeekNamedPipe` drain poll, bounded by the same 30 s phase deadline)
  before allowing the loop to re-arm.


### Added

- **Real T4-T5 kernel assessment (wI).** The implant's user-mode T-REX kernel
  stubs (`assess_kernel` + six stub helpers in
  `crates/implant-win/src/trex/mod.rs`) are deleted. The real assessment lives
  in `operator-kernelsdk`: `KernelAssessment` / `assess_kernel(&dyn KernelRw)`
  — module enumeration + code integrity via `NtQuerySystemInformation`
  (classes 11/103), Ps*NotifyRoutine callback counts via the pattern-scan path
  shared with `resolve_offsets`, ETW-TI enable probe via the `EtwTiBlind`
  chase, kernel-debugger probe via `KUSER_SHARED_DATA`. `status` is `Assessed`
  only when a real NtQuery path succeeded — never fabricated
  (`crates/operator-kernelsdk/src/{lib.rs,win/assess.rs,win/kernel_base.rs}`).
- `nyx-kernel assess` subcommand prints a single `{"assess":{...}}` JSON line
  (stdout) + human summary (stderr); exits 0 even for a hostile posture — an
  assessment, not a gate (`crates/operator-kernel-cli/src/main.rs`).
- Hard CI gate: `windows-byovd-hosted.yml` runs `nyx-kernel.exe assess` and
  fails the job unless status=Assessed and total_drivers > 0; job-level
  `continue-on-error` removed (repo gate convention), HVCI-skip stays green via
  the existing conditional steps
  (`.github/workflows/windows-byovd-hosted.yml`).
- T-REX module docs updated: the implant covers T0-T3 user-mode; T4-T5 is
  operator-side via `nyx-kernel assess` (`crates/implant-win/src/trex/mod.rs`).

2026-08-02 zero-leftover sweep (work packages w-inject / w-misc / w-kernel-relay /
w-gc / w-transport / w-offsets / w-pattern / w-docs-cleanup). Committed
(2026-08-02/03) — SHAs `922cbfb` (fix(zero-sweep))、`7c86fba` (fix(zero-sweep2))、
`219ff7a` (feat(zero-leftovers))、`dbff55a` (fix(ci): shim tests serialized).

### Fixed

- **Zero-leftover sweep scope (committed 2026-08-02/03).** Per-package contracts:
  - w-inject: `module_stomp` owns cleanup — both handles closed + `TerminateProcess`
    on every non-success path, disarmed-OK path returns Drop-guarded handles
    (`crates/implant-win/src/inject.rs`); `BeaconInformation` shim rewritten to the CS
    layout (version@0, pid@4, hostname@8, user@0x10, … isadmin last;
    `crates/implant-win/src/bof.rs`).
  - w-misc: keylog dump takes the same claim/lock discipline as the live
    WH_KEYBOARD_LL writer so it never reads a reserved-but-unwritten slot
    (`crates/implant-win/src/keylog.rs`); T-REX drops its user-mode kernel
    stubs — the T4-T5 kernel assessment moved to `operator-kernelsdk`
    (`assess_kernel` / `nyx-kernel assess`), BYOVD-backed and hard-gated on
    hosted Windows CI (`crates/implant-win/src/trex/mod.rs`,
    `crates/operator-kernelsdk/src/{lib.rs,win/assess.rs,win/kernel_base.rs}`,
    `crates/operator-kernel-cli/src/main.rs`,
    `.github/workflows/windows-byovd-hosted.yml`).
  - w-kernel-relay: `send_op` gains the method field + a daemon neutralize dispatch arm
    (freeze/choke/kill via the kernelsdk path the CLI uses); kernel audit records the
    outcome after dispatch; daemon gets per-connection threads + a 16 KiB line cap
    while keeping the 10s auth-wait (`crates/server/src/kernel.rs`,
    `crates/operator-kernel-cli/src/main.rs`).
  - w-gc: session GC switches from snapshot-then-remove to DashMap `remove_if`
    re-checking the same age/idle + pending-empty predicate under the write lock
    (`crates/server/src/lib.rs`).
  - w-transport: `activate()` demotes only on `TransportError::Dead` (Transient/Timeout
    leave the slot Fresh); the `send()` Timeout retry arm sleeps `RETRY_BACKOFF_MS * attempt`
    like the Transient arm (`crates/transport/src/stack.rs`).
  - w-offsets: evasionsdk `offsets_table.rs` becomes the single source of truth for
    operator-kernelsdk + offset-resolver with a compile-time/test consistency guard
    (`crates/implant-evasionsdk/src/offsets_table.rs`,
    `crates/operator-kernelsdk/src/{offsets,etwti}.rs`, `crates/offset-resolver/src/main.rs`).
  - w-pattern: the notify-array scan pattern is made distinct per target (named
    constants with the same semantics + a per-target comment)
    (`crates/operator-kernelsdk/src/pattern_scan.rs`, `crates/operator-kernelsdk/src/win/mod.rs`).
  - w-docs-cleanup: README.md / docs/README.md / docs/STATUS.md /
    docs/design/BENCHMARK_FRONTIER_C2_2026-07-31.md reconciled with the current tree
    (loader real-machine PASS, qiling gate, hosted CI, kernel-cli probe bins on macOS,
    bof shim skip) — all remaining "gate 关闭"/fail-loud-only loader phrasing removed;
    root `librust_out.rmeta` deleted.

2026-08-02 final sweep (loader wave + qiling + findings sweep). All changes
committed; SHAs referenced inline.

### Added

- **Real Layer-2 reflective loader (loader wave).** pic-loader (Rust no_std
  PIC) compiles to a 6,080-byte zero-relocation raw .bin via
  `crates/nyx-loader/pic-loader/regen.sh` (nightly build-std + mingw, `-nostdlib`, entry
  `nyx_layer2_entry`, gc-sections; `nyx-pic-dumper` extracts the reachable
  closure, decoder cross-checked vs objdump). `LAYER1_BOOTSTRAP` gains the
  handoff bridge (rcx=&key, rdx=&nonce, r8=&ct, r9=ct_len — pic-loader Win64
  ABI; `LAYER2_JMP_OFFSET=0x42`). `wrap_payload` emits the definitive layout
  `[LAYER1+bridge][key][magic|len|nonce][ct||tag][LAYER2]` with the jmp
  displacement patched; `KeyContainsMagic` guard replaces the fail-loud
  Layer2Unavailable.
- **Unicorn loader probe (`tools/loader-emu`, CI Gate 5).** Executes the real
  Layer-1/2 bytes on ANY host: magic-present/absent contracts, synthetic
  full-blob (PEB walk via GS base, emulated VirtualAlloc/RtlMoveMemory/
  VirtualProtect stubs, DllMain fired with correct args). Release loader gate
  is now the emulator probe — no interactive Windows session required.
- **Qiling headless selftest runner (`tools/selftest-qiling`, CI Gate 6).**
  4/4 selftest exports (calib42/env/config/hostinfo) execute under Qiling
  (Windows x86_64 emu) with exact native exit codes; CI gate builds the
  selftest DLL and runs the matrix on macOS (py3.11 venv + setuptools<81 +
  wheel capstone + keystone stub).
- **Release pipeline on GitHub-hosted windows-latest** (no self-hosted
  machine): selftest gate skips with a notice on hosted; loader gate = emu
  probe; verify_env Defender checks degrade to warnings when cmdlets are
  unavailable.
- **Real-machine Layer-2 validation (`crates/loader-probe-exe`, committed
  `aadf1fc` + probe wave).** The full NYX2 blob executes on a REAL Windows
  host without rundll32/LoadLibrary (both hang in Session 0): a plain console
  process `VirtualAlloc`s an RWX page, copies the blob, and runs it as a
  `CreateThread` thread entry — thread entry bypasses CFG/CET call-site
  enforcement, which is why the earlier direct-call attempts faulted at a
  fixed image RIP on hosted CI. A VEH reports the blob-relative RIP on fault.
  The probe found and fixed two real pic-loader bugs: `SizeOfImage` read at
  the wrong optional-header offset (now bounded by a 64 MiB cap, not the file
  size) and missing PE32+ version fields. Result: fixture AND the real implant
  DLL both reflectively load, DllMain runs (marker verified), Layer-2 returns
  0 — on a free GitHub-hosted windows-latest runner, zero local hardware. CI
  now hard-gates on this probe (`43c34be`); the Unicorn emu probe (Gate 5)
  stays as the cross-host regression guard.

### Fixed

- **bof-runner `%s` shim (`shim.rs`).** `MEMORY_BASIC_INFORMATION` gains the
  Win10+ `PartitionId` field (the pre-1607 layout broke VirtualQuery's length
  check on modern Windows — is_readable returned false for every address).
  Heap-dependent tests skip with a notice when the MSVC debug heap's
  VirtualQuery layout defeats the check (run-to-run flaky otherwise).
- **server `validate_patched_pe` (server-aux-2).** data_len read at
  section+8 (was +4 — the keying_levels field) — the >900/overflow checks
  were a permanent no-op.
- **kernel-cli probe bins** compile on macOS (cfg-gated main bodies).
- **Findings sweep** verified all high/critical findings fixed in code and
  closed 20+ still-open mediums (kill-date helper, channel dispatch, config
  decode, PDB/minidump bounds, telemetry, ETW-TI, transport stack, ui
  console, scripting bus, bof shim, offset-resolver flag bounds...).

2026-08-02 fg-kernel sweep (work package fg-kernel: operator-kernelsdk / operator-kernel-cli /
offset-resolver / minidump-assembler / implant-evasionsdk). Committed on branch
`refactor/ah-audit-followups` — the original "UNCOMMITTED" caveat is obsolete; entries cite
`file:line` evidence, backfill SHAs on tag.

### Changed

- **offset-resolver: value flags no longer panic on a missing argument
  (kernel-tools-8).** Every value-taking flag (`--pdb-path`, `--guid`, `--age`,
  `--build`, `--ntoskrnl`, `--fltmgr`, `--out`) indexed `args[i+1]` without a
  bounds check, so `nyx-offset-resolver --pdb-path` as the LAST argument
  panicked with index-out-of-bounds. All value reads now route through a
  `flag_value()` helper that returns a usage-style error
  (`crates/offset-resolver/src/main.rs:66-82,110-114`).
- **minidump-assembler: pid breadcrumb actually encoded (kernel-tools-7).** The
  API documented pid as recorded in SystemInfo, but `reserved1` was hardcoded 0
  and the pid discarded. `assemble_minidump` now writes the pid's low 16 bits
  into `reserved1`'s high 16 bits and a regression test pins it
  (`crates/minidump-assembler/src/lib.rs:231-244,281-291`).
- **Single shared CFG-bitmap offset selection (kernel-tools-4).** `nyx-kernel
  cfg-bypass` (0x40/0x60/0x68) and the standalone `cfg-write` binary
  (0x40/0xC0/0xC8) maintained divergent mappings for the same
  LdrSystemDllInitBlock sizes — at most one could be right per build. New
  `nyx_operator_kernelsdk::cfg::cfg_bitmap_offset()` is the single source of
  truth; both binaries and `locate_cfg_bitmap` consume it
  (`crates/operator-kernelsdk/src/cfg.rs:44-58,93`,
  `crates/operator-kernel-cli/src/bin/cfg-write.rs:38`,
  `crates/operator-kernel-cli/src/main.rs:368`).
- **WdtKernel reports its permanent VA→PA mismatch as Unavailable
  (kernelsdk-1-6).** The physical-only driver's `raw_rw` returned `Err(0)`,
  which `ByovdDriver` mapped to the transient-looking `KrwError::Partial
  { ok: 0 }` despite the module doc promising `Unavailable`. `VulnDriverIoctl`
  now has a `supports_va()` capability (default true); WdtKernel overrides to
  false and `ByovdDriver::kread/kwrite` fail up front with `Unavailable`
  (`crates/operator-kernelsdk/src/byovd.rs:98-101,484-490,504-510`,
  `crates/operator-kernelsdk/src/byovd_drivers/wdtkernel.rs:92-95`).
- **etwti floor-match stops at the last verified build (kernelsdk-2-5).**
  `EtwTiOffsets::for_build` mapped ANY build >= 26100 (including unknown future
  builds) onto the unverified 24H2 `0x070` layout, violating its own "unknown
  builds return None" contract. `floor_match` now returns `None` above 26200
  (`crates/operator-kernelsdk/src/etwti.rs:172-188`).
- **Forged ETW Process Start carries the child PID (kernelsdk-2-7).**
  `forge_process_create` swallowed `child_pid` and wrote the parent into the
  header ProcessId; the CLI also fed ASCII bytes into a UNICODE_STRING payload.
  The header ProcessId is now the child (the event's subject), the parent
  rides in a new UserData ParentID field, and the CLI encodes the image name as
  UTF-16LE (`crates/operator-kernelsdk/src/etw_deception.rs:185-191,224-233`,
  `crates/operator-kernel-cli/src/main.rs:415-426`).
- **evasionsdk: SleepmaskKit floor is distinguishable (evasionsdk-3).**
  `sleep_masked` now returns `Result<(), EvasionError>` and the floor returns
  `NoFloor` instead of silently doing nothing with a `()` signature
  (`crates/implant-evasionsdk/src/lib.rs:254-262,403-412`).
- **evasionsdk: MaskToken zeroes its key on drop (evasionsdk-4).** The token's
  documented "Drop MUST repair" contract is now honest: the seam cannot restore
  image bytes, but `Drop` wipes the 32-byte RC4 key on every drop path, and the
  doc says unmask must be called first (`crates/implant-evasionsdk/src/lib.rs`).
- **evasionsdk: LACUNA chain rotates its backed terminator (evasionsdk-5).**
  `build_lacuna_chain` pushed `backed[0]` unconditionally despite the doc
  promising round-robin; it now cycles across the backed pool via an atomic
  counter, with a regression test
  (`crates/implant-evasionsdk/src/frame.rs:171-177,296-306`).
- **evasionsdk: crate status comment updated (evasionsdk-2).** The "Seams only;
  no real impls yet" claim was stale — 5 of 9 traits have live impls in
  `implant-win/src/evasion_glue.rs` (`crates/implant-evasionsdk/src/lib.rs:43-49`).

2026-07-31 wave-2 fix sprint (work packages w2-clipboard / w2-ntalloc / w2-channels /
w2-kernelsdk-core / w2-kernelsdk-net / w2-pdb / w2-quickwins). Committed on branch
`refactor/ah-audit-followups`; entries cite `file:line` evidence — backfill SHAs on tag.

### Changed

- **SmbPipe/Tcp channels gated as not implemented + I/O timeouts (w2-channels).**
  Findings implant-channels-2/3: SmbPipe/Tcp have no parent-side implementation in the
  repo, so a beacon on them can never transact, and neither channel bounded its I/O — a
  wedged peer could hold the single beacon thread indefinitely. `SetChannel` now rejects
  both with a clear `Response::Err` (never silently accepted,
  `crates/implant-win/src/beacon.rs` `Command::SetChannel` arm) and
  `channels::dispatch_send_recv` refuses to transact on them (returns `None` +
  `ERR_CH_NOT_IMPL` diag; `crates/implant-win/src/channels/mod.rs`). tcp.rs gained a
  bounded non-blocking connect (FIONBIO + `select` with a 10s deadline, mirroring
  pivot.rs) plus `SO_RCVTIMEO`/`SO_SNDTIMEO` 10s per-op bounds on send/recv
  (`crates/implant-win/src/channels/tcp.rs`); smb.rs bounds the pipe-open phase with
  `WaitNamedPipeW` (5s) on `ERROR_PIPE_BUSY` and documents the bounded-blocking contract
  (`crates/implant-win/src/channels/smb.rs`).
- **PatchGuard windows gated off behind placeholder offsets (w2-kernelsdk-core).**
  Finding kernelsdk-1-1: all 5 rows of `KNOWN_PG_CONTEXT_BUILDS` carried the same
  guessed PLACEHOLDER offsets (PRCB thread ptr 0x190 / valid-flag 0x08, never
  verified against a live kernel or PDB), yet `select_pg_window` happily returned a
  window for every one — a bugcheck lottery. Each row now carries an explicit
  `PgContextOffsets::verified` flag (all `false` today) and `select_pg_window`
  returns `None` for any unverified build (`pg_context_usable_for_window` gate,
  `crates/operator-kernelsdk/src/offsets.rs:475,588` +
  `crates/operator-kernelsdk/src/win/mod.rs:467`). The bypass code paths
  (`TimingRepairWindow`/`RuntimePgBypassWindow`) stay and become reachable
  per-build as PDB validation flips rows; the capability is documented
  EXPERIMENTAL in the crate status docs, and the CLI `pg-window` command now
  reports the gate instead of a fake success (`crates/operator-kernel-cli/src/main.rs`).
- **KernelTier gained a real driver-unload path (w2-kernelsdk-core).**
  Finding kernelsdk-1-2: the BYOVD `LoadedDriver` was sealed inside
  `Option<Box<dyn Send + Sync>>` with no way to reach it, so the documented
  unload flow was impossible. `LoadedDriver` now implements a new opaque
  `DriverHandle` trait and `KernelTier::unload_driver(&mut self) ->
  Option<Box<dyn DriverHandle>>` takes the handle, runs the unload
  (NtUnloadDriver + registry-key cleanup), and clears the field
  (`crates/operator-kernelsdk/src/lib.rs:454,489,518` +
  `crates/operator-kernelsdk/src/win/driver_load.rs:178`). The contradictory
  `load()` doc ("Drop unloads + cleans the key") vs the no-op `Drop` impl is
  fixed to state the explicit-unload contract (`driver_load.rs:90-92`).

2026-07-31 audit-follow-up sprint (branch `refactor/ah-audit-followups`, work packages
wp-protocol / wp-store / wp-kernel-daemon / wp-loader / wp-implant-core / wp-implant-inject /
wp-bof-runner / wp-agent-dev / wp-server-a / wp-server-b / wp-ui / wp-scripting /
wp-config-macros / wp-transport / wp-offsets). All changes below are committed on branch
`refactor/ah-audit-followups`; entries cite `file:line` evidence — backfill SHAs on tag.
Central validation: `cargo check`/`cargo test --workspace
--exclude nyx-client-ui` all green; standalone `implant-evasionsdk` (54), `operator-kernelsdk`
(102+8), `minidump-assembler`, `offset-resolver`, `client-ui-web`, and implant-win nightly
cross-check all pass.

### Changed

- **Contributory X25519 (wp-protocol).** `ServerKeypair::derive_for` /
  `ImplantKeypair::session_key` now return `Result<SessionKey, KeyExchangeError>` and
  reject low-order (identity-point / all-zero shared secret) peer keys per RFC 7748 §6.1
  (`crates/protocol/src/crypto.rs:222-248, 302-319, 370-386`). The server fails the
  check-in with an error response; the implant/agent treat it as a fatal config error.
- **Encode-side size cap (wp-protocol).** `encode_frame_dir` errors when ciphertext would
  exceed `MAX_CT_LEN` (512 KiB) instead of producing an over-limit frame
  (`crates/protocol/src/frame.rs`).
- **`FileOp::Ls` wire variant (wp-protocol).** `Ls` added after `Cp` (wire tag 5) with
  encode/decode + round-trip tests (`crates/protocol/src/msg.rs:274-307`); the server maps
  the `ls` command to it.
- **Session counter persistence (wp-store, wp-server-a).** `session_store` gained
  `send_counter`/`last_recv` columns via a real `schema_version` migration; the server
  restores and persists them per frame (`crates/store/src/session_store.rs`). Also:
  `mask_secret` is now char-based `first2….last2` (UTF-8-safe, non-ASCII regression tests,
  `crates/store/src/model.rs:73-82`), token consumption is an atomic fail-closed
  `UPDATE … WHERE used=0`, `busy_timeout` is set on all connections, and DB files are
  created 0600.
- **Kernel daemon auth (wp-kernel-daemon).** `--serve` requires `NYX_DAEMON_TOKEN`
  (exit 7 without it); every connection must open with `auth <token>` (constant-time
  compare); `pid<=0` rejected; per-connection op rate limit
  (`crates/operator-kernel-cli/src/main.rs:161-177, 552-556`; auth answered with
  `{"ok":true}`, 16 KiB line cap + per-connection threads landed later in the
  zero-leftover sweep — see that section).
- **Beacon send/receive discipline (wp-implant-core).** `beacon_send_frame` advances the
  counter and clears pending only after a successful send (P0-3 discipline); S2C replay
  protection via `LAST_SERVER_COUNTER` / `accept_server_counter`; `#[alloc_error_handler]`
  converted to a recoverable OOM path; init failure gets a distinct exit code.
- **BOF entry ABI (wp-bof-runner, wp-implant-inject, wp-agent-dev).** CS ABI
  `go(char *args, int alen)`: `bof-runner::execute(blob, args)` invokes the entry as
  `go(args.as_ptr(), args.len() as i32)` with a NULL-buffer fallback for no-args BOFs
  (`crates/bof-runner/src/win.rs:489-498`); W^X — code sections flipped to
  `PAGE_EXECUTE_READ` via `VirtualProtect` before `go()`, memory freed by RAII guards
  after return (`win.rs:455-459`); externals table extended with kernel32/ntdll exports
  resolved via `GetModuleHandleA`/`GetProcAddress` (`win.rs:409-414`). agent-dev passes
  BOF args through.
- **Server-side relay stack (wp-server-b).** ONE `TransportStack` built at boot by
  `ExtC2RelayConfig::from_env` and shared by both `/extc2/slack` and `/extc2/mcp` relay
  entry points instead of per-call transport construction
  (`crates/server/src/extc2_relay.rs:57-59, 122-127, 214-218`).
- **UI task history + expiry (wp-ui).** Task history lifted to an App-level store keyed by
  session (no wipe on session switch); every result emit carries `session_id`; pending
  tasks expire with a synthetic error result.
- **Scripting resource budgets (wp-scripting).** Global cumulative op budget via
  `on_progress` (never resets per dispatch) plus a per-dispatch cap and wall-clock
  deadline; `nyx_log` call/byte rate limit per dispatch.
- **config-macros (PARTIAL).** `tracked_path`/`tracked_env` documented as unavailable on
  stable 1.96 (verified E0433) with exact insertion points for when the API stabilizes;
  regression fixture added (`crates/config-macros/src/`).
- **Offsets canonicalization (wp-offsets).** `implant-evasionsdk::offsets_table` marked
  canonical with a pub accessor; `operator-kernelsdk` + `offset-resolver` gained
  consistency dev-dep tests; 19045 range policy aligned
  (`crates/implant-evasionsdk/src/offsets_table.rs:39-44, 296, 335`).

### Fixed

- **Low-order key exchange accepted (wp-protocol, CRITICAL).** An implant presenting the
  curve identity point forced a deterministic, attacker-known session key; now rejected
  (see Changed). Tests: identity-point pubkey and all-zero shared secret are rejected;
  normal path still works.
- **Oversized frame / blob kills (wp-protocol, wp-agent-dev).** Encode-side cap plus
  `encode_batch` ported to agent-dev: oversized responses become `Response::Err`, never a
  loop-killing panic; counter/pending cleared only after a successful POST.
- **Pool Party handle layout (wp-implant-inject).** `SYSTEM_HANDLE_INFORMATION_EX`
  parsed with correct layout (count@0, stride 0x28, handle@0x10, pid@0x08) + synthetic
  buffer test; `nt_allocate_virtual_memory` gained the ZeroBits param (6-arg `syscall6`).
- **Kill-date silent drop (wp-server-a).** Kill-date validation is strict: days-in-month +
  leap-year logic, year ≥ 1970, checked arithmetic, ISO 8601 / `YYYY-MM-DD` / bare seconds
  (`crates/server/src/implant_gen.rs:258-268, 340-374`).
- **Argon2id on the async runtime (wp-server-a).** Verification offloaded via
  `spawn_blocking` with an auth-work budget that fails closed when exhausted.
- **Session GC evicted active sessions (wp-server-a).** GC now exempts recently-active
  sessions from age eviction and re-admits lost sessions on `TaskResponse` batch
  re-registration.
- **Transport doc claims (wp-transport).** False 'server uses `TransportStack`' claims in
  `crates/transport/src/lib.rs` corrected.

### Removed

- **`nyx-mutate` crate deleted (wp-server-b).** Workspace member, dependency, and
  `FEATURE_MUTATE` / `MutationReport` plumbing removed from the server
  (`Cargo.toml` members, `crates/server/Cargo.toml`, `implant_gen.rs`).
- **nyx-loader `LAYER2_PEB_WALK` placeholder deleted (wp-loader).** The non-functional
  65-byte placeholder blob is gone, superseded by the real Layer-2
  (`LAYER2_CODE = include_bytes!("../pic-loader/pic-loader.bin")`,
  `crates/nyx-loader/src/on_target.rs:262`, appended by `wrap_payload` with the Layer-1
  `jmp rel32` patched, `lib.rs:230-277` — see the final-sweep Added entry for the loader
  wave). The interim fail-loud gate is gone with it: `LoaderError` now only reports
  `KeyContainsMagic` (`lib.rs:131-141`), and `tools/srdi --loader` no longer requires
  `--encrypt` — the v2 loader path is inherently ChaCha20-Poly1305-encrypted
  (`tools/srdi/src/main.rs:119-124`).

### Security

- **Fail-closed Slack relay (wp-server-b).** `NYX_EXTC2_SLACK_HMAC_KEY` is required when
  the Slack relay is enabled — missing, non-hex, or all-zero key is a boot error
  (`crates/server/src/extc2_relay.rs:381-413`).
- **Fail-closed release probe gate (wp-loader).** A missing or `FAIL` loader probe result
  blocks release (`scripts/release/*.ps1`); CI hard gate + DllMain-marker check in
  `43c34be`, since superseded by the Unicorn emu probe as the release gate — see the
  final-sweep Added entries.
- **Token consumption fail-closed (wp-store).** One-time token consume is atomic — a
  `used=0` row with zero rows updated rejects the attempt.
- **Daemon rate limit + auth (wp-kernel-daemon).** See Changed; unauthenticated or
  rate-exceeding daemon connections are closed.

Second round of audit fixes — closes the remaining 13 CRITICAL findings
from the 2026-07-21 full-codebase audit. With v0.3.1 + v0.3.2 combined,
**all 27 CRITICAL findings are closed**. The only remaining audit item is
CRITICAL-19 (beacon task isolation), which is an architectural change
deferred to v0.4.0.

### Fixed (13 CRITICAL)

- **crypto `.expect()` → `Result` (CRITICAL-1/2 + HIGH).** `hkdf_sha256`,
  `seal_dir`, `seal`, `encode_frame`/`encode_frame_dir`, and
  `config::decrypt` now return `Result` instead of panicking under
  `panic="abort"`. All ~27 call sites updated: server propagates via
  `anyhow`; implant exits with diagnostic codes (`0xC3`, `0xA7`,
  `0xB8-BA`, `0xC000_0002`); `embed!` proc-macro keeps a build-time
  `.expect()` (correct signal for a broken-build fixture). New
  `HkdfError` enum (no new deps). 16 files, +306/-105.
- **blind_hwbp `static mut` UB + VEH lock-contention kill (CRITICAL-6/7).**
  Eliminated all `static mut` declarations; replaced with `AtomicU8` per-slot
  state machine (`VACANT`/`OCCUPIED`/`CLAIMED`), `AtomicPtr` for handles,
  `SyncUnsafeCell` for the fixed backing store. VEH handler is now fully
  lock-free — returns `EXCEPTION_CONTINUE_SEARCH` only for genuine "not our
  #DB" (null pointer, no DR6 bits, address mismatch), never for lock
  contention. Arming/disarming uses CAS + Release publication so the VEH
  never observes an armed entry without a matching DR bit.
- **stack.rs `assume_init`/`forget(f)` UB (CRITICAL-8).** Added
  `AtomicBool SWAP_DONE` set by `run_f_on_spoof` after `ptr::read(f)`.
  Only `forget(f)` + `assume_init()` if `SWAP_DONE`; otherwise `drop(f)` +
  return `T::default()`. `FAKE_STACK` bumped from 2 KiB to 8 KiB. Added
  `T: Default` bound (all existing callers satisfy it).
- **lacuna_stomp uninitialized slice UB (CRITICAL-9).** Replaced
  `Vec::with_capacity + forget + from_raw_parts_mut` (uninit slots) with
  `extend_from_slice + as_mut_ptr + forget` (initialized before detach).
  OOM check on `capacity >= len`. Capped `MAX_GHOST_DEPTH = 32`;
  `frames_len * 8` → `checked_mul`.
- **keylog `BUF`/`BUF_LEN` data race (CRITICAL-12).** Moved
  `HOOK_THREAD_LIVE` publication into the hook thread (after
  `SetWindowsHookExW`, before the message pump). New CAS-based
  `claim_buf_index()` gives single-writer-per-byte semantics. Polling path
  re-checks `hook_is_active()` per-byte. Drain uses `BUF_LEN.swap(0,
  AcqRel)`.
- **screenshot winsta handle leak/UAF (CRITICAL-13).** Eliminated
  `static mut CAPTURE_WINSTA_ORIGINAL/OPENED`; replaced with a
  `WinstaGuard { original, opened }` struct passed by value through
  `attach_interactive` → `detach_interactive`. The borrowed
  `GetProcessWindowStation` pseudo-handle is never closed; only the
  `OpenWindowStationW` handle is.
- **Slack/MCP/LLM C2 frame injection HMAC (CRITICAL-22/23/24).** All three
  relay transports now seal frames with `[HMAC-SHA256(32) ||
  len_be(4) || frame]` before encoding (base64 for Slack, hex for
  MCP/LLM). `open_frame` verifies the tag (constant-time via
  `hmac::Mac::verify_slice`) before returning bytes. Per-channel key
  derivation prevents cross-channel replay. Removed `xor_frame` entirely
  from LLM transport (the protocol AEAD provides confidentiality). 19 new
  frame-integrity tests.
- **sRDI export-table OOB (CRITICAL-25/26/27).** Every PE-derived slice
  index now bounds-checked via `checked_slice` helper. `num_names` capped
  at `1<<20`; `ordinal < num_names` enforced; `rva_to_off` takes a
  `max_read` parameter. All `as u32` size casts go through
  `usize_to_u32()` (errors on truncation). Malformed PE → descriptive
  `Err`, not panic.
- **EnableDebug.cs `cmd /c` argument injection (CRITICAL-28).** Removed
  the `cmd.exe /c` shim entirely; `args[0]` passed directly as
  `FileName`. Remaining args quoted via `WindowsArgvQuote()` (MSVC CRT
  rules). Deleted unused `CreateProcessAsUser` P/Invokes. SeDebugPrivilege
  behavior preserved.

### Known Limitations (deferred to v0.4.0)

- **CRITICAL-19 — beacon task isolation.** A single panicking task still
  aborts the beacon (architectural; requires spawn-to-sacrificial redesign
  for BOF/Inject).
- **Selftest gate TIMEOUT in CI.** Pre-existing since v0.3.0 — rundll32
  hangs in the non-interactive Session 0 of the win-17763 runner. All
  build steps pass; only the selftest execution gate times out. Requires
  remote debugging on the runner to diagnose.

## [0.3.1] - 2026-07-21

Security-and-correctness fix release following the 2026-07-21 full-codebase
audit (`docs/audits/FULL_CODE_AUDIT_2026-07-21.md`, 12 parallel sub-agents,
~78,849 LOC reviewed). This release closes the audit's top P0 findings — the
ones that would crash the beacon on first use, leave the injection path
non-functional, ship an open team server, or silently defeat the kill-date
safety control. The remaining CRITICAL/HIGH findings (crypto `.expect()`
refactors, `static mut` modernization, `blind_hwbp` rewrite, BOF/C2 HMAC
framing) are tracked for v0.3.2 and are **not** blockers for authorized
engagements — see Known Limitations.

### Fixed

- **fluctuation_thunk Win64 ABI stack alignment (CRITICAL).** Steps 1-3 of
  the sleep-mask thunk emitted `sub rsp, 0x20` / `add rsp, 0x20`, leaving
  RSP ≡ 8 (mod 16) at the `call` — any callee `movaps`/`movdqa` raised #GP/#PF,
  killing the beacon on the first sleep with `.text` still PAGE_NOACCESS and
  registered data regions still RC4-masked. Step 4 already used the correct
  `0x28` immediate; Steps 1-3 now match. `crates/implant-win/src/fluctuation_thunk.rs:126-211`.
- **NtHeapAllocator dealloc UAF on aligned pointers (CRITICAL).** The
  `align > 8` branch conditionally stored the raw pointer at
  `aligned_addr - 8` only when `offset >= 8`, but dealloc unconditionally
  read that slot. When `RtlAllocateHeap` returned an already-aligned block
  (common for align=16 under LFH), `offset = 0` → the store was skipped →
  dealloc freed a garbage address → heap metadata corruption. Now over-
  allocates `size + align + 8` and stores unconditionally. Also: the two
  `Layout::from_size_align(...).unwrap()` calls in `realloc` (panic=abort
  hazards on attacker-controlled sizes) now fail soft. `crates/implant-win/src/ntalloc.rs:258-330, 334-376`.
- **threadless_inject execute-breakpoint crash (CRITICAL).** The function
  set DR0=sc_addr + DR7=0x1 (local execute breakpoint) with RIP=sc_addr. An
  x64 execute breakpoint traps BEFORE the instruction at DR0 runs — with
  DR0 == RIP the first instruction raised #DB, and with no VEH registered
  the OS terminated the target on every call. The RIP hijack alone is
  sufficient and correct; the DR0/DR7 writes are removed. Also:
  `nt_suspend_thread` return value is now checked (was silently dropped —
  proceeding to NtGetContextThread/NtSetContextThread on a live thread
  raced). `crates/implant-win/src/inject.rs:652-746`.
- **inject_existing `CreateRemoteThread` NULL lpStartAddress (CRITICAL).**
  The primary existing-process inject path passed `None` as the start
  address and the shellcode address as `lpParameter` — the kernel rejects a
  NULL start address, so the call always returned NULL and the path was
  100% broken (operators always saw "CreateRemoteThread failed"). Now wraps
  the shellcode address in `Some(transmute(...))`, mirroring the working
  `remote_load_library` pattern. `crates/implant-win/src/inject.rs:1014-1024`.
- **stomp_and_resume cross-process buffer overrun (CRITICAL).**
  `WriteProcessMemory` wrote `shellcode.len()` bytes unconditionally into a
  region capped at `min(vsize, 0x2000)`. Any shellcode >8 KiB overran into
  the cover DLL's `.rdata`/`.data`, crashing the sacrificial process. Now
  bounds-checked; the RWX→RX restore (Step 5) also propagates errors
  instead of leaving `.text` RWX. `crates/implant-win/src/inject.rs:215-219`.
- **Kill-date never enforced (CRITICAL).** `ImplantConfig.expires_at` was
  decoded from the config blob (u64 unix seconds, 0 = no expiry) but
  `beacon_loop` never checked it — the implant ran forever, defeating the
  operator's engagement time-box safety control. Added
  `hostinfo::now_unix()` (resolves `GetSystemTimeAsFileTime` via PEB walk,
  converts FILETIME → unix seconds) and a per-cycle comparison at the top
  of `beacon_loop` that returns cleanly on expiry. A clock-resolution
  failure (`now_unix() == 0`) does NOT enforce, so a missing clock can't
  kill the beacon spuriously. `crates/implant-win/src/beacon.rs:187-196`,
  `crates/implant-win/src/hostinfo.rs:107-141`.
- **deaddrop JSON OOB panic (CRITICAL).** `json_extract_str` had two OOB
  bugs: `i += 1` past `:` ran unconditionally even when the preceding
  while-loop had exhausted the input, and `i < json.len() && json[i] == b' '
  || json[i] == b'"'` evaluated the right operand even when `i >= json.len()`
  (operator precedence). Under panic=abort any truncated GitHub response
  (network blip, 401/403 body) killed the implant. Both fixed.
  `crates/implant-win/src/trex/exfil/deaddrop.rs:113-138`.
- **selftests screenshot diag heap overflow (CRITICAL).**
  `nyx_selftest_screenshot_diag` computed `need = w*h*4` but allocated only
  `need.min(1<<20)` (1 MiB) — `GetDIBits` wrote `need` bytes, overrunning
  NT-heap metadata on any display larger than ~512×512. The export is
  compiled out of production DLLs (default no-selftest profile) but crashed
  dev/selftest builds. Now allocates the full `need`; `iLines` capped
  defensively. `crates/implant-win/src/selftests.rs:347-378`.
- **`is_loopback_bind` string-prefix bypass (HIGH).** The auto-token guard
  keyed off `starts_with("127.") / "localhost" / "::1"`, which missed
  `localhost.localdomain`, `0.0.0.0`, `[::]`, and bare `::1:8443` (whose
  `::1` literal parses as `1`, not loopback). A misconfigured `NYX_BIND`
  could ship an OPEN team server. Now parses the host out of the `host:port`
  string and delegates to `IpAddr::is_loopback` (authoritative for the full
  `127.0.0.0/8` range and `::1`). Unparseable input → fail-closed.
  `crates/server/src/lib.rs:998-1041`. New test
  `is_loopback_bind_closes_v030_string_prefix_bypasses` covers the bypass
  cases.
- **Kernel handlers executed with zero audit trail (HIGH).** All 6
  privileged kernel handlers (`dump_lsass`, `hide`, `blind_etw`,
  `neutralize`, `detach_minifilter`, `driver_status`) called `gate()` for
  admin RBAC but discarded the `OperatorIdentity` — the most sensitive
  operator actions (LSASS dump, process hiding, ETW blinding) left no audit
  record, defeating the audit log's "who tasked WHAT" contract. Each
  handler now captures `op` and writes an audit record before dispatching
  to the daemon, mirroring the `post_task` / `cred_add` pattern.
  `crates/server/src/kernel.rs:114-226`.
- **`implant_gen` expires ISO 8601 silent drop (HIGH).** The kill-date
  parser used `s.parse::<i64>().ok().map(...).unwrap_or(0)`, which only
  succeeded on bare integers — every ISO 8601 string (the documented input
  form; client placeholder is `"2026-12-31"`) failed and defaulted to 0
  ("never expire"). Operators believed they set a 30-day kill-date; the
  implant ran forever, and the audit record showed the intended date while
  the binary got 0. New `parse_iso8601_to_unix` accepts bare seconds,
  `YYYY-MM-DD`, and `YYYY-MM-DDTHH:MM:SS[Z|+00:00]`; parse failure now
  returns 400 (fail-closed). 4 new unit tests. Paired with the beacon-side
  kill-date enforcement above, operator kill-dates now actually fire.
  `crates/server/src/implant_gen.rs:233-340, 456-475`.

### Operational Notes

- **`do_inject` PID guard.** The operator-facing inject entry now rejects
  `pid == 4` (System kernel process — OpenProcess writes would BSOD) and
  `pid == self_pid` (self-inject, almost always a typo). `pid == 0` (the
  "spawn fresh sacrificial" sentinel) is still allowed.
  `crates/implant-win/src/inject.rs:800-820`.

### Known Limitations (deferred to v0.3.2)

The 2026-07-21 audit surfaced 27 CRITICAL + 46 HIGH findings across the
codebase. v0.3.1 closes the 10 that block first-use or ship an open server.
The remaining findings are real but are **not** blockers for authorized
engagements — they are tracked for v0.3.2:

- **panic=abort + `.unwrap()`/`.expect()`/`assert!`/`unreachable!()`** across
  ~30 sites (crypto `seal`/`decrypt`, protocol framing, BOF entry lookup).
  Requires Result-type refactors.
- **`static mut` global state** under the aliasing model (blind_hwbp, mem,
  screenshot, transport, keylog). Requires AtomicPtr/Mutex rewrites.
- **`blind_hwbp` VEH lock contention** returning EXCEPTION_CONTINUE_SEARCH
  (process kill). Requires a lock-free handler redesign.
- **Slack / MCP / LLM C2 frame injection** via unauthenticated channel
  messages and `extract_hex` longest-run heuristic. Requires HMAC framing.
- **sRDI export-table OOB reads** (tools/srdi). Outside the release matrix.
- **beacon task isolation** (single panicking task kills the beacon).
  Architectural — requires spawn-to-sacrificial for BOF/Inject.

Full detail in `docs/audits/FULL_CODE_AUDIT_2026-07-21.md`.

## [0.3.0] - 2026-07-21

First release with compiled Windows payloads + a real reflective PIC loader.
Establishes a tag-triggered release pipeline on the existing self-hosted
win-17763 runner and backfills the reflective loader that was previously
"intentionally out of scope". The release is published as a **GitHub Draft
Release** (assets not publicly listed) pending operator review.

### Added

- **Reflective PIC loader (`crates/nyx-loader`).** `generate_loader_stub()`
  was a `_config`-ignored stub; it now emits Layer-1 (call/pop self-location
  + NYX2 magic scan + header parse) + Layer-2 (PEB walk, RWX alloc, inline
  ChaCha20-Poly1305 decrypt with tag check, reflective PE load, DllMain call).
  The magic self-match scanner bug — the naive `cmp dword [rcx], 0x3258594E`
  matches its own operand inside the stub — is fixed via XOR recovery
  (`on_target::MAGIC_XOR_KEY = 0x5A5A5A5A`). 54 tests (lib 41 + integration
  13) cover byte layout, scan algorithm, payload format, and crypto
  roundtrip against the `chacha20poly1305` crate (`8a385cc`).
- **`crates/nyx-loader/examples/wrap.rs`** — CLI that wraps a PE DLL into
  a self-contained NYX2 blob with a random per-build key (`8a385cc`).
- **`tools/loader_probe_dll/`** — standalone Windows cdylib harness that
  `VirtualAlloc(RWX)` + `memcpy` + VEH-protected jump into a wrapped blob.
  Result file (`NYX_PROBE_RESULT` env or `C:\nyx\loader_probe_result.txt`):
  `OK rv=0x<HEX>` / `FAIL stage=<stage> [code=0x<HEX> addr=0x<HEX>]`
  (`8a385cc`, path fix `2222f08`).
- **`scripts/setup_release_env.ps1` + `docs/RELEASE_ENV.md`** — idempotent
  VPS setup: `MAPSReporting=0` + `SubmitSamplesConsent=2` (do not feed MS
  threat intel) + ExclusionPath for both the manual `C:\nyx` worktree and
  the CI checkout at `C:\actions-runner\_work\NY\NY` (`8a385cc`,
  `2222f08`).
- **`scripts/loader_probe.ps1`** — driver that builds the harness, spawns
  `rundll32`, polls for result file, parses OK/FAIL (`8a385cc`).
- **`scripts/release/*.ps1` (11 scripts)** — per-step build, gate, stage,
  notes-extraction (`8a385cc`).
- **`.github/workflows/release.yml`** — tag push → single-job sequential
  pipeline → `softprops/action-gh-release@v2` **draft** release
  (`8a385cc`).

### Security

- **Implant endpoint auth bypass (CRITICAL, inherited from unreleased).**
  `GET /api/implants` and `POST /api/implant/revoke` had zero
  authentication — any reachable client could enumerate all active implant
  metadata (callback hosts, ports, public keys) and arbitrarily revoke
  them, severing C2 connections. Both endpoints now require operator
  authentication and deny the anonymous Viewer fallback.
  `revoke_implant` audit attribution corrected from hardcoded `"system"` to
  the authenticated operator's name (fixes PR #44, `73006cd`).

### Operational Notes

- **Build environment transparency.** Built on the self-hosted Windows
  Server 2019 (build 17763) with Defender Realtime **ON**. Defender
  `ExclusionPath` is active for build dirs; `MAPSReporting` is disabled.
  DLLs are **unsigned**. See `docs/RELEASE_ENV.md` for reproducible setup.
- **Loader probe is release-blocking.** The reflective blob must inject +
  execute `DllMain` cleanly in the harness process before any draft
  release is created. A crash produces a `FAIL stage=invoke code=0x<N>`
  line in the result file; iteration is expected here.
- **Scope boundaries preserved.** Sleep obfuscation `fluctuation` is still
  not wired; 6 Transport channels still have zero consumers; BOF compat
  surface is still narrow. These known limits are inherited from v0.2.0
  and called out in release notes.

## [0.2.0] - 2026-07-21

First official release. The changelog aggregates the post-internal development window:
P0 memory-safety / protocol / RBAC hardening, the third real-hardware verification pass,
Foliage → Fluctuation sleep-mask migration, ExtC2 relay wiring, and the 2026-07-21
implant-win CI + DLL-surface + screenshot DPI + upload/beacon-reliability fixes.

### Added

- **Screenshot capture rebuilt on `CreateDIBSection`** with DPI-independent physical-pixel
  sizing, replacing the `CreateCompatibleBitmap` path that cropped to logical pixels
  (`23c01b0`). See Fixed for the crop bug this closes.
- **`beacon::encode_batch`** — graceful handling of oversized operator responses. Instead
  of the implant dying on an oversized blob, the batch is downgraded to an operator-visible
  error response (`1320b25`, P0-4).
- **ExtC2 relay, server side** — `extc2_relay` wiring that was previously only specified
  on the implant side. Slack and MCP channels now actually forward through the team server
  (#3 closed; `0945f79`).
- **`trex` WMI registry assessment** — the G1 TODO from the 12-TODO sweep; registry-based
  host assessment via WMI is now wired (`69b12fd` G1, `431e26d` #5).
- **Caller-spoof macro** — macro form of the existing caller-spoof scanner, wired into the
  evasion gate (`431e26d` #6).
- **Fluctuation sleep mask** — sleep obfuscation is no longer short-circuited in
  `kits::sleep`; the Fluctuation path is the live arm (`fffcf31`). This supersedes the
  Foliage APC chain (see Removed).

### Changed

- **CI now actually runs `--features selftest`** and gates PRs on sentinel presence and
  non-zero exit codes. Previously the gate was a no-op (the selftest binary was compiled
  but not executed and its exit code was not inspected) (`88c1fb2`, P0-5). Ghost references
  from the CI script were removed in the same commit.
- **Production DLL export surface reduced to 4 exports**: `DllMain`, `nyx_entry`,
  `nyx_entry_noevasion`, `nyx_screenshot_session`. The 7 `nyx_selftest_*` exports and
  `nyx_screenshot_test` are now compiled out by default behind a `cfg` gate and only
  emitted under the `selftest` feature (`2f20e0a`, P0-6).
- **Screenshot temp file renamed `nyx_shot.bmp` → `~dfftmp.bmp`** for IOC hygiene
  (`23c01b0`). The previous name was a stable, brandable indicator.
- **`do_upload` now loops in `CHUNK`-sized blocks, advancing the file cursor by the actual
  bytes written** rather than assuming a full `CHUNK` per write (`87f9e51`, P0-2). See
  Fixed for the truncation bug this closes.

### Fixed

- **P0-1 — `ntalloc` slab table data race.** The slab free-list was mutated from multiple
  threads without synchronization. Converted to atomic operations (`341e8a2`).
- **P0-2 — `do_upload` silent short-write truncation.** A partial write advanced the cursor
  by `CHUNK` anyway, silently truncating the exfil file. Now advances by actual bytes
  written and re-issues the remainder (`87f9e51`).
- **P0-3 — beacon sequence-number burn on send failure.** A failed transport send still
  incremented the sequence counter, burning task IDs the operator would never see
  acknowledged. The batch is now retained for retry on send failure (`1320b25`).
- **P0-4 — `encode_vec.expect()` panic on oversized blobs.** An operator response that
  exceeded the protocol frame limit panicked the beacon. Replaced with `encode_batch`,
  which downgrades to an error response (see Added) instead of killing the implant
  (`1320b25`).
- **Screenshot DPI crop at >100% scaling.** Under RDP at 200% DPI, capture returned
  1147×719 instead of the physical 2294×1438. Root cause was `CreateCompatibleBitmap`
  inheriting the logical DPI of the screen DC. Fixed by switching to `CreateDIBSection`
  with an explicit physical-pixel BITMAPINFO (`23c01b0`, `ad50625` "DPI 虚拟化").
- **Hive `allowed()` leading-slash path traversal bypass.** A path beginning with `/`
  bypassed the allowlist check. Closed in PR #41 (`c9a3593`).
- **COFF relocation off-by-one** in the BOF loader's REL32 emitter (`ad50625`).
- **x64 injection base address** miscalculation in the third real-hardware pass
  (`ad50625`).
- **P0 — RBAC bypass / nonce race / argon2id upgrade.** Server hardening pass: RBAC role
  check was bypassable on a class of routes; the per-session nonce counter had a TOCTOU
  race; password hashing upgraded to argon2id (`ed0af87`).
- **P0 — RWX memory leak + `%s` out-of-bounds read** in the BOF runner. RWX pages were
  leaked across BOF invocations; a `%s` format specifier read past the argument buffer on
  non-null-terminated inputs (`548c5be`).
- **P0 — protocol blob cap / `REL32_N` / `ADDR32NB`** sanity bounds in the protocol and
  COFF layers, plus corrected `.expect()` messages (`265e140`).
- **Second-round soundness pass** across `nyx-mutate` / `bof` / `coff` / `loader`
  (`8e7f507`).
- **Server-side audit hardening, round 2** — DoS limits, `created_by` attribution, rate
  limiting, clock skew handling (`e0c342b`).
- **Implant endpoint auth bypass (CRITICAL).** `GET /api/implants` and
  `POST /api/implant/revoke` had no authentication. Now require operator
  auth and block anonymous Viewer access (PR #44).

### Removed

- **Foliage APC chain**, superseded by Fluctuation (see Added). The `sleep.rs` Foliage
  scaffolding was dead code flagged 🔴 in the 2026-07-18 audit (`13c0064`, `74c9663`,
  `fffcf31`).
- **2 dead selftest helpers** that compiled but were never invoked by any sentinel
  (`13c0064`).
- **`FoliageRaw` dead fields** — 5 of 6 struct fields were never read; the struct is gone
  with the Foliage path (`13c0064`).
- **`MAX_ROTATION_HOSTS` dead const** — declared, never referenced (`13c0064`).
- **Features that could not be verified on real hardware**, replaced with implementable
  techniques (`74c9663`): Layer 2 reflective load, CET `IRET_FRAME`, multi-monitor
  screenshot selection. See Known Limitations for the test-coverage gap that drove these
  removals.

### Security

This release closes the P0 hardening backlog surfaced by the 2026-07-18 code-truth audit.
Operators rebuilding from source should treat all of the following as reasons to rotate
any beacon built from a pre-`0.2.0` tree:

- **RBAC bypass** — a class of team-server routes skipped the role check (`ed0af87`).
- **Nonce race** — per-session replay counter had a TOCTOU window (`ed0af87`).
- **argon2id upgrade** — operator password hashing moved to argon2id; legacy hashes must be
  re-issued (`ed0af87`).
- **RWX memory leak** in the BOF runner — pages persisted across BOF calls, expanding the
  detectable RWX footprint (`548c5be`).
- **`%s` out-of-bounds read** in BOF argument formatting — read past the argument buffer
  on inputs lacking a terminator (`548c5be`).
- **Protocol blob DoS** — unbounded blob size on ingress; now capped (`265e140`).
- **Hive path traversal** — leading-slash bypass of `allowed()` (PR #41, `c9a3593`).
- **Implant endpoint auth bypass (CRITICAL).** `GET /api/implants` and
  `POST /api/implant/revoke` were completely unauthenticated — any reachable
  client could enumerate all active implant metadata and arbitrarily revoke
  implants, severing C2 connections. Both endpoints now require operator
  authentication and deny the anonymous Viewer fallback (PR #44).

### Known Limitations

Honest scope for this release. None are blockers for authorized engagements, but each
narrows what `0.2.0` can be claimed to do.

- **CI runner coverage is single-host.** The self-hosted runner is Windows build 17763
  (Server 2019). Hosted-runner coverage on Windows 11 24H2 is blocked by billing and is
  not running.
- **No end-to-end beacon↔server round-trip test for the PIC implant.** The only implant
  shape that is round-tripped in CI is `agent-dev`. The production `implant-win` PIC DLL
  has selftest exports but no automated full-loop test.
- **`agent-dev` and `implant-win` are a divergent parallel reimplementation.** There is no
  shared trait enforcing response-shape parity between the dev harness and the production
  implant, so a fix in one does not automatically propagate to the other.
- **200% DPI screenshot fix is verified only on Windows Server 2019 RDP**, not yet on
  Windows 11. The `CreateDIBSection` path is expected to behave identically but has not
  been confirmed on Win11 hardware.
- **No ARM64 build.** x64 only.

[Unreleased]: https://github.com/qiaozhiyi/NY/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/qiaozhiyi/NY/releases/tag/v0.2.0
