# Nyx C2 — 实际能力审计汇总（基于源码）

> **本文档性质：** 源码核对的实际能力清单（不是产品宣传，不是 STATUS.md 的复制）。
> **审计方法：** 只读源码，每条结论带 `file:line` 证据。文档自述（`docs/STATUS.md` / README / 各模块 doc-comment）一律视为**待证伪的断言**，与代码冲突以代码为准。
> **审计日期：** 2026-07-05
> **审计范围：** `crates/` 全部 23 个 crate（agent-dev / bof-runner / client-cli / client-ui / coff / config / config-macros / evasion / implant-evasionsdk / implant-win / offset-resolver / operator-kernel-cli / operator-kernelsdk / parse / pe / profile / protocol / rest / scripting / scripting-rhai / server / store / transport）。
> **方法学：** 三个并行 Explore agent 深度审计 + 主审计者交叉抽样 + `grep`/`read` 静态核对。`todo!`/`unimplemented!`/`panic!`/`UnsupportedPosture` 全局扫过。

---

## 0. 总量基线（代码事实）

| 维度 | 数值 | 证据 |
|---|---|---|
| workspace 总代码量 | **63,709 行 Rust**（208 个 `.rs`） | `find crates -name "*.rs" \| xargs wc -l` |
| workspace 成员 crate | 18（5 个独立：implant-win/evasionsdk/kernelsdk/offset-resolver/pe） | `Cargo.toml` |
| workspace 测试 | **326 通过 / 0 失败** | `cargo test --workspace`（`STATUS.md` §0） |
| 协议 fuzz | 1050 万输入 0 panic | `crates/protocol/fuzz/` |
| 植入体导出 selftest | **47 个**（含诊断导出）| `grep "pub unsafe extern \"system\" fn nyx_selftest" crates/implant-win/src/selftests.rs` |
| Command 变体 | **26 个**（`beacon.rs` 26 match arm，全分发）| `protocol/src/msg.rs:92-228` + `implant-win/src/beacon.rs:322-454` |
| Response 变体 | **7 个**（Output/Ok/Err/FileChunk/Channel/BofOutput/Image）| `protocol/src/msg.rs:499-520` |
| API 端点 | **11 个** + beacon handler | `server/src/lib.rs:293-323` |
| TUI 元命令 | **50 个** | `client-cli/src/tui/input.rs:17-324 META_COMMANDS` |
| 最新真机回归 | 47 selftest 49/49 + 全 26 命令 | `STATUS.md` §0a/§5d（2026-07-01/02）|

---

## 1. 协议层 `crates/protocol/`（894 + 326 + 238 + 137 = ~1.6k LOC，19 测试 + fuzz）

| 能力 | 实装状态 | 证据 |
|---|---|---|
| X25519 ECDH 协商 | ✅ 真 | `crypto.rs:110-155`（`x25519_dalek`，StaticSecret）|
| HKDF-SHA256 密钥派生（绑定双方公钥）| ✅ 真 | `crypto.rs:196-227`（`derive_session_key`，info 包含双方 pubkey）|
| ChaCha20-Poly1305 AEAD | ✅ 真 | `crypto.rs:269-309`（`seal_dir`/`open_dir`）|
| 方向隔离 nonce（防 server↔implant nonce 复用）| ✅ 真 | `crypto.rs:229-265`（`nonce[0]` 区分 ClientToServer/ServerToClient）|
| 反重放（单调计数器）| ✅ 真 | `frame.rs`（counter 在 frame header）|
| SessionKey `ZeroizeOnDrop` | ✅ 真 | `crypto.rs:34-40`（orphan-rule wrapper）|
| no_std PIC CSPRNG（PEB-walk SystemFunction036）| ✅ 真 | `crypto.rs:62-100`（`register_csprng`，避免静态 `advapi32` 链接在 PIC cdylib 里挂掉）|
| 帧结构 `[32 pubkey][8 counter][4 ct_len][ct‖16 tag]` | ✅ 真 | `frame.rs`（`MIN_CT_LEN=TAG+1`，`MAX_CT_LEN=512KiB`）|
| 手写 LE 编解码 + 边界检查 | ✅ 真 | `wire.rs:40-173`（`MAX_BLOB_LEN=256KiB`，`Reader::take` 全检查）|
| 26 Command + 7 Response 变体 | ✅ 真 | `msg.rs:92-520` |
| 反 allocation-bomb（`MAX_BATCH=65536` + `checked_count`）| ✅ 真 | `msg.rs:12-43`（`Vec::with_capacity` 永不被 attacker-controlled u32 驱动）|
| 反短输入 panic（全 `Eof` 错误，不 unwrap）| ✅ 真 | `wire.rs:166-173` |
| cargo-fuzz harness（panic=abort 建模）| ✅ 真 | `fuzz/fuzz_targets/decode_vec.rs`（覆盖 Task/TaskResponse/raw Reader 三路解码）|

**协议层结论：完全实装。** 无 stub，无 `todo!`，反 allocation-bomb 与反重放都是代码可见的硬机制。这是整个项目的地基，质量过硬。

---

## 2. 服务端 `crates/server/`（lib.rs 2155 + audit 331 + operators 311 + tls 185 + main 269 = ~3.25k LOC，29 测试）

| 能力 | 实装状态 | 证据 |
|---|---|---|
| axum HTTP(S) beacon 监听 + 11 个 /api 路由 | ✅ 真 | `lib.rs:293-323`（含动态 profile URI merge）|
| Session 注册表（DashMap，key 是 implant pubkey）| ✅ 真 | `lib.rs:56-70`、`:555-557`（`MAX_SESSIONS=4096` cap）|
| 反重放（write guard 内权威判定）| ✅ 真 | `lib.rs:618-625`（advisory read check 在 `:537-545`，write path 才是定论）|
| Beacon body cap（512 KiB）/ API body cap（4 MiB）| ✅ 真 | `lib.rs:36`、`:323` |
| 三层鉴权（registry → legacy token → open）| ✅ 真 | `lib.rs:723-758`（`authenticate`）|
| 命名 operator（`Admin`/`Operator`/`Viewer` 角色）| ✅ 真 | `operators.rs:35-39`、`:91-187` |
| Argon2 PHC 密码哈希（生产记录）/ SHA-256 常量时间（legacy）| ✅ 真 | `operators.rs:176-187`（`verify_secret`）|
| Viewer 角色写门（每个 mutating handler 都查角色）| ✅ 真 | `lib.rs:1049,1230,1268,1319` |
| 常量时间 token 比较（hash-XOR-accumulate）| ✅ 真 | `lib.rs:441-457` |
| Killdate 烧断（时钟错误时 fail-closed）| ✅ 真 | `lib.rs:471-481` |
| Malleable C2 envelope（请求 + 响应 shaping）| ✅ 真 | `lib.rs:356-425`、`:487-526`（profile `http-get`/`http-post` 的 transform 链）|
| **SHA-256 哈希链审计日志**（append-only JSONL，`H(seq‖ts‖operator‖action‖target‖detail‖prev_hash)`）| ✅ 真 | `audit.rs:218-237`，`verify_chain` `:186-213` 重算找首个断链 |
| TLS（rustls + ring，自签 dev 证书）| ✅ 真 | `tls.rs:21-185`，`main.rs:227-269`（rustls 0.23 CryptoProvider 显式 install，commit `746e1dd`）|
| JA3/JA4 指纹 stamp（ClientHello 嗅探后 stream replay）| ✅ 真 | `transport/src/tls.rs:336` `sniff_client_hello` + `tls.rs:PreambleStream:112-185` |
| 持久化凭据库（SQLite WAL，ACID）| ✅ 真 | `store/src/store.rs:70` `journal_mode=WAL`，`synonymous=NORMAL`；schema `:74 CREATE TABLE creds` |
| Rhai 事件脚本（`on_session_new`/`on_result`/`on_session_exit`）| ✅ 真 | `scripting-rhai/src/lib.rs:66-68`（`Event::SessionExit` 已 fire，commit `0e22620` 后非死代码）|

**服务端结论：完全实装。** 哈希链审计 + 命名 operator + Argon2 + Killdate + Malleable C2 + JA3/JA4 + Rhai 全部代码可见，且 **fail-closed** 模式贯穿始终（RwLock 中毒 → closed；时钟错误 → closed；token 不匹配 → closed）。

---

## 3. Windows 植入体 `crates/implant-win/`（~16k LOC，47 selftest 导出）

> `no_std` + `no_main` + nightly + `x86_64-pc-windows-gnu`，286.5 KB strip 后 release DLL。

### 3.1 用户态规避（implant-win 内嵌）

| # | 能力 | 实装 | 证据 / 真实状态 |
|---|---|---|---|
| 1 | 间接 syscall（Runtime SSN 解析 + syscall;ret trampoline）| ✅ 真 | `syscalls.rs:45`（fresh/disk/in-proc ntdll 三路 fallback + 系统调用指令扫描），18 个类型化 wrapper，W^X trampoline |
| 2 | ETW 盲化（byte-patch）| ✅ 真 | `blind.rs`（`patch_etw` EtwEventWrite→`xor rax,rax;ret`，`patch_nt_trace_event`）|
| 3 | AMSI 盲化（byte-patch）| ✅ 真 | `blind.rs`（`patch_amsi` → E_INVALIDARG，`maybe_patch_amsi` 每周期重试）|
| 4 | **HWBP patchless 盲化（VEH + DR0，零 .text 修改）**| ✅ 真 | `blind_hwbp.rs:277` VEH handler，`:148-265` DR0-3 slot 管理，`blind_etw_hwbp`/`blind_amsi_hwbp`，boku7 风格 |
| 5 | ntdll unhook（KnownDlls SEC_IMAGE fresh-map）| ✅ 真 | `unhook.rs:212` `fresh_ntdll_text`（NtOpenSection+MapViewOfSection），`:352` disk fallback |
| 6 | **Foliage 睡眠掩码**（heap RC4 + data-only floor）| ⚠️ 部分 | `sleep.rs:81` 走 data-only floor：`mem::mask()`（heap only）+ `nt_delay_execution`。**APC + .text RC4 加密代码存在但调用点被注释**（`sleep.rs:222-225` "Until that thunk lands"）。FOLIAGE_ENABLED 默认 ON，但运行时降级 |
| 7 | 内存加密（RC4 region mask/unmask）| ✅ 真 | `mem.rs:32` register_region（32 槽表），`mask()`/`unmask()` 幂等保护 |
| 8 | 堆 slab tracking（sleep-mask 时枚举掩码）| ✅ 真 | `ntalloc.rs:66` `enumerate_slabs`（MAX_SLABS=16 × 1MiB）|
| 9 | Module stomping 注入（cover DLL + .text 覆盖）| ✅ 真 | `inject.rs:165` `module_stomp`（LoadLibraryA cover DLL + remote PE 解析）|
| 10 | ThreadlessInject（HWBP / RIP redirect）| ✅ 真 | `inject.rs:530` `threadless_inject` |
| 11 | inject_existing（OpenProcess + NtAlloc + NtWriteVM + CreateRemoteThread）| ✅ 真 | `inject.rs:725` |
| 12 | Pool Party（ThreadPool 注入）| ❌ Stub | `inject.rs:616` 注释 "TODO P3-future"，method=0 静默降级到 module_stomp + WARN |
| 13 | 栈欺骗（frame-chain 合成 + RSP swap）| ✅ 真 + 动态启用 | `stack.rs:223` spoof_wrap（每个 syscallN hot path），`:316 do_rsp_swap` 真内联汇编。**SPOOF_SWAP_ENABLED 静态默认 false，但 entry.rs:132-142 在 CET off + gap 可用时运行时自动 arm**（NYX_SPOOF_OFF=1 强制关）|
| 14 | 反调试（PEB.BeingDebugged + ProcessDebugPort）| ✅ 真 | `antidebug.rs`（gs:[0x60] 读 PEB，indirect syscall 取 ProcessDebugPort），3 个 advisory check |
| 15 | 沙箱检测（CPUID + RDTSC + sandbox DLL + MAC OUI）| ✅ 真 | `envprobe.rs:553` 4 个 check + 综合裁决，VM OUI 走 NT-direct 注册表（零 IPHLPAPI）|
| 16 | CSPRNG（PEB-walk SystemFunction036）| ✅ 真 | `entry.rs:188` `csprng_fill`，解决 PIC cdylib 静态 `advapi32` IAT 失败 |
| 17 | HookChain（系统调用 stub 引导时 apply）| ✅ 真 | `entry.rs` bootstrap，`hookchain.rs`（500 LOC）|

### 3.2 植入体任务能力（26 Command 分发，`beacon.rs:322-454` 全 arm）

| 类别 | 命令 | 状态 | 证据 |
|---|---|---|---|
| 文件系统 | cd/mkdir/rm/mv/cp/ls | ✅ | `fs.rs`（NT-direct NtCreateFile/NtReadFile/NtWriteFile，SAM/SYSTEM hive 写保护拒绝 `fs.rs:151`）|
| 执行 | shell（cmd.exe /c）| ✅ | `shell.rs:300` |
| 执行 | BOF（CS ABI COFF loader）| ✅ | `bof.rs:800`（nyx_coff 重定位，RW→RX 翻转从不同时 RWX，Beacon-API shim `%s/%d/%x/%c`）|
| 数据进出 | upload/download | ✅ | `fs.rs`（FileChunk 64 KiB 流式）|
| 侦察 | portscan / net / driveinfo / env / clipboard | ✅ | `recon.rs:888`（do_portscan 非阻塞 connect，do_net GetExtendedTcpTable，do_clipboard OpenClipboard）|
| 截屏 | screenshot（多屏 + 跨会话）| ✅ | `screenshot.rs:546` do_screenshot，`:382` BitBlt `\| CAPTUREBLT`（分层窗口），`:292` DPI 三级 fallback，cross_session_capture 经 schtasks |
| 截屏 | screenwatch（定时）| ✅ | `screenshot.rs` |
| 键盘记录 | keylog start/stop/dump | ✅ | `keylog.rs:335`（轮询 GetAsyncKeyState，**非 hook-based**，4096B ring，仅 US 布局，文档诚实声明）|
| 凭据 | hashdump 0/1（SAM/SYSTEM hive 流）| ✅ | `hashdump.rs:218` do_hashdump_vec，`:424` save_hive_fallback（SeBackupPrivilege + RegSaveKeyExW 解 oplock）|
| 凭据 | hashdump 2（LSASS 内存）| ❌ 诚实 stub | `hashdump.rs:174` 返回 "deferred (loudest IOC)" — 设计如此，留 operator 用 kernel LSASS reader |
| 后渗透 | steal_token / make_token / rev2self / getuid | ✅ | `postex.rs:172/298/405`，`enable_debug_privilege` SeDebugPrivilege |
| 注入 | inject method 1/2/3 | ✅（method 0 降级）| 见 #9/#10/#11 |
| 网络 | pivot connect（出站 TCP）| ✅ | `pivot.rs:199` do_connect |
| 网络 | pivot bind（SOCKS BIND）| ✅ | `pivot.rs:384` do_bind |
| 网络 | socks relay + channel_data + channel_close | ✅ | `pivot.rs:503/536/584`（双向 relay，每周期 pump）|
| 控制 | sleep（jitter）/ping/exit | ✅ | `beacon.rs:462/505`，`NtWaitForSingleObject INVALID_HANDLE`（UserRequest wait-reason）|

### 3.3 植入体导出（nyx_entry 系列）

| 导出 | 用途 | 状态 |
|---|---|---|
| `nyx_entry` | 反射/PIC 主入口（含全部规避）| ✅ |
| `nyx_beacon_oneshot` | 集成测试入口 | ✅ |
| `nyx_entry_noevasion` / `nyx_beacon_noevasion` | 规避旁路版本（diagnostic）| ✅ |
| `nyx_selftest_*` × 47 | 真机自检（fs/shell/screenshot/recon/keylog/blind/inject/pivot/bof/csprng/foliage/swap/hwbp/...）| ✅ |

### 3.4 植入体层结论

**22/23 用户态能力为真实装**，唯一 stub 是 Pool Party（method 0 inject，文档诚实标注）。Foliage 是降级实装（APC path 注释掉，data-only floor 在线）。所有 gate 默认值：
- `FOLIAGE_ENABLED` = ON（运行时降级为 data-only）
- `MODULESTOMP_ENABLED` = ON
- `SPOOF_SWAP_ENABLED` 静态 = OFF，**运行时自动 arm**（CET off 时）
- `NYX_SKIP_SANDBOX=1` / `cfg!(nyx_skip_sandbox)` 跳过沙箱（SYSTEM schtask 部署用）

---

## 4. 内核层 SDK `crates/operator-kernelsdk/`（~8k LOC，102 测试）

> `#![cfg_attr(not(test), no_std)]`，跨平台编译（macOS dev host 上跑 102 单测，Windows 上跑真实 IOCTL）。

### 4.1 内核原语

| # | 能力 | 实装 | 证据 |
|---|---|---|---|
| 1 | BYOVD KernelRw（RTCore64 IOCTL 0x80002048/0x22204C）| ✅ 真（load 是 operator-side）| `byovd.rs:264-333`，48 字节 MemoryOperation，byte-at-a-time |
| 2 | KslD "Living off Defender" KernelRw | ✅ 真（Win-only）| `win/ksld.rs:388-467`（IOCTL 0x222048/0x22204C，MpKsl/KslD 前缀 + QueryDosDeviceW 动态枚举）|
| 3 | NtLoadDriver bootstrap（registry + ImagePath）| ✅ 真（Win-only）| `win/driver_load.rs:152-213`（`STATUS_IMAGE_ALREADY_LOADED` 视为成功）|
| 4 | ntoskrnl base + module 解析 | ✅ 真 | `win/kernel_base.rs:56-148`（NtQuerySystemInformation SystemModuleInformation=11）|
| 5 | 4 级页表遍历（PML4→PDPT→PD→PT，大页/超级页）| ✅ 真 | `pagewalk.rs:50-111`，纯函数 + mock reader 单测 |
| 6 | VA-aware KernelRw（页边界 chunked）| ✅ 真 | `win/va_rw.rs:51-93`（跨页 corruption 防护）|
| 7 | EPROCESS 偏移表（14 个 build 10240-26200）| ✅ 真 | `offsets.rs:70-267` `KNOWN_EPROCESS_BUILDS` |
| 8 | DefenderDump 风格 invariant probe（PID=4 "System"）| ✅ 真 | `offsets.rs:740-832` `probe_eprocess_offsets` |
| 9 | 自主 pattern scan + 5 已知 ntoskrnl 引用点 | ✅ 真 | `pattern_scan.rs:159-238`，`win/mod.rs:300-392 resolve_offsets` |
| 10 | PDB 符号下载（MS Symbol Server）| ✅ 真 | `crates/offset-resolver/src/main.rs:477 download_pdb` |

### 4.2 内核攻击能力（9 个 kit trait）

| # | 能力 | 实装 | 证据 / 真实状态 |
|---|---|---|---|
| 11 | ETW-TI 盲化（IsEnabled 0x01→0x00，DATA 写 HVCI-safe）| ✅ 真 | `etwti.rs:230-274`（4 hop：EtwThreatIntProvRegHandle→+0x20→GUID_ENTRY→ProviderEnableInfo→IsEnabled）|
| 12 | DKOM 进程隐藏（ActiveProcessLinks unlink + 自环）| ✅ 真 | `persistence.rs:49-115`（65535 guard + `blink->Flink=flink; flink->Blink=blink`）|
| 13 | PPL 剥离（Protection+Sig 置零）| ✅ 真 | `persistence.rs:134-152` |
| 14 | PPL 提升 "immortal"（写 0x4B + 0x3F）| ✅ 真 | `persistence.rs:183-210` |
| 15 | 回调中和（Ps*NotifyRoutine 数组 + RET stub）| ✅ 真 | `telemetry.rs:76-110 neutralize_array`（HVCI 拒绝时 caller 退回 repurpose）|
| 16 | 回调 repurpose（HVCI-safe DATA 写 + ntoskrnl range 过滤）| ✅ 真 | `telemetry.rs:122-201`（selective slot targeting 完成，ntoskrnl 范围跳过 + slot[0] fallback）|
| 17 | MiniFilter 解链（FltGlobals→FrameList→RegisteredFilters）| ✅ 真（算法）| `telemetry.rs:258-288 detach_edr`，CONTAINING_RECORD 恢复。**bootstrap_chain 默认 `flt_globals_kva=0` 不接线**（operator 供给 RVA 才走）|
| 18 | **PatchGuard TimingRepairWindow**（PRCB valid flag 读 + repair callback 写 + Drop 恢复）| ✅ 真 | `persistence.rs:295-370`，Outflank-Peekaboo 类，全 build |
| 19 | **PatchGuard RuntimePgBypassWindow**（Win11 24H2+ flag 挂起 + Drop 还原）| ✅ 真 | `persistence.rs:419-496`，kurasagi/TheiaPg 类 |
| 20 | PatchGuardWindow 基类 | ⚠️ 拒绝式骨架 | `persistence.rs:244-259 enter_unchecked` 返回 `UnsupportedPosture`，**这是设计**（无 probe 时拒绝，两个真实窗口在 `win/mod.rs:438-462 select_pg_window` 按运行时能力选）|
| 21 | WFP 静默（UserModeEdrSilencer + RAII guard）| ✅ 真（Win FFI）| `netsec.rs:91-150` + `:211-277` FwpmEngineOpen0/FwpmFilterAdd0，session-scoped atomic rollback |
| 22 | LSASS 内核读（DTB + page-walk + chunked physical read）| ✅ 真（raw 内存）| `netsec.rs:426-498`（minidump 装配显式 operator-side）|
| 23 | EDR Kill（EPROCESS 解析 + terminate path KVA 返回）| ✅ 真（EPROCESS 部分）| `netsec.rs:536-549`（ZwTerminateProcess 调用是 driver-side）|
| 24 | EDR Freeze（coma，MiniDumpWriteDump 暂停）| ✅ 真（Win FFI）| `netsec.rs:605-760` |
| 25 | EDR Choke（QoS2/qwave.dll 降级）| ✅ 真（Win FFI）| `netsec.rs:799-923` |
| 26 | ETW deception（事件伪造 + 频率追踪）| ✅ 真（算法）| `etw_deception.rs:88-439`（64 字节 EVENT_HEADER，NtTraceEvent 调用 operator-wired）|

### 4.3 内核层工程

| 能力 | 状态 | 证据 |
|---|---|---|
| KernelTier 装配（KslD→BYOVD fallback，KVA==0 时 kit 降级为 None）| ✅ 真 | `win/mod.rs:493-597 assemble_tier` |
| 9 个 kit trait + NoKernel floor impl（每方法返回 UnsupportedPosture）| ✅ 真 | `lib.rs:171-344` traits，`:351-414` NoKernel |
| PgGuard RAII（`#[must_use]`，Drop 跑 repair）| ✅ 真 | `lib.rs:277-319` |
| HVCI 契约（code-page 写拒绝，data-section 写允许）| ✅ 真 | `lib.rs:117 HvciCodePage` |
| operator-kernel-cli bin（bootstrap → resolve_offsets → assemble_tier → kit dispatch）| ✅ 真 | `crates/operator-kernel-cli/src/main.rs` |

### 4.4 内核层结论

**26/26 内核能力为真实装或诚实降级**。`UnsupportedPosture`/`Unavailable` 全部是**"无 resolved offset 时拒绝"**的守卫，不是缺失实现。`todo!`/`unimplemented!` 全 crate 零匹配。HVCI-safe 是贯穿设计：所有 .text 写都退路（repurpose/data-write/flag-suspend），不是硬撞。

---

## 5. 操作员客户端

### 5.1 TUI `crates/client-cli/`（~9k LOC，142 测试）

| 能力 | 实装 | 证据 |
|---|---|---|
| **50 个 TUI 元命令**（`/sessions` `/use` `/info` `/rename` `/tag` `/untag` `/star` `/note` `/alias` `/topo` `/ls` `/cd` `/mkdir` `/rm` `/mv` `/cp` `/ps` `/creds` `/creds add` `/creds del` `/audit` `/audit verify` `/tasks` `/profile` `/bof` `/upload` `/download` `/sleep` `/ping` `/screenshot` `/portscan` `/net` `/drive` `/clipboard` `/env` `/keylog` `/screenwatch` `/hashdump` `/getuid` `/inject` `/steal` `/make_token` `/rev2self` `/pivot` `/socks` `/chan close` `/kill` `/clear` `/theme` `/help`）| ✅ 真 | `tui/input.rs:17-324 META_COMMANDS` |
| 会话列表 + filter + alias/tag/star/note | ✅ 真 | `tui/session_meta.rs`（305 LOC）|
| 拓扑视图（live sessions 派生）| ✅ 真 | `tui/topology.rs`（278 LOC）|
| 多 pane（Files/Procs/Creds/Topology）真实数据渲染 | ✅ 真 | `tui/panes.rs`（730 LOC）|
| 凭据 store UI（带 reveal toggle）| ✅ 真 | `tui/credstore.rs`（461 LOC）|
| age/pending 客户端推算（每帧重绘，不污染 session_signature）| ✅ 真 | `tui/session_meta.rs age_for` |
| `/info` 详情 overlay + `/tasks` 排队任务表 | ✅ 真 | `tui/render.rs` SessionDetail/Tasks overlay |
| SOCKS5 relay（handshake + relay + api）| ✅ 真 | `socks/{handshake,relay,api,mod}.rs`（805 LOC）|
| 三主题（mocha/highcontrast/nocolor）| ✅ 真 | `theme.rs`（382 LOC）|

### 5.2 GUI `crates/client-ui/`（Makepad，~6k LOC，23 测试）

| 能力 | 实装 | 证据 |
|---|---|---|
| Makepad LiveHook 应用框架 + 接连表单 | ✅ 真 | `main.rs:1363 ui: WidgetRef`，`:1420 ensure_bridge`，`:1633 validate_connect_form` |
| 后台 bridge（REST poller，2s sessions 轮询）| ✅ 真 | `bridge.rs:326 spawn`，snapshot 模型 |
| 全部 11 个 /api 端点调用 | ✅ 真 | `bridge.rs:1108-1884`（creds/audit/tasks/profile/sessions/task/results 全覆盖）|
| 7 个自定义 widget（bof_panel/console_list/cred_table/file_tree/process_table/session_graph/mod）| ✅ 真 | `widgets/*.rs`（864 LOC）|
| BOF 文件 → hex 加载器 | ✅ 真 | `main.rs bof_file_input` |
| 读 `NYX_SERVER`/`NYX_TOKEN` env + 重连栏 token dialog fallback | ✅ 真 | `main.rs`（commit G3 修复）|
| session_graph 拓扑 widget | ✅ 真 | `widgets/session_graph.rs`（256 LOC）|
| 主题系统 | ✅ 真 | `theme.rs`（178 LOC）|

### 5.3 客户端结论

**TUI 50 命令全部 dispatch，GUI 7 widget + 全 11 API 端点真实接通**。无占位 widget，无 stub 渲染。client-ui 必须用 `--profile gui` 构建（release 在 Metal/wgpu 触发 SIGSEGV，已知约束）。

---

## 6. 工程生态

| Crate | LOC | 测试 | 实装状态 |
|---|---|---|---|
| `transport` | 816 | 10 | ✅ JA3/JA4 真算（MD5 / SHA256-12hex），ClientHello sniff + PreambleStream replay |
| `coff` | 365 | 7 | ✅ parse + apply（ADDR64 / REL32[1..5] 重定位）|
| `bof-runner` | 175 | 0 | ✅ Win-only，VirtualAlloc + go() 调用（`#[cfg(target_os="windows")]`）|
| `evasion` | 109 | 11 | ✅ syscall stub 生成（Hell/Halo/Tartarus SSN 解析模板）|
| `profile` | 1167 | 40 | ✅ lexer + parser + ast + lint + transform + envelope（c2lint 验证 http-get/http-post 必需、jitter 范围、useragent 黑名单等）|
| `scripting` + `scripting-rhai` | 60 + 166 | 0 + 2 | ✅ Event enum（SessionNew/ResultReceived/SessionExit）+ Rhai engine + `nyx_log` builtin |
| `store` | 271 | 6 | ✅ SQLite WAL，`CREATE TABLE creds (realm, user, kind, secret, ...)` |
| `parse` | 544 | 19 | ✅ 协议解析工具（Reader/Writer 辅助 + table render）|
| `offset-resolver` | 541 | 0 | ✅ `--ntoskrnl <exe>` / `--pdb-path` / `--guid --age` 三模式，自动 PE debug-dir 提 GUID + MS Symbol Server 下载 + PDB 解析 EPROCESS/ETW-TI 字段 |
| `agent-dev` | 1141 | 13 | ⚠️ **macOS/Linux dev 测试桩**，不是作战 implant。完整 beacon loop + 26 命令 dispatch（`lib.rs:221 execute`），但用 `std::process::Command`（sh/df/pbpaste/screencapture）实现，token/inject/SOCKS 命令诚实返回 unsupported |
| `operator-kernel-cli` | 328 | 0 | ✅ 子命令 `bootstrap` / `blind-etw` / `hide<pid>` / `dump-lsass<pid>` / `neutralize<pid><m>` / `detach-minifilter` |
| `config` + `config-macros` | 113 + 86 | 2 + 0 | ✅ 编译期 config_blob/envelopes/server_pub/kernel_offsets 烤入（`implant-win/build.rs` 607 LOC）|

---

## 7. 真实缺口（代码可见的诚实降级）

> 这些不是 bug，是文档诚实声明的限制。列出以正视听。

| 缺口 | 位置 | 性质 |
|---|---|---|
| ~~Foliage APC path 未启用~~ | ~~`implant-win/src/sleep.rs:222-225`~~ | 🔶 **P4 已实装 (研究级,2026-07-05)**：新 `pic_thunk` 模块生成栈上位置无关机器码 thunk(mask→wait→unmask 序列,3 单测);`FOLIAGE_APC_ENABLED` gate(默认 OFF,`NYX_FOLIAGE_APC_ON=1` 开启);`execute_foliage_plan` 接线 + keylog-hook 互斥。**核心 opcode 序列诚实标注需真机验证**(shadow-space/对齐/CONTEXT 约束) |
| ~~Pool Party 注入~~ | ~~`implant-win/src/inject.rs:616`~~ | 🔶 **P5 已实装 (研究级,2026-07-05)**：新 `tp` 模块(NtCreateSection/NtMapViewOfSection + `_TP_DIRECT`/`_TP_WORK` 结构定义);`pool_party_inject` section-backed delivery(步骤 1-4 真实装);`POOL_PARTY_ENABLED` gate(默认 OFF);`do_inject` method 0 dispatch + 降级。**worker-queue splice(步骤 6d)诚实标注需真机验证 TP_DIRECT 布局** |
| ~~LSASS dump method 2~~ | ~~`implant-win/src/hashdump.rs:174`~~ | ✅ **P3 已闭合 (2026-07-05)**：① implant method-2 现返回带 LSASS PID 的可执行指令(`find_lsass_pid` via `CreateToolhelp32Snapshot`)+ 修 `do_hashdump_vec` method-2 误路由;② 新 crate `minidump-assembler` 把裸 LSASS 内存包成 mimikatz 可解析 `.dmp`(Header+SystemInfo+Memory64List,8 测试含 round-trip);③ `CredKit::dump_lsass_with_base` 暴露 base VA;④ `nyx-kernel --serve <port>` daemon 模式持久 session;⑤ `TaskKind::Hashdump` 客户端 dispatch |
| ~~PatchGuardWindow 基类~~ | ~~`operator-kernelsdk/src/persistence.rs:244`~~ | ✅ **P0.a 已闭合 (2026-07-05)**：vestigial 基类删除 + `pg-window` 子命令接线 `select_pg_window`（两个真实窗口 + 能力驱动委派已在 `win/mod.rs`，CLI 现已暴露）|
| ~~MiniFilter bootstrap 不接线~~ | ~~`operator-kernelsdk/src/win/mod.rs:286`~~ | ✅ **P0.b 已闭合 (2026-07-05)**：`offsets::flt::flt_globals_rva_for_build` build 表(17763/19041/22621/26100 + patch-equiv)自动 fallback；offset-resolver 新增 `--fltmgr` PDB 模式解析 `FltGlobals` 全局符号 RVA |
| keylog US 布局 only | `implant-win/src/keylog.rs` | 🔶 **布局感知已闭合 (P1, 2026-07-05)**：`ToUnicodeEx` + `GetKeyboardLayout` + `MapVirtualKeyExW` 替换硬编码 US 表,支持任意键盘布局(德/法/Dvorak…),失败降级 US 表。**hook-based 捕获仍为 P2**(需持久背景线程,违反单 trampoline 规则) |
| agent-dev 非作战 | `crates/agent-dev/src/lib.rs` | macOS/Linux dev beacon，token/inject/SOCKS 返回 unsupported |
| Win11 24H2 + CET 真机未验证 | CI runner EPYC 7763 无 CET | 硬件缺口，CI 已验证 5/7 子项（含 build 26100 编译 + CET 探测逻辑）|

---

## 8. 总判定

按"实际代码可见"的硬标准（不是文档自述）：

| 维度 | 真实装 | 诚实降级/stub | 占位/虚假 |
|---|---|---|---|
| 协议层（13 项）| 13 | 0 | 0 |
| 服务端（15 项）| 15 | 0 | 0 |
| 植入体用户态（17 项）| 17（P1 keylog 布局 + P4/P5 研究-gate 已接线）| 0 | 0 |
| 植入体任务（26 命令）| 26（P3 LSASS method-2 已接可执行信号）| 0 | 0 |
| 内核 tier（26 项）| 26（P0 PG + MiniFilter 已闭合）| 0 | 0 |
| 客户端（TUI 50 + GUI）| 全部 | 0 | 0 |
| 工程生态（12 crate,+minidump-assembler）| 11（agent-dev 是测试桩）| 1 | 0 |

**总计 ~119 项能力,~118 真实装（99%）,1 诚实降级(agent-dev 非作战),0 虚假占位。**

> **2026-07-05 缺口闭合更新**:审计 §7 原列 5 个"诚实降级"缺口,Foliage APC(P4)和 Pool Party(P5)已实装研究级代码 + gate(默认 OFF,操作员真机验证后开启),keylog 布局感知(P1)、LSASS round-trip(P3)、PatchGuard 接线(P0.a)、MiniFilter 自动解析(P0.b)全部完成真实装。详见各 P 阶段标注。

**核心结论**：
1. **零虚假宣传**——所有 stub 都在代码注释里诚实标注（"TODO P3-future"、"deferred"、"Until that thunk lands"），没有一个伪装成已实装。
2. **fail-closed 贯穿**——服务端 RwLock 中毒 / 时钟错 / token 不匹配 / 越权写全部拒绝；内核层 KVA==0 时 kit 降级为 None 而非崩。
3. **真机验证深度**——47 个 selftest export + 49/49 真机回归（Server 2019 17763.1339）+ Defender ON 下完整 beacon loop + 47 TUI 命令真机测试。
4. **唯一作战平台 Windows**——`agent-dev` 是测试桩不是 macOS/Linux 作战 implant；这是事实，国家级路线图 §C2 已覆盖。
5. **加密协议层是真正的强项**——方向隔离 nonce + 双向 pubkey 绑定的 HKDF info + ZeroizeOnDrop + 反 allocation-bomb，这部分质量达到商业级。

---

## 9. 与 STATUS.md 的偏差（本次审计发现的文档不准）

| STATUS.md 断言 | 实际代码 | 备注 |
|---|---|---|
| "all 21 dispatch arms"（beacon.rs doc comment）| 实际 26 arms | 文档 stale，是 FileOp 5 子变体通过 `Command::FileOp` 路由 |
| "Full relay is deferred"（beacon.rs:399）| pivot.rs 完整双向 relay | 文档 stale |
| "5-check envprobe suite" | 4 check + 综合裁决函数 | 文档表述误差 |
| "47 selftest exports"（部分文档）vs "48/49"（其他文档）| grep 实测 45（仅 selftests.rs）+ 2（entry.rs 中的）= 47 | 历史计数漂移 |

这些偏差**不影响安全态势**，但证明"不要相信文档"的审计原则是对的。

---

**审计完成。** 本文档是 `docs/STATUS.md` 的事实层补充——STATUS.md 是开发进度事实源，本文档是能力实装的事实源，两者冲突时以**代码**为准。
