# NYX 代码实情审计报告 (CODE_TRUTH) — ⚠️ 已被取代 (SUPERSEDED)

> ⚠️ **本文档已被 [`CODE_TRUTH_2026-07-18.md`](CODE_TRUTH_2026-07-18.md) 取代。**
> 本报告的状态结论(LOC/test/Command 计数、能力状态)已过时:实测 LOC 68,751(非 88,874)、Command 28(非 27)、test 488(非 674)、睡眠混淆未接线等关键修正见新报告。
> **本报告 §7 安全发现仍有效**,保留作历史参考。数字基准以 [`AUTHORITATIVE_FACTS_2026-07-18.md`](AUTHORITATIVE_FACTS_2026-07-18.md) 为准。

- **日期**: 2026-07-15
- **分支**: `main`
- **Commit**: `e70692e`
- **方法**: 以源码为唯一依据,不引用旧审计结论。每条声明附 `file:line` 证据。
- **审计范围**: 全部 26 crate + tools/srdi,共 88,874 LOC
- **取代**: 本报告取代 2026-07-03/07-05/07-08/07-10 四轮审计中的**状态结论**(安全发现仍有效,见 §7)

---

## §0 全局事实表(实测值)

| 指标 | 实测值 | 旧文档声明(漂移) | 测量方法 |
|---|---|---|---|
| 总 LOC | **88,874** | 69,509 / 77K / 88K | `find crates tools -name '*.rs' \| xargs wc -l` |
| crate 数 | **26 + 1 tool**(pe 死) | 25 / 26 | 目录计数 |
| `#[test]` 函数 | **674** | 88 / 119 / 142 / 326 / 44 | `grep -rE '#\[test\]' crates/` |
| selftest 导出 | **55** | 53 / 54 | 见 §0a |
| Command 变体 | **27** | 26 / 28 | `msg.rs:131-271` 枚举体 |
| Response 变体 | **7** | 7 | `msg.rs:562-584` |
| NYX_* env 变量 | **44**(含 1 测试哨兵) | — | `grep -rhoE 'NYX_[A-Z_]+'` |

### §0a selftest 导出分布(55 个)

| 文件 | 数量 |
|---|---|
| `implant-win/src/selftests.rs` | 48 |
| `implant-win/src/hookchain.rs` | 2 |
| `implant-win/src/entry.rs` | 2 |
| `implant-win/src/trex/mod.rs` | 1 |
| `implant-win/src/envprobe.rs` | 1 |
| `implant-win/src/syscalls.rs` | 1 |
| **合计** | **55** |

### §0b LOC 按 crate 实测

| crate | LOC | .rs 文件 |
|---|---|---|
| implant-win | 30,848 (+762 build.rs) | 63 |
| client-cli | 13,813 | 17 |
| operator-kernelsdk | 9,789 | 24 |
| client-ui | 6,337 | 11 |
| server | 5,956 | 7 |
| transport | 4,018 | 13 |
| implant-evasionsdk | 2,028 | 8 |
| protocol | 2,464 | 7 |
| profile | 2,240 | 11 |
| agent-dev | 1,181 | 2 |
| operator-kernel-cli | 865 | 5 |
| store | 842 | 4 |
| offset-resolver | 657 | 3 |
| nyx-mutate | 634 | 1 |
| coff | 557 | 2 |
| parse | 544 | 1 |
| bof-runner | 431 | 4 |
| nyx-loader | 448 | 2 |
| minidump-assembler | 469 | 1 |
| evasion | 412 | 4 |
| config-macros | 192 | 1 |
| config | 176 | 2 |
| pe (死) | 224 | 2 |
| scripting | 237 | 5 |
| scripting-rhai | 166 | 1 |
| rest | 164 | 1 |
| tools/srdi | 415 | 1 |

### §0c `#[test]` 按 crate 实测

| crate | tests | crate | tests |
|---|---|---|---|
| client-cli | 174 | implant-evasionsdk | 53 |
| operator-kernelsdk | 112 | transport | 75 |
| profile | 40 | protocol | 40 |
| server | 44(含 8 e2e + 4 beacon_limits) | store | 16 |
| parse | 19 | agent-dev | 13 |
| nyx-loader | 12 | evasion | 11 |
| nyx-mutate | 9 | minidump-assembler | 8 |
| coff | 7 | config | 6 |
| client-ui | 23 | pe | 4 |
| scripting-rhai | 2 | rest | 3 |
| scripting | 1 | bof-runner | 0 |
| config-macros | 0 | | |
| **合计** | **674** | | |

---

## §1 Route 1 — implant-win (30,848 LOC)

### 1.1 睡眠混淆

| 能力 | 代码实情 | 证据 file:line |
|---|---|---|
| Foliage APC 链 | 🔴死代码 + 🔴损坏 | `sleep.rs:256-259,416-419,980-983,1288-1291` 四处 FATAL 注释"Do NOT wire this into a code path";`execute_foliage_plan:261`、`execute_foliage_apc:421`、`rc4_shim:985`、`foliage_helper:1293` 全 `#[allow(dead_code)]`,零调用方 |
| `sleep::sleep()` 入口 | 🟡存在但 beacon 不调 | `sleep.rs:146-150` 委托给 fluctuation。beacon 走 `kits::sleep`(beacon.rs:511,644,661),从不调 `sleep::sleep`。仅 selftests 调 |
| `FOLIAGE_ENABLED` flag | 🟡真但无运行时效果 | `sleep.rs:49` 默认 ON;`foliage_enabled()` 只被死代码 `execute_foliage_plan` 读 |
| Fluctuation sleep mask | ✅完成并接线,默认ON | `fluctuation.rs:9-16,25-33`;`kits::sleep`(kits.rs:61-67)→ `Foliage` kit → `fluctuation::sleep`。`NYX_FLUCTUATION_OFF=1` 关闭 |
| Heap RC4 mask | ✅完成,stays ON | `mem.rs:185-206` CAS 守护的 RC4;fluctuation thunk Step 4 + `MaskGuard` drop 双保险 |
| `NYX_FOLIAGE_OFF` | 编译期,默认 ON | `sleep.rs:55` 读取;无运行时效果(死代码) |
| `NYX_FLUCTUATION_OFF` | 编译期,默认 ON | `fluctuation.rs:12`;OFF→退到 `beacon::sleep_seconds` |

**关键偏差**:STATUS.md:194 称"Foliage 睡眠掩码(APC 链 + RC4 .text + 堆掩码) ✅ FOLIAGE_ENABLED=ON"——**假**。APC 链从不可达,beacon 连 `sleep::sleep()` 都不调。实际跑的是 Fluctuation(PAGE_NOACCESS 翻转),不是 RC4 原地加密。

### 1.2 栈欺骗 SPOOF_SWAP

| 能力 | 代码实情 | 证据 file:line |
|---|---|---|
| 帧链合成 `StagedChain` | ✅真 | `stack.rs:144-189` |
| `mov rsp` 交换 asm | 🟡实现但 f 未在伪造栈执行 | `stack.rs:317-450`;selftests.rs:2528-2530 自认"f runs on the REAL stack...needs the CET-repair seam" |
| `#CP` 修复缝 | 🔴仅 doc | `stack.rs:40-51` 模块文档提 SSTIC-2025;无 `KiControlProtectionFault`/`RtlRestoreContext` 实现 |
| CET 探测 | ✅真 | `version.rs:66-88` `IsProcessorFeaturePresent(41)` |
| `SPOOF_SWAP_ENABLED` 默认 | 🟡运行时自动 arm ON | 静态 `false`(stack.rs:82),但 `entry.rs:143-150` 在 CET-off + gaps 可用时 `set_swap_enabled(true)`。在目标机(Server 2019 CET-off)上**实际开着** |
| `NYX_SPOOF_OFF` | 编译期,默认未设→armed | `entry.rs:137`;`=1` 才关 |

**关键偏差**:STATUS.md:195,235 称"默认 OFF(保守关闭)"——**误导**。静态初始化是 false,但 entry.rs 运行时自动 arm。在 CET-off 主机上实际 ON。

### 1.3 通道(9-channel dispatcher)

`channels/mod.rs:228-244` `dispatch_send_recv` 路由全部 9 个:

| 通道 | 代码实情 | 证据 |
|---|---|---|
| Https (0) | ✅完整 | `channels/https.rs`;WinHTTP + rotation/fronting/proxy + optional `NYX_SAFE_HTTP` |
| DohDns (1) | 🟡URI 伪装,非真 DoH 隧道 | `channels/doh.rs:46-77` 只是 `post_frame` 到 `/doh` |
| Dns (2) | 🟡URI 伪装,非 raw-UDP DNS | `channels/dns.rs:25-40` |
| SmbPipe (3) | ✅真 kernel32 FFI | `channels/smb.rs:158-250` |
| Tcp (4) | ✅真 ws2_32 FFI reverse_tcp | `channels/tcp.rs:263-384` |
| SlackApi (5) | 🟡server 中转,非直连 Slack | `channels/extc2.rs:44-58` → `/extc2/slack` |
| LlmApi (6) | 🟡server 中转 | `extc2.rs:65-79` → `/extc2/llm` |
| Mcp (7) | 🟡server 中转 | `extc2.rs:86-100` → `/extc2/mcp` |
| DiscordApi (8) | 🟡server 中转 | `extc2.rs:107-121` → `/extc2/discord` |
| 热切换 `set_active` | ✅真 | `channels/mod.rs:142-149` |
| Fallback 链 | 🟡stub | `DEFAULT_FALLBACK_CHAIN = &[Channel::Https]`(mod.rs:255),`next_fallback` 永返 None |

### 1.4 Implant 命令(27 个 wire 变体)

`beacon::execute`(beacon.rs:407-589)分发全部 27 个 Command 变体,无缺失:

| 命令 | 实情 | 命令 | 实情 |
|---|---|---|---|
| Ping | ✅ | Screenshot | ✅流式 |
| Sleep | ✅ | Portscan | ✅ |
| Shell | ✅ | Net | ✅ |
| Upload | ✅ | DriveInfo | ✅ |
| Download | ✅流式 | Clipboard | ✅ |
| Exit | ✅ | Env | ✅ |
| Bof | ✅ | Keylog | 🟡轮询采样,非 hook |
| Connect | 🟡仅 open+confirm,relay deferred | Screenwatch | 🟡阻塞 burst |
| Socks | 🟡控制面 | Hashdump | 🟡SAM/SYSTEM ✅;LSASS 🔴deferred Err |
| FileOp(Cd/Mkdir/Rm/Mv/Cp) | ✅ | ChannelData/Close | ✅ |
| StealToken | ✅ | MakeToken | ✅ |
| Rev2Self | ✅ | GetUid | ✅ |
| Inject | ✅(见 1.8) | Trex | ✅ |
| SetChannel | ✅ | | |

### 1.5 运行时 NYX_* gate

| gate | 读取点 | 默认 | 效果 |
|---|---|---|---|
| `NYX_POOL_PARTY_ON` | `tp.rs:59` | OFF | OFF→method 0 返回 Err 或退到 method 2 |
| `NYX_SAFE_HTTP` | `channels/https.rs:38` | OFF | `=1` 时 POST 包裹 mem::mask/unmask |
| `NYX_SKIP_SANDBOX` | `entry.rs:65`(运行时) | OFF(沙箱检查跑) | `=1` 跳过 envprobe + antidebug |
| `NYX_FS_ALLOW_PROTECTED` | `fs.rs:173`(运行时) | OFF | `=1` 允许 SAM/SYSTEM hive |
| `NYX_BYOVD` | **不存在** | — | grep 全 crate 无此 env 读取点;BYOVD 仅作概念出现在注释里 |

### 1.6 build.rs

- 读取:`NYX_SERVER_PUB`、`NYX_CONFIG`、`NYX_CONFIG_KEY`、`NYX_PROFILE`、`NYX_OFFSETS`(`build.rs:29-33,221,339`)
- config 加密:**始终加密**(`build.rs:149-162`)。`NYX_CONFIG_KEY` 设→用 ops key;未设→OsRng 随机 key + warning。key 与 ct 同嵌入二进制——obfuscation 非 confidentiality(文档诚实声明 `build.rs:147-148`)
- **07-10 审计称"build.rs bypasses config encryption"——假**

### 1.7 selftests(55 个)

见 §0a 分布。48 个在 selftests.rs(behind `#[cfg(feature="selftest")]`),7 个在 hookchain/trex/envprobe/syscalls/entry(不 feature-gate,始终编译)。

### 1.8 注入(inject.rs)

| 技术 | 实情 | 证据 |
|---|---|---|
| Module Stomp (method 2) | ✅默认ON | `inject.rs:56` `MODULESTOMP_ENABLED=true`;`stomp_and_resume:193-223` |
| Threadless HWBP (method 1) | ✅真 | `inject.rs:544-638` DR0/DR7 + 间接 syscall |
| Existing-process (pid≠0) | ✅真 | `inject.rs:832-923` |
| Pool Party (method 0) | 🟡仅投递半,非 threadless | `tp.rs:1-44` 自认"only delivery half...falls back to NtCreateThreadEx, classic IOC IS PRESENT";默认 OFF |

### 1.9 后渗透模块

| 模块 | 实情 |
|---|---|
| fs (upload/download/fileop) | ✅ |
| hashdump | 🟡 SAM/SYSTEM ✅;LSASS 🔴deferred |
| keylog | 🟡轮询采样,非 hook |
| screenshot | ✅ GDI + 跨会话 Task Scheduler helper |
| recon (driveinfo/env/clipboard/portscan/net) | ✅全实现 |
| pivot | 🟡控制面 ✅;全异步 relay deferred |
| postex tokens | ✅ |
| bof | ✅ W^X loader + CS shim;**leak 已修**(见 §7) |
| trex | ✅ scanner 真,`TREX_SCANNERS_IMPLEMENTED=true` |

### 1.10 规避

| 能力 | 实情 |
|---|---|
| unhook (NTDLL fresh-map) | ✅ KnownDlls + disk fallback + RAII unmap |
| blind (byte-patch AMSI/ETW/NtTraceEvent) | ✅ fallback 路径 |
| blind_hwbp (patchless HWBP VEH) | ✅ 主路径,bootstrap 调用 |
| HookChain | ✅ bootstrap 调用 |
| caller_spoof | ✅ scanner;`caller_spoof_thunk.rs` 🟡 调试 0xC0000005 |
| lacuna / insomniac | ✅ |
| cfg_user / proxy_veh | ✅ |

### 1.11 已知 bug 确认

| bug | 状态 |
|---|---|
| ntalloc UAF | ✅仍存在(故意不修)——`ntalloc.rs:64-78` 明确"NO EVICTION...accept bounded leak instead" |
| BOF section-memory leak | ✅**已修**——`SectionGuard::Drop`(bof.rs:720-757)`VirtualFree`+清零;07-10 审计过时 |
| Fluctuation RAII 不覆盖硬件异常 | 🟡部分缓解——inline thunk unmask 关闭唤醒后窗口;但 PAGE_NOACCESS 睡眠期间 `#PF` 仍杀进程(Drop 无法兜底) |

---

## §2 Route 2 — operator-kernelsdk + CLI + offset-resolver (11,311 LOC)

### 2.1 MiniFilter 解链

| 能力 | 代码实情 | 证据 |
|---|---|---|
| `MiniFilterUnlinker` 算法 | ✅完整+接线 | `telemetry.rs:249-332` |
| `flt_globals_kva` 解析 | ✅完整 | `win/mod.rs:231-236` |
| 三层 FltGlobals 解析 | ✅完整 | `win/mod.rs:380-389`(ops `--flt-rva` → build 表 → 0) |
| offset-resolver PDB 工具 | ✅真实现,非 stub | `offset-resolver/src/main.rs:539-617` 下载 fltmgr.pdb + 走节表 |
| CLI→server→client 全链 | ✅接线 | `operator-kernel-cli/main.rs:270-285`;`server/src/lib.rs:505`;`client-cli/rest.rs:1955`;`tui/mod.rs:2489` |

**校准**:STATUS 称"部分"——**低估**。端到端完整。

### 2.2 BYOVD(4 driver pack)

| driver | 代码实情 | 证据 |
|---|---|---|
| RtCore64 (CVE-2019-16098) | ✅可加载(默认 trait impl) | `byovd.rs:215-254`;IOCTL 0x80002048/0x8000204C |
| Iqvw64e (CVE-2015-2291) | ✅可加载 | `byovd.rs:283-355`;IOCTL 0x80862007 |
| Shield (EAZShield) | ✅可加载 | `byovd_drivers/shield.rs:57-145`;IOCTL 0x96102014 |
| WDTKernel (Dell WDT) | 🔴不可作 KernelRw(按契约 loud error) | `byovd_drivers/wdtkernel.rs:90-104` `raw_rw` 返 `Err(0)` |
| `default_driver()` | ✅默认 Shield | `byovd.rs:606-613` |
| `bootstrap_byovd` | ⚠️硬编码 RtCore64,忽略 `default_driver()` | `win/mod.rs:133-140`;`NYX_BYOVD` 对此路径无效 |
| KslD.sys (LivingOffDefender) | ✅完整,优先于 BYOVD | `win/ksld.rs:268-475` |

**关键偏差**:07-10 审计称"3/4 silently broken"——**假**。3 个完全可用 + 1 个按契约 loud error。真正的问题是 `bootstrap_byovd` 硬编码 RtCore64。

### 2.3 ETW-TI

| 能力 | 代码实情 | 证据 |
|---|---|---|
| `EtwTiBlind` (4-hop, write IsEnabled=0) | ✅完整+接线 | `etwti.rs:222-274`;`win/mod.rs:521-528` |
| build 表 (17763/18362-19044/20348-22000/22621-22631/26100-26200) | ✅ | `etwti.rs:124-203` |
| `etw_deception.rs` 事件伪造 | 🟡完整代码但**死代码**(无 tier/CLI 调用方) | `etw_deception.rs:117-333`;仅 `lib.rs:71` `pub mod` |
| "malformed EVENT_HEADER at :61" | 🔴**不存在** | layout 完全正确,`EVENT_HEADER_SIZE=80` 匹配 evntcons.h |

### 2.4 DKOM / 进程隐藏

| 能力 | 代码实情 |
|---|---|
| `ProcessHider` (ActiveProcessLinks unlink) | ✅完整+接线 `persistence.rs:32-124` |
| `ps_active_process_head_kva` pattern scan | ✅ `win/mod.rs:367-371` |
| CLI `hide <pid>` | ✅ `main.rs:176-190` |
| 注意:CLI `hide` 不自动包 `pg-window`——operator 编排缺口,非代码缺陷 |

### 2.5 回调摘除(Ps*NotifyRoutine)

| 能力 | 代码实情 |
|---|---|
| `CallbackNeutralizer::neutralize` (ret-stub 0xC3) | ✅ `telemetry.rs:84-142` |
| `repurpose` (HVCI-safe data write) | ✅ `telemetry.rs:154-238` |
| 三种数组(CreateProcess/CreateThread/LoadImage) | ✅ `telemetry.rs:44-48` |
| array KVA pattern scan | ✅ `pattern_scan.rs:164-205` |
| 接线 | 🟡assemble 了但 **CLI 无子命令**——只 examples 驱动 |

### 2.6 PatchGuard 窗口

| 能力 | 代码实情 |
|---|---|
| `TimingRepairWindow` (Outflank 式,全 build) | ✅ `persistence.rs:260-349` |
| `RuntimePgBypassWindow` (kurasagi 式,Win11 24H2+) | ✅ `persistence.rs:385-475` |
| 数量 | **2 real, 0 skeleton** |

**关键偏差**:旧文档"3 no-op"或"2-real/1-skeleton"——**假**。代码 `persistence.rs:9-13` 明确"the two real PG-bypass families...No skeleton base"。

### 2.7 offset-resolver

- PDB 下载(ureq HTTP)+ PE debug-dir GUID 提取(goblin)+ type-stream 解析:✅全真实现
- **模块文档 stale**:main.rs:28-33 称"PDB walker is next iteration"——实际已实现
- `detect_build_from_pdb`:🟡找到 NtBuildNumber 符号但读不出值,返 None 退回 17763

### 2.8 operator-kernel-cli

9 个子命令 + daemon 模式全工作:`blind-etw`/`hide`/`dump-lsass`/`neutralize`/`detach-minifilter`/`pg-window`/`cfg-bypass`/`bootstrap`/`--serve`。缺:callback-neutralize CLI、ETW deception CLI。

### 2.9 其他 kernel 能力

| 能力 | 代码实情 |
|---|---|
| WFP silencer (`UserModeEdrSilencer`) | 🔴装配了但运行时必失败——`block_outbound_for_pid` 永返 Err(P0-9 安全 stub);tier 却报 `wfp=true` |
| `EdrNeutralizer::kill` | 🟡只解析 EPROCESS KVA,不 terminate——terminate 留给 operator |
| PPL stripper (attack_edr_ppl / make_immortal) | ✅ `persistence.rs:131-232`;assemble 了但无 CLI 子命令 |
| CFG bitmap | ✅ lib 完整;CLI `cfg-bypass` 用内联实现,不调 `cfg.rs` |
| `KernelLsassReader` (dump_lsass) | ✅接线 `netsec.rs:463-508` |

---

## §3 Route 3 — server + protocol + rest + store (9,426 LOC)

### 3.1 wire 协议 crypto

| 能力 | 代码实情 |
|---|---|
| X25519 密钥交换 | ✅ `crypto.rs:268-275,321-328` |
| HKDF-SHA256 派生(双方 pubkey 绑定) | ✅ `crypto.rs:340-370` |
| ChaCha20-Poly1305 AEAD 帧 | ✅ `crypto.rs:412-452`;帧布局 `[32 pubkey][8 ctr][4 ct_len][ct‖16 tag]` |
| 方向隔离 nonce(防重放) | ✅ `crypto.rs:383-408`;nonce[0]=方向判别(C2S=0x00,S2C=0x01) |
| pubkey 作 AAD | ✅ `frame.rs:64` |
| 零化(Drop) | ✅ SessionKey/Keypair 全 impl Drop |
| 全零 scalar 拒绝 | ✅ `crypto.rs:180-186` |
| 反重放(单调 counter) | ✅ advisory `lib.rs:769-777`;authoritative `lib.rs:961-968` |

**无重大 crypto 弱点。**

### 3.2 消息类型

- **27 Command 变体**(tag 1-27),全 encode/decode,零 stub
- **7 Response 变体**(tag 1-7),全 encode/decode
- 批量编解码有 allocation-bomb 守卫(`MAX_BATCH=65536`、`MAX_WIRE_COUNT=256`)

### 3.3 SessionInfo(8 字段)

全编码全解析:`beacon_id`/`hostname`/`username`/`os`/`arch`/`pid`/`is_admin`/`auth_token`。

### 3.4 server HTTP 路由

| 类别 | 路由数 | 说明 |
|---|---|---|
| Beacon check-in | 7 固定 + 动态 profile URI | `/beacon`/`/doh`/`/dns`/`/extc2/{slack,discord,llm,mcp}` |
| Operator API | 14 | `/api/sessions`/`/task`/`/tasks`/`/results`/`/creds`/`/creds/delete`/`/audit`/`/audit/verify`/`/profile`/`/generate-implant`/`/implants`/`/implant/revoke` |
| Kernel API | 6(仅 `NYX_KERNEL_DAEMON` 设时注册) | `/api/kernel/{status,blind-etw,hide,dump-lsass,neutralize,detach-minifilter}` |

### 3.5 operator auth

- 三机制并存:`NYX_BOOTSTRAP_OPERATOR`(argon2 哈希)→ `NYX_OPERATORS_FILE`(JSON)→ `NYX_TOKEN`(legacy,sha256)
- 三角色:Admin / Operator / Viewer
- 常量时间比较(`subtle::ConstantTimeEq`)+ 定时均衡(防用户枚举)
- 锁中毒 fail-closed

### 3.6 implant 生成

✅真实工作:PE 模板加载 → 每 implant X25519 keypair → config ECDH+HKDF 派生 → ChaCha20-Poly1305 加密 → `.nyx_cfg` 节 patch → mutation → 一次性 auth_token + SHA-256 存储 → PE 重验 → rate limit(10/h)→ SQLite 持久化 → 撤销。`format` 字段接 `dll`/`shellcode`/`exe` 但只实现了 dll patching。

### 3.7 SQLite store

- WAL + synchronous=NORMAL + foreign_keys=ON
- `creds` 表(PK realm+user+kind)+ `implants` 表(UNIQUE implant_pub,3 index)
- **无 migration**——仅 `CREATE TABLE IF NOT EXISTS`
- **sessions 不持久化**——in-memory DashMap,重启丢失(仅 keypair 持久化)

### 3.8 审计日志

✅真实:JSONL + SHA-256 hash-chain(append-only,0600,flush-per-record)+ `/api/audit/verify` 验证端点 + 非管理员只看自己。

### 3.9 `rest` crate

🟡**"single source of truth" 半假**——server 定义自己的 view struct,**不依赖** `nyx-rest`。只有两个 client 用它。drift 靠人工约定维持,非编译期强制。

### 3.10 fuzz target

✅真实:cargo-fuzz 独立 workspace,3 个 decode 面 + 交叉校验,`panic=abort` 威胁模型。

---

## §4 Route 4 — client-cli + client-ui (20,150 LOC)

### 4.1 TUI 命令

**64 个 `MetaCmd` 条目**(~58 个独立顶层命令),**零 stub**。全部分发到真实 REST 调用或本地 overlay。按类别:session(10)/fileop(7)/exec(4)/recon(10)/priv(3)/keylog(3)/hashdump(1)/control(4)/kernel(6)/pivot(1)/socks(4)/creds(6)/audit(2)/implant-gen(3)/client(3)。

### 4.2 已知 bug 确认

| bug | 状态 |
|---|---|
| SOCKS5 auth bypass (handshake.rs:72-84) | ✅**已修**——有 creds 时强制 0x02,拒 0x00 回退;测试锁定 |
| /connect HTTP policy gap (rest.rs:513-517) | ✅**已修**——`enforce_http_policy` 在 spawn + /connect 两处执行;513-517 现在只是 TaskKind 注释 |

### 4.3 TUI 布局

✅全功能:tmux 式递归 pane 树 + 6 pane 视图 + 11 全屏 overlay + slash 命令 popup + 破坏性操作 y/N 确认 + 状态栏 + toast + 5 主题热切。

### 4.4 Makepad GUI

✅**非骨架,是 TUI 子集**:startup/connect ✅、session list ✅、console tab ✅、BOF tab ✅、file/proc/cred pane ✅、~35 命令动词 ✅、主题切换 ✅。
**缺**:kernel 端点、implant 生成/撤销、trex、channel 切换、keylog stream、SOCKS relay。
`main.rs`(3169 行)零测试。

### 4.5 client env

| var | 读取点 | 默认 |
|---|---|---|
| `NYX_SERVER` | client-cli/main.rs:20;client-ui/main.rs:2068 | `http://127.0.0.1:8443` |
| `NYX_TOKEN` | 两端 | none |
| `NYX_ALLOW_HTTP` | client-cli/rest.rs:442 | 未设→拒非 loopback 明文 |
| `NYX_CREDS_ENCRYPT` | client-cli/tui/credstore.rs:128 | 未设→允许明文;设→**拒绝**存储(不加密) |
| `NYX_START_DARK` | client-ui only | 未设→light |
| `NYX_AUTO_CONNECT` | client-ui only | 未设→显示对话框 |

### 4.6 凭据持久化

- operator token:**不持久化**(仅进程内存)
- harvested creds:**明文存** `~/.nyx/creds.json`(0600)
- `NYX_CREDS_ENCRYPT`:**名字误导**——不加密,是"拒绝明文存储"闸门。真加密未实现。

### 4.7 两端 REST 对齐

- wire 类型:✅共享 `nyx-rest`
- `Cmd` enum:🟡**各自定义,已分化**——GUI 缺 ~10 个 CLI 有的变体
- 端点:🟡GUI 缺 `/api/kernel/*`、`/api/generate-implant`、`/api/implants`、`/api/implant/revoke`

### 4.8 残留问题

- `/api/results` 调用漏 `authed()`(rest.rs:2924)——secured server 上结果轮询会断
- GUI 启动塞 3 个假 session(mock_1/2/3)直到首次真实 fetch 覆盖

---

## §5 Route 5 — 支撑 crate (13,957 LOC, 16 crate)

### 5.1 transport crate — 通道 + TLS beacon bug

`transport/` crate 有 8 个 `Transport` impl + 1 个 stub:

| channel | 代码实情 |
|---|---|
| Malleable HTTP (CS-style) | ✅ `malleable.rs:256` |
| DoH DNS | ✅ `doh_dns.rs:211` |
| SMB named pipe | ✅ `smb_pipe.rs:126`(Windows-only) |
| Slack API | ✅ `slack_api.rs:58` |
| LLM API | ✅ `llm_api.rs:181` |
| MCP (JSON-RPC) | ✅ `mcp.rs:230` |
| WebTransport (QUIC/H3) | 🔴**STUB**——全方法返 `Dead` |
| TCP / ICMP / WebSocket / HTTP/2 channel | 🔴**不存在** |

**关键**:implant-win 的 9-channel dispatcher(`channels/mod.rs`)是独立实现,不走 `transport/` crate。`transport/` crate 的 `TransportStack` **零消费者**(orphaned)——只有 JA3/JA4 计算接在 server 上。

**WinHTTP TLS beacon bug**:确认在 `implant-win/src/transport.rs:347-354` + `:615-622`——`WinHttpSetOption` 在 `WinHttpSendRequest` 失败后调。但**默认不走此路径**(`tls_insecure_retry()` 默认 false,需 `NYX_TLS_INSECURE=1`)。明文 HTTP + 有效 CA 的 HTTPS 不受影响。

### 5.2 TLS 指纹

| 能力 | 代码实情 |
|---|---|
| JA3/JA4 计算 | ✅接在 server 上 `tls.rs:196,239` |
| ClientHello 解析/sniff | ✅ |
| HTTP/2 Akamai 指纹计算 | ✅但仅测试用 `h2.rs:78` |
| HPACK 伪头序 | 🔴未解析(stub 字段) |
| **指纹 emitter(出站伪装)** | 🔴**死代码**——`emitter.rs` 自认"NOT WIRED";`rquest` feature 空占位 |

### 5.3 malleable C2 profile

✅最完整 crate 之一:lexer + parser(泛型 AST)+ c2lint bin + data-transform engine(Base64/Netbios/Mask/Prepend/Append)+ server 消费 + implant build-time bake。`mask` CS 互操作不声称(用自洽 FNV 方案)。

### 5.4 evasion SDK

- 9 trait seam + no-op floor + EvasionStack 组合:✅
- 纯 Rust 核心(gap/frame/rc4/foliage/apc/swap):✅有单测
- **5/9 trait 有 live impl**(implant-win/evasion_glue.rs):PdataGapScanner/StackSpoofKit/BlindKit/MemoryMaskKit/ProcessInjectKit/SleepmaskKit
- `lib.rs:44` 自称"Seams only; no real impls yet"——**stale**,低估了

### 5.5 syscall 解析

✅ Hell's Gate + Halo's Gate + Tartarus' Gate 全真实现,`resolve_table` 三级 fallback,直接/间接 syscall stub 模板。

### 5.6 COFF + BOF

- COFF 解析(AMD64)+ 重定位:✅覆盖 CS-BOF 相关子集(ADDR64/ADDR32NB/REL32/REL32_1..5)
- BOF run:✅ W^X loader + CS Beacon-API shim
- **"BOF section-memory leak"——假,已修**(SectionGuard::Drop,双重确认)

### 5.7 nyx-loader

- ChaCha20-Poly1305 payload 加密 + NYX2 header 组装:✅
- **反射 PE 加载:🔴未实现**——PIC stub 以 `ret` + NOP sled 结尾(`stub.rs:74`),PEB walk/import resolve/DllMain 是 Phase-2b 占位

### 5.8 nyx-mutate

| pass | 实情 |
|---|---|
| NOP 插入(rel32 修复) | ✅ `lib.rs:126` |
| 寄存器轮转 | ✅ `lib.rs:207` |
| 密钥随机化 | ✅ `lib.rs:352` |
| **指令替换** | 🔴**不存在** |

接在 server implant_gen 上(`server/src/implant_gen.rs:499-505`)。

### 5.9 config + config-macros

- `embed!` proc-macro + AEAD 加密:✅
- `NYX_CONFIG_KEY` 64-hex override:✅
- **"build.rs bypasses config encryption"——假**,始终加密
- 诚实:caveat 是 key 同嵌入二进制(obfuscation 非 confidentiality)

### 5.10 scripting + scripting-rhai

✅Rhai 真接在 server 上:3 个 event(SessionNew/ResultReceived/SessionExit)+ `nyx_log` host fn + 资源 cap。缺更多 event 种类。

### 5.11 parse

✅6 个解析器全测:POSIX ls/ps、Windows tasklist/dir(含 de-DE)、mimikatz creds、auto-detect。

### 5.12 agent-dev

✅真实参考实现:完整 beacon 协议循环 + ~16 个 POSIX 命令。Windows-only 原语(StealToken/MakeToken/Rev2Self/Inject/Trex/SetChannel)stub Err。

### 5.13 minidump-assembler

✅真实:MDMP envelope + SystemInfoStream + Memory64ListStream。产 mimikatz 最小可行 .dmp。接在 operator-kernel-cli 上。故意省略 ThreadList/ModuleList。

### 5.14 pe crate

✅确认死:零依赖、workspace exclude、唯一 pub fn `resolve_export` 只被自己测试调。

---

## §6 偏差汇总(代码实情 ≠ 旧文档声明)

| # | 旧文档声明 | 代码实情 | 严重性 |
|---|---|---|---|
| 1 | STATUS:Foliage APC "✅ FOLIAGE_ENABLED=ON" | 🔴死代码,beacon 不调,FATAL 注释 | 高(粉饰) |
| 2 | STATUS:SPOOF_SWAP "默认 OFF" | 🟡运行时自动 arm ON(CET-off 主机) | 高(误导) |
| 3 | STATUS:MiniFilter "部分" | ✅端到端完整 | 中(低估) |
| 4 | STATUS/BYOV:"3/4 BYOVD broken" | 3 可用 + 1 loud-error | 高(假) |
| 5 | 旧审计:"etw_deception.rs:61 malformed EVENT_HEADER" | layout 正确,bug 不存在 | 高(假) |
| 6 | 旧文档:"PG 3 no-op"/"2-real/1-skeleton" | 2 real, 0 skeleton | 中(假) |
| 7 | 07-10:"BOF section-memory leak" | ✅已修(SectionGuard::Drop) | 高(过时) |
| 8 | 07-10:"build.rs bypasses config encryption" | 始终加密 | 高(假) |
| 9 | 07-10:"SOCKS5 auth bypass" | ✅已修 | 高(过时) |
| 10 | 07-10:"/connect HTTP policy gap" | ✅已修 | 高(过时) |
| 11 | STATUS:"26 Command 变体" | 27 | 低(旧) |
| 12 | STATUS:"selftest 54 个" | 55 | 低(差一) |
| 13 | README:"69,509 LOC" | 88,874 | 低(漂移) |
| 14 | 各处测试数 88/119/142/326/44 | 674 | 低(漂移) |
| 15 | rest:"single source of truth" | server 不依赖它,只 client 用 | 中(架构) |
| 16 | "9 channels" headline | implant-win dispatcher 9 个(4 个 ExtC2 仅 server 中转);transport/ crate 8 个(1 stub)+ 零消费者 | 中(过度) |
| 17 | nyx-mutate:"指令替换" | 不存在 | 中(假) |
| 18 | nyx-loader:反射加载 | 🔴未实现(stub) | 中(假) |
| 19 | implant-evasionsdk:"Seams only, no real impls" | 5/9 有 live impl | 低(stale) |
| 20 | `NYX_CREDS_ENCRYPT`:加密 | 不加密,是拒绝存储闸门 | 中(误导) |
| 21 | `NYX_BYOVD` gate | 不存在(env 无读取点) | 中(假) |
| 22 | GUI 与 TUI 功能对等 | GUI 是 TUI 子集 | 中(过度) |
| 23 | WFP silencer | 装配但运行时必失败 | 中(假可用) |
| 24 | 指纹 emitter | 死代码,出站指纹不可控 | 中(过度) |
| 25 | fallback 链 | 只有 Https 一个元素,`next_fallback` 永返 None | 中(假可用) |

---

## §7 活跃缺陷(沿用 07-10 + 本次校准)

### 本次校准:**移除**(已修或假)

| 原级别 | 条目 | 移除原因 |
|---|---|---|
| HIGH | BOF section-memory leak | SectionGuard::Drop 已修(Route 1+5 双确认) |
| HIGH | build.rs bypasses config encryption | 假,始终加密(Route 5 确认) |
| HIGH | SOCKS5 auth bypass | 已修(Route 4 确认) |
| HIGH | /connect HTTP policy gap | 已修(Route 4 确认) |
| HIGH | etw_deception malformed EVENT_HEADER | 假,layout 正确(Route 2 确认) |

### 仍活跃

| 级别 | 条目 | 证据 |
|---|---|---|
| HIGH | ntalloc UAF(故意不修,受控泄漏) | `ntalloc.rs:64-78` |
| HIGH | WFP silencer 装配但必失败,tier 误报 wfp=true | `netsec.rs:327-337`;`win/mod.rs:579` |
| MED | Fluctuation RAII 不覆盖睡眠期间硬件异常 | `fluctuation.rs:35-51` |
| MED | `/api/results` 调用漏 `authed()` | `client-cli/rest.rs:2924` |
| MED | `bootstrap_byovd` 硬编码 RtCore64,忽略 `default_driver()` | `win/mod.rs:133-140` |
| MED | etw_deception 死代码(完整但无调用方) | `etw_deception.rs` |
| MED | callback neutralize 无 CLI 子命令 | `operator-kernel-cli/main.rs` |
| MED | GUI 缺 kernel/implant-gen/trex/channel 端点 | `client-ui/bridge.rs` |
| MED | rest crate 非 server 真相源,drift 无强制 | `server/src/lib.rs` vs `rest/src/lib.rs` |
| MED | transport/ crate 零消费者(orphaned) | `transport/src/traits.rs` |
| MED | 指纹 emitter 死代码 | `transport/src/emitter.rs` |
| MED | nyx-loader 反射加载未实现 | `nyx-loader/src/stub.rs:74` |
| MED | fallback 链仅 Https | `channels/mod.rs:255` |
| LOW | 无 SQLite migration | `store/src/store.rs` |
| LOW | sessions 不持久化 | `server/src/lib.rs:80` |
| LOW | GUI main.rs 零测试 | `client-ui/src/main.rs` |
| LOW | GUI 启动塞 3 假 session | `client-ui/src/main.rs:42-75` |
| LOW | `detect_build_from_pdb` 读不出值 | `offset-resolver/src/main.rs:182-212` |
| LOW | GUI `Cmd` enum 与 CLI 分化 | `bridge.rs:112` vs `rest.rs:147` |

---

## 附录:审计方法

- 5 路并行 agent,每路只读一个子系统,代码为唯一依据
- 计数冲突(Command 27 vs 28、selftest 47 vs 55)由主审亲自 `grep`/`wc` 核实
- LOC/test/selftest/env 全部实测,非引用旧文档
- 07-10 审计的 20 HIGH 逐条核对:5 条移除(已修/假),其余沿用或降级
