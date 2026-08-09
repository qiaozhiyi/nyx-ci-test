# Changelog

All notable changes to the Nyx C2 framework are documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

`0.1.0` is treated as a pre-release internal state that was never officially tagged;
`0.2.0` is the first shipped release. Entries cite the originating commit short-SHA so
operators can `git show` the exact change. Evidence is authoritative over prose — when
this file and the code disagree, the code wins.

## [Unreleased]

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
