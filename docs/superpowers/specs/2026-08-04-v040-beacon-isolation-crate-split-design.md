# v0.4.0 专项设计:Beacon 任务隔离 + 巨函数拆分 + implant-win crate 拆分

**日期:** 2026-08-04
**状态:** 已批准(用户逐节确认)
**来源:** `docs/design/NYX_REMEDIATION_PROGRAM_2026Q3.md` M1/M2;`docs/audits/FULL_CODE_AUDIT_2026-07-21.md` CRITICAL-19;`docs/audits/ANTI_HUMAN_AUDIT_2026-07-23.md` AH-1/AH-2
**分支:** `refactor/ah-audit-followups`(后续按工作包切子分支)

## 1. 目标与范围

关闭整改计划中三个相互关联的开放项:

| 工作包 | 审计来源 | 内容 |
|---|---|---|
| WP-A | AH-2 | 巨函数拆分:全部 35 个超 50 行函数 |
| WP-B | CRITICAL-19 | beacon 任务隔离:VEH 护栏 + panic 站点清零 + 可选 BOF 子进程模式 |
| WP-C | AH-1 | implant-win 拆分为 4 rlib + 1 cdylib 壳 |

**执行顺序:** WP-A → WP-B(B1→B2)→ WP-C(断环三刀→core→evasion→net→tasks)→ B3(BOF 子进程,依赖 WP-C 的 core crate)。每个工作包独立提交、独立过 CI、独立可回退。

**非目标:** 不新增未经验证的能力;不改变能力状态口径(BOF 子进程模式初发布标"受限交付");不顺手做 AH-9 剩余 `static mut`、AH-4 服务端拆分等清单外项。

## 2. 核心约束(现状调查事实)

1. implant-win 是 `no_std` + `no_main` + `panic=abort` 的 cdylib,不在根 workspace(自带 `[workspace]`),目标是 nightly `x86_64-pc-windows-gnu`。**macOS 开发机无法编译验证,全部验收走 CI**。
2. implant 的 `bof.rs` 自带 no_std COFF 加载 + Beacon-API shim,**不依赖** `nyx-bof-runner`(std 主机侧 crate)。BOF 子进程 host 代码从 `bof.rs` 抽。
3. VEH 已有先例:`blind_hwbp.rs` 以 `AddVectoredExceptionHandler(1, ...)` 挂链首,只处理 `STATUS_SINGLE_STEP`。护栏 handler 必须对 SINGLE_STEP 一律 `EXCEPTION_CONTINUE_SEARCH`。
4. `veh_chain_has_handlers` 探针发现链上有 handler 会永久禁用 HWBP(`VEH_SAFE=false`)——护栏须临时注册(任务前挂、任务后摘),不常驻。
5. 匿名管道 + 句柄继承模板在 `shell.rs`(`CreatePipe` + `STARTF_USESTDHANDLES` + `bInheritHandles=1`);section 交付代码在 `tp.rs:312-403`;PIC blob 管线(cdylib → `tools/srdi` / `crates/nyx-loader`)现成。
6. `create_sacrificial`(`inject.rs:152`)当前 `bInheritHandles=0`、STARTUPINFOW 全零,不支持输出重定向,需扩展变体。
7. 审计 3-crate 方案按真实依赖 DAG 不可落地,存在反向边:`fluctuation→beacon::sleep_seconds`、`kits↔beacon` 双向、`evasion_glue→inject::module_stomp`、跨层 `mem/channels→entry`(csprng/diag)。

## 3. WP-A:巨函数拆分(AH-2)

**范围:** 审计清单全部 35 个超 50 行函数。Top 10(implant-win 侧)优先:`cross_session_capture`(291)、`beacon_loop`(253)、`add_hwbp`(227)、`capture_bmp`(204)、`bof::run`(204)、`fluctuation_thunk::build`(203)、`post_frame_enhanced`(202)、`post_frame`(189)、`run_shell_inner`(187)、`hijack_worker_factory`(186);其余 25 个(含 server 侧 `handle_frame`、`generate_implant`、`main`)在动手前重新扫描确认清单(代码自审计以来已变)。

**方法:**

- 纯 extract-method 重构,**零行为变更**:不改控制流语义、错误码、日志文本、static 访问顺序。
- 按"阶段"切分(如 `bof::run` → parse / alloc / relocate / flip / call / capture 六段);子函数私有,不扩 pub 面。
- `beacon_loop` 和 `bof::run` 排在 WP-A 最后——WP-B 要动它们,先拆干净再动行为。
- 每个函数拆完立即过该 crate 现有测试;implant-win 改动以 CI Gate 5/6 + windows-ci 为验收。

**验收:** 35 个函数全部 <50 行(或记录例外及理由);workspace 测试全绿;CI Gate 1-6 + windows-ci 全绿;selftest bitmask 矩阵不变。

## 4. WP-B:CRITICAL-19 任务隔离(混合方案)

### B1 VEH 任务护栏

- 新模块 `task_guard.rs`,在 `beacon_dispatch_tasks` 的 `execute()` 调用点包一层。
- `AddVectoredExceptionHandler(0, guard_handler)` —— **First=0 挂链尾**,排在 blind_hwbp handler(First=1)之后;对 `STATUS_SINGLE_STEP` 永远 `EXCEPTION_CONTINUE_SEARCH`。
- 只认致命异常码:`STATUS_ACCESS_VIOLATION`、`STATUS_ILLEGAL_INSTRUCTION`、`STATUS_STACK_OVERFLOW` 等。
- 恢复机制:任务前 `RtlCaptureContext` 快照 beacon 线程上下文存入专属 static slot;命中时恢复 RSP/RIP/RBP,返回 `EXCEPTION_CONTINUE_EXECUTION`;`execute()` 走"任务崩溃"路径返回 `Response::Err("task crashed: ...")`,beacon 循环继续。
- 快照 slot 用 `AtomicU8` 状态机(空/已快照/处理中)防 VEH 内重入;单线程假设与全 crate 一致。
- **临时注册**:任务前挂、任务后摘,不常驻,不触发 `VEH_SAFE` 探针禁用 HWBP。
- Rust panic(panic=abort)不在护栏范围——abort 不可恢复,由 B2 负责;护栏只兜硬件异常。

### B2 任务路径 panic 站点清零

- 系统性扫描 `execute()` 可达路径(bof/inject/fs/shell/screenshot/keylog/trex/postex/recon)的 `unwrap/expect/assert!/unreachable!/panic!/切片索引`。
- 全部改 `Result`/`Option` 传播,在 `execute()` 边界统一转 `Response::Err`。
- 已知残留点:`trex/mod.rs:1179` from_utf8 unwrap、`bof.rs` 参数打包、`context.rs`/`tp.rs` 守卫型 unwrap 复核。

### B3 BOF 子进程模式(operator 可选,实施排在 WP-C core 抽出后)

- **bof-host blob:** 新 standalone crate `crates/bof-host`(no_std cdylib,复用 srdi/nyx-loader PIC 管线)。执行核心从 `bof.rs` 抽(parse/alloc/relocate/flip/call);BeaconPrintf shim 输出目标从 static OUT 换成 `WriteFile` 到继承 stdout;`resolve`/`heap` 依赖由 bof-host 自带最小子集(两模块无上层依赖)。
- **交付:** implant 侧扩展 `create_sacrificial` 变体(`STARTF_USESTDHANDLES` + `bInheritHandles=1`,照 `shell.rs` 模板);bof-host blob + `[u32 blob_len][blob][u32 args_len][args]` 打包,复用 `tp.rs` section 交付注入牺牲进程,恢复主线程。
- **回收:** 父端 ReadFile 到 EOF → `Response::BofOutput`;崩溃/超时(默认 60s,`WaitForSingleObject`)→ 退出码转 `Response::Err`;`SacrificialProcess` Drop-guard 防僵尸/句柄泄漏。
- **协议:** `Command::Bof` 加 `isolate: bool`(wire 尾部可选字段,后向兼容;旧组合按内联执行)。默认内联 + B1 护栏,operator 显式选隔离。
- **验证:** 新 selftest 导出 `nyx_selftest_bof_isolated`(跑 `bof_print.o` fixture,断言管道回收 "BOF-PRINT-OK")+ 故意崩溃 BOF fixture 断言 beacon 存活;windows-ci 真机跑,Qiling Gate 6 纳入 bitmask 矩阵;新旧 server/implant 组合兼容测试。
- **回退:** B1/B2/B3 独立提交;B3 有协议开关,关闭即回 B1+B2 状态。子进程模式失败可回退内联(带 WARN 前缀,照 pool party → module stomp 先例)。

## 5. WP-C:crate 拆分(AH-1,基于真实依赖 DAG)

修正后方案:**4 rlib + 1 cdylib 壳**,依赖方向单向:

```
nyx-implant-core ← nyx-implant-evasion ← nyx-implant-net ← nyx-implant-tasks ← nyx-implant-win(壳)
```

| crate | 模块 | 对外接口 |
|---|---|---|
| **core** | heap, cell, fmt, resolve, ntalloc, unhook, stack, version, syscalls, context, hostinfo, config + diag(csprng_fill/diag_mark,从 entry 抽出) | 解析/系统调用运行时/分配器/配置解密/SessionInfo 采集 |
| **evasion** | antidebug, blind, blind_hwbp, cfg_user, proxy_veh, caller_spoof, hookchain, lacuna, lacuna_stomp, sleep, fluctuation(+thunk), mem, insomniac, envprobe + evasion_glue 的 sleepmask 半 | AMSI/ETW blinding、HWBP、sleep mask、hookchain |
| **net** | envelopes, transport, channels/*(dns/doh/extc2/https/smb/tcp) | post_frame、ChannelCtx、dispatch_send_recv |
| **tasks** | beacon, bof, config_placeholder, env_keying, fs, hashdump, inject, keylog, kits, pivot, postex, recon, screenshot, shell, tp, trex, selftests + evasion_glue 的 inject 半 | beacon_loop/oneshot、命令处理、注入、BOF |
| **壳**(现 implant-win) | lib.rs(allocator/panic handler 注册)、entry、dllmain、server_pub、build.rs | `#[no_mangle]` PIC 入口、DllMain |

**断环三刀(前置,纯模块内移动,可独立验证):**

1. `beacon::sleep_seconds` 的 jitter sleep 下沉 evasion → 断 `fluctuation→beacon`;
2. `evasion_glue` 拆两半:sleepmask 半留 evasion,inject 半上移 tasks;
3. `entry` 的 `csprng_fill`/`diag_mark` 抽 diag 模块下沉 core → 断 `mem/channels→entry`。

**障碍与对策:**

- 全局唯一项(`#[global_allocator]`、`#[panic_handler]`、`#[alloc_error_handler]`、`server_pub` include)只能留壳;build.rs 烘焙逻辑随迁或改壳生成。
- 共享 static(`EVASION_ACTIVE`、`BLIND_OK/BLIND_ERR`、`mem::REGIONS/MASK_KEY`、`syscalls::GLOBAL_RT`)跨 crate 扩 pub 面;entry init 序列(`syscalls::init_global → blind → hookchain → mem key …`)文档化 + 顺序断言。
- ~17 处 `pub(crate)` 转 `pub`,逐个人工核对,不批量放开。
- 拆分顺序:断环三刀 → core → evasion → net → tasks,每抽一个过一次 CI。
- 4 个新 crate 继承独立 workspace 状态(不进根 workspace),纳入 CI Gate 4 standalone 构建清单;顺带补 AH-13:windows-gnu target 下对这些 crate 跑 clippy/fmt。

## 6. 整体验证策略与 Definition of Done

每个工作包关闭前必须全部满足(照整改计划 §3.2):

- 任务写明问题、范围、风险、负责人、回退方式;
- 有正向、异常、回归测试;
- CI 全绿:Gate 1-6(fmt/clippy/workspace tests/standalone 构建/Unicorn 仿真/Qiling 双构建)+ windows-ci(真机 Layer-2 probe、selftest 回归、内核评估);
- implant-win 变更以 windows-latest CI 为准;本地 macOS 无法编译的事实如实记录为"环境约束",不谎报本地验证;
- 协议变更(`Command::Bof.isolate`)做新旧组合兼容测试;
- 用户可见限制同步到 STATUS.md / CHANGELOG;BOF 子进程模式初发布标"受限交付";
- 变更不扩大未验证功能的默认可用范围。

**CI 门禁现状(验收所依据):**

- `.github/workflows/ci.yml`:Gate 1-3 fmt/clippy/tests;Gate 4 六个 standalone crate;Gate 5 loader-emu(Unicorn 仿真 LAYER1 契约,ubuntu);Gate 6 selftest-qiling(macos,mingw+nightly 双 DLL 构建,Qiling 逐个调 `nyx_selftest_*` 导出)。
- `.github/workflows/windows-ci.yml`(windows-latest):implant DLL 构建、真机 Layer-2 probe(HARD gate)、内核评估(HARD gate)、selftest 回归、live PDB 偏移解析。
- `.github/workflows/g6-verify.yml`(windows-2025):MSVC target selftest 构建、符号服务器偏移交叉验证。

## 7. 风险与回退

| 风险 | 缓解 |
|---|---|
| implant-win 只能 CI 验证,反馈慢 | 每 WP 小步提交;selftest/Qiling 先行;真机 probe 为最终门禁 |
| VEH 护栏与 HWBP/sleepmask 交互引入新崩溃 | First=0 链尾 + SINGLE_STEP 放行 + 临时注册;崩溃 BOF fixture 专项测试 |
| crate 拆分破坏初始化顺序 | init 序列文档化 + 顺序断言;自底向上每步过 CI |
| B3 协议变更破坏新旧互操作 | wire 尾部可选字段 + 组合兼容测试;默认关闭 |
| 35 函数拆分的机械 churn 引入行为漂移 | 零行为变更纪律 + 每步现有测试 + selftest bitmask 矩阵不变 |
