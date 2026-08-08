# Bypass 能力清单

> **日期:** 2026-06-27（内核 H-K 全链路真机验证完成，含 callback 诊断全量数据）
> **验证环境:** Windows Server 2019 Datacenter 17763.1339 + RTCore64.sys (CVE-2019-16098)
> **授权:** 仅限授权红队 / 安全研究
> **事实口径:** 数字、接线状态、crate 状态以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。本文成文较早，下方凡是与 AUTHORITATIVE_FACTS 冲突处已在对应条目中以"⚠️ 审计修正（2026-07-18）"标注。

每个手段标注真实状态：✅ 真机验证 · 🔶 代码完成待验证 · ❌ 未实现
接线状态：🟢 已接通 · 🟡 部分接通 · 🔴 未接通

---

## 一、用户态 bypass（implant 侧，DLL 内）

### 1. 间接 Syscall（不调 ntdll 的 `syscall` 指令）✅

**对抗：** EDR 的 ntdll hook（ETW + inline hook）、用户态 API 监控

**原理：** 不通过 `ntdll.dll` 导出的 API 发 syscall。运行时扫 ntdll `.text` 段找 `syscall; ret` gadget，解析 SSN（Hell's Gate / Halo's Gate / Tartarus's Gate），然后从一个 RX trampoline 页直接执行 `syscall` 指令。调用栈上不出现 ntdll API 地址。

**实现：**
- `syscalls.rs` — `Runtime` 运行时 + SSN 解析（djb2 哈希查找）+ trampoline 定位
- Halo's Gate / Tartarus's Gate 邻居遍历（应对 SSN 被 hook 抹零）
- 已封装 wrapper：`nt_close` / `nt_create_file` / `nt_write_file` / `nt_read_file` / `nt_set_information_file` / `nt_delay_execution` / `nt_protect_virtual_memory` / `nt_queue_apc_thread` / `nt_continue` / `nt_get/set_context_thread` / `nt_open_thread`

**真机验证：** `nyx_selftest_syscall_rt` exit=0b11 ✅

---

### 2. ETW 盲化（NtTraceEvent byte patch）✅

**对抗：** ETW Threat Intelligence 的用户态通知路径、Defender ETW 订阅

**原理：** patch `ntdll!NtTraceEvent` 的第一字节为 `0xC3`（ret），使 ETW 写入在用户态直接返回，内核收不到事件。幂等（重复 patch 不崩溃）。

**实现：** `blind.rs::patch_nt_trace_event()` — PEB walk 解析 ntdll → 定位 NtTraceEvent → VirtualProtect RX→RW → 写 `0xC3` → 恢复 RX

**附加：** `disable_etw_provider()` — `NtTraceControl` 尝试禁用 provider（⚠️ 真机验证：用户态对内核 provider 返回 `0xC000000D`，无效，需内核 blind）

**真机验证：** `nyx_selftest_blind_nttrace` exit=0b1111 ✅ · PE-sieve 检出 1 hooked（即此 patch，预期）

---

### 3. AMSI 盲化 ✅

**对抗：** AMSI（Anti-Malware Scan Interface）脚本扫描

**原理：** patch `amsi.dll!AmsiScanBuffer` 使其返回 `AMSI_RESULT_CLEAN`，绕过 PowerShell/脚本的内容扫描。

**实现：** `blind.rs::patch_amsi()` — 解析 amsi.dll → 定位 AmsiScanBuffer → patch 返回值

**真机验证：** 代码完成，selftest 框架就绪 🔶（未单独 selftest，但 blind() 调用链已验证）

---

### 3b. HWBP Patchless Blind（硬件断点 + VEH，无 .text 修改）✅

**对抗：** PE-sieve `.text` hash-mismatch、`VirtualProtect`-on-code-page 信号 —— §2/§3 的 byte-patch blind 都要 `VirtualProtect`（RX→RW→RX）改 `.text` 字节，这个内存属性变化本身是检测信号。

**原理：** **不修改任何 `.text` 字节、不调 `VirtualProtect`**。在 `ntdll!NtTraceEvent`（和 `amsi!AmsiScanBuffer`，若已加载）的第一条指令上设 DR0 **execute** 硬件断点（通过 `NtSetContextThread` 写 debug 寄存器），并注册一个 VEH handler。CPU 命中 DR0 → 抛 `STATUS_SINGLE_STEP` → VEH 把 RIP 重定向到一个 shadow stub（`xor eax,eax;ret` 让 ETW 返回 0 / `mov eax,E_INVALIDARG;ret` 让 AMSI 返回错参），并设 EFLAGS 的 Resume Flag（RF）让 shadow 执行一次。目标函数从未真正执行，但调用方拿到干净的返回值。下一次调用再次命中 HWBP（RF 是一次性的）。

**实现：**
- `blind_hwbp.rs::add_hwbp()` — `NtGetContextThread`(CONTEXT_FULL) → 写 DR0=target、DR6=0、DR7=L0(execute) → `NtSetContextThread`(CONTEXT_DEBUG_REGISTERS) → 注册 `hwbp_veh_handler`
- `blind_hwbp.rs::hwbp_veh_handler` — VEH：校验 `STATUS_SINGLE_STEP` + DR6.B0–B3 → 清 DR6 → 设 RIP=shadow stub → 设 RF → `EXCEPTION_CONTINUE_EXECUTION`
- `blind_hwbp.rs::init_shadow_buffer()` — VirtualAlloc RWX 一个 4KB 页，写入两个 shadow stub（ETW/AMSI 各一）
- `entry.rs` — bootstrap 先试 HWBP，失败降级到 P2.1b byte-patch blind

**真机验证：** `nyx_selftest_hwbp_blind` exit=255 (0xFF)，诊断 `01abcdxyzefghijkSTUZ` 全程通过 ✅

> **历史：** 此能力曾因 `resolve.rs` PE 转发导出解析 bug 崩溃（exit `0xC0000005`），根因不在 HWBP/VEH。完整复盘见 `docs/p2-2026-06-hwbp-resolve-forwarder-postmortem.md`。

---

### 4. ntdll Unhook（从磁盘重映射干净 .text）✅

**对抗：** EDR 在 ntdll `.text` 段插的 inline hook

**原理：** 从 `\Windows\System32\ntdll.dll`（磁盘原始文件）映射一份干净的 `.text` 段，与内存中被 hook 的版本做 diff，把干净字节覆盖回去。支持磁盘读取 + 已映射 ntdll 读取两种路径。

**实现：** `unhook.rs` — `fresh_ntdll_text()` / `fresh_ntdll_text_disk()` / `text_diff_count()` / `scan_syscall_gadget_range()`

**真机验证：** 代码完成 🔶（未单独 selftest，是 unhook 模块的标准能力）

---

### 5. Foliage 睡眠掩码（APC 链加密 .text）✅ 算法真 · 🔴 未接线

> ⚠️ **审计修正（2026-07-18，AUTHORITATIVE_FACTS §1/§2）**：Foliage / Fluctuation / mem::mask 的算法与单元测试均真，但 **implant 睡眠混淆路径整体未接线**——`implant-win/src/kits.rs:65-71` 短路到 `beacon::sleep_seconds`，Fluctuation/Foliage/mem::mask 全部死路径。下文"默认 ON""已接通"等表述为成文时（2026-06-27）自评，**当前不成立**。这是 AUTHORITATIVE_FACTS §3 #1 优先级缺口（接线睡眠混淆）。算法层的 selftest 验证结果（foliage / foliage_apc）仍然有效，因为它们测的是算法子模块而非端到端睡眠路径。

**对抗：** 内存扫描器（PE-sieve / Moneta / BeaconEye）在 beacon 睡眠时扫描 implant 内存

**原理：** beacon 线程睡眠时，一个 helper 线程通过 APC 链：`NtProtectVirtualMemory(.text RX→RW)` → RC4 加密整个 `.text` → beacon 在 `NtDelayExecution` 中睡眠（此时 `.text` 是密文）→ 唤醒后 RC4 解密 → `NtProtectVirtualMemory(RW→RX)` 恢复。扫描器在睡眠窗口内看到的是密文，不是可识别的 PE 代码。

**实现：**
- `evasionsdk/foliage.rs` — 10 步状态机（纯算法，5 测）
- `evasionsdk/apc.rs` — APC/NtContinue 链合成（纯算法，5 测）
- `evasionsdk/rc4.rs` — SystemFunction032 RC4 加密（6 测）
- `implant-win/sleep.rs` — `execute_foliage_apc()`：真 helper 线程 + APC 编排 + raw export 解析（避免间接 Runtime 的 trampoline 竞态）
- `implant-win/context.rs` — x64 CONTEXT 结构体（1232B，编译期 size/align 断言）
- `implant-win/mem.rs` — `enumerate_beacon_heap_regions()` / `mask_heap_regions()` / `unmask_heap_regions()`：注册区域 + 分配器 slab 联合枚举 + RC4 遮蔽
- `implant-win/ntalloc.rs` — slab tracking（`SlabDesc[16]`），`enumerate_slabs()` / `heap_bytes()`
- 默认 **ON**（`FOLIAGE_ENABLED = true`，`sleep.rs:40`）—— .text + 堆区域掩码开箱即用
- **堆区域集成（2026-06-27）：** Foliage helper 在 .text RC4 之后追加 `mask_heap_regions(key)`，唤醒时在 .text 解密之前执行 `unmask_heap_regions(key)`（堆先于 .text 恢复）

**真机验证：** `nyx_selftest_foliage` exit=0b1 ✅ · `nyx_selftest_foliage_apc` exit=0b11（3/3 稳定，round-trip 字节校验）✅ · PE-sieve armed 扫描 0 新增命中 ✅

---

### 6. 栈欺骗（BYOUD-Gap RSP swap）🔶 需显式启用 · caller-spoof 仅 scanner

> ⚠️ **审计修正（2026-07-18，AUTHORITATIVE_FACTS §3 #7）**：`caller_spoof` 宏实现当前**仅 scanner**（扫描器侧），未实现完整的运行时调用方欺骗宏；`.pdata` gap / frame / swap 算法真且已 selftest，但端到端"任意敏感调用都自动 spoof"的宏未完成。下文接线现状为成文时自评。

**对抗：** 栈回溯检测（call stack 上出现 implant 地址 / RX 私有页）

**原理：** 扫描 ntdll 的 `.pdata` 找"gap"（函数之间的空隙，无异常处理信息的地址）。把假栈搭建在这些 gap 地址上（看起来像合法 ntdll 调用链），然后 `mov rsp` 把栈指针切到假栈上执行。CET-on 主机自动降级（不执行 swap，避免 `#CP`）。

**实现：**
- `evasionsdk/gap.rs` — .pdata gap 枚举（10 测）
- `evasionsdk/frame.rs` — BYOUD 假帧链合成（8 测）
- `evasionsdk/swap.rs` — CET-aware 决策（悲观降级，5 测）
- `implant-win/stack.rs` — `with_spoofed_stack()`：staging + `spoof_trampoline` + per-`<T,F>` 单态化桥 + `MaybeUninit` out-slot。f 真在 spoofed RSP 上执行。
- `implant-win/version.rs` — `cet_active()`：真 `IsProcessorFeaturePresent(41)` 探测
- 默认 gated **OFF**（`SPOOF_SWAP_ENABLED = false`，`stack.rs:82`）—— CET-on host 前保守关闭，避免 `#CP`。**接线现状：** gap-pool 装填 + staging + `with_spoofed_stack` 内的 CET/gaps 运行时降级（`decide()`）均为真且已 selftest 验证；缺的只是 `core_bootstrap` 时的自动 arm 决策——CET-off 且 gaps 可用的主机目前仍需 operator 手动 `set_swap_enabled(true)`。自动化激活见 `entry.rs` 的栈欺骗 arm 路径（任务 #2）。

**真机验证：** `nyx_selftest_swap_decision` exit=0b11 ✅ · `nyx_selftest_swap_armed` exit=0b1111（5/5 稳定，f 在 spoofed 栈执行无崩溃）✅

---

### 7. 进程注入（Module Stomping）✅

**对抗：** Moneta 的 unbacked/exec-private 内存检测

**原理：** 在 sacrificial 进程（如 notepad.exe）中 LoadLibrary 一个合法签名的 cover DLL（如 `xpsservices.dll`），然后覆写 cover DLL 的 `.text` 段为 shellcode。因为 shellcode 跑在一个有合法 backing 的模块里，Moneta 的 "unbacked private commit" 检测扫不出。

**实现：** `inject.rs::module_stomp()` — `CreateRemoteThread(LoadLibraryA)` 加载 cover DLL → 远程 PE 解析（真 `.text` VA/size）→ `VirtualProtectEx` RX→RWX → `WriteProcessMemory` shellcode → 恢复 RX → `ResumeThread`
- 修了跨进程指针 bug（旧代码把 implant 本地指针当远程参数传）
- 默认 **ON**（`MODULESTOMP_ENABLED = true`，`inject.rs:56`）—— module stomping + ThreadlessInject 开箱即用

**已知限制：** module stomping 的 `.text` 被覆盖仍可能被高级扫描器察觉；**ThreadlessInject (HWBP)** 是补充手段，**已实现**（`inject.rs:489-632`：RWX 分配→shellcode→线程挂起→CONTEXT DR0/DR7→`NtSetContextThread`→恢复），与 module stomp 并列可用。

**真机验证：** `nyx_selftest_inject` exit=0b1111 ✅ · `nyx_selftest_inject_armed` exit=0b1111（2/2 真实 .text 覆写+执行）✅

---

### 8. 反调试 / 反沙箱 ✅

**对抗：** 调试器附加检测、低 uptime 沙箱环境检测

**实现：** `antidebug.rs`
- `is_debugged()` — PEB `BeingDebugged` 标志（PEB+0x02）
- `is_remote_debugged()` — `CheckRemoteDebuggerPresent`
- `uptime_secs()` — `GetTickCount64` 转 uptime
- `looks_sandboxed(min_uptime)` — uptime < 阈值判定沙箱

**真机验证：** `nyx_selftest_antidebug` exit=0b111 ✅

---

### 9. 内存区域加密（运行时 mask/unmask）✅ 算法真 · 🔴 未接线（端到端睡眠路径）

> ⚠️ **审计修正（2026-07-18）**：`mem::mask` / `unmask` / `mask_text` 算法真且单元测试通过，但端到端睡眠路径下 `kits.rs:65-71` 短路，mem::mask 与 Foliage 同为死路径（见 §5 修正）。selftest_mem 仍有效（测的是 mask 算法本身）。

**对抗：** 静态内存扫描发现 implant 数据（配置、密钥、payload）

**实现：** `mem.rs`
- `register_region()` — 注册需要加密的 `&'static mut [u8]` 区域
- `mask()` / `unmask()` — RC4 加密/解密所有注册区域（per-boot key）
- `mask_text()` / `unmask_text()` — 专门加密 `.text` 段（RX↔RW flip + RC4），供 Foliage 链调用
- `enumerate_beacon_heap_regions()` — 注册区域 + 所有 allocator slab 联合枚举（2026-06-27）
- `mask_heap_regions()` / `unmask_heap_regions()` — RC4 遮蔽所有堆区域（2026-06-27）
- `ntalloc.rs` slab tracking — `SlabDesc[16]` + `enumerate_slabs()` + `heap_bytes()`（2026-06-27）

**真机验证：** `nyx_selftest_mem` exit=0b11 ✅

---

## 二、内核态 bypass（operator 侧，需 BYOVD driver）

> **⚠️ 前置条件（适用本章节 §10–§17 全部能力）：必须先成功加载一个合法签名的漏洞驱动获取内核读写（`KernelRw`）能力。** 未加载驱动时，本章节所有能力均不可用。`byovd.rs` 头部明确标注 "CODE SHIPPED, NOT LOADED"——代码已就绪，但驱动加载是 operator 的显式动作，非默认行为。
>
> **驱动加载链：** 优先 KslD.sys（Living off the Defender, §18）→ 回退 RTCore64.sys (CVE-2019-16098, §10)。驱动层已抽象为 `VulnDriverIoctl` trait，可插拔其他 Nday/白驱动（见 §10 末尾）。
> 真机验证在 Server 2019 17763.1339 上完成（2026-06-26，任务 G-K 全通过）。

### 10. BYOVD 内核读写（KernelRw via RTCore64）✅

**对抗：** 无内核权限的 EDR 检测

**原理：** 加载一个有漏洞的合法签名驱动（RTCore64.sys，MSI Afterburner），通过其 IOCTL 通道读写任意物理地址。配合 4 级页表遍历（VA→PA），实现内核虚拟地址的读写。

**实现：**
- `byovd.rs` — `ByovdDriver`（IOCTL 封包/解包，48 字节固定协议）+ `RtCore64`（device_path + IOCTL codes + protocol 枚举）
- `win/driver_load.rs` — `NtLoadDriver` bootstrap（注册表 key + ImagePath + DeviceName + Type=内核 + 加载/卸载）
- `win/pagewalk.rs` — x64 4 级页表遍历 VA→PA（纯算法，5 测）
- `win/va_rw.rs` — `VaKernelRw`：VA→PA→物理读写的 KernelRw 适配器
- `win/resolve.rs` — `resolve_sym()` + `GetModuleHandleA` + `GetProcAddress` + `LoadLibraryA` fallback + `resolve_module_by_partial_name` 模糊查找
- `win/kernel_base.rs` — ntoskrnl 基址（`NtQuerySystemInformation`，含 Win11 24H2 KASLR 置零处理）
- `byovd.rs::resolve_kernel_symbol` — ntoskrnl 导出表解析（RVA）

**接线状态：** 🟢 100% — `operator_kernelsdk::win::bootstrap_byovd()` 完整接通：driver_load → ByovdDriver::open → 返回 (LoadedDriver, ByovdDriver)

**真机验证（任务 H，2026-06-27）：**
- RTCore64 加载成功 ✅，ntoskrnl base=`0xfffff8057fa19000`
- PE header 校验通过 ✅（MZ + PE\0\0 + export dir size=0xA7B80）
- 10MB 连续内核读成功 ✅
- ntoskrnl 导出表解析：ETW_THREAT_INT=0x40A6B0, PSP_PROCESS=0x4D9D70, PS_ACTIVE_HEAD=0x40E5C0 ✅

---

### 11. ETW-TI 内核盲化（IsEnabled=0）✅

**对抗：** ETW Threat Intelligence provider（Defender 依赖它检测内核内存操作）

**原理：** 通过内核读写，定位 `EtwThreatIntProvRegHandle`（非导出全局，需 PDB 解析 RVA）→ 追链 GUIDEntry → ProviderEnableInfo → 写 `IsEnabled=0`。provider 被 disable 后，所有 ETW-TI 消费者（含 DefenderApiLogger）不再收到内核 VM 操作事件。

**实现：** `etwti.rs::EtwTiBlind` — `init_from_runtime()` + GUID chase（3 级指针解引用）+ IsEnabled 写零
- 跨版本 offset 表：17763 EnableInfo @0x060，22621+ @0x070
- UBR 敏感：17763 RTM(UBR<1075) @0x050 vs patched @0x060

**接线状态：** 🟢 100% — `operator_kernelsdk::win::blind_etw_ti_full()` 完整接通：bootstrap_byovd → EtwTiBlind::blind()

**真机验证（任务 I，2026-06-27）：**
- `IsEnabled` `0x000000ff00000001` → `0x0000000000000000`，provider DISABLED ✅
- EtwThreatIntProvRegHandle 地址：0xffffc30c32652c80 ✅

---

### 12. 进程隐藏（DKOM ActiveProcessLinks unlink）✅

**对抗：** `tasklist` / `Get-Process` / 进程枚举型 EDR

**原理：** 从 `PsActiveProcessHead` 遍历双向链表找到目标 EPROCESS，把它的 `ActiveProcessLinks` 从链表中摘除（unlink）。进程继续运行但不在枚举结果里。用完恢复（relink 回链表头）。

**实现：** `persistence.rs::ProcessHider` — `find_eprocess()`（PID 匹配）+ `unlink()`（Flink/Blink 指针操作）
- EPROCESS offset 跨版本（17763 PID@0x2e0 Links@0x2e8，20348+ @0x440/@0x448）

**接线状态：** 🟢 100% — 通过 `KernelBootstrap::as_kernel_rw()` 调用 `ProcessHider::hide_pid()`

**真机验证（任务 J，2026-06-27）：**
- 启动 notepad.exe (PID=7756)，`PsActiveProcessHead` KVA = `0xfffff8057fe275c0`
- EPROCESS 查找成功 @ `0xffffc30c40e83080`，ImageFileName = "notepad.exe" ✅
- unlink 前 `tasklist` count = 1 → unlink 后 count = **0** → relink 后 count = **1** ✅
- PatchGuard 未触发 ✅

---

### 13. PPL 保护级别剥离 ✅

**对抗：** Protected Process Light（受保护进程无法被 OpenProcess 操作）

**原理：** 写目标 EPROCESS 的 `Protection` 字段为 `PS_PROTECTION.UNPROTECTED`（全零），降级保护级别。之后可以正常 OpenProcess 操作该进程。

**实现：** `persistence.rs::strip_protection()` — `SignatureLevel`/`SectionSignatureLevel`/`Protection` 三字段清零
- Protection offset 跨版本（17763 @0x6ca，20348+ @0x87a）

**真机验证：** 算法 + offset 已验证 🔶（未单独 selftest，offset 真机确认正确）

---

### 14. EDR 回调中和（repurpose ctx 指针）✅

**对抗：** `PsSetCreateProcessNotifyRoutine` 回调（Sysmon / WdFilter / KslD 等的进程创建监控）

**原理：** 不覆写回调函数的 `.text`（会导致 triple fault，因为 slot[0] 是 ntoskrnl 内部分发器）。而是**数据写**：把回调的 `ctx+0x00` 指针改指向 ntoskrnl 内的一个 `ret` gadget。内核调用回调时立即返回，EDR 收不到进程创建通知。用完恢复（写回原始 routine 指针）。

**实现：**
- `telemetry.rs::CallbackKit` — `routine = *(ctx+0)` offset 已真机验证 ✅
- `telemetry.rs::CallbackNeutralizer::repurpose()` — **DATA 写路径已迁入库代码**（2026-06-26），HVCI-safe（非 .text 写），**selective slot targeting 已完成**（2026-06-27）：range-based ntoskrnl skip + slot[0] fallback
- `examples/callback_repurpose_test.rs` — 完整 repurpose 逻辑（ret gadget 解析 + 跳过 ntoskrnl 内部 slot + 数据写 ctx 指针）
- `telemetry.rs::neutralize()` — ⚠️ 已知危险（.text 写 → triple fault），仅在 PG 窗口内使用

**接线状态：** 🟢 100% — repurpose DATA 写路径已迁入，**selective slot targeting 已完成**（range-based ntoskrnl skip + slot[0] fallback）

**真机验证（任务 K，2026-06-27，三阶段）：**

*K-A: callback_probe_readonly（只读诊断，10 slot 全量扫描）*
| slot | packed | ctx+0x00 (routine) | 所属驱动 | 备注 |
|---|---|---|---|---|
| 0 | 0xffffc30c32650c3f | 0xfffff8057fa95e50 | **ntoskrnl.exe +0x7CE50** | ⚠️ 内部分发器，不可中和 |
| 1 | 0xffffc30c326fef9f | 0xfffff80420229640 | cng.sys +0x9640 | |
| 2 | 0xffffc30c33059b1f | 0xfffff80420b50e00 | WdFilter.sys +0x30E00 | Defender |
| 3 | 0xffffc30c33059def | 0xfffff8041fe8c410 | ksecdd.sys +0x1C410 | |
| 4 | 0xffffc30c33059d2f | 0xfffff80421e25db0 | tcpip.sys +0x5DB0 | |
| 5 | 0xffffc30c335a51df | 0xfffff80421279ae0 | **SysmonDrv.sys +0x9AE0** | ← repurpose 目标 |
| 6 | 0xffffc30c335a595f | 0xfffff804201af320 | CI.dll +0x6F320 | |
| 7 | 0xffffc30c335a5b9f | 0xfffff804214320d0 | dxgkrnl.sys +0x20D0 | |
| 8 | 0xffffc30c412c1b5f | 0xfffff80423223c90 | peauth.sys +0x43C90 | |
| 9 | 0xffffc30c412bf3cf | 0xfffff80422eaa0f0 | KslD.sys +0xA0F0 | BYOVD 驱动 |

- ret gadget: ntoskrnl+0x17F0 = `0xfffff8057fa1a7f0` (bytes=[c3 cc cc cc]) ✅
- telemetry.rs `routine=*(ctx+0)` 假设：全部 10 slot 一致确认 PLAUSIBLE ✅

*K-B: callback_owner_map（slot→驱动映射 + ntoskrnl 边界判定）*
- ntoskrnl range: `0xfffff8057fa19000` – `0xfffff80580489000` (size=0xA70000)
- slot[0] routine=0xfffff8057fa95e50 ∈ ntoskrnl range → 正确标记为 ntoskrnl internal ✅
- 156 loaded modules 枚举成功 ✅

*K-C: callback_repurpose_test（repurpose 验证 + Sysmon EID1 静默/恢复）*
| 阶段 | marker | Sysmon EID1 记录 | 预期 | 结果 |
|---|---|---|---|---|
| BASELINE | MARKER_BASELINE_1111 | ✅ true | callback 活跃 | ✅ |
| REPURPOSED | MARKER_REPURPOSED_2222 | ❌ false | callback 静默 | ✅ **SILENCED** |
| RESTORED | MARKER_RESTORED_3333 | ✅ true | callback 恢复 | ✅ **RESUMED** |
- SysmonDrv 位于 slot[5]，ctx+0x00 从 `0xfffff80421279ae0` → `0xfffff8057fa1a7f0` (ret gadget) → 恢复 ✅
- DATA 写（非 .text），HVCI-safe ✅

---

### 15. WFP 网络过滤规则生成 🔶

**对抗：** EDR 的网络通信（C2 beacon 检测、遥测上报）

**原理：** 生成 WFP（Windows Filtering Platform）filter 规则，按 EDR PID 阻断其出站网络。

**实现：** `netsec.rs::WfpRuleSet` — `rules_for(edr_pids)` 生成 block 规则

**真机验证：** 算法完成 🔶（WFP filter 注入需要内核调用站 binding，未真机执行）

---

### 16. LSASS 内存读取 🔶

**对抗：** 凭据提取时的 LSASS 保护

**原理：** 通过内核读写直接读 LSASS 进程内存（绕过 PPL 保护和用户态 OpenProcess 限制）。

**实现：** `netsec.rs` — `read_process_mem()` 框架

**真机验证：** 框架就绪 🔶（LSASS 特定的解密/解析未实现）

---

### 18. KslD.sys Living off the Defender（优先驱动加载路径）✅

**对抗：** BYOVD 驱动加载检测（RTCore64.sys 不在所有主机上存在）

**原理：** 优先从 Defender 自带的 `KslD.sys`（KrnlSecLab Driver，Windows 10 1809+）获取内核读写能力。KslD.sys 由 Defender 安装、有合法签名、在 Defender-on 的主机上总是存在。通过注册表 + `NtLoadDriver` 加载后，用其 IOCTL 通道执行内核物理读写（和 RTCore64 相同的 ByovdDriver 适配）。

**实现：**
- `operator-kernelsdk/src/win/driver_load.rs` — `load_ksld()` 完整 NtLoadDriver 注册表 bootstrap
- `operator-kernelsdk/src/win/mod.rs` — `bootstrap_chain()` Priority 1: KslD → Priority 2: RTCore64 fallback
- `operator-kernelsdk/src/byovd.rs` — `ByovdDriver`（RTCore64 专用）；KslD 的完整 KernelRw 在 `win/ksld.rs`（`LivingOffDefender`，`QueryDosDeviceW` 动态设备枚举 + 逐字节 kread/kwrite）

**接线状态：** 🟢 100% — `bootstrap_chain()` 已接通 KslD 优先路径 + `LivingOffDefender::open()` 支持动态 `QueryDosDeviceW` 枚举 MpKsl* 设备名

**真机验证（任务 G）：** RTCore64 路径验证通过（KslD 路径待独立验证） ✅

---

### 19. MiniFilter 断开（list-unlink 已注册过滤器）🔶 算法完成，接线缺

**对抗：** 内核态文件系统监控（Defender/WdFilter 的文件过滤回调）

> ⚠️ **纠正历史虚构**：早期文档（及 `docs/archive/` 中的报告）曾声称存在
> `operator-kernelsdk/src/win/minifilter.rs` 实现 `FltRegisterFilter` /
> `FltUnregisterFilter` / `pause()` / `resume()`——**该文件不存在**。实际能力是
> 以下 unlink 算法，而非加载/卸载/暂停一个 filter driver。

**实际原理：** 不加载新的 MiniFilter driver。而是遍历 `FLTMGR!FltGlobals →
FrameList → RegisteredFilters`，把目标 EDR 过滤器（如 WdFilter）从注册链表上
**unlink**（数据写，HVCI-safe）。过滤器进程仍在，但内核不再派发文件 I/O 给它。

**实现：** `operator-kernelsdk/src/telemetry.rs::MiniFilterUnlinker::detach_edr`
（`telemetry.rs:248-289`）—— `LIST_ENTRY` 遍历 + unlink。

**接线状态：** 🔴 算法已写，**`bootstrap_chain()` 未接线** —— `win/mod.rs:286`
`flt_globals_kva: 0`（需 fltmgr PDB/pattern 解析 FLTMGR 的 `FltGlobals` 全局）。
无 `minifilter.rs`，无 `FltRegisterFilter`。

**真机验证：** 代码完成 🔶（未接线，故未上真机）

**真机验证：** 代码完成 🔶

---

## 三、跨版本通用化

### 17. 跨版本内核 Offset 解析（编译期烘焙 + 运行时表）✅

**对抗：** Windows 版本更新导致 EPROCESS/ETW 结构体偏移漂移

**两层架构：**
1. **运行时表**（`offsets_table.rs`）— 覆盖 Win10 1809→Win11 25H2 共 8 个 build，按 PEB OSBuildNumber 查表
2. **Pattern scan**（预留）— 未知 build 的兜底

> 注：编译期烘焙（`NYX_OFFSETS`/`bake_offsets`）已于 2026-08-08 移除——生成文件自始无 `include!` 消费方（offset-resolver 的产出物无下游），偏移单一来源为 evasionsdk 运行时表。目标侧零解析由查表实现。

**覆盖版本：**
| Build | 版本 | PID offset | Protection offset |
|---|---|---|---|
| 17763 | Server 2019 / 1809 | 0x2e0 | 0x6ca |
| 18362-19045 | Win10 19H1-22H2 | 0x2e8 | 0x6fa |
| 20348/22000 | Server 2022 / Win11 21H2 | 0x440 | 0x87a |
| 22621/22631 | Win11 22H2/23H2 | 0x440 | 0x87a |
| 26100/26200 | Win11 24H2/25H2 | 0x450 | 0x87e |

**真机验证：** Server 2019 build_number=17763 + CET=off ✅（`IsProcessorFeaturePresent(41)` 真实探测）

---

## 四、能力矩阵（按检测器对抗维度）

| 检测手段 | 对抗能力 | 状态 |
|---|---|---|
| **ETW Threat Intelligence** | 用户态 NtTraceEvent patch（盲化用户态通知）+ 内核 IsEnabled=0（盲化 provider） | ✅ |
| **ntdll inline hook** | 间接 syscall（不经过 ntdll）+ ntdll unhook（磁盘重映射） | ✅ |
| **AMSI** | AmsiScanBuffer patch | ✅ |
| **内存扫描（PE-sieve）** | Foliage .text RC4 加密（算法真）+ 间接 syscall trampoline 在合法页 | 🔴 **睡眠路径未接线**（kits.rs:65-71 短路，见 §5 修正） |
| **内存扫描（Moneta）** | Module stomping（backed 内存）+ Foliage（算法真） | 🔴 睡眠路径未接线（见 §5） |
| **睡眠检测（HSB/BeaconEye）** | Foliage APC 链（.text 加密 + NtDelayExecution）| 🔴 **未接线**（kits.rs 短路，AUTHORITATIVE_FACTS §3 #1） |
| **栈回溯检测** | BYOUD-Gap RSP swap（假栈搭建在 ntdll gap 地址）| ✅ |
| **调试器** | PEB BeingDebugged + CheckRemoteDebuggerPresent | ✅ |
| **沙箱（低 uptime）** | uptime 检测 | ✅ |
| **进程枚举** | DKOM ActiveProcessLinks unlink | ✅ |
| **PPL 保护** | Protection 字段剥离 | ✅ |
| **EDR 回调（Sysmon/WdFilter）** | ctx 指针 repurpose → ret gadget（DATA 写，HVCI-safe，**selective slot 已完成**） | ✅ 真机验证 EID1 SILENCED/RESUMED |
| **驱动加载（BYOVD）** | bootstrap_chain(): KslD 优先（动态 `QueryDosDeviceW` 枚举）→ RTCore64 回退 | ✅ 真机（KslD 设备动态解析 + RTCore64） |
| **MiniFilter 文件过滤** | `telemetry.rs::MiniFilterUnlinker`（list-unlink 已注册过滤器，数据写） | 🔶 算法完成，**bootstrap 未接线**（`flt_globals_kva=0`） |
| **PE .text hash（PE-sieve）** | ThreadlessInject (HWBP)（`inject.rs:489-632`） | ✅ 已实现 |
| **CET shadow stack** | 悲观降级（CET-on 不执行 RSP swap，`SPOOF_SWAP_ENABLED=false`） | ✅ 降级安全 |
| **PatchGuard** | `TimingRepairWindow` + `RuntimePgBypassWindow`（真实数据写窗口）+ 短暂 DKOM + 回调 repurpose（数据写不碰 .text） | ✅ 2/3 窗口真实 / PG 未触发 |
| **HVCI** | .text 代码写不可用（用数据写 ctx 指针代替） | ✅ 数据写安全 |
| **TLS 指纹（JA3/JA4）** | transport crate 有 JA3/JA4 计算引擎，但 `build_impersonating_client` 是 **Err stub**；emitter 未接线 | 🔴 **stub**（AUTHORITATIVE_FACTS §3 #5）—— team server JA3 暴露 |
| **多信道传输（DoH/Slack/LLM/MCP/SMB）** | transport crate 6 个 Transport impl | 🔴 **全部零消费者**（AUTHORITATIVE_FACTS §0/§1/§3 #4）—— 代码在，implant/server 不消费 |

---

## 五、未实现 / 接线中的 bypass（明确列出）

> 注：下方几项**曾经是 TODO 但已实现**，从"未实现"移出——见 §5/§19/矩阵：
> ThreadlessInject ✅、PDB field walker ✅、Pattern scan ✅、NtContinue CONTEXT 伪造 ✅。

| 能力 | 说明 | 状态 |
|---|---|---|
| **睡眠混淆接线** | `kits.rs:65-71` 短路到 `beacon::sleep_seconds`，Fluctuation/Foliage/mem::mask 全死路径 | 🔴 **未接通**（AUTHORITATIVE_FACTS §3 #1，最高优先级） |
| **TLS 指纹 emitter** | `transport/src/emitter.rs` 是 Err stub；JA3/JA4 引擎有但 emission 未接线 | 🔴 **stub**（AUTHORITATIVE_FACTS §3 #5） |
| **transport 信道消费** | 6 个 Transport impl（Malleable/DoH/Slack/LLM/MCP/SMB）全部零消费者 | 🔴 **未接通**（AUTHORITATIVE_FACTS §3 #4） |
| **caller-spoof 运行时宏** | 当前仅 scanner，缺任意敏感调用的自动 spoof 宏 | 🔴 未接通（AUTHORITATIVE_FACTS §3 #7） |
| **MiniFilter 接线** | `telemetry.rs::MiniFilterUnlinker` 算法已写，但 `bootstrap_chain()` 未解析 `flt_globals_kva` | 🔴 算法在，接线缺（G4） |
| **driver 加载的 HVCI/CI 绕过** | HVCI-on 主机上 RTCore64 可能被 CI 拒绝 | 当前目标 HVCI-off；HVCI-on 需 DMA 或 driverless CVE |
| **WFP filter 注入** | netsec 规则生成的内核调用站 binding | 🔶 算法就绪，binding 未接 |
| **LSASS 凭据解析** | `read_process_mem` 框架就绪，LSASS 特化的 drypt 解析未实现 | 🔶 框架就绪 |
| **postex token 操作接线** | `postex.rs` 有 steal/use/revert 实现，但无 `Command` 调用（仅 selftest） | 🔴 未接线（G1） |

---

*每个能力的状态基于 2026-06-27 的代码 + Server 2019 真机验证。内核 H-K 任务全量数据见各节。未标注真机验证的项 = 代码完成但未在真机上执行。接线状态标注：🟢 100% · 🟡 部分（见各节说明） · 🔴 未接通。*
*2026-07-18 审计裁定（AUTHORITATIVE_FACTS）：睡眠混淆路径、TLS emitter、6 个 transport 信道消费、caller-spoof 宏均未接线——以上条目已就地标注"审计修正"。当前代码总量 68,751 LOC / wire Command 28 变体 / selftest 导出 50 符号（49 `nyx_selftest_*` + 1 `nyx_linger*`），数字以 AUTHORITATIVE_FACTS §0 为准。*
