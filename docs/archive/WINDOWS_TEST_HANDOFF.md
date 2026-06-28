# Windows 测试交接说明 v2（内核 + 用户态全覆盖）

> **机器:** `ssh win` / `administrator@154.201.73.219`，Windows Server 2019 Datacenter 17763.1339
> **仓库:** `C:\Users\administrator\Desktop\nyx\pentest`
> **工具链:** nightly `rustc 1.98` + rust-src + `x86_64-pc-windows-msvc` + MSVC 14.44 (`C:\BuildTools`)
> **DLL:** `crates\implant-win\target\…\release\nyx_implant_win.dll`（已构建，209KB）
> **Defender:** 实时保护开启，无排除路径
> **当前测试:** 9/9 selftest 绿 + 36 内核测试绿 + 47 SDK 测试绿

---

## 已验证的（别重跑

**用户态 selftest（9 个全绿）：** calib42, syscall_rt, gap_scan, blind_nttrace, mem, foliage, swap_decision, inject, antidebug

**内核 + SDK 单元测试（全绿）：**
```
cargo test --manifest-path crates\operator-kernelsdk\Cargo.toml    :: 36 passed
cargo test --manifest-path crates\implant-evasionsdk\Cargo.toml    :: 47 passed
cargo test --manifest-path crates\evasion\Cargo.toml               :: 11 passed
```

**重建 implant（改了代码后）：**
```
cmd /c "call C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat >nul 2>&1 && cd C:\Users\administrator\Desktop\nyx\pentest && cargo +nightly build --release --manifest-path crates\implant-win\Cargo.toml --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort"
```

---

## 测试任务清单（按顺序，每步出结果）

### 任务 A：PE-sieve 内存扫描【用户态，安全】

**目标：** implant 存活时 PE-sieve 扫不出 suspicious region。

1. 下载 PE-sieve 到 `%TEMP%\nyx_detectors\pe-sieve64.exe`
   - https://github.com/hasherezade/pe-sieve/releases/latest
2. 编译 EnableDebug.exe（SeDebugPrivilege 包装器）：
   ```
   cd C:\Users\administrator\Desktop\nyx\pentest\scripts
   C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe EnableDebug.cs
   ```
3. 运行扫描：
   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\Users\administrator\Desktop\nyx\pentest\scripts\scan_linger.ps1
   ```
4. **记录：** PE-sieve 报告里 suspicious / dumped / implanted 的计数

**预期：** 间接 syscall trampoline 页（RWX private commit）可能被标——已知项。gap pool / blind patch 不应被标。

### 任务 B：Foliage armed 扫描对比【用户态，安全】

**目标：** 对比 foliage arm 前后的扫描结果。

1. 在 `selftests.rs` 的 `nyx_linger` 导出后加一个 `nyx_linger_foliage`（复制 nyx_linger，开头加 `crate::sleep::set_foliage_enabled(true);`）
2. 重建 DLL
3. 复制 scan_linger.ps1 改名为 scan_linger_foliage.ps1，改导出名
4. 跑扫描，对比 A 的结果

### 任务 C：blind provider-disable 真效【用户态，安全】

**目标：** NtTraceControl 让 ETW-TI provider 沉默。

1. `logman query "Microsoft-Windows-Threat-Intelligence"` 看 provider 状态（可能需要管理员权限）
2. 跑 nyx_linger（它会调 blind + disable_etw_provider）
3. 再 `logman query` 确认状态变化
4. 如果有 ETW collection session：`tracerpt` 生成 CSV，对比 blind 前后事件数

### 任务 D：inject stomp 完整执行【用户态，⚠️ Defender 可能拦】

**目标：** arm `modulestomp_enabled` 后跑完整 stomp + resume。

1. ⚠️ 先检查 Defender：`Get-MpComputerStatus | Select RealTimeProtectionEnabled`
2. 在 selftest 或临时脚本里调 `crate::inject::set_modulestomp_enabled(true)`
3. 跑 nyx_selftest_inject（arm 后会 stomp + resume）
4. 观察 notepad.exe 行为 + Defender 是否拦截

### 任务 E：Foliage .text APC 链【写代码】

**目标：** 让 beacon 线程停靠时 helper 线程加密 .text。

当前 `sleep.rs` 的 `execute_foliage_plan` 只加密数据区（mem::mask），不碰 .text。完整实现需要：
1. `CreateThread` 一个 helper 线程
2. helper: `NtProtectVirtualMemory(.text RX→RW)` → RC4 → 等主线程睡完 → RC4 解密 → protect RW→RX
3. 主线程: `NtDelayExecution`（睡眠窗口内 .text 是密文）

已有 syscall wrapper（`syscalls.rs`）：nt_queue_apc_thread, nt_continue, nt_get/set_context_thread。
纯算法核心（`evasionsdk`）：foliage.rs（10 步状态机）+ apc.rs（APC 链合成）。

### 任务 F：RSP swap mov rsp asm【写代码】

**目标：** `with_spoofed_stack` 真的 swap RSP。

当前 staging + 决策已完成，asm 执行是空壳。需要写 per-T naked function（nightly `#[naked]`）。
CET 决策已完整（`swap.rs` + `version::cet_active()`），Server 2019 CET=off 所以安全。

---

## 内核 tier 测试（⚠️ 有 BSOD 风险，建议 VM）

> **前置：** 内核测试需要放一个 vulnerable signed driver（如 RTCore64.sys）到机器上。
> 当前机器上**没有** driver 文件，Defender 实时保护**开着**。

### 任务 G：准备 driver + Defender 排除【前置】

1. 获取 RTCore64.sys（CVE-2019-16098，MSI Afterburner 驱动）
   - 从 loldrivers.io 下载，或从真实 MSI Afterburner 安装包提取
   - 放到 `C:\Users\administrator\RTCore64.sys`
2. **⚠️ Defender 排除（否则会立刻删掉 driver）：**
   ```powershell
   Add-MpPreference -ExclusionPath "C:\Users\administrator\RTCore64.sys"
   ```
3. 启用 SeLoadDriverPrivilege（operator 进程需要）：
   - 以 Administrator 运行即可（内置管理员有此权限）
   - 或用 `whoami /priv` 确认 SeLoadDriverPrivilege

### 任务 H：BYOVD driver 加载测试【内核，⚠️ BSOD 风险】

**目标：** `win::driver_load::LoadedDriver::load` 成功加载 RTCore64。

1. 写一个临时测试程序（或 PowerShell 脚本调用），调 `bootstrap_byovd`
2. 确认：
   - `sc query RTCore64` 显示 RUNNING
   - `\\.\RTCore64` 设备可打开（CreateFileW 返回非 INVALID_HANDLE_VALUE）
3. 测完 unload：`NtUnloadDriver` + 删注册表 key + `sc query RTCore64` 确认没了

### 任务 I：内核 ETW-TI blind【内核，⚠️ BSOD 风险】

**目标：** 真的 blind `Microsoft-Windows-Threat-Intelligence` provider。

1. `bootstrap_byovd` → 拿到 KernelRw
2. `kernel_base::ntoskrnl_base()` → 拿内核基址
3. 解析 `EtwThreatIntProvRegHandle`（通过 `resolve_kernel_symbol`）
4. 读 build number（`version::build_number()` = 17763）→ `offsets_table::for_build(17763)` → 拿 ETW-TI offset
5. `EtwTiBlind::blind(krw)` → 写 IsEnabled=0
6. **验证：** `logman query "Microsoft-Windows-Threat-Intelligence"` 显示 disabled

### 任务 J：进程隐藏【内核，⚠️ BSOD 风险】

**目标：** `persistence::ProcessHider` 隐藏一个进程。

1. 启一个测试进程（如 notepad.exe），记 PID
2. 拿到 KernelRw（任务 H 的链路）
3. 找 PID 的 EPROCESS（遍历 ActiveProcessLinks 或 PsLookupProcessByProcessId）
4. `ProcessHider::hide(krw, pid)` → unlink ActiveProcessLinks
5. **验证：** `tasklist | findstr notepad` 看不到 / `Get-Process notepad` 报错

### 任务 K：EDR 回调中和【内核，⚠️ BSOD 风险】

**目标：** `telemetry::CallbackNeutralizer` 中和 Ps*NotifyRoutine 回调。

1. 拿到 KernelRw + 解析 Ps*NotifyRoutine 数组地址
2. `CallbackNeutralizer::neutralize(krw)` → 用 ret-stub 覆写
3. **验证：** 启个进程，确认 EDR 不告警（如果有 EDR）；Sysmon EID 1 停止

---

## 完成后

每个任务做完，把结果（扫描报告 / exit code / logman 输出 / sc query）记到：
`docs\windows-test-results.md`

做完后同步回 macOS：
```powershell
# 在 Windows 上
cd C:\Users\administrator\Desktop\nyx\pentest
# 如果改了代码，git init + add + commit（当前没 git，可装）
winget install --id Git.Git -e
git add -A && git commit -m "windows test results + code changes"
# 或 tar 打包
tar czf C:\Users\administrator\nyx_results.tar.gz -C C:\Users\administrator\Desktop --exclude="*/target" nyx
```

然后 macOS 拉：
```bash
scp win:"C:/Users/administrator/nyx_results.tar.gz" /tmp/ && tar xzf /tmp/nyx_results.tar.gz -C ~/Desktop/
```

---

## 文件地图

```
crates\implant-win\src\        ← 用户态 implant（DLL）
  version.rs      build_number() + cet_active() 真实探测
  sleep.rs        Foliage 执行器（同步骨架，APC 链待写 = 任务 E）
  stack.rs        RSP swap（决策+staging，asm 待写 = 任务 F）
  blind.rs        ETW/AMSI patch + provider-disable
  inject.rs       module stomp（骨架 gated = 任务 D）
  syscalls.rs     +5 wrapper（queue_apc/continue/get/set_context）
  kits.rs         SleepmaskKit NoMask→Foliage
  evasion_glue.rs PdataGapScanner + BlindKit + InjectKit glue
  selftests.rs    +foliage/swap_decision 导出

crates\implant-evasionsdk\src\ ← 纯算法核心（no_std，本机可测）
  foliage.rs      Foliage 10 步状态机（5 测）
  apc.rs          APC 链合成（5 测）
  swap.rs         CET 决策（5 测）
  offsets_table.rs 跨版本 offset 表（8 builds，8 测）
  gap/frame/rc4   已有（24 测）

crates\operator-kernelsdk\src\ ← 内核 tier
  etwti.rs        ETW-TI blind 算法（跨版本表，6 测）
  byovd.rs        BYOVD KernelRw via IOCTL（算法完整）
  telemetry.rs    回调中和算法（4 测）
  persistence.rs  进程隐藏/PPL/PG 算法（5 测）
  netsec.rs       WFP/LSASS/EDR 算法（3 测）
  offsets.rs      17763 偏移常量 + RuntimeOffsets（3 测）
  win\            ← 内核 Windows 外壳（NEW）
    resolve.rs    resolve_sym 真绑定（GetModuleHandleA+GetProcAddress，3 测）
    driver_load.rs NtLoadDriver bootstrap（注册表+加载+卸载）
    kernel_base.rs ntoskrnl 基址（NtQuerySystemInformation）
    pagewalk.rs   x64 4 级页表遍历 VA→PA（5 测）
    va_rw.rs      VaKernelRw 适配器
    mod.rs        bootstrap_byovd() + blind_etw_ti_full()

crates\offset-resolver\        ← 服务端 PDB→toml 工具
  src\main.rs    --build N → offsets.toml pipeline

scripts\
  scan_linger.ps1       PE-sieve 扫描（任务 A）
  run_all_selftests.ps1 全 selftest 跑表
  EnableDebug.cs        SeDebugPrivilege 包装器
```
