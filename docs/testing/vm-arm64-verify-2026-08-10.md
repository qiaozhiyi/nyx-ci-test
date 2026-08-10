# ARM64 VM 全链路红队演练验证 — 2026-08-10

> **目的:** 在本机 Parallels Windows 11 ARM64 虚拟机上，以真实红队操作方式对 NYX
> 用户层做端到端验证：team server → generate-implant → beacon 回家 → 全任务面演练
> → Defender 对照。演练中暴露并修复了三个"植入体根本没法用"级别的根因。
> **测试人:** 自动化（vm_bridge 零接触执行通道 + drill.sh C2 任务驱动）
> **授权:** 本机自有 VM，红队授权测试

---

## 1. 测试环境

| 项 | 值 |
|---|---|
| 目标 VM | Parallels "Windows 11" ARM64, build 26100 (24H2), IP 10.211.55.4 |
| 宿主机 | macOS (本机), 10.211.55.2 (bridge100) |
| 快照 | `pre-nyx-test` {e8c1b5ef-5329-4263-8ce5-a2f9d362baa7}（演练前打） |
| 执行通道 | `scripts/vm_bridge.sh`：prlctl 自研 runner，VM 内 **SYSTEM** 同步 shell，零接触（不落盘 agent） |
| 共享通道 | `\\Mac\Home\Desktop\pentest\NY` = 仓库根（Parallels 共享夹） |
| team server | `NYX_BIND=0.0.0.0:8443`，明文 dev 模式，bearer `admin:nyxtest123` |
| 植入体 | `POST /api/generate-implant`（`"tls":false` + `"deliver":"inline"`），x64 DLL 经 Prism 仿真运行于 ARM64 Windows |
| 杀软 | **Windows Defender 实时保护全程开启** |

> ⚠️ 植入体是 x64，VM 是 ARM64 —— 全程跑在 Windows 11 的 x64 仿真层（Prism）下。
> 这既是限制（见 §7 未闭环项），也意外成为了有效的兼容性测试面：暴露了一个
> 只在仿真下触发的 syscall 路径崩溃。

## 2. 关键基础设施：vm_bridge

`prlctl exec` 单文件参数限制 → 自研 `tmp/vm-bridge/runner.exe`：把多行 bat 写进
job 文件，runner 在 VM 内以 SYSTEM 执行并回写 stdout。Mac 侧 `scripts/vm_bridge.sh
exec '<bat>'` 一键调用。C2 任务驱动用 `tmp/vm-bridge/drill.sh <session> '<json>'`。

踩过的坑（记录在案）：
- 批内 `start rundll32` 会挂住 runner，须用 `powershell "Start-Process ..."`。
- 常驻 beacon 由 mac 侧后台任务跑同步桥驻留。
- **回放保护**：同一 implant 文件共享 `implant_priv` → 同 session id + 计数器，
  只能跑一个实例；oneshot 探测会消耗计数器导致常驻实例被拒。要第二个 beacon
  必须重新 generate。
- server 每次重启生成新 keypair，植入体必须跟着重新 generate。
- `/api/results` 是 drain 语义：大文件分块一次 drain 不干净，关键命令间先 drain 再发。

## 3. 演练中修复的三大根因

### 3.1 LTO 常量折叠吞掉服务器补丁 —— 「generate-implant 产出的植入体从来没回过家」

**现象:** VM 侧 implant 永远不连 10.211.55.2:8443，团队服务器零会话。
**根因:** `crates/implant-tasks/src/config_placeholder.rs` 的运行时配置加载读
`NYX_CFG_PLACEHOLDER` 静态数组；fat LTO 把这些读取**常量折叠**成编译期初始值。
服务器在链接后 out-of-band 补丁 `.nyx_cfg` 段字节，但导出函数内读的仍是旧常量
→ 回退到编译期 callback 127.0.0.1。
**实证:** 探针进程外读 section = 已补丁（首字节 0xEF）；导出函数内读 = 未补丁
（0x41）。加 `core::hint::black_box` 后两者一致。
**修复:** `load_runtime_config_locate_ct()` 读 placeholder 处加 `black_box`；
新增 `nyx_selftest_cfgstage` 诊断导出（阶段码 0x60–0x64 + host 首字节）。
**影响面:** 这是**生成管线级** bug —— 此前所有 `generate-implant` 产出的植入体
在真网环境下全是死 implant。

### 3.2 Prism 仿真拒绝间接 syscall —— 0xC000026F

**现象:** 仿真下凡走间接 syscall（gadget 位点）的路径即崩
`STATUS_INVALID_IMAGE_WIN_64 (0xC000026F)`。
**根因:** Prism 只接受从 ntdll 原生 stub 位点到达的 syscall 指令；evasion 的
间接 syscall 从伪造 gadget 进入被拒。
**修复:** `crates/implant-core/src/syscalls.rs` 新增
`is_x64_emulated_on_arm64()` 探测；仿真时 syscall4/5/6/11 直调 ntdll 导出
（方案 B 既定降级取舍）。`crates/implant-evasion/src/fluctuation.rs` 仿真降级为
纯 sleep。新增 `nyx_selftest_rt_dump` 诊断导出。
**实测:** 修复后 fs=127 / rm_file=1 / hashdump=4 / syscall_rt=3 / fs_edge=15
自检全中，零新崩溃。

### 3.3 getuid 三连 ABI bug

**根因（三个独立 bug 叠在同一调用链）:**
1. `postex.rs` `GetTokenInformation` 的 class 参数声明为 `u8` —— x64 ABI 下
   rdx 高位留垃圾，advapi32 读全 32 位 → 改为 `u32`（注释说明）。
2. `LookupAccountSidW` 的 `peUse` 输出参数声明 `*mut u8` —— API 写 4 字节，
   踩坏相邻栈 → 改 `*mut u32`。
3. `getuid_sid` 返回的 SID 指针指向**已弹栈的调用帧** → 改用调用方持有的
   `&mut [u8; 64]` 缓冲。

**实测:** 修复后真 C2 会话 getuid 输出 `QIAOZHIYI7FA4\qiaozhiyi`（用户会话、
未提权），正确。

## 4. 自测套件结果（59 导出，VM 仿真环境）

| 桶 | 数量 | 定性 |
|---|---|---|
| 精确校验通过 | 29 / 37 | ✅ |
| mismatch：0xC000026F 桶 | 若干 | 仿真差距 —— **已由 §3.2 修复** |
| mismatch：screenshot / screenwatch | 2 | session 0 伪影 —— 真 C2 用户会话里截图 11.4MB BMP **实证成功**，非缺陷 |
| bof_isolated 超时 | 1 | 自测框架怪癖 —— live isolate 实测返回 `BOF-PRINT-OK 42`，非缺陷 |

即 8 个 mismatch **全部定性**，无一指向真实用户层缺陷。

## 5. 真 C2 演练结果

### 5.1 用户会话 beacon（`schtasks /RU qiaozhiyi /IT` 交互会话）

| 任务 | 结果 |
|---|---|
| ping / env | ✅ |
| shell | ✅ 命令执行回显正常 |
| ls / driveinfo / net | ✅ |
| upload / download / mv / rm | ✅ 双向文件传输 |
| screenshot | ✅ 拿到 11.4MB 真桌面 BMP |
| clipboard | ✅ 拿到真剪贴板内容 |
| portscan | ✅ 8443 open 判定正确 |
| keylog start + dump | ✅ |
| trex | ✅ EnterpriseEDR 分级返回 |
| BOF 内联 + 隔离 | ✅ 隔离进程返回 `BOF-PRINT-OK 42` |
| getuid | ✅ `QIAOZHIYI7FA4\qiaozhiyi`（修复后） |

### 5.2 SYSTEM 会话 beacon（桥直接起 rundll32）

| 任务 | 结果 |
|---|---|
| hashdump method=0 | ✅ SAM hive 45KB (regf) 到手 |
| hashdump method=1 | ✅ SYSTEM hive ~10.9MB 到手（可离线提 hash） |
| stealtoken | 返回 ok；whoami 不变属预期（线程模拟只影响新起进程的继承 token，非失败） |

入口统一用 `nyx_entry_noevasion`（见 §7）。

## 6. Defender 对照

- 演练全程 `RealTimeProtectionEnabled=True`。
- 套件 + 全部演练后 `Get-MpThreatDetection` **为空**：0 检出、0 隔离。
- 植入体生成 → 落地 → 加载 → 持久化任务 → 网络回连 → 截屏/键记/hashdump，
  全链路无任何告警。

## 7. 未闭环 / 不能外推的项（诚实清单）

- **全 evasion 入口 `nyx_entry` 在 ARM64 仿真下仍 0xC000026F**：evasion init 有
  绕开 syscall shim 直用 gadget 的路径。`noevasion` 入口正常。**真 x64 上无此问题**
  （2026-07-20 run 已验证），属仿真独有。
- 仿真下 evasion 是**降级**运行的（syscall 直调、fluctuation 纯 sleep）——
  本报告不证明 evasion 在真 x64 上的对等强度；那部分证据在真 x64 run + CI。
- CET 在仿真下不存在，CET 相关结论（含 25H2 已知限制）不以本演练为据。
- `hookchain` 自检导出在仿真下仍崩（自检代码，非 beacon 路径）。
- **内核层（HVCI / PatchGuard / 驱动）依旧无环境**：ARM64 Windows 连 x64 驱动都
  载不了，内核 tier 状态不变。

## 8. 清理与可复现性

- VM 侧：`rundll32.exe` 全杀、`nyx_live` 计划任务删除；`C:\nyx` 留档（有快照可回滚）。
- Mac 侧：team server、HTTP 暂存服务已停。
- 复现路径：`scripts/vm_bridge.sh` + `scripts/vm_bootstrap.ps1` +
  `docs/testing/vm-route-a-guide.md`。

## 9. 结论

在真 Windows（ARM64 VM + Prism x64 仿真）上，本轮修掉了三个"植入体根本没法用"
级别的根因——其中 LTO 常量折叠意味着 **generate-implant 此前产出的全是死 implant**。
修复后：beacon 真实回家，用户层任务面（文件/shell/截屏/剪贴板/键记/端口扫描/
BOF/hashdump/getuid）全绿，Defender 实时保护下零检出。**用户层在此环境实证可用。**
