# Nyx C2 Framework — 全方位代码审计报告

**日期:** 2026-06-26
**审计范围:** 全 workspace 22 个 crate + implant-win 独立 crate + operator-kernelsdk
**审计方法:** 静态代码审计，覆盖 crypto、wire protocol、server API、implant 内存安全、kernel SDK、辅助模块

---

## 📊 概览

| 严重级别 | 数量 | 说明 |
|----------|------|------|
| 🔴 HIGH (高危) | **3** | bof-runner 中的 RWX 分配 + transmute、agent-dev 命令注入 |
| 🟠 MEDIUM (中危) | **9** | 无速率限制、无 TTL 清理、多处 OOB panic 风险、DKOM 非原子操作等 |
| 🟡 LOW (低危) | **18** | 密钥未 zeroize、SSN 算术溢出、诊断计数器下溢等 |
| ℹ️ INFO | **10** | 设计决策记录（by design） |

**总体评价:** 代码质量较高，大部分 crate 设计合理、错误处理完善。**无 critical 级别漏洞**，但存在 3 个高危问题需要立即修复。

---

## 🔴 HIGH — 必须修复

### H-01: bof-runner — RWX 内存分配 (dev-only, 禁止上线)

**文件:** `crates/bof-runner/src/win.rs:70-77`
```rust
VirtualAlloc(
    std::ptr::null_mut(),
    total,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,  // ⚠️ 同时可写可执行
)
```
**问题:** 分配 PAGE_EXECUTE_READWRITE 内存，同时可写可执行。虽然标注为 dev-only，但代码中没有编译时/运行时保护阻止其在生产 implant 中被使用。EDR 会标记此行为。

**修复建议:** 添加 `#[cfg(not(feature = "prod"))]` 编译门控，或在 implant 生产构建中排除此路径。

---

### H-02: bof-runner — transmute 无地址验证

**文件:** `crates/bof-runner/src/win.rs:157-160`
```rust
let go: extern "C" fn() = std::mem::transmute(loaded.entry);
go();
```
**问题:** `loaded.entry` 来自 COFF 符号表的 `u64` 地址，直接 transmute 为函数指针并跳转。如果 COFF 文件被篡改或损坏，将跳转到任意地址 → 崩溃或代码执行。

**修复建议:** 在跳转前验证 `entry` 地址是否落在已分配的可执行区域内: `assert!(entry >= base && entry < base + total)`。

---

### H-03: agent-dev — Shell 命令注入

**文件:** `crates/agent-dev/src/lib.rs:488-491`
```rust
let user = name_str.trim_end_matches(".plist");
let shadow = std::process::Command::new("sh")
    .arg("-c")
    .arg(format!("dscl . -read /Users/{user} AuthenticationOptions ..."))
```
**问题:** `user` 来自文件系统目录名，直接拼接进 shell 命令字符串。恶意文件名如 `evil$(cmd)` 或 `foo; rm -rf /` 会被 shell 解释执行。

**修复建议:** 使用 `Command::new("dscl").arg(".").arg("read").arg(format!("/Users/{}", sanitized_user))` 而非 `sh -c`，或对 `user` 做正则过滤 `[a-zA-Z0-9._-]+`。

---

## 🟠 MEDIUM — 建议修复

### M-01: server — 无 IP 级速率限制

**文件:** `crates/server/src/lib.rs` (全局)
**问题:** 服务器无连接频率/请求频率限制。攻击者可：
1. 用不同临时密钥洪水注册新 session，填满 `MAX_SESSIONS=4096`
2. 每次无效帧仍触发 `derive_for()`（X25519 密钥派生 + ChaCha20 解密）

**修复建议:** 添加 per-IP 连接节流，或在 `derive_for()` 前添加 challenge-response。

### M-02: server — 无 stale session 清理 / TTL

**文件:** `crates/server/src/lib.rs:57-71`
**问题:** Session 有 `created: Instant` 但无过期扫描。死掉的 implant session 永远留在 DashMap 中，占用内存和 session 配额。攻击者可填充僵尸 session。

**修复建议:** 添加定期 sweep，移除超过 TTL（如 24h）且无活动的 session。

### M-03: implant-win — FreshTextSource::read 缺少边界检查

**文件:** `crates/implant-win/src/unhook.rs:652-657`
```rust
self.fresh_base.add(rva as usize)
// 然后 from_raw_parts(ptr, len) — 无检查 rva+len 是否超出映射区域
```
**问题:** 如果 RVA + len 超出 KnownDlls 映射区域，产生未定义行为。实际上 ntdll RVA 总是有效（内核维护），但缺少防御性检查。

**修复建议:** 添加 `if rva as usize + len > self.fresh_size { return Err(...) }`。

### M-04: coff — 辅助函数 panic on OOB

**文件:** `crates/coff/src/lib.rs:131-138`
```rust
fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])  // panic if o+1 >= b.len()
}
```
**问题:** `u16le`/`u32le`/`i16le` 直接索引切片，越界时 panic。虽然调用方目前都做了边界检查，但未来新增调用点可能遗漏。

**修复建议:** 改为返回 `Option`，与 `pe` crate 一致（`pe` 的 `u16le`/`u32le` 返回 `Option`）。

### M-05: transport — u16be 同类问题

**文件:** `crates/transport/src/tls.rs:40-42`
同 M-04，`u16be` 在越界时 panic。

### M-06: kernel SDK — 驱动加载 TOCTOU

**文件:** `crates/operator-kernelsdk/src/win/driver_load.rs:86-123`
**问题:** 注册表服务键创建 → `NtLoadDriver` 之间存在时间窗口，可被篡改 `ImagePath`（需要 `SeLoadDriverPrivilege`）。

**缓解:** 这是 operator-side 代码，攻击面有限。

### M-07: kernel SDK — ETW-TI 指针链非原子

**文件:** `crates/operator-kernelsdk/src/etwti.rs:177-199`
**问题:** 三级指针链追踪过程中，ETW provider 可能被注销，导致写入已释放内存 → bugcheck。

**缓解:** NULL 检查覆盖了最常见的场景，窗口很小。

### M-08: kernel SDK — DKOM LIST_ENTRY 非原子操作

**文件:** `crates/operator-kernelsdk/src/persistence.rs:80-99`
**问题:** 读取 Flink/Blink → 写入之间，其他 CPU 可能修改链表（新进程创建）。

**缓解:** 已正确文档化——必须在 `PatchGuardKit` 窗口内执行。

### M-09: protocol — 批量解码循环未使用 cap 值

**文件:** `crates/protocol/src/msg.rs:299-305, 477, 518`
```rust
let cap = checked_count(r, n_raw)?;  // capped
let n = n_raw as usize;              // ⚠️ 用的是 uncapped 值
for _ in 0..n {
    args.push(r.str()?);
}
```
**问题:** `Vec::with_capacity` 使用了 capped 值，但循环迭代使用 uncapped 的 `n_raw`。恶意输入可导致额外的 push-grow 开销（虽有上限，但仍为 DoS 放大向量）。

**修复建议:** 将 `let n = n_raw as usize;` 改为 `let n = cap;`。

---

## 🟡 LOW — 可选修复

| ID | Crate | 文件:行 | 问题 |
|----|-------|---------|------|
| L-01 | protocol | `Cargo.toml:33` | `StaticSecret` 在 `no_std` 构建中不 zeroize（`zeroize` feature 仅在 `std` 下启用） |
| L-02 | protocol | `crypto.rs:18` | `SessionKey` 是裸 `[u8; 32]` 别名，无 zeroize 语义 |
| L-03 | protocol | `crypto.rs:116` | HKDF expand 使用 `expect()` 而非 `?`（数学上不可能失败） |
| L-04 | protocol | `msg.rs:324-328` | `FileOp::dest` 字节 ≠ 0/1 时静默视为 None，应拒绝未知值 |
| L-05 | server | `operators.rs:167` | Argon2 使用默认参数（m=19MiB, t=2, p=1），离线暴力破解可能过快 |
| L-06 | server | `operators.rs:172-177` | `plain:` 标记使用无盐 SHA-256（向后兼容，但弱） |
| L-07 | server | `lib.rs:1111` | Cred/audit 错误信息暴露内部 SQLite 细节 |
| L-08 | server | `main.rs:43` | Kill-date 启动检查使用 `unwrap_or(0)`，时钟异常时绕过检查 |
| L-09 | implant-win | `blind_hwbp.rs:490` | `HWBP_COUNT` 双重移除时 usize 下溢 |
| L-10 | implant-win | `unhook.rs:596` | `parse_text_section` 无 `n_sec` 上限检查（内核镜像可信） |
| L-11 | implant-win | `inject.rs:56` | `MODULESTOMP_ENABLED` 默认 ON，跨进程 WriteProcessMemory 无 operator 门控 |
| L-12 | evasion | `syscalls.rs:73,127,130` | SSN 算术无 `checked_add`（实际值远离溢出） |
| L-13 | agent-dev | `lib.rs:780` | `rand::random::<u64>() % span` 有 modulo bias |
| L-14 | kernel SDK | `driver_load.rs:88-94` | 服务名无正则验证 |
| L-15 | kernel SDK | `etw_deception.rs:174` | Unicode 字符串长度 u16 截断 |
| L-16 | kernel SDK | `persistence.rs:96-97` | Self-loop 写入忽略错误 |
| L-17 | kernel SDK | `va_rw.rs:31` | CR3 可能过时（已文档化） |
| L-18 | kernel SDK | `pattern_scan.rs:120-146` | 硬编码 pattern 可能在新版本失效 |

---

## ℹ️ INFO — 设计决策记录（已知，by design）

| ID | Crate | 说明 |
|----|-------|------|
| I-01 | server | Open mode（无 auth）授予 `Role::Admin` — dev/CI 用 |
| I-02 | server | `FileOp::path` 无服务器端路径验证 — operator 控制模型 |
| I-03 | server | `Shell::args` 无长度限制 — body cap (4MB) 是唯一限制 |
| I-04 | server | `CHAN_SEQ` u32 在 ~4B 后回绕 — 实际不可达 |
| I-05 | implant-win | TLS 证书验证禁用 — 红队场景下自签名 redirector |
| I-06 | implant-win | RC4 sleep mask 密钥非 CSPRNG — 威胁模型是 snapshot 非离线取证 |
| I-07 | implant-win | `dealloc` 是空操作 — bump allocator 生命周期 = 进程生命周期 |
| I-08 | kernel SDK | `neutralize()` (.text 写入) 在 HVCI-on 时被拒绝 — 回退到 `repurpose()` |
| I-09 | kernel SDK | DKOM 操作必须在 PG 窗口内执行 — 已文档化 |
| I-10 | kernel SDK | Drop 不自动卸载驱动 — operator 需显式调用 `unload()` |

---

## ✅ 做得好的方面

### 1. 密码学（protocol crate）
- ✅ X25519 ECDH + HKDF 密钥绑定双方 pubkey
- ✅ 方向分离 nonce 空间（client→server vs server→client）
- ✅ AEAD AAD 绑定 implant pubkey，防止跨 session 密文替换
- ✅ 零 `unsafe` 代码
- ✅ 无 timing side-channel（X25519-dalek 和 ChaCha20-Poly1305 均为 constant-time）

### 2. Wire Protocol
- ✅ 边界检查的 `Reader` — 所有读操作检查 `remaining()`
- ✅ `MAX_CT_LEN` (256KB) 防止分配炸弹
- ✅ `checked_count` 防止批量解码炸弹
- ✅ 帧精确长度验证，拒绝 trailing bytes

### 3. Server 架构
- ✅ 常量时间 token 比较（`constant_time_eq`）
- ✅ DashMap 并发安全 + TOCTOU 修复（680+ 字注释）
- ✅ Body 大小限制（beacon 512KB，API 4MB）
- ✅ 生产代码零 `unwrap()` — 所有错误路径使用 `?` 或 `.ok_or_else()`
- ✅ 审计日志永不 panic（锁中毒处理）
- ✅ 脚本事件在 DashMap guard 外触发（避免持锁过久）

### 4. Kernel SDK
- ✅ `#![forbid(unsafe_op_in_unsafe_fn)]` — 最佳实践
- ✅ 所有 unsafe 块有 SAFETY 注释
- ✅ 零 `unwrap()` 在生产代码中
- ✅ 类型化错误枚举（`KrwError`, `KitError`）带 `#[non_exhaustive]`
- ✅ 算法/引导分离 — 每个 kit 可用 mock `KernelRw` 单元测试
- ✅ `patch_guard_window` / `timing_repair_window` 正确处理 PatchGuard

### 5. Implant-win
- ✅ bump allocator CAS 循环正确处理并发（单线程 beacon 模型下安全）
- ✅ Foliage helper thread 绕过共享 trampoline page（避免竞态）
- ✅ `MASK_STATE` CAS 防止双重 mask（RC4∘RC4 损坏）
- ✅ Panic handler 干净退出（`ExitProcess(0xC000_0001)`）
- ✅ CONTEXT 布局编译时断言（1232 字节, 16 字节对齐）
- ✅ RSP swap 有 CET 检查门控

### 6. PE / COFF 解析
- ✅ `pe` crate: 所有辅助函数返回 `Option`，全面 checked arithmetic
- ✅ `coff` crate: 重定位引擎使用 `checked_add`/`checked_mul`
- ✅ `pe` crate: `MAX_EXPORT_NAMES = 1 << 20` 限制病态导出表

---

## 📋 修复优先级建议

### 第一批（HIGH — 立即修复）
1. **H-01 + H-02:** bof-runner 添加编译门控 + 跳转前地址验证
2. **H-03:** agent-dev hashdump 改用 `Command::new` 直接参数而非 `sh -c`

### 第二批（MEDIUM — 本迭代修复）
3. **M-01 + M-02:** server 添加 IP 速率限制 + stale session TTL sweep
4. **M-03:** implant-win `FreshTextSource::read` 添加边界检查
5. **M-04 + M-05:** coff/transport 辅助函数改为返回 `Option`
6. **M-09:** protocol 批量解码循环改用 `cap` 值

### 第三批（LOW — 后续迭代）
7. **L-01 + L-02:** 启用 `x25519-dalek/zeroize` 对 no_std 构建，包装 `SessionKey`
8. **L-05 + L-06:** Argon2 使用显式参数，迁移 away from `plain:` SHA-256
9. 其余 LOW 项按需处理

---

*报告生成于 2026-06-26，基于 `p2-evasion-synced` 分支代码。*
