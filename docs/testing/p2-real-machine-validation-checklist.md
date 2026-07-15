# P2 Bypass 模块 — Windows 真机验证清单

> **本清单本会话不执行**。以下是为在 `ssh win`（Server 2019, build 17763）
> 上验证本批 bypass 实现而准备的逐步检查表。每项标注"通过条件"。
> 本会话交付的验证边界：macOS 单元测试 + `x86_64-pc-windows-gnu` 交叉 check。

## 前置（一次性）
- [ ] Windows 机构建：`cargo +nightly build --release --target x86_64-pc-windows-msvc -Z build-std=core,alloc,panic_abort`
- [ ] 检测器就位：PE-sieve、Moneta、Hunt-Sleeping-Beacons、BeaconEye、MalMemDetect（放 `$env:TEMP\nyx_detectors\`）

## 1. 算法核心 mock 测试（本机已绿，真机再确认）
- [ ] `cargo test --manifest-path crates\operator-kernelsdk\Cargo.toml` → 27 passed
- [ ] `cargo test --manifest-path crates\implant-evasionsdk\Cargo.toml` → 39 passed

## 2. selftest bitmask（rundll32 nyx_implant_win.dll,<export>）
| 导出 | 期望 bitmask | 检查 |
|---|---|---|
| nyx_selftest_gap_scan | `0b1111`(15) | 4 位全置（gap_count>0, ghosts/nops>0, ntdll 贡献）|
| nyx_selftest_blind_nttrace | `0b1111`(15) | patch + 字节验证 + 幂等 + 可解析 |
| nyx_selftest_mem | `0b11`(3) | mask/unmask 框架 + RC4 round-trip |
| **nyx_selftest_foliage** (新) | `0b1`(1) | Foliage mask/sleep/unmask 无崩溃（arm 后）|
| **nyx_selftest_swap_decision** (新) | `0b11`(3) | gaps staged + decide 逻辑无 panic |
| nyx_selftest_inject | `0b1111`(15) | 数据通路（stomp gated off）|

## 3. 内存扫描（nyx_linger 30s 存活）
- [ ] `scan_linger.ps1`（默认 NoMask）：PE-sieve 零 suspicious region
- [ ] **nyx_linger_foliage**（arm foliage）：PE-sieve .text 不报 implanted（RC4 加密后，扫描窗口内存非明文）
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

---

## 实现状态总览（2026-06-24）

| 层 | 模块 | 代码 | 本机测试 | 真机验证 |
|---|---|---|---|---|
| SDK | gap/frame/rc4 | ✅ | ✅ 24 测 | — |
| SDK | foliage (10步状态机) | ✅ | ✅ 5 测 | — |
| SDK | apc (链合成) | ✅ | ✅ 5 测 | — |
| SDK | swap (CET 决策) | ✅ | ✅ 5 测 | — |
| Kernel algo | etwti/byovd/telemetry/persistence/netsec/offsets | ✅ | ✅ 27 测 | driver load (operator) |
| Kernel shell | win/ | 🔶 占位 | — | — |
| implant-win | Foliage executor (gated) | ✅ | 🔶 交叉 check | 待 bitmask |
| implant-win | stack RSP swap 决策 | ✅ | 🔶 交叉 check | 待 CET 探测 |
| implant-win | .text mask | ✅ | 🔶 交叉 check | — |
| implant-win | blind provider-disable | ✅ | 🔶 交叉 check | 待 logman |
| implant-win | inject stomp (gated) | ✅ | 🔶 交叉 check | 待 PE-sieve |
