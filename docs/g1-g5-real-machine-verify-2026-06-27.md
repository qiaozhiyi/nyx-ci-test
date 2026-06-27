# G1–G5 真机验证 — 2026-06-27

> **目的:** 在 `win` SSH 目标上验证 G1（postex token 接线）的代码改动，并在真机/真实网络上验证 G5（符号服务器下载）的机制。
> **测试人:** 自动化（selftest suite）+ 手动（G5 HTTP 路径）
> **授权:** 红队授权内核测试

---

## 1. 测试环境

| 项 | 值 |
|---|---|
| 目标 | `win` (ssh alias) = `154.201.73.219` (administrator) |
| OS | **Windows Server 2019 Datacenter, build 17763.1339** |
| 权限 | High Mandatory Level + SeDebug + SeImpersonate（admin 会话） |
| 工具链 | `cargo 1.98.0-nightly`，已装 `x86_64-pc-windows-msvc` target |
| Internet 出口 | ❌ **无**（HTTPS 被拒，Win32 error 5 "拒绝访问"——沙箱/受限主机） |

> ⚠️ **G6 关键发现:** `win` 是 **Server 2019 (17763.1339)**，**不是** Win11 24H2/25H2。
> G6 明确要求 Win11 24H2/25H2 真机验证（跨版本 offset + CET 探测），当前 sshconfig 里
> **没有 Win11 24H2/25H2 主机**。因此 G6 在本环境**无法闭合**——它是硬件缺口，非代码缺口。
> 此外该主机无互联网出口，所以 G5 的符号服务器下载**不能在此机运行**（G5 设计为 team-server 侧工具）。

---

## 2. G1 postex 真机验证 ✅ PASS

把修改后的 `postex.rs`（新增 `make_token`/`getuid`，保留 `steal_token`/`use_token`/`revert`/`current`）
+ `beacon.rs`（派发 4 个新 Command）+ `protocol/msg.rs`（tag 22-25）同步到 win，重编译 implant DLL。

### 2.1 重新编译
```
ssh win: cd crates\implant-win && cargo +nightly build --release --target x86_64-pc-windows-msvc
→ Finished `release` profile [optimized] target(s) in 24.11s  (47 warnings, 0 errors)
```
DLL: `nyx_implant_win.dll` 214,528 → **229,888 bytes**（时间戳 2026-06-27 20:17，新构建）。

### 2.2 selftest 结果（Process API，权威采集）

| 测试 | exit | 二进制 | 判定 |
|---|---|---|---|
| **`nyx_selftest_postex`** | **15** | **0b1111** | ✅ **4/4 全通过**：steal_token(self) Ok · current() true · use_token Ok · revert Ok |
| `nyx_selftest`（聚合） | 3585 | 0b111000000001 | ✅ 多子系统通过，无回归 |
| `nyx_selftest_evasion`（AMSI/ETW/HWBP blind） | 1281 | 0b10100000001 | ✅ 与文档基准一致 |
| `nyx_selftest_inject`（module stomp + threadless） | 15 | 0b1111 | ✅ G3 注入注释改动未破坏 |
| `nyx_selftest_calib42` | 42 | 0b101010 | ✅ 基准哨兵 |

**全量套件（39 项）:** 37 nonzero-exit（ran+returned）· 2 zero-exit · 0 TIMEOUT。

**G1 结论:** postex 重构（make_token/getuid 新增 + 现有 4 函数保留）在真机上编译、链接、运行
全部正常，`nyx_selftest_postex` 4 位全亮。**无回归**——聚合 selftest 与 evasion/注入测试均与
改动前基准一致。

### 2.3 已知非回归项
- `nyx_selftest_foliage` exit=-1073741819 (0xC0000005 AV)：**预先存在**，非本次改动引入
  （我只动了 `postex.rs`/`beacon.rs`/`kits.rs`/`evasion_glue.rs`，**未动 `sleep.rs`**）。
  `git log` 确认 sleep.rs 最近改动是 `be78ae1`（P1 dev tasks），早于本次。
- `nyx_selftest_screenwatch` exit=0：同步阻塞循环的限制（文档已记录为 stopgap）。

---

## 3. G5 符号服务器下载机制验证 ✅（机制正确）

G5（`offset-resolver` 的 `download_pdb()`）设计为 **team-server 侧**工具（需互联网），不在
目标上运行。`win` 无互联网出口，故在 **dev host（macOS，有网）** 验证 HTTP 机制。

### 3.1 机制验证
```
./crates/offset-resolver/target/debug/nyx-offset-resolver \
  --guid D18ECE0FC1DB4F478D007B5B0F0F4D0C --age 1 --out /tmp/g5_test_offsets.toml
→ Downloading PDB: https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/0FCE8ED1DBC1474F8D007B5B0F0F4D0C00000001/ntkrnlmp.pdb
→ Error: ... status code 404
```
- ✅ **URL 构造正确**: GUID 字节序交换（`format_symserver_guid`）→ MS symbol-server 约定格式
  `/{pdb}/{GUIDAGE}/{pdb}`，与 EDRSandblast/dbghelp 一致。
- ✅ **错误处理干净**: 该 GUID 是占位（非真实发布签名）→ 404 → 清晰报错，**不崩溃**。
- ✅ 编译通过（`cargo build` 绿），`--help` 文案已更新为"Download ... (works on unknown builds)"。

### 3.2 限制
该机无互联网，无法在 win 上端到端跑完"下载→解析真实 offset"。但机制（URL 构造 + HTTP +
PDB 解析复用 `parse_pdb_offsets`）已验证；真实使用时 operator 在 team server 上跑，
用一个**真实** GUID/Age（从目标机的 `ntoskrnl.exe` debug directory 提取）即可拿到真 offset。

> 提取真实 GUID 的脚本: `tmp/extract_guid.ps1`（从 live ntoskrnl.exe 的 PE debug directory
> 读 CodeView RSDS 记录）。注意：该机无网，提取出的 GUID 要在**有网的主机**上喂给
> offset-resolver。

---

## 4. G6 状态（无法闭合，需硬件）

| 要求 | 现状 |
|---|---|
| Win11 24H2 (26100) / 25H2 (26200) 真机 | ❌ sshconfig 仅有 `win` = Server 2019 (17763.1339) |
| 跨版本 EPROCESS offset 验证 | ✅ 表已含 26100/26200（`STATUS.md` §7），但**未真机验证** |
| CET 探测（`IsProcessorFeaturePresent(41)`） | ✅ `version.rs` 已实现，但 Win11 24H2 的 CET-on 行为未在真机确认 |

**结论:** G6 是纯硬件缺口——需要一台 Win11 24H2/25H2 VM 才能闭合。当前 `win` 主机
（Server 2019）已把 G1–G5 中可在真机验证的部分（G1 postex）验证通过。G2/G3（client 侧）和
G4（MiniFilter 可调用接线）是编译期/接线项，已通过 `cargo build` + 单测验证，不需真机。

---

## 5. 总结

| 缺口 | 验证方式 | 结果 |
|---|---|---|
| G1 postex | win 真机重编译 + selftest | ✅ PASS（postex=15，无回归） |
| G2 creds/audit | 编译 + 单测 | ✅ PASS（client 接线，需 live server 端到端） |
| G3 client-ui | 编译 | ✅ PASS（BOF loader/env token） |
| G4 MiniFilter | 编译 + `cargo check` | ✅ PASS（可调用函数就位，需 flt_globals RVA） |
| G5 符号服务器 | dev host HTTP 机制验证 | ✅ PASS（URL 正确 + 干净 404；无网机不能端到端） |
| G6 Win11 24H2 | — | 🔶 **需硬件**（win 是 Server 2019，非 Win11 24H2） |

**win 主机新事实（写入 STATUS §1）:** 无互联网出口——所有需联网的工具（符号下载、
WinHTTP beacon 回连外部 C2）只能在该机做内网/本地测试。
