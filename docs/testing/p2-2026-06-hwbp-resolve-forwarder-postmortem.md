> ⚠️ **历史快照** — 本文档记录 2026-06-26 的状态，可能已过时。
> 最新项目事实以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准。
> 如需当前能力状态，请查阅 [`README.md`](../../README.md)。

# Postmortem — `hwbp_blind` 0xC0000005 崩溃（根因：resolve.rs 转发导出解析两个叠加 bug）

> **日期:** 2026-06-26 · **分支:** `p2-evasion-synced`
> **症状:** `nyx_selftest_hwbp_blind` 真机运行立即崩溃，exit code `-1073741819`（`0xC0000005` STATUS_ACCESS_VIOLATION）
> **修复文件:** `crates/implant-win/src/resolve.rs`
> **回归测试:** `nyx_selftest_resolve_forwarder`（exit=7 = 0b111）
> **授权:** 仅限授权红队 / 安全研究

---

## 0. TL;DR

崩溃**不在 VEH handler，也不在 HWBP / DR 寄存器逻辑**。根因是 PEB-walk 导出解析器 `resolve::export_addr_by_hash_pub` 处理 **PE 转发导出（forwarded export）** 时有两个叠加 bug：

1. **转发边界判定用错了字段** —— 用 `ExportDirectory.number_of_functions`（函数**计数**，~1800）当字节长度，而不是 `export_dir_size`（真正的**字节数**，~200000）。高 RVA 的转发导出逃过检测，被当成真函数，**返回转发字符串的 ASCII 地址**而不是代码地址。
2. **转发模块名匹配不上** —— 转发串里是缩写名（`NTDLL`），PEB loader 列表里是全名（`ntdll.dll`），`djb2` 哈希永远不匹配，`resolve_forwarder` 返回 `None`。

bug #1 把 bug #2 掩盖了：#1 让转发检测根本不触发（直接返回字符串地址），所以 #2 的 "解析失败" 路径从没被走到。只有修了 #1 之后 #2 才暴露（解析变 `None`），两个一起修掉才通。

**为什么"靠读代码猜"修不好：** 崩溃现场（`AddVectoredExceptionHandler` 调用）和真正的 bug（`resolve.rs` 导出解析）隔了两层间接。VEH handler 和 DR 寄存器代码本身完全正确。前一轮在 VEH/竞态上打转，方向从一开始就错了。

---

## 1. 调试过程（systematic-debugging 四阶段）

### Phase 1 — 取证，不猜

**修好测试框架的 exit-code 捕获**（坑）：cmd 里 `rundll32 ... & echo %ERRORLEVEL%` —— `%ERRORLEVEL%` 在单行里是**解析时**展开的，捕到的是 `del` 的退出码而不是 rundll32 的。改成 `.bat` 文件里 `set EC=%ERRORLEVEL%` + 单独行才拿到真值。

**真实崩溃签名：**
```
EXIT_CODE = -1073741819   # = 0xC0000005 STATUS_ACCESS_VIOLATION（OS 抛的，不是 Rust panic）
hwbp_diag.txt = 01abcdxy   # 停在 'y'（即将调用 AddVectoredExceptionHandler），缺 'z'（AVEH 返回后）
```
注意 `0xC0000005` ≠ `0xC0000001`（Rust panic handler 调 ExitProcess(0xC0000001)）—— 证明这是 **CPU/OS 直接抛的 AV**，绕过 Rust panic。

### Phase 2 — 模式分析（隔离变量）

跑了 4 个隔离实验，逐步缩小范围：

| 实验 | 诊断输出 | 退出码 | 结论 |
|---|---|---|---|
| 1. 完整 `hwbp_blind`（VEH+DR+shadow） | `01abcdxy`（缺 `z`） | 0xC0000005 | 崩在 AVEH 调用 |
| 2. AVEH 隔离（**无 DR、无 HWBP、无 shadow**，只注册 handler） | `1AB`（缺 `C`） | 0xC0000005 | **裸 AVEH 注册就崩**，跟 HWBP 无关 |
| 3. AVEH + **noop handler**（`fn()->0`） | `2A`（缺 `C`） | 0xC0000005 | 跟 handler 代码无关 |
| 4. 对照组：`GetLastError`+`Sleep` 都正常返回，**唯独 AVEH 崩** | `3gGsSa`...（AVEH 处崩） | 0xC0000005 | 解析器对 AVEH 返回了**错地址** |

实验 3 是关键转折：noop handler 也崩 → 排除 handler 代码 → 问题在 **AVEH 地址本身**。

### Phase 3 — 假设验证（找到铁证）

实验 4 里 dump 解析出的 AVEH 地址处的 16 字节：
```
4e 54 44 4c 4c 2e 52 74 6c 41 64 64 56 65 63 74
→ ASCII: "NTDLL.RtlAddVect..."
```
**解析器返回的是转发字符串的地址，不是代码。** 跳进 ASCII 字符串执行 → 第一条指令就是垃圾字节 → 立刻 AV。

### Phase 4 — 修复 + 红绿验证

修了 bug #1 后，`resolve_forwarder` 才被走到，但返回 `None`（bug #2）—— 一起修掉才通。

**红绿循环**（证明回归测试不是假绿）：
- 回退修复 → `nyx_selftest_resolve_forwarder` 崩 `-1073741819`（红）
- 恢复修复 → exit `7`（绿）
- 全套 41 测试：39 PASS + 2 预期零退出 + 0 超时 + 0 崩溃

---

## 2. Bug #1 — 转发边界判定用错了字段

**位置:** `resolve.rs::export_addr_by_hash_pub`

**错误代码:**
```rust
let num_funcs = (*dir).number_of_functions as usize;  // ← 这是函数计数，不是字节长度
let dir_start = export_rva as usize;
let dir_end = dir_start + num_funcs;                    // ← 应该用 export_dir_size
...
if (fn_rva as usize) >= dir_start && (fn_rva as usize) < dir_end {
    return resolve_forwarder(base, fn_rva as usize);    // ← 永远走不到（高 RVA 转发器）
}
return Some(base.add(fn_rva as usize) as usize);         // ← 返回字符串地址
```

**为什么坑:** `number_of_functions`（~1800）比 `export_dir_size`（~200000）小两个数量级。低 RVA 的真函数不受影响（它们的 RVA 在 export 目录之后，本来就该返回真地址）；但**高 RVA 的转发器**（RVA 在 `[dir_start+1800, dir_start+200000)` 区间）逃过检测，被当成真函数返回。

**修复:** 从 PE 头读真正的 size（数据目录第 0 项的第二个 u32）：
```rust
let export_dir_size = *(opt.add(dd_off + 4) as *const u32) as usize;
let dir_end = dir_start + export_dir_size;
```

---

## 3. Bug #2 — 转发模块名缩写 vs 全名不匹配

**位置:** `resolve.rs::resolve_forwarder`

**转发串格式:** `NTDLL.RtlAddVectoredExceptionHandler`（缩写模块名）

**错误代码:**
```rust
let fwd_mod = find_module_by_hash(djb2(mod_part))?;   // mod_part = "NTDLL"
```

**问题:** `find_module_by_hash` 在 PEB loader 列表里按**全名**匹配（`ntdll.dll`、`kernelbase.dll`），但转发串给的是**缩写名**（`NTDLL`、`KERNELBASE`）。`djb2("NTDLL")` ≠ `djb2("ntdll.dll")` → 永远 `None`。

**修复:** 新增 `find_module_for_forwarder`，专门处理转发样式的缩写名：
- 非 API-set 名（`NTDLL`/`KERNELBASE`）：按去掉 `.dll`/`.exe` 后缀的 stem 匹配 loader 条目
- API-set 名（`api-ms-...`/`ext-ms-...`）：按全名逐字匹配（loader 用 contract 名解析到宿主 DLL）

`resolve_forwarder` 改用 `find_module_for_forwarder` 替代 `find_module_by_hash`。

---

## 4. 修复后的验证证据

| 测试 | 修复前 | 修复后 |
|---|---|---|
| `nyx_selftest_hwbp_blind`（完整 HWBP: VEH+DR0+NtTraceEvent） | 0xC0000005 崩溃 | **255 (0xFF)**，诊断 `01abcdxyzefghijkSTUZ` 全程通过 |
| `nyx_selftest_resolve_forwarder`（新回归测试） | N/A（新增） | **7 (0b111)** |
| 全套 selftest（41 个） | hwbp_blind 崩溃 | 39 PASS + 2 预期零退出 + 0 超时 |

**红绿循环:** 回退 bug #1 修复 → 回归测试崩 `-1073741819`（红）；恢复 → `7`（绿）。证明测试真能抓 bug。

---

## 5. 经验教训

1. **"竞态条件"几乎从来不是竞态。** 当有人（或上一轮 AI）说是竞态，先怀疑证据。竞态是"读代码猜不出来"的万能挡箭牌。
2. **崩溃签名决定方向。** `0xC0000005`（OS 抛 AV）vs `0xC0000001`（Rust panic）是两条完全不同的调查路径。先把 exit code 抓准（cmd `%ERRORLEVEL%` 有解析时展开的坑）。
3. **隔离实验比读代码快。** 实验 2（裸 AVEH）一跑就把 HWBP/DR/handler 全部排除，省下大量在错方向上读代码的时间。
4. **dump 地址处的字节。** 当怀疑"解析返回错地址"时，dump 目标地址的 16 字节就能立刻区分"代码 vs 转发字符串"。
5. **叠加 bug 会互相掩盖。** bug #1 让 #2 的失败路径永远走不到。修 #1 后 #2 才暴露。每修一个就跑一次测试，不要攒着一起测。
6. **回归测试必须做红绿。** 只跑绿（pass）不能证明测试有效——可能压根没测到那个 bug。回退修复确认红，再恢复确认绿。

---

## 6. 相关文件

| 文件 | 角色 |
|---|---|
| `crates/implant-win/src/resolve.rs` | **修复处** —— `export_addr_by_hash_pub`（bug #1）+ `resolve_forwarder`/`find_module_for_forwarder`（bug #2） |
| `crates/implant-win/src/blind_hwbp.rs` | HWBP patchless blind 主体（**本身无 bug**，被 resolve 连累） |
| `crates/implant-win/src/selftests.rs` | 新增 `nyx_selftest_resolve_forwarder`（回归测试）+ `noop_veh_handler` |
| `tmp/run_full_selftest.ps1` | runner 加入两个新测试（`resolve_forwarder` + `hwbp_blind`） |

---

*基于 2026-06-26 真机调试（Windows Server 2019 17763.1339）。systematic-debugging 四阶段全程取证，无猜测。*
