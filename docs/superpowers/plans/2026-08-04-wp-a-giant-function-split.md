# WP-A 巨函数拆分(AH-2)Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 implant-win / server / transport 三个 crate 中全部约 140 个超 50 行的非测试函数拆分为 <50 行,纯 extract-method 重构,零行为变更。

**Architecture:** 按文件分任务(一文件一提交),阶段式提取私有 helper;transport → server → implant-win 顺序推进,WP-B 要动的 `beacon.rs`/`bof.rs` 排最后。本地验证:server/transport 跑 `cargo test`;implant-win 用 mingw 交叉 `cargo +nightly check`(已验证 8s 可用)。

**Tech Stack:** Rust stable(workspace)/ nightly + x86_64-pc-windows-gnu(implant-win,no_std)、Python3(清单脚本)。

**Spec:** `docs/superpowers/specs/2026-08-04-v040-beacon-isolation-crate-split-design.md` §3

## Global Constraints

- **零行为变更**:不改控制流语义、错误码/错误文本、日志文本、static 访问顺序、pub 接口面。只移动代码,不重写逻辑。
- 提取出的 helper 一律私有(`fn`,不加 `pub`)、放被拆函数之后;注释随代码一起搬。
- 一个文件一个提交;锚点行号是 2026-08-04 扫描值,会漂移,**以函数名定位**。
- 排除范围(不拆):`crates/implant-win/src/selftests.rs` 整个文件;所有 `#[cfg(test)]` 模块与 `#[test]` 函数;`nyx_selftest*` 导出(entry.rs、syscalls.rs);server/transport 中的测试函数(名如 `*_roundtrip`、`*_honors_*`、`touch_throttle_limits_writes`、`exit_task_fires_session_exit_exactly_once`、`concurrent_persist_no_torn_write`、`audit_rotation_archives_and_resets_chain`)。
- implant-win 禁止在 macOS 上尝试完整 build(link 需要 mingw,CI 才有);本地只跑下面的 cross-check 命令。
- 每个任务结束必须重跑扫描脚本,确认该文件已无超 50 行非测试函数。

## 标准任务协议(每个任务都按此执行)

每个任务的步骤序列相同,只有目标文件/函数表/验证命令不同:

- [ ] **Step 1: 基线验证** — 运行该任务的验证命令(见任务内),确认改动前绿。
- [ ] **Step 2: 逐函数提取** — 对任务函数表中的每个函数:
  1. 通读函数,按"阶段"切分(解析/分配/主循环/清理/返回),每阶段提取为私有 helper;
  2. helper 命名 `<函数名>_<阶段>` 或描述性名称(如 `read_pe_headers`),签名只传所需参数;
  3. 被拆后的入口函数保留原签名、原 doc 注释、原调用顺序;
  4. 循环体大时优先提取循环体为 helper;match 大臂提取为 helper;
  5. unsafe 块、static 访问、错误返回路径**原样搬运**,不改写。
- [ ] **Step 3: 验证** — 运行任务的验证命令,确认绿。
- [ ] **Step 4: 复扫** — 运行扫描脚本(Task 0 产出),确认该文件无 >50 行非测试函数。
- [ ] **Step 5: 提交** — 使用该任务给出的 commit 命令。

### 提取范例(模式参考,`crates/implant-win/src/antidebug.rs` `is_remote_debugged` 57 行)

原函数两个自然阶段:syscall-runtime 路径 + export 回退路径。拆为:

```rust
/// `NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &port, ...)`.
/// Returns true if a debugger port is set. Goes through the indirect-syscall
/// runtime when it's up (falls back to the resolved export otherwise).
pub fn is_remote_debugged() -> bool {
    // Prefer the indirect-syscall runtime if initialized.
    if let Some(rt) = crate::syscalls::global() {
        if let Some(debugged) = is_remote_debugged_via_syscall(rt) {
            return debugged;
        }
        // Fall through to the export path if the syscall didn't return success.
    }
    is_remote_debugged_via_export()
}

/// Returns Some(port != 0) when the indirect syscall succeeded, None otherwise.
fn is_remote_debugged_via_syscall(rt: &'static crate::syscalls::Runtime) -> Option<bool> {
    let mut port: usize = 0;
    let mut retlen: u32 = 0;
    // NtQueryInformationProcess is 5 args → syscall6 padded.
    let st = unsafe {
        crate::syscalls::syscall6(
            rt,
            crate::resolve::djb2(b"ntqueryinformationprocess"),
            usize::MAX, // GetCurrentProcess pseudohandle (-1 = 0xFFFF...FFFF).
            PROCESS_DEBUG_PORT as usize,
            &mut port as *mut usize as usize,
            core::mem::size_of::<usize>(),
            &mut retlen as *mut u32 as usize,
            0,
        )
    };
    match st {
        Some(0) => Some(port != 0),
        _ => None,
    }
}

/// Export-resolution fallback path (kernel32 GetCurrentProcess + ntdll NQIP).
fn is_remote_debugged_via_export() -> bool {
    type GetCurrentProcess = unsafe extern "system" fn() -> *mut c_void;
    type NtQueryInformationProcess = unsafe extern "system" fn(
        *mut c_void, u32, *mut c_void, u32, *mut u32,
    ) -> i32;
    let gcp: GetCurrentProcess = match unsafe { export_addr(b"kernel32.dll", b"GetCurrentProcess") }
    {
        Some(a) => unsafe { core::mem::transmute(a) },
        None => return false,
    };
    let nqip: NtQueryInformationProcess =
        match unsafe { export_addr(b"ntdll.dll", b"NtQueryInformationProcess") } {
            Some(a) => unsafe { core::mem::transmute(a) },
            None => return false,
        };
    // … remainder of the original export-path body, moved verbatim …
}
```

要点:返回语义完全一致(原来 fall-through,现在 None → fall-through);type alias 随使用它的路径走;doc 注释留在入口。

---

### Task 0: 冻结函数清单

**Files:**
- Create: `scripts/count_long_fns.py`
- Create: `docs/superpowers/plans/wp-a-function-inventory.txt`(脚本产出)

- [ ] **Step 1: 写扫描脚本** `scripts/count_long_fns.py`,内容:

```python
#!/usr/bin/env python3
"""List non-test Rust functions longer than N lines (default 50).

Excludes: selftests.rs, #[cfg(test)] modules, #[test] fns, nyx_selftest* exports.
Usage: python3 scripts/count_long_fns.py [roots...]  (default roots below)
"""
import re, os, sys

THRESH = 50
ROOTS = sys.argv[1:] or ["crates/implant-win/src", "crates/server/src", "crates/transport/src"]
SKIP_FILES = {"selftests.rs"}
FN_RE = re.compile(
    r'^(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]*"\s+)?fn\s+([A-Za-z0-9_]+)'
)

def funcs(path):
    lines = open(path, encoding="utf-8").read().splitlines()
    out, i, skip_depth = [], 0, None
    # skip_depth: brace depth at which a #[cfg(test)] module opened; None = not in test mod
    depth = 0
    pending_test_attr = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if "#[cfg(test)]" in stripped:
            pending_test_attr = True
        m = FN_RE.match(stripped) if not stripped.startswith("//") else None
        if m and skip_depth is None and not pending_test_attr:
            name = m.group(1)
            fdepth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": fdepth += 1; started = True
                    elif ch == "}": fdepth -= 1
                if started and fdepth == 0: break
                j += 1
            if not name.startswith("nyx_selftest"):
                out.append((name, j - i + 1, i + 1))
            i = j + 1
            continue
        for ch in line:
            if ch == "{":
                depth += 1
                if pending_test_attr and skip_depth is None:
                    skip_depth = depth
                pending_test_attr = False
            elif ch == "}":
                if skip_depth is not None and depth == skip_depth:
                    skip_depth = None
                depth -= 1
        if not line.endswith("\\"):
            if pending_test_attr and "fn" not in stripped and not stripped.startswith("mod"):
                pending_test_attr = False
        if skip_depth is not None and m:
            # function inside cfg(test) module: skip its lines too
            fdepth, started, j = 0, False, i
            while j < len(lines):
                for ch in lines[j]:
                    if ch == "{": fdepth += 1; started = True
                    elif ch == "}": fdepth -= 1
                if started and fdepth == 0: break
                j += 1
            i = j + 1
            continue
        i += 1
    return out

for root in ROOTS:
    for dirpath, _, files in os.walk(root):
        for f in sorted(files):
            if not f.endswith(".rs") or f in SKIP_FILES:
                continue
            p = os.path.join(dirpath, f)
            for name, length, line in funcs(p):
                if length > THRESH:
                    print(f"{length:4d}  {p}:{line}  {name}")
```

- [ ] **Step 2: 运行并冻结清单**

Run: `python3 scripts/count_long_fns.py | tee docs/superpowers/plans/wp-a-function-inventory.txt | wc -l`
Expected: 输出 140±10(行数会随已完成任务减少;首次运行即基线)

- [ ] **Step 3: 人工核对清单** — 对照排除范围,确认无 `selftests.rs`、`#[test]` 函数、`nyx_selftest*` 混入;若混入,修脚本重跑。

- [ ] **Step 4: Commit**

```bash
git add scripts/count_long_fns.py docs/superpowers/plans/wp-a-function-inventory.txt
git commit -m "chore(wp-a): freeze >50-line non-test function inventory + scan script"
```

---

## Phase 1: transport(本地可测)

### Task 1: transport/src/tls.rs

**Files:** Modify `crates/transport/src/tls.rs`
**函数表:** `parse_client_hello`(133 行 @47)、`ja4`(97 行 @239)
**Interfaces:** Consumes: 无。Produces: 私有 helper;`parse_client_hello`/`ja4` 签名不变。

- [ ] Step 1 基线: `cargo test -p nyx-transport 2>&1 | tail -3` — Expected: `test result: ok`(109+ 通过)
- [ ] Step 2 提取: `parse_client_hello` 按 record 头解析/扩展遍历/ALPN+cipher 收集切段;`ja4` 按指纹字段拼装各段切段。
- [ ] Step 3 验证: 同上命令,Expected: ok
- [ ] Step 4 复扫: `python3 scripts/count_long_fns.py crates/transport/src/tls.rs` — Expected: 无输出
- [ ] Step 5 Commit:

```bash
git add crates/transport/src/tls.rs
git commit -m "refactor(transport): split tls parse_client_hello/ja4 into stage helpers (zero behavior change)"
```

### Task 2: transport/src/stack.rs

**Files:** Modify `crates/transport/src/stack.rs`
**函数表:** `send`(121 行 @225)
**Interfaces:** Produces: 私有 helper;`send` 签名与重试语义(probe → init → retry → demote)不变。

- [ ] Step 1 基线: `cargo test -p nyx-transport 2>&1 | tail -3` — Expected: ok
- [ ] Step 2 提取: 按 channel 生命周期阶段切(probe/init/retry 循环体/demote)。
- [ ] Step 3 验证: 同上 — Expected: ok
- [ ] Step 4 复扫: `python3 scripts/count_long_fns.py crates/transport/src/stack.rs` — Expected: 无输出
- [ ] Step 5 Commit:

```bash
git add crates/transport/src/stack.rs
git commit -m "refactor(transport): split TransportStack::send into lifecycle stage helpers"
```

### Task 3: transport extc2 API + smb_pipe(三文件三提交)

**Files:** Modify `crates/transport/src/discord_api.rs`、`crates/transport/src/slack_api.rs`、`crates/transport/src/smb_pipe.rs`
**函数表:** `discord_api::poll_messages`(53 @206)、`slack_api::poll_history`(52 @209)、`smb_pipe::CreateFileW`(69 @34)

- [ ] Step 1 基线: `cargo test -p nyx-transport 2>&1 | tail -3` — Expected: ok
- [ ] Step 2 提取: 每个函数按 请求构造/响应解析 两段切。
- [ ] Step 3 验证: 同上 — Expected: ok
- [ ] Step 4 复扫: `python3 scripts/count_long_fns.py crates/transport/src/discord_api.rs crates/transport/src/slack_api.rs crates/transport/src/smb_pipe.rs` — Expected: 无输出
- [ ] Step 5 Commit(每文件一个):

```bash
git add crates/transport/src/discord_api.rs && git commit -m "refactor(transport): split discord poll_messages"
git add crates/transport/src/slack_api.rs && git commit -m "refactor(transport): split slack poll_history"
git add crates/transport/src/smb_pipe.rs && git commit -m "refactor(transport): split smb_pipe CreateFileW wrapper"
```

---

## Phase 2: server(本地可测)

所有 server 任务统一验证命令: `cargo test -p nyx-server 2>&1 | tail -3` — Expected: `test result: ok`(72+ 通过);复扫命令: `python3 scripts/count_long_fns.py <目标文件>` — Expected: 无输出。

### Task 4: server/src/audit.rs

**函数表:** `append`(66 @189)、`query`(54 @277)、`verify_chain`(54 @349)
- [ ] 按标准协议执行;`append` 按 序列化/哈希链更新/落盘 flush 切;`query` 按 过滤条件解析/记录扫描 切;`verify_chain` 按 逐条重算/比对 切。
- [ ] Commit: `git add crates/server/src/audit.rs && git commit -m "refactor(server): split audit append/query/verify_chain"`

### Task 5: server/src/dns_responder.rs

**函数表:** `ingest_chunk`(76 @202)、`answer_wire_query`(55 @410)
- [ ] 按标准协议执行;`ingest_chunk` 按 chunk 解码/会话查找/重组 切;`answer_wire_query` 按 wire 解析/应答构造 切。
- [ ] Commit: `git add crates/server/src/dns_responder.rs && git commit -m "refactor(server): split dns_responder ingest/answer"`

### Task 6: server/src/extc2_relay.rs

**函数表:** `from_env`(138 @217)
- [ ] 按标准协议执行;按通道(Slack/LLM/Discord/MCP)各提取一个配置解析 helper,`from_env` 只做编排 + fail-closed 判断。
- [ ] Commit: `git add crates/server/src/extc2_relay.rs && git commit -m "refactor(server): split extc2_relay::from_env per channel"`

### Task 7: server/src/implant_gen.rs A

**函数表:** `validate_patched_pe`(52 @118)、`parse_iso8601_to_unix`(70 @269)、`validate_generate_request`(69 @522)、`check_rate_limit`(54 @601)
- [ ] 按标准协议执行;解析类函数按 字段校验/边界检查 切。
- [ ] Commit: `git add crates/server/src/implant_gen.rs && git commit -m "refactor(server): split implant_gen validation helpers"`

### Task 8: server/src/implant_gen.rs B

**函数表:** `generate_implant_keys`(63 @658)、`patch_implant_template`(96 @804)、`store_and_audit_implant`(107 @904)
- [ ] 按标准协议执行;`patch_implant_template` 按 占位符定位/写入/重校验 切。
- [ ] Commit: `git add crates/server/src/implant_gen.rs && git commit -m "refactor(server): split implant_gen keygen/patch/store stages"`

### Task 9: server/src/operators.rs

**函数表:** `resolve`(86 @317)、`rehash_operator`(77 @413)、`load_or_bootstrap`(70 @505)、`resolve_named_and_legacy`(52 @684)
- [ ] 按标准协议执行;`resolve` 按 RBAC 判定阶段切,deny-list 语义不变。
- [ ] Commit: `git add crates/server/src/operators.rs && git commit -m "refactor(server): split operators resolve/rehash/bootstrap"`

### Task 10: server/src/smb_listener.rs

**函数表:** `serve_transaction`(80 @174)
- [ ] 按标准协议执行;按 读取请求/解密+分发/密封回复/drain 等待 切(2026-08-03 刚修过 drain 竞态,行为必须逐字节等价)。
- [ ] Commit: `git add crates/server/src/smb_listener.rs && git commit -m "refactor(server): split smb_listener serve_transaction stages"`

### Task 11: server/src/lib.rs A(启动路径)

**函数表:** `load_persisted_sessions`(91 @421)、`load_or_create_keypair`(63 @600)、`spawn_session_gc`(115 @705)
- [ ] 按标准协议执行。
- [ ] Commit: `git add crates/server/src/lib.rs && git commit -m "refactor(server): split startup path helpers (sessions/keypair/gc)"`

### Task 12: server/src/lib.rs B(路由与 beacon 入口)

**函数表:** `router`(136 @821)、`shape_beacon_response`(70 @1089)、`handle_beacon`(73 @1251)、`authenticate`(53 @1949)
- [ ] 按标准协议执行;`router` 按路由组提取。
- [ ] Commit: `git add crates/server/src/lib.rs && git commit -m "refactor(server): split router/beacon-entry helpers"`

### Task 13: server/src/lib.rs C(handle_new_session 268 行)

**函数表:** `handle_new_session`(268 @1357)
- [ ] 按标准协议执行;按 帧解码/密钥协商/会话注册/审计/应答 阶段切。这是 server 最大函数,单独一个任务。
- [ ] Commit: `git add crates/server/src/lib.rs && git commit -m "refactor(server): split handle_new_session into handshake stages"`

### Task 14: server/src/lib.rs D(handle_existing_session + into_command)

**函数表:** `handle_existing_session`(174 @1686)、`into_command`(106 @2162)
- [ ] 按标准协议执行;`into_command` 按命令族提取 match 臂。
- [ ] Commit: `git add crates/server/src/lib.rs && git commit -m "refactor(server): split handle_existing_session/into_command"`
- [ ] Step 4 复扫整个文件: `python3 scripts/count_long_fns.py crates/server/src/lib.rs` — Expected: 无输出

---

## Phase 3: implant-win(cross-check 验证)

所有 implant-win 任务统一验证命令(8 秒,已在 macOS 实测可用):

```bash
cd crates/implant-win && RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" \
  cargo +nightly check --target x86_64-pc-windows-gnu -Zbuild-std=core,compiler_builtins,alloc
```

Expected: `Finished` + 仅既有 warning(18 个,不新增)。复扫: `python3 scripts/count_long_fns.py <目标文件>` — Expected: 无输出。cd 回根目录再复扫与提交。

**特别注意:** implant-win 无本地测试,语义等价完全靠提取纪律;unsafe 块、transmute、static 访问顺序原样搬运。

### Task 15: antidebug.rs

**函数表:** `is_remote_debugged`(57 @46) — 按上方范例模式拆。
- [ ] Commit: `git add crates/implant-win/src/antidebug.rs && git commit -m "refactor(implant): split is_remote_debugged syscall/export paths"`

### Task 16: cfg_user.rs

**函数表:** `mark_single_nt`(67 @198)、`query_region`(56 @271)
- [ ] Commit: `git add crates/implant-win/src/cfg_user.rs && git commit -m "refactor(implant): split cfg_user mark/query"`

### Task 17: hostinfo.rs

**函数表:** `is_admin`(60 @168)、`machine_sid`(73 @254)、`primary_mac`(51 @331)
- [ ] Commit: `git add crates/implant-win/src/hostinfo.rs && git commit -m "refactor(implant): split hostinfo collectors"`

### Task 18: resolve.rs

**函数表:** `export_addr_by_hash_pub`(52 @458)、`fwd_name_matches`(66 @583)
- [ ] Commit: `git add crates/implant-win/src/resolve.rs && git commit -m "refactor(implant): split resolve forwarder matching"`

### Task 19: ntalloc.rs

**函数表:** `alloc`(83 @254)、`realloc`(54 @369)
- [ ] 全局分配器热路径,逐行搬运,不改任何 Layout/对齐计算。
- [ ] Commit: `git add crates/implant-win/src/ntalloc.rs && git commit -m "refactor(implant): split ntalloc alloc/realloc stages"`

### Task 20: unhook.rs

**函数表:** `fresh_ntdll_text`(78 @212)、`read_ntdll_file`(82 @381)
- [ ] Commit: `git add crates/implant-win/src/unhook.rs && git commit -m "refactor(implant): split unhook ntdll read/map"`

### Task 21: insomniac.rs + lacuna_stomp.rs(两文件两提交)

**函数表:** `insomniac::check_preservation`(73 @34);`lacuna_stomp::install_ghost_chain`(52 @45)、`with_ghost_stack`(54 @110)
- [ ] Commits:
```bash
git add crates/implant-win/src/insomniac.rs && git commit -m "refactor(implant): split insomniac check_preservation"
git add crates/implant-win/src/lacuna_stomp.rs && git commit -m "refactor(implant): split lacuna_stomp ghost-chain helpers"
```

### Task 22: envprobe.rs

**函数表:** `read_nic_mac_oui`(93 @375)、`running_process_count`(77 @624)
- [ ] Commit: `git add crates/implant-win/src/envprobe.rs && git commit -m "refactor(implant): split envprobe NIC/process probes"`

### Task 23: config.rs

**函数表:** `decode`(76 @148)
- [ ] Commit: `git add crates/implant-win/src/config.rs && git commit -m "refactor(implant): split config decode stages"`

### Task 24: config_placeholder.rs

**函数表:** `load_runtime_config`(175 @84)
- [ ] 按 密文定位/AEAD 解密/字段解析/kill-date 校验 切。
- [ ] Commit: `git add crates/implant-win/src/config_placeholder.rs && git commit -m "refactor(implant): split load_runtime_config stages"`

### Task 25: blind_hwbp.rs A(小函数)

**函数表:** `diag`(74 @230)、`init_shadow_buffer`(62 @307)、`veh_chain_has_handlers`(51 @636)、`add_hwbp`(64 @900)
- [ ] Commit: `git add crates/implant-win/src/blind_hwbp.rs && git commit -m "refactor(implant): split blind_hwbp small helpers"`

### Task 26: blind_hwbp.rs B(大函数)

**函数表:** `hwbp_veh_handler`(184 @431)、`remove_hwbp`(137 @995)
- [ ] VEH handler 是 WP-B 护栏的参照实现;按 异常码判定/槽位匹配/RIP 重定向 切,返回值约定(CONTINUE_EXECUTION=-1 / CONTINUE_SEARCH=0)不变。
- [ ] Commit: `git add crates/implant-win/src/blind_hwbp.rs && git commit -m "refactor(implant): split hwbp_veh_handler/remove_hwbp stages"`

### Task 27: fluctuation.rs + fluctuation_thunk.rs(两文件两提交)

**函数表:** `fluctuation::do_fluctuate`(123 @70);`fluctuation_thunk::build`(204 @58)
- [ ] thunk 是生成汇编字节的构建器,按 步骤 1-3/prologue/epilogue 切;栈对齐字节(0x28)不得改。
- [ ] Commits:
```bash
git add crates/implant-win/src/fluctuation.rs && git commit -m "refactor(implant): split do_fluctuate stages"
git add crates/implant-win/src/fluctuation_thunk.rs && git commit -m "refactor(implant): split thunk build steps"
```

### Task 28: evasion_glue.rs

**函数表:** `scan`(115 @45)
- [ ] Commit: `git add crates/implant-win/src/evasion_glue.rs && git commit -m "refactor(implant): split evasion_glue scan"`

### Task 29: hookchain.rs

**函数表:** `redirect_module_iat`(103 @139)、`alloc_persistent_stub`(66 @332)
- [ ] Commit: `git add crates/implant-win/src/hookchain.rs && git commit -m "refactor(implant): split hookchain iat redirect/stub alloc"`

### Task 30: proxy_veh.rs

**函数表:** `register_section_backed_handler`(286 @177) — implant-win 最大函数,单独任务。
- [ ] 按 section 创建/gadget 解析/VEH 注册/错误清理 切。
- [ ] Commit: `git add crates/implant-win/src/proxy_veh.rs && git commit -m "refactor(implant): split register_section_backed_handler stages"`

### Task 31: stack.rs

**函数表:** `do_rsp_swap`(193 @301)
- [ ] RSP 切换是 sleepmask 核心,栈几何一字节不改,按 保存/切换/恢复 切。
- [ ] Commit: `git add crates/implant-win/src/stack.rs && git commit -m "refactor(implant): split do_rsp_swap stages"`

### Task 32: syscalls.rs

**函数表:** `init`(132 @48) — `nyx_selftest_rt_steps` 属排除范围,不拆。
- [ ] 按 fresh-ntdll 解析/SSN 表填充/全局安装 切。
- [ ] Commit: `git add crates/implant-win/src/syscalls.rs && git commit -m "refactor(implant): split syscalls init stages"`

### Task 33: hashdump.rs A

**函数表:** `stream_file`(91 @51)、`do_hashdump`(71 @148)、`do_hashdump_vec`(67 @222)、`find_lsass_pid`(63 @297)
- [ ] Commit: `git add crates/implant-win/src/hashdump.rs && git commit -m "refactor(implant): split hashdump stream/collect/pid helpers"`

### Task 34: hashdump.rs B

**函数表:** `enable_privilege`(86 @477)、`save_hive_fallback`(152 @568)
- [ ] Commit: `git add crates/implant-win/src/hashdump.rs && git commit -m "refactor(implant): split privilege enable/hive fallback"`

### Task 35: postex.rs A

**函数表:** `enable_debug_privilege`(103 @66)、`steal_token`(73 @174)
- [ ] Commit: `git add crates/implant-win/src/postex.rs && git commit -m "refactor(implant): split postex privilege/token steal"`

### Task 36: postex.rs B

**函数表:** `make_token`(101 @300)、`getuid`(131 @407)
- [ ] Commit: `git add crates/implant-win/src/postex.rs && git commit -m "refactor(implant): split make_token/getuid stages"`

### Task 37: recon.rs

**函数表:** `do_driveinfo`(65 @169)、`do_env`(80 @240)、`do_clipboard`(100 @344)、`probe_one`(54 @554)、`do_portscan`(97 @612)、`net_connections`(73 @871)
- [ ] Commit: `git add crates/implant-win/src/recon.rs && git commit -m "refactor(implant): split recon task handlers"`

### Task 38: fs.rs A

**函数表:** `allowed`(90 @198)、`do_upload`(87 @477)、`do_download`(108 @567)
- [ ] Commit: `git add crates/implant-win/src/fs.rs && git commit -m "refactor(implant): split fs path-policy/upload/download"`

### Task 39: fs.rs B

**函数表:** `fileop_rm`(64 @773)、`fileop_mv`(74 @864)、`fileop_cp`(110 @940)、`fileop_ls`(121 @1055)
- [ ] Commit: `git add crates/implant-win/src/fs.rs && git commit -m "refactor(implant): split fileop rm/mv/cp/ls"`

### Task 40: keylog.rs

**函数表:** `keylog_hook_thread`(78 @492)、`map_vkey_layout_aware`(72 @790)、`poll_once`(61 @917)、`start_hook_thread`(73 @993)、`stop_hook_thread`(52 @1070)、`do_keylog`(121 @1123)
- [ ] static mut 状态(LAST/BUF/HOOK_PARAMS)访问顺序不动(AH-9 不在本计划范围)。
- [ ] Commit: `git add crates/implant-win/src/keylog.rs && git commit -m "refactor(implant): split keylog hook/poll/dispatch"`

### Task 41: pivot.rs

**函数表:** `do_connect`(158 @201)、`do_bind`(109 @386)、`pump_channels`(73 @583)
- [ ] Commit: `git add crates/implant-win/src/pivot.rs && git commit -m "refactor(implant): split pivot connect/bind/pump"`

### Task 42: inject.rs A(远程辅助)

**函数表:** `create_sacrificial`(63 @152)、`remote_load_library`(94 @374)、`remote_module_base`(91 @480)、`remote_text_region`(84 @578)
- [ ] `create_sacrificial` 是 WP-B B3 要扩展的函数,先拆干净。
- [ ] Commit: `git add crates/implant-win/src/inject.rs && git commit -m "refactor(implant): split inject remote helpers"`

### Task 43: inject.rs B(threadless/existing)

**函数表:** `threadless_inject`(130 @748)、`inject_existing`(105 @1117)
- [ ] Commit: `git add crates/implant-win/src/inject.rs && git commit -m "refactor(implant): split threadless_inject/inject_existing"`

### Task 44: inject.rs C(do_inject)

**函数表:** `do_inject`(198 @909)
- [ ] 按 PID 守卫/方法分发/pool-party 回退 切;WARN 前缀文本不变。
- [ ] Commit: `git add crates/implant-win/src/inject.rs && git commit -m "refactor(implant): split do_inject dispatch stages"`

### Task 45: screenshot.rs A(小函数)

**函数表:** `attach_interactive`(93 @363)、`write_all_to_file`(61 @824)、`dpi_probe_diag`(57 @895)、`read_file`(80 @1392)
- [ ] Commit: `git add crates/implant-win/src/screenshot.rs && git commit -m "refactor(implant): split screenshot io/attach helpers"`

### Task 46: screenshot.rs B(大函数)

**函数表:** `capture_bmp`(205 @613)、`run_screenshot_task`(69 @1151)、`run_cmd_wait`(101 @1252)
- [ ] Commit: `git add crates/implant-win/src/screenshot.rs && git commit -m "refactor(implant): split capture_bmp/screenshot task/run_cmd_wait"`

### Task 47: shell.rs

**函数表:** `run_shell_inner`(188 @129)
- [ ] 管道+句柄继承是 WP-B B3 的模板,按 CreatePipe/STARTUPINFO/CreateProcessW/ReadFile 循环 切,语义逐字节等价。
- [ ] Commit: `git add crates/implant-win/src/shell.rs && git commit -m "refactor(implant): split run_shell_inner pipe/process/read stages"`

### Task 48: transport.rs

**函数表:** `ensure_winhttp`(80 @129)、`post_frame`(239 @225)、`post_frame_enhanced`(241 @506)
- [ ] Commit: `git add crates/implant-win/src/transport.rs && git commit -m "refactor(implant): split winhttp ensure/post_frame stages"`

### Task 49: channels/(三文件三提交)

**函数表:** `channels/https.rs::send_recv`(78 @55);`channels/smb.rs::send_recv`(124 @205);`channels/tcp.rs::ensure_ws2_32`(89 @166)、`tcp_exchange`(122 @441)
- [ ] Commits:
```bash
git add crates/implant-win/src/channels/https.rs && git commit -m "refactor(implant): split https channel send_recv"
git add crates/implant-win/src/channels/smb.rs && git commit -m "refactor(implant): split smb channel send_recv"
git add crates/implant-win/src/channels/tcp.rs && git commit -m "refactor(implant): split tcp channel helpers"
```

### Task 50: tp.rs

**函数表:** `pool_party_inject`(131 @312)、`threadless_inject`(153 @479)、`hijack_worker_factory`(138 @653)
- [ ] section 交付片段是 WP-B B3 要复用的代码,按 section 创建/双映射/写入/队列拼接 切。
- [ ] Commit: `git add crates/implant-win/src/tp.rs && git commit -m "refactor(implant): split tp pool-party/threadless/hijack stages"`

### Task 51: trex/(三文件三提交)

**函数表:** `trex/cleanup.rs::self_delete`(66 @83)、`wipe_prefetch`(55 @152);`trex/mod.rs::scan_service_manager`(74 @323)、`match_process_name`(79 @687)、`match_driver_name`(57 @848)、`query_reg_value`(74 @1116)、`wmi_run_string_query`(157 @1223)、`write_report`(120 @1525);`trex/exfil/deaddrop.rs::upload_gist`(129 @160)
- [ ] `trex/mod.rs` 可分两次提交(scanners 一次、wmi/report 一次)。
- [ ] Commits:
```bash
git add crates/implant-win/src/trex/cleanup.rs && git commit -m "refactor(implant): split trex cleanup helpers"
git add crates/implant-win/src/trex/mod.rs && git commit -m "refactor(implant): split trex scanners/matchers"
git add crates/implant-win/src/trex/mod.rs && git commit -m "refactor(implant): split trex wmi query/report"
git add crates/implant-win/src/trex/exfil/deaddrop.rs && git commit -m "refactor(implant): split deaddrop upload_gist"
```

### Task 52: entry.rs

**函数表:** `bootstrap`(184 @28)、`diag_mark`(74 @333) — `nyx_selftest`/`nyx_selftest_evasion` 排除。
- [ ] `bootstrap` 按 resolve/alloc/evasion init/通道 init 阶段切;init 顺序不变。
- [ ] Commit: `git add crates/implant-win/src/entry.rs && git commit -m "refactor(implant): split entry bootstrap/diag_mark"`

### Task 53: implant lib.rs

**函数表:** `write_panic_diag`(141 @207)
- [ ] panic handler 诊断写入,按 格式化/截断/写文件 切。
- [ ] Commit: `git add crates/implant-win/src/lib.rs && git commit -m "refactor(implant): split write_panic_diag"`

### Task 54: beacon.rs A(WP-B 前置,先拆干净)

**函数表:** `beacon_init`(65 @96)、`execute`(215 @707)
- [ ] `execute` 按命令族提取 match 臂 helper;这是 WP-B 的挂载点,拆完 WP-B diff 才清晰。
- [ ] Commit: `git add crates/implant-win/src/beacon.rs && git commit -m "refactor(implant): split beacon_init/execute dispatch"`

### Task 55: beacon.rs B(beacon_oneshot)

**函数表:** `beacon_oneshot`(205 @451)
- [ ] 按 check-in/单轮任务/退出码映射 切;0xAF/0xC0..0xCF 退出码语义不变。
- [ ] Commit: `git add crates/implant-win/src/beacon.rs && git commit -m "refactor(implant): split beacon_oneshot stages"`

### Task 56: bof.rs(WP-A 最后一个函数文件)

**函数表:** `format_into`(63 @212)、`run`(212 @944)
- [ ] `run` 按 parse/alloc/relocate/flip/call/capture 六段切(spec §3 既定);BeaconPrintf shim 与 static OUT 捕获机制不动。
- [ ] Commit: `git add crates/implant-win/src/bof.rs && git commit -m "refactor(implant): split bof run into six stages"`

---

### Task 57: 终验门禁

- [ ] **Step 1: 全量复扫**

Run: `python3 scripts/count_long_fns.py`
Expected: 无输出(三个 crate 无 >50 行非测试函数)

- [ ] **Step 2: workspace 全量验证**

Run: `cargo fmt --check && cargo clippy --workspace -- -D warnings 2>&1 | tail -3 && cargo test --workspace 2>&1 | tail -5`
Expected: fmt 无 diff;clippy 无 error;全部 `test result: ok`

- [ ] **Step 3: implant-win cross-check + 生产 feature 矩阵**

Run:
```bash
cd crates/implant-win && \
RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" cargo +nightly check --target x86_64-pc-windows-gnu -Zbuild-std=core,compiler_builtins,alloc && \
RUSTFLAGS="-Zunstable-options -Cpanic=immediate-abort" cargo +nightly check --features selftest --target x86_64-pc-windows-gnu -Zbuild-std=core,compiler_builtins,alloc
```
Expected: 两个 feature 组合都 `Finished`,无 error

- [ ] **Step 4: 更新 STATUS.md / CHANGELOG** — [Unreleased] 加一条:WP-A 巨函数拆分完成(140 个函数 <50 行,零行为变更);STATUS.md「进行中的整改」加 v0.4.0 专项条目。

- [ ] **Step 5: Commit**

```bash
git add docs/STATUS.md CHANGELOG.md
git commit -m "docs(wp-a): AH-2 giant-function split complete — 140 fns <50 lines, zero behavior change"
```

- [ ] **Step 6: 推送触发 CI(可选,需用户确认)** — CI Gate 1-6 + windows-ci 全绿后 WP-A 关闭。
