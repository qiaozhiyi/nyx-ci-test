# 权威事实摘要 (AUTHORITATIVE_FACTS)

- **日期**: 2026-07-18
- **审计方法**: 6 路并行 code-explorer agent 逐 crate 审计 + 主会话亲验争议点
- **作用**: 所有文档（README、CODE_TRUTH、agent 定义、design/testing/bypass 文档）必须以本文件数字为准。数字冲突时以本文件为准。

---

## §0 硬指标（实测，2026-07-18，commit 未提交前）

| 指标 | 权威值 | 测量命令 / 证据 |
|---|---|---|
| 总 Rust LOC | **68,751** | `find crates -name '*.rs' -not -path '*/target/*' \| xargs wc -l` |
| workspace 成员 | **18** | `Cargo.toml [workspace] members` |
| 独立 crate（非 workspace） | **6** | implant-win, implant-evasionsdk, operator-kernelsdk, operator-kernel-cli, offset-resolver, minidump-assembler |
| crate 目录总数 | **24** | `ls -d crates/*/` |
| `#[test]` / `#[tokio::test]` | **488**（含独立 crate） | `grep -rE '^\s*#\[(test\|tokio::test)\]' crates --include='*.rs'` |
| workspace 内测试（cargo test --workspace） | **~267** | 实跑 |
| wire `Command` 变体 | **28** | `protocol/src/msg.rs:130` |
| wire `Response` 变体 | **7** | `protocol/src/msg.rs:560` |
| GUI 命令（已解析） | **29** | `client-ui-web/src/components/CommandInput.tsx` |
| server 路由 | 14 静态 API + 7 beacon + 6 kernel(条件) + 动态 profile | `server/src/lib.rs:716-779` |
| selftest 导出符号 | **49 个 `nyx_selftest_*` + 1 个 `nyx_linger*` = 50** | `implant-win/src/selftests.rs`（feature-gated） |
| BYOVD 驱动 | **3 可用 + 1 stub** | Shield / RTCore64 / Iqvw64e / WdtKernel(stub) |
| Windows build 覆盖 | 8 主 + 6 patch-equiv = 14 distinct | `implant-evasionsdk/src/offsets_table.rs` |
| transport `Transport` impl | **6 个，全部零消费者** | Malleable/DoH/Slack/LLM/MCP/SMB |
| 加密协议测试数 | 40 | `protocol/tests/roundtrip.rs` 等 |

> **旧 CODE_TRUTH_2026-07-15 的过时值**：LOC 88,874（错，含注释/空行重复计）/ test 674（错）/ Command 27（错，实际 28）/ selftest 55（错，实际 50）。本次审计已取代。

---

## §1 逐 crate 状态（一行一 crate，✅完整 / 🟡部分 / 🔴缺失）

| crate | LOC | 状态 | 一句话实情 |
|---|---|---|---|
| protocol | 1,895 | ✅ | X25519+HKDF+ChaCha20-Poly1305，方向隔离 nonce，零化，40 测试，无 stub |
| server | 5,615 | ✅ | tokio/axum，14 API + 7 beacon 路由，argon2id RBAC，哈希链审计，SQLite 持久化 |
| store | 1,321 | 🟡 | 真实 SQLite WAL；`mask_secret()` 是 stub 永返 `********`；migration 仅基线 |
| transport | 3,420 | 🟡 | JA3/JA4 接入 server；6 个 Transport impl **零消费者**；emitter 是 Err stub |
| rest | 189 | ✅ | 类型库，3 测试，最干净的 crate |
| parse | 544 | ✅ | 5 解析器 + 2 自动检测，19 测试，无 stub |
| profile | 1,733 | ✅ | Malleable C2 解析 + c2lint + 7 变换；`mask` 非 CS 线兼容（已文档化） |
| implant-win | 29,202 | 🟡 | 28 Command 全派发；间接 syscall/HWBP blind/CFG/LACUNA/栈欺骗真；**睡眠混淆未接线** |
| operator-kernelsdk | 9,791 | 🟡 | 9/10 kit 算法真；PatchGuard 偏移未验证；WfpKit 永返 Err；WdtKernel stub |
| operator-kernel-cli | 912 | ✅ | 9 子命令 + daemon 模式，Windows-only |
| offset-resolver | 657 | 🟡 | PDB 解析真；`detect_build_from_pdb` 返 None（stub） |
| minidump-assembler | 469 | ✅ | LSASS 裸内存→.dmp，8 测试，无 stub |
| nyx-loader | 1,225 | 🔴 | 加密+组装真；PIC stub 自定位后 `ret`，反射加载仅 std 参考实现 |
| nyx-mutate | 804 | ✅ | 4 趟变异：NOP/寄存器/密钥/**指令替换**（已实现） |
| evasion | 264 | ✅ | Hell/Halo/Tartarus Gate 全真，11 测试 |
| implant-evasionsdk | 2,028 | 🟡 | 9 trait 全 floor；算法子模块真且测试但 dead_code |
| client-ui-web | 613 Rust + ~4500 ts/tsx | ✅ | Tauri2+React+Three.js，29 命令，3D 拓扑真；无会话元数据 |
| agent-dev | 1,181 | ✅ | 完整协议循环；Windows 原语返 Err |
| bof-runner | 421 | 🟡 | 仅 `BeaconPrintf` shim；每次执行泄漏 RWX 页；零测试 |
| coff | 365 | ✅ | AMD64 解析+重定位，7 测试，稳健 |
| scripting | 237 | ✅ | 3 event bus，接入 server |
| scripting-rhai | 166 | ✅ | Rhai 绑定 + 资源配额 |
| config | 153 | ✅ | 编译期 ChaCha20 加密真 |
| config-macros | 192 | ✅ | embed! proc-macro 真，含 deprecated 警告 |

---

## §2 关键争议点裁定（亲验，file:line 为准）

| 争议 | 裁定 | 证据 |
|---|---|---|
| Command 变体 27 还是 28 | **28** | `protocol/src/msg.rs:130` 逐行列数 |
| WinHTTP TLS `SetOption` 时机 | **正确（在 send 之前）** | `implant-win/src/transport.rs:332-353`，注释明说 after 会被拒 |
| implant 里是否有 WFP silencer | **没有**（grep 零命中） | 失败的 WfpKit 在 `operator-kernelsdk/src/netsec.rs`，非 implant |
| `cargo +nightly check -p nyx-implant-win` | **不可用**（implant 不在 workspace） | 必须 `(cd crates/implant-win && cargo +nightly check --target ...)` |
| nyx-mutate 指令替换是否存在 | **存在** | `nyx-mutate/src/lib.rs:479-545`，3 种 opcode 替换 |
| 睡眠混淆是否工作 | **不工作** | `kits.rs:65-71` 短路到 `beacon::sleep_seconds`，Fluctuation/Foliage/mem::mask 全部死路径 |

---

## §3 最高优先级缺口（Roadmap 排序依据）

1. **接线睡眠混淆**（`kits.rs:65-71` 短路问题）——决定睡眠期内存扫描对抗
2. **nyx-loader 反射加载** on-target 实现
3. **BOF API 扩面**（仅 BeaconPrintf）+ 补页释放
4. **transport/ 接线**（6 个零消费者 channel）
5. **TLS 指纹 emitter**（`build_impersonating_client` stub）
6. PatchGuard 偏移 PDB 验证
7. caller-spoof 宏实现（当前仅 scanner）
8. GUI 会话元数据 overlay
9. CET 物理机验证
10. `mask_secret` 真实现
