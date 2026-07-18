# NYX 代码实情审计报告 (CODE_TRUTH 2026-07-18)

- **日期**: 2026-07-18
- **分支**: `main`(HEAD: 27d67e2 + 未提交的 syscalls.rs diag_mark)
- **方法**: 6 路并行 code-explorer agent 逐 crate 审计 + 主会话亲验 4 个争议点
- **审计范围**: 全部 24 个 crate 目录,共 **68,751 LOC**
- **取代**: [`CODE_TRUTH_2026-07-15.md`](CODE_TRUTH_2026-07-15.md)(其状态结论已过时,安全发现仍有效)
- **配套**: 数字基准见 [`AUTHORITATIVE_FACTS_2026-07-18.md`](AUTHORITATIVE_FACTS_2026-07-18.md)

---

## §0 全局事实表(实测值)

| 指标 | 2026-07-18 实测 | 2026-07-15 旧值(漂移) | 测量方法 |
|---|---|---|---|
| 总 LOC | **68,751** | 88,874(含注释/空行重复) | `find crates -name '*.rs' -not -path '*/target/*' \| xargs wc -l` |
| workspace 成员 | **18** | 26 | `Cargo.toml [workspace] members` |
| 独立 crate | **6** | (混计) | implant-win/evasionsdk/kernelsdk/kernel-cli/offset-resolver/minidump-assembler |
| `#[test]` 函数 | **488**(含独立 crate) | 674 | `grep -rE '^\s*#\[(test\|tokio::test)\]'` |
| Command 变体 | **28** | 27 | `protocol/src/msg.rs:130` |
| Response 变体 | **7** | 7 | `protocol/src/msg.rs:560` |
| selftest 导出 | **50**(49 nyx_selftest_ + 1 nyx_linger) | 55 | `implant-win/src/selftests.rs` |
| GUI 命令 | **29**(Tauri) | 64 MetaCmd(TUI,已删) | `client-ui-web/src/components/CommandInput.tsx` |
| BYOVD 驱动 | **3 可用 + 1 stub** | 同 | `operator-kernelsdk/src/byovd_drivers/` |

---

## §1 加密协议层(`protocol/` 1,895 LOC)— ✅ 完整

唯一全绿、零 stub 的层。40 个测试(`tests/roundtrip.rs` 21 + 内联 19)。

| 能力 | 实情 | 证据 |
|---|---|---|
| X25519 ECDH | ✅ 双向派生一致 | `crypto.rs:268-328` |
| HKDF-SHA256 | ✅ server_pub 作 salt + 双 pubkey 进 info | `crypto.rs:340-370`(P1-2 修复) |
| ChaCha20-Poly1305 | ✅ 方向隔离 nonce 空间 | `crypto.rs:383-408` |
| SessionKey 零化 | ✅ 真 `Drop` + redacted `Debug` | `crypto.rs:63-81` |
| 防重放 | ✅ 单调计数器 + 写守卫 TOCTOU 关闭 | server `lib.rs` |
| 分配炸弹防护 | ✅ declared count > 65536 拒绝 | `msg.rs:35-41` |
| blob 上限 | ✅ MAX_BLOB_LEN=256KiB / MAX_CT_LEN=512KiB | `wire.rs:94-110`,`frame.rs:22` |

无 `todo!`/`unimplemented!`/`allow(dead_code)`。no_std 分支正确传播 CSPRNG 失败(`crypto.rs:163-167`)。消费者:server / agent-dev / implant-win / nyx-loader。

**已知小瑕疵**(非阻塞):
- `Command::encode` 对 >256 args 静默截断而非报错(`msg.rs:335-339`)
- HKDF info buffer 80 字节但只写 78(`crypto.rs:354-362`,无害)
- `seal_dir` 用 `expect("infallible")` 表述误导(`crypto.rs:430`)

---

## §2 团队服务器(`server/` 5,615 LOC)— ✅ 完整

37 测试 + 24 集成测试。真实生产形态的 C2 team server。

### §2.1 路由清单(`lib.rs:716-779`)

**Beacon 面(加密,无鉴权,512KiB body cap):**
`POST /beacon` `/doh` `/dns` `/extc2/{slack,discord,llm,mcp}` + profile 动态 URI(`http-get`/`http-post` 块)

**Operator API 面(鉴权,4MiB cap):**
| 方法 | 路径 | 角色限制 |
|---|---|---|
| GET | `/api/sessions` | 认证即可 |
| POST | `/api/task` | 非 Viewer |
| GET | `/api/tasks` `/api/results` | `/results` 非 Viewer |
| GET | `/api/profile` `/api/creds` | `/api/creds?reveal=1` 非 Viewer |
| POST | `/api/creds` `/api/creds/delete` | 非 Viewer |
| GET | `/api/audit` | 非 Admin 仅见自己行 |
| GET | `/api/audit/verify` | Admin |
| POST | `/api/generate-implant` | 认证 |
| GET | `/api/implants` POST `/api/implant/revoke` | 认证 |

**Kernel API(条件注册,仅 `NYX_KERNEL_DAEMON` 设):**
`/api/kernel/{status,blind-etw,hide,dump-lsass,neutralize,detach-minifilter}` — 全部要求 Admin(`kernel.rs:84-99`)。无 daemon 时这 6 路由不存在(404)。

### §2.2 RBAC
3 角色:Admin / Operator / Viewer(`operators.rs:62-68`)。argon2id + `plain:` legacy fallback + dummy-hash 时序均衡(`operators.rs:127-158`)。**注意:open 模式下 `_anonymous` 解析为 Admin**(`lib.rs:1445-1448`),即 dev/CI 下 RBAC 实质旁路。

### §2.3 持久化
SQLite WAL + synchronous=NORMAL + foreign_keys=ON。cred/implant/session 三 store 共享一个 DB 文件。**session 持久化真且实测**:2026-07-16 重启 server 同 id 复原。

### §2.4 已知缺陷
- **`created_by` 归因**:`implant_gen.rs:620` TODO,永为 None
- **migration 框架有但空**:`store.rs:96-124` `CURRENT_SCHEMA_VERSION=1`,v0→v1 是 no-op
- `implant_gen.rs:384` 一处 dead-store zeroization(有意防御)
- `/api/kernel/*` 无 daemon 时静默 404(易误解为功能缺失)

---

## §3 传输层(`transport/` 3,420 LOC)— 🟡 零消费者

**这是全项目最大的"代码存在 ≠ 功能可用"陷阱。**

### §3.1 唯一接入部分
JA3/JA4 计算 + ClientHello 解析接入 server(`server/src/main.rs:427-430`),存入 `DashMap<SocketAddr, Fingerprint>`。

### §3.2 零消费者部分(6 个 Transport impl)
| impl | LOC | 测试 | 真实消费者 |
|---|---|---|---|
| MalleableTransport | 522 | 12 | **0** |
| DohDnsTransport | 512 | 13 | **0** |
| SlackTransport | 353 | 4 | **0** |
| LlmApiTransport | 358 | 9 | **0** |
| McpTransport | 451 | 13 | **0** |
| SmbPipeTransport | 416 | 6 | **0** |
| `Transport` trait 本身 | 52 | — | **0** |

server 用裸 `tokio-rustls`,implant 用自滚 WinHTTP。这 6 个 impl 全部编译通过 + 单元测试自洽,但**没有任何 beacon 调用它们**。

### §3.3 永久 stub
- `build_impersonating_client` → `Err(BackendUnavailable)`(`fingerprint.rs:144-148`),`rquest` 依赖未在 Cargo.toml。出站 JA3 **不可控**。
- `validate_ja3(_: &())` → `Err(BackendUnavailable)`(`fingerprint.rs:154-156`),签名无意义

### §3.4 设计性限制(已文档化,非 bug)
- DoH 经 cloudflare-dns.com 实际 exfil 不可靠(TXT 缓存 + 不一定递归)
- McpTransport `extract_hex` 是模糊启发式(≥8 hex),可被恶意响应劫持通道
- LlmApiTransport `recv` 忽略 timeout,单次 60s HTTP

---

## §4 Windows PIC 植入体(`implant-win/` 29,202 LOC)— 🟡 核心完整,睡眠混淆死

61 个 .rs 文件。审计重点结论:

### §4.1 ✅ 真实运行(生产 beacon 循环路径)
- **间接 syscall**:`Runtime::init`(`syscalls.rs:48`),SSN 解析优先 KnownDlls fresh map → 磁盘 → hooked in-process(Halo/Tartarus 邻走),gadget 扫 `0F 05 C3`,单 RW 页翻 RX
- **28 Command 全派发**:`beacon.rs:467-649`(注意 `beacon.rs:9` 注释说"all 21"已过时)
- **AMSI/ETW blind**:HWBP-VEH(默认,`blind_hwbp.rs`)+ 字节 patch fallback(`blind.rs`)
- **CFG 用户态 bitmap**:`cfg_user.rs` SetProcessValidCallTargets + NtSetInformationVirtualMemory fallback
- **LACUNA**:`.pdata` 间隙扫描,跨版本
- **栈欺骗 SPOOF_SWAP**:真 `mov rsp` 内联汇编(`stack.rs:400-415`),CET probe via `IsProcessorFeaturePresent(41)`,CET-off 自动 arm
- **Module Stomping**(`inject.rs:165`,默认 arm AtomicBool::new(true))+ **ThreadlessInject HWBP**(`inject.rs:544`)
- **WinHTTP HTTPS** + 域前置 + 命名代理(`post_frame_enhanced`)
- **Malleable C2 envelope shaping**
- **9 通道**:Https/DohDns/Dns/SmbPipe/Tcp(直连)+ Slack/LLM/MCP/Discord(server 中转 ExtC2)
- **fallback 链**:仅 Https→DohDns→Dns(`channels/mod.rs:259`)

### §4.2 🔴 睡眠混淆完全未接线(最高优先级缺口)
这是本次审计最重要的发现,直接决定睡眠期内存扫描对抗:

```
beacon loop → sleep_jitter → kits::sleep (kits.rs:65-71)
                                ↓ 短路!
                          beacon::sleep_seconds (纯 NtWaitForSingleObject)
```

`kits.rs:66-69` 注释承认:"Avoids the Foliage fluctuation sleep-mask which RC4-encrypts .text during sleep — that crashes in noevasion mode"。

后果:
- `fluctuation.rs`(PAGE_NOACCESS flip + RC4 mask)**实现完整但永不调用**
- `fluctuation_thunk.rs`(PIC x86-64 thunk 字节序列)**永不执行**
- `sleep.rs` Foliage APC **仅脚手架**,`sleep::sleep()` 零调用方,文档提到的 `execute_foliage_plan`/`FOLIAGE_ENABLED` 符号**不存在**
- `mem.rs` `mask()`/`unmask()` 注册了 config/session_key/heap 区域(`beacon.rs:84,108`)但**永不调用**

**中睡眠时 .text / config 明文 / session key 全部明文驻留内存。**

### §4.3 亲验争议点裁定

| 争议 | 裁定 | 证据 |
|---|---|---|
| `WinHttpSetOption` 时机 | **✅ 正确(在 send 之前)** | `transport.rs:332-353`,注释明说 "setting them after a failed send is rejected" |
| implant 是否有 WFP silencer | **🔴 没有**(grep 零命中) | 失败的 WfpKit 在 kernelsdk 的 `netsec.rs`,非 implant |

### §4.4 🟡 部分实现 / scanner-only
- **caller-spoof**:仅扫 `ADD RSP,imm8;RET` stub(`caller_spoof.rs:70`),文档所述 `call_with_spoofed_return!` 宏**不存在**
- **proxy_veh**:`register_section_backed_handler` 完整(KnownDlls SEC_IMAGE + code cave trampoline),但 HWBP 路径直接用 `AddVectoredExceptionHandler`,gadgets 扫描后未消费
- **Pool Party**:`tp.rs` 全实现(section 投递 + worker-factory 劫持 + `_TP_DIRECT` splice),仅 `NYX_POOL_PARTY_ON=1 && method=0 && pid!=0` 触发

### §4.5 编译期 gate(亲验)
| gate | 读取方式 | 默认 | 实际效果 |
|---|---|---|---|
| `NYX_FLUCTUATION_OFF` | `option_env!`(`fluctuation.rs:11`) | ON | **无运行时效果**(本就未接线) |
| `NYX_SPOOF_OFF` | `option_env!`(`entry.rs:137`) | OFF(arm) | 真 arm `mov rsp` swap |
| `NYX_TLS_INSECURE` | `option_env!`(`transport.rs:108`) | OFF | ON 时 send 前 set_option |
| `NYX_POOL_PARTY_ON` | `option_env!`(`tp.rs:75`) | OFF | ON 时 method=0 走 pool party |
| `NYX_SKIP_SANDBOX` | **运行时 env**(`entry.rs:58`) | OFF | 跳过 envprobe + antidebug |

---

## §5 内核层 SDK(`operator-kernelsdk/` 9,791 LOC)— 🟡 算法真,部分 stub

~117 测试(全 mock over `&dyn KernelRw`)。10 trait,`NoKernel` floor 全返 Err。

### §5.1 ✅ 真实算法(9/10 kit)
- **ETW-TI blind** 4-hop:`etwti.rs:35-117`
- **DKOM 进程隐藏**:走 PsActiveProcessHead 解链,`persistence.rs:148-285`
- **回调中和**:首字节写 `0xC3` RET,跳 slot[0],`telemetry.rs:64-180`
- **回调重定向**:data-write 改 `_EX_CALLBACK_ROUTINE_BLOCK::Function`,`telemetry.rs:195-260`
- **MiniFilter 解链**:走 fltmgr RegisteredFilters,`telemetry.rs:282-372`
- **PPL strip**:Protection=0x72 / SignatureLevel=0x3F,`persistence.rs:380-540`
- **LSASS 内核读**:DTB 切换 + 4 级页走 + PEB ImageBase,`netsec.rs:380-560`
- **CFG bitmap**:`cfg.rs`
- **ETW 事件伪造**:`etw_deception.rs:90-280`(但无 tier 装配,仅 CLI forge-etw 调用)

### §5.2 BYOVD 驱动(4 个)
| 驱动 | CVE/来源 | IOCTL | 状态 |
|---|---|---|---|
| RtCore64 | CVE-2019-16098 | 0x80002048/0x8000204C | ✅ REAL |
| Iqvw64E | CVE-2015-2291 | 0x80862007 case 0x33 | ✅ REAL |
| Shield | LOLDrivers #344 | 0x96102014 bidirectional | ✅ REAL |
| WdtKernel | LOLDrivers #290 | 0x9C412420/0x9C41242C phys | 🟡 raw_rw=Err(0) stub |

KslD "Living off the Defender"(`win/ksld.rs:60-220`)优先于 BYOVD,真 Windows impl。

### §5.3 🟡/🔴 缺陷
- **WfpKit 永返 Err**(`netsec.rs:block_outbound_for_pid`),`assemble_tier` 设 `wfp: None`
- **PatchGuard bypass 偏移未验证**:`persistence.rs:550-720` 用 valid_flag 置零法,偏移 `prcb_pg=0x190`/`valid=0x08` 代码自标需 PDB 验证。**非** Outflank Peekaboo 法
- **EdrNeutralizer::kill** 只 resolve KVA,不终止(`netsec.rs:880-920`)
- **`detect_build_from_pdb`** 返 None(offset-resolver,PDB build 值提取未实现)

---

## §6 操作端(`client-ui-web/` ~5,100 LOC)— ✅ 可用

Tauri 2 + React + Three.js。旧 ratatui TUI / Makepad GUI 已 commit `c5064dc` 归档。

### §6.1 ✅ 真实功能
- Rust 后端 613 LOC:12 个 `#[tauri::command]`,2s 轮询 + 签名增量检测(`poll.rs:54-58`),3 次失败才致命
- 通用 `send_command` 透传 `serde_json::Value` 到 `/api/task`(`commands.rs:42-77`),无命令分派表
- 前端 ~4,500 LOC ts/tsx:ConnectPage / Workspace(SessionTable + CommandConsole)/ TopologyPage / CredsPage / ImplantPage / EventsPage
- **3D 拓扑真实**:`topology-scene.ts`(1001 LOC)WebGLRenderer + Reinhard tone mapping + OrbitControls + UnrealBloom + 700 点星空 + 射线点击 + GPU 释放
- **29 命令解析**(`CommandInput.tsx:214-454`)
- 命令生命周期状态机处理 `task-submitted` ack 早于 promise 的竞态(`CommandConsole.tsx`)

### §6.2 🟡 缺陷
- **无会话元数据 overlay**(rename/tag/star/alias)—— TUI 曾有,GUI 无
- `ProcessTable.tsx`(99 LOC)**死文件**,零导入
- `image`/`channel`/`file` 结果是占位符(`TaskBlock.tsx:133-144`)
- `fetch_profile` 定义但前端未调
- pivot 边无 server 数据,全 live-session 合成 HTTPS egress 到假 `__srv__` 节点

---

## §7 脚本 / 扩展层

### §7.1 scripting(237 LOC)+ scripting-rhai(166 LOC)— ✅ 可用
3 event(`SessionNew`/`ResultReceived`/`SessionExit`),接入 server(`lib.rs:108,173-175,1158,1230,1324-1363,1868`)。Rhai 引擎硬配额(max_call_levels 64 / max_operations 1M / max_string 64KB 等),`NYX_SCRIPT` env 加载。`FirstBloodHook`(首次 checkin 自动 TTP)开箱即用。

### §7.2 BOF(coff 365 + bof-runner 421 LOC)— 🟡 兼容面窄
- `coff` 解析+重定位**稳健**,AMD64 only,7 测试,全 checked_add 溢出防护
- `ADDR32NB` 常量声明但 apply 不处理(`lib.rs:37` vs `lib.rs:334-360`)—— 文档 vs 代码矛盾
- **bof-runner Beacon-API 表只有 `BeaconPrintf`**(`win.rs:179`)。多数社区 BOF 重定位时 `Unresolved` 失败
- 每次执行**泄漏 RWX 页** + trampoline 页(`win.rs`,无 Drop)
- **bof-runner 零测试**
- `BeaconPrintf` `%s` 读最多 4096 字节不验指针(`shim.rs:85`)
- agent-dev 集成(`lib.rs:736-763`)4MB 栈线程

### §7.3 nyx-loader(1,225 LOC)— 🔴 反射加载未实现
- 加密+组装真:`wrap_payload` ChaCha20-Poly1305,layout `[PIC_STUB 50B][NYX2 magic][encrypted_len u32][nonce 12B][ct N][tag 16B]`
- **PIC stub 自定位后 `ret`**(`stub.rs:71-89`,50 字节,offset 0x16 是 `0xC3`,后 27 NOP 空间未 patch)
- 反射加载是 **std 参考实现**:section map + reloc + IAT 真且有测试,但 PEB walk / NtAllocateVirtualMemory / DllMain **未实现**(委托给"implant-win toolchain")

### §7.4 nyx-mutate(804 LOC)— ✅ 4 趟全真
**指令替换已实现**(`lib.rs:479-545`,3 种 opcode:`0x90→xchg eax,eax`/`0x50→push rax ModRM`/`0x58→pop rax ModRM`)。NOP 插入 + 寄存器轮转 + 密钥随机化也都真。13 测试。旧 README/审计说"指令替换不存在"是**错的**。

### §7.5 evasion(264 LOC)+ implant-evasionsdk(2,028 LOC)
- **Hell/Halo/Tartarus Gate 全真**(`syscalls.rs`),11 测试,direct/indirect stub 模板真
- **implant-evasionsdk 9 trait 全 floor**(仅 `Floors` no-op,`lib.rs:366-413`)
- 算法子模块(gap/frame/rc4/foliage/apc/swap/offsets_table)**真且测试**(53 测试),但非 test build 下 `#[allow(dead_code)]`,implant-win 尚未把它们接成 trait impl

### §7.6 config + config-macros(345 LOC)— ✅ 真
编译期 ChaCha20-Poly1305 AEAD。proc-macro 读文件 → OsRng key+nonce → 加密 → 随机 0..256 decoy 前缀 → quote! 烤入。无自定义 key 时 emit `#[deprecated]` 警告 operator。两 crate 顶部都明确警告"obfuscation NOT confidentiality"。

### §7.7 store / parse / rest / profile — ✅
- store:真 SQLite,但 `mask_secret()` 永返 `********`(`model.rs:72-74`,文档承诺 first2…last2 未实现)
- parse:5 解析器全真,19 测试
- rest:189 LOC 最干净,3 测试
- profile:c2lint 真,`mask` 非 CS 线兼容(已文档化)

---

## §8 与旧审计(2026-07-15)的关键差异

| 项 | 07-15 声称 | 07-18 实测 | 性质 |
|---|---|---|---|
| LOC | 88,874 | 68,751 | 07-15 计数含注释/空行/重复 |
| Command | 27 | **28** | 07-15 漏数 |
| test | 674 | 488 | 07-15 统计口径不同 |
| WinHTTP TLS | "有 bug,send 失败后才设" | **已正确**(send 之前设) | 07-15 描述过时,代码已修 |
| implant WFP | "装配但必失败" | **implant 无 WFP 代码** | 07-15 把 kernelsdk 的 WfpKit 误归 implant |
| nyx-mutate 指令替换 | "不存在" | **已实现** | 07-15 错误 |
| 睡眠混淆 | 标为"部分限制" | **完全未接线** | 07-15 未发现 kits.rs 短路 |
| transport 零消费者 | 未强调 | **6 impl 全零消费者** | 本次重点确认 |

---

## §9 Roadmap 优先级(据本次审计重排)

1. **接线睡眠混淆** — 修 `kits.rs:65-71` 短路,让 beacon 走 `fluctuation::sleep`。**最高优先级**
2. **nyx-loader 反射加载** on-target(PEB walk / import resolve / DllMain)
3. **BOF API 扩面** + 补页释放
4. **transport/ 接线**(激活 6 个零消费者 channel)
5. **TLS 指纹 emitter**(`build_impersonating_client`)
6. PatchGuard 偏移 PDB 验证 / 改 Outflank Peekaboo
7. caller-spoof 宏实现
8. GUI 会话元数据 overlay
9. CET 物理机验证(Win11 25H2)
10. `mask_secret` 真实现

---

## §10 安全发现(承自 07-15,仍有效)

详见 [`CODE_TRUTH_2026-07-15.md`](CODE_TRUTH_2026-07-15.md) §7 安全发现部分。本次审计未发现新增安全缺陷,上述功能性缺陷(睡眠混淆未接线、BOF 泄漏、`%s` 不验指针等)部分具有安全含义,已在各 § 标注。
