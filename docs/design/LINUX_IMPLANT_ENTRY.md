# Linux 生产植入体 — 入口设计（第一增量）

> **状态**：设计（本文件不交付代码）  
> **日期**：2026-08-28  
> **范围**：Debian x86_64 本机可实现并测试的第一增量。  
> **非目标**：不重写 [ROADMAP P16](ROADMAP_2026-2027.md)（2027.02 八周 ELF PIC / ptrace / 容器逃逸）。P16 与 [STATUS.md](../STATUS.md)「跨平台生产 implant」均为更长周期口径。

---

## 1. 代码事实（不是规划）

| 组件 | 实际身份 |
|---|---|
| `crates/agent-dev` | std 协议验证桩。crate 描述与 `lib.rs` 写明：**不是** Windows PIC agent，用来在开发机上跑完整加密 beacon 循环。Windows 原语（StealToken / Inject / Trex / Keylog 等）返回 `Response::Err`。 |
| `crates/implant-core` | Windows PIC 核心层（WP-C 从 `implant-win` 拆出）。`lib.rs` 仅 `heap`/`fmt` 无 OS 门；`ntalloc`/`resolve`/`syscalls`/`unhook`/`stack`/`hostinfo`/`config`/`context`/`diag`/`cell`/`version` 均为 `cfg(target_os = "windows")`（PEB、ntdll gadget、`NtAllocateVirtualMemory`）。独立 crate，nightly + Windows，**不是跨平台 HAL**。[NATIONAL_TIER_MASTER_DESIGN](NATIONAL_TIER_MASTER_DESIGN.md) §C2 的「平台无关 implant-core」未落地。 |
| `crates/implant-win` | 唯一作战 implant（PIC DLL）。 |
| `nyx-protocol` | 共享 wire：X25519 + HKDF-SHA256 + ChaCha20-Poly1305；`Command`/`Response`/`SessionInfo`。server / agent-dev / PIC 共用。 |

不移植：HWBP、VAD、FLS、module stomp、BOF/COFF（`implant-evasion` / `implant-tasks` / `bof-runner` / `coff` / `bof-host`）。这些绑定 Windows 调试寄存器、VAD、PEB FLS、COFF ABI。

---

## 2. 复用（不另起协议栈）

- **协议**：`encode_frame_dir` / `open_frame_dir` / `Task::decode_vec`；check-in 后 counter 仅在 POST 成功后前进（agent-dev P0-3）。
- **任务队列**：`POST /api/task` → `sessions.pending`，超 `MAX_PENDING_PER_SESSION` 返回 503（`server/src/lib.rs`）。回复帧打包待执行任务，mid-flush 必须消费 reply（agent-dev BUG-1）。
- **profile**：`NYX_PROFILE` 可选；`padding_min/max` 自定界、`padding_max==0` 时 wire 与旧 profile 逐字节一致；`timing_baseline=bursty` 对齐 agent-dev `bursty_sleep` / `implant-net::bursty_delay`（`BURST_LEN=4`）。
- **DoH**：`nyx-transport::DohDnsTransport` + server `dns_responder.rs`；agent-dev `NYX_CHANNEL=doh`。
- **生成**：`POST /api/generate-implant` 对模板 `.nyx_cfg` 占位（`0x41414141`+`0xAA`）原地补丁加密配置（`implant_gen.rs`）。Linux 模板复用同一补丁契约（ELF note/section），不是每次 server 上 `cargo build`。第一增量可先用环境变量（`NYX_SERVER`/`NYX_SERVER_PUB`）把循环跑通，再接线 ELF 补丁。

---

## 3. Platform trait 草图（本 PR 不实现）

后续 crate：`crates/implant-linux`（**本文件不建 crate**）。不把现有 `implant-core` 改成 HAL。

```text
trait Platform {
    fn alloc(&mut self, n: usize) -> Result<*mut u8, PlatErr>;
    fn sleep(&self, d: Duration);
    fn now(&self) -> u64;                 // 单调时钟，供 jitter / kill-date
    fn spawn(&self, argv: &[&str]) -> Result<Output, PlatErr>;
    fn file_read(&self, path: &str) -> Result<Vec<u8>, PlatErr>;
    fn file_write(&self, path: &str, data: &[u8]) -> Result<(), PlatErr>;
    fn send(&mut self, frame: &[u8]) -> Result<Vec<u8>, PlatErr>;  // HTTPS 或 DoH
}
```

第一增量：`std` 实现（`std::alloc` / `thread::sleep` / `Instant` / `Command` / `fs` / ureq 或 `DohDnsTransport`）。`no_std` ELF PIC、syscall 表、vDSO SSN 不在本增量。

---

## 4. 第一增量（本机可交付）

**产物**：`x86_64-unknown-linux-gnu` 静态 bin 或 `cdylib` `.so`（`std`，stable workspace）。入口：bin=`main`，so=`constructor`/显式导出。不是 day-one PIC。

**循环**：从 `agent-dev::run` 克隆，不从 `implant-win` beacon 抄 Windows 睡眠混淆：

1. `ImplantKeypair::generate` → ECDH(`NYX_SERVER_PUB`)；低阶点退出（agent-dev `0xB1`）。
2. 封装 `SessionInfo` check-in；失败 sleep 重试。
3. `sleep ± jitter`，profile 为 bursty 时套 `bursty_sleep`。
4. 上报 pending → 解密任务 → `execute` → 超 `MAX_CT_LEN` 分帧；`Exit` 尽力 flush。

**任务面（Linux 真做）**：`Ping` / `Sleep`（真正改间隔；agent-dev 目前忽略）/ `Shell`（`/bin/sh -c`，无 shell 拼接）/ `Upload` `Download` `FileOp`（操作员路径，`std::fs`；EACCES/ENOENT → `Response::Err`）/ `Env` / `Portscan`（`TcpStream::connect_timeout`，不依赖 `nc`）/ `GetUid`（`geteuid` + `pwd`，不 `whoami`）/ `Exit`。

**显式收集（非 check-in 附带）**：独立命令读 `/etc/shadow` 与 `~/.ssh/`（私钥、`authorized_keys`、`known_hosts`）。不得复用 `Hashdump method=3`（协议注释：macOS dslocal）。权限不足、非文件、路径逃逸 → `Response::Err`。**fail-closed**：不 `sudo`、不 setuid、不提 `CAP_DAC_OVERRIDE`、不因 EACCES 改读 `/etc/passwd` 充数。

**Windows / PIC 命令**：`StealToken` `MakeToken` `Rev2Self` `Inject` `Trex` `SetChannel` `Bof` `Keylog` 等保持 `Response::Err("linux implant: … Windows primitive")`。

**后一切片（仍非 P16 全量）**：systemd user unit（`~/.config/systemd/user/`）。crontab / `authorized_keys` / `.bashrc` 后门不在第一增量。

---

## 5. 明确不做（第一增量）

| 项 | 原因 |
|---|---|
| `ptrace` / `process_vm_writev` / `memfd_create` 注入 | ROADMAP P16c；本机沙箱与生产 Linux 注入面不同 |
| 对云沙箱宿主机的容器逃逸 | P16g；会打到共享宿主 |
| eBPF hide / 内核模块 | 无 Linux 内核对抗栈；Windows BYOVD 不平移 |
| `no_std` PIC、LD_PRELOAD 劫持、keyring/KWallet | 依赖 HAL / 持久化切片，本增量之后 |
| 把 `implant-core` 去 Windows 门改成 trait | 会破坏 PIC DAG（`core ← evasion ← net ← tasks ← win`） |

---

## 6. 测试计划（`implant-linux` 存在之前）

本 Debian x86_64 盒、loopback，不交叉编译 Windows。

1. `cargo test -p nyx-protocol -p nyx-profile -p nyx-transport -p nyx-server -p nyx-agent-dev`（workspace 稳定工具链）。
2. loopback：`nyx-server`（`127.0.0.1:8443`）+ `nyx-agent-dev`（`NYX_SERVER`/`NYX_SERVER_PUB`）。断言 check-in → `Shell`/`FileOp`/`Env`/`Portscan` → `Exit`。可选 `NYX_PROFILE=profiles/stealth.profile`（padding + bursty）与 `NYX_CHANNEL=doh`（需 `NYX_DOH_DOMAIN`）。
3. 第一增量落地后：同套 loopback 换 Linux bin/so；另测非 root 下 `/etc/shadow` 为 `Err`、可读临时 `~/.ssh` 夹具为 `Output`。不测 ptrace/逃逸/eBPF。

验收：加密循环 + §4 任务面在本机绿。不是 P16 验收（PIC + systemd + Docker 逃逸）。
