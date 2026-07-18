# Nyx → 国家级 / 军用级 C2 平台 — 总设计

> **本文档性质：** 拓展总设计（master design），定义 Nyx 从当前"商业级单平台高级威胁模拟器"演化为"国家级 / 军用级全栈行动平台"的目标架构、工程拆分、阶段路线与验收准则。
> **优先级口径：** 设计文档，非现状事实源。当前代码现状一律以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) 为准（STATUS.md 次之，冲突时以 AUTHORITATIVE_FACTS 为准）；本文只描述**目标态**与**演进路径**。
> **起草日期：** 2026-07-05 · **目标 horizon：** 18–24 个月（4 阶段） · **授权边界：** 仅限授权红队 / 国家授权安全研究 / 合法防御演练。
>
> ⚠️ **现实口径：** 国家级 APT 平台（NSO Pegasus / Equation Group / APT29 级）的核心资产**不是代码**，而是 0day 储备 + 投递链 + 域名基础设施 + 持续运营。本设计**只覆盖代码与工程层面可达的能力**；0day 研发、移动端 0click chain、固件级 implant 等需独立研发预算与硬件资源的部分，列为**外部依赖**而非本工程交付物（见 §7）。

---

## 0. 设计目标与术语对齐

### 0.1 "国家级 / 军用级"的可验证定义

本文档将"国家级"拆解为**六项可独立验收的工程能力**，而非一个模糊形容词：

| # | 能力维度 | 国家级基线（可验收口径） |
|---|---|---|
| **C1** | **流量生存性** | 单一 IOC（域名/证书/IP/JA3）泄露后，全网 implant 72 小时内不哑火；至少 3 条异构回流通道同时在线 |
| **C2** | **平台广度** | Windows + Linux + macOS 三平台 production-grade implant；移动端 / 网络设备列为外部依赖 |
| **C3** | **投递与利用链** | stageless + 多阶段 loader 框架；至少 1 条端到端 LPE + 1 条凭据提权链（无需 0day，用 N-day 公开漏洞即可） |
| **C4** | **OPSEC / 反取证** | 任意任务执行后，目标 IR 团队用 Volatility / KAPE / autopsyyy 标准流程取证，关键痕迹（USN/MFT/Prefetch/EventLog/内存字符串）按策略可清 |
| **C5** | **横向移动** | 在标准 AD 域环境（林级别）中，从普通域用户走到 Enterprise Admin，可用 Kerberos 全家族 + DCSync + RBCD 自动化 |
| **C6** | **C2 韧性与可协同** | team server 联邦（多节点 session 迁移）、操作员协同锁、目标资产拓扑追踪、air-gap 跨网段双向 pivot |

### 0.2 当前基线（事实，引用 AUTHORITATIVE_FACTS_2026-07-18）

> ⚠️ 数字以 [`docs/audits/AUTHORITATIVE_FACTS_2026-07-18.md`](../audits/AUTHORITATIVE_FACTS_2026-07-18.md) §0/§1 为准。下方为 2026-07-05 起草时的快照 + 审计修正。

- 总 Rust LOC **68,751**（AUTHORITATIVE_FACTS §0 实测）；workspace 18 成员 + 6 独立 crate
- Windows 单平台 implant，~286 KB strip，`no_std` PIC DLL；wire `Command` 变体 **28**（`protocol/src/msg.rs:130`）
- 用户态规避：算法层完整但 **睡眠混淆未接线**（`implant-win/src/kits.rs:65-71` 短路，Fluctuation/Foliage/mem::mask 全死路径，AUTHORITATIVE_FACTS §1/§2）。"98% 完成度"自评不再适用。
- 内核 tier 100% 算法 + 7/7 真机（operator-kernelsdk 🟡：9/10 kit 算法真，WfpKit 永返 Err，WdtKernel stub，PatchGuard 偏移未验证）
- 加密协议：X25519 + HKDF + ChaCha20-Poly1305，方向隔离 nonce，反重放计数器（`crates/protocol/src/crypto.rs`），40 测试
- 流量层：implant 实际回连单一 HTTPS（axum + rustls）；`transport/` crate 共 **3,420 LOC**（非 816），含 **6 个 Transport impl（Malleable/DoH/Slack/LLM/MCP/SMB）全部零消费者**；TLS emitter 是 Err stub（AUTHORITATIVE_FACTS §0/§1）
- 横向：4 个 token 原语（`postex.rs`），无 Kerberos / AD 攻击
- 投递链：nyx-loader 加密+组装真，但反射加载仅 std 参考实现（on-target 反射为空，AUTHORITATIVE_FACTS §1 nyx-loader 🔴）；真机测试靠手动 `schtasks`
- 反取证：0 行代码

### 0.3 能力差距矩阵（C1–C6 × 当前 vs 目标）

| 维度 | 当前 | 国家级目标 | 工程差距 |
|---|---|---|---|
| C1 流量 | 1 通道（HTTPS） | ≥3 异构 + 域前置 + 合法服务外溢 + DGA | ~5× 重写 |
| C2 平台 | Windows | Win + Linux + macOS | 2× 重写（每平台） |
| C3 投递 | 0 | stager 框架 + N-day LPE 链 | 全新 |
| C4 OPSEC | 0 | 全栈痕迹清理 + 内存 only 路径 | 全新 |
| C5 横向 | 4 原语 | Kerberos 全家族 + AD 攻击套件 | ~10× 扩展 |
| C6 韧性 | 单 server + 哈希链审计 | 多节点联邦 + 协同锁 + 双向 pivot | ~3× 扩展 |

---

## 1. 六大支柱设计

### C1. 流量生存性（Traffic Resilience）

**现状根因**：`crates/transport` 共 **3,420 LOC**（AUTHORITATIVE_FACTS §1，非旧文 594 行），含 6 个 Transport impl（Malleable/DoH/Slack/LLM/MCP/SMB）**全部零消费者**；`tls.rs`/`h2.rs` 实现 JA3/JA4 嗅探，但 `emitter.rs`（`build_impersonating_client`）是 **Err stub**——emission 未接线。`crates/implant-win/src/transport.rs` 仅 HTTPS。一旦域名被 EDR 上传 → VirusTotal → sinkhole，全网 implant 哑火。

**目标架构**：将"传输"抽象为**多通道并发复合层**（multiplexed channel mesh），每条 implant 同时维护 ≥3 条异构通道，任一可用即存活。

```
crates/
├── transport/                    # 保留：TLS 指纹嗅探（JA3/JA4）
├── channel-mesh/                 # 新：通道复合层 + 调度策略
│   └── src/
│       ├── lib.rs                # Channel trait + Mesh 编排
│       ├── policy.rs             # 选路策略（latency/stealth/health）
│       └── jitter.rs             # 行为拟合（基于真实用户样本）
├── channel-https/                # 现 implant transport 抽出
├── channel-dns/                  # 新：DNS 隧道 + DoH/DoT 外溢
├── channel-icmp/                 # 新：ICMP 隧道（ping payload）
├── channel-legit/                # 新：合法服务外溢（Telegram/GitHub/Slack/Dropbox API）
├── channel-domainfront/          # 新：域前置（CloudFront/Azure AMP/Fastly）
├── channel-p2p/                  # 新：P2P mesh（implant↔implant，已有 pivot 雏形扩展）
└── infra-dga/                    # 新：DGA + 域名生命周期 + sinkhole 抗性
```

**Channel trait 契约**（所有通道实现统一接口，implant 不感知底层）：
```rust
pub trait Channel: Send + Sync {
    fn send(&self, payload: &[u8]) -> Result<(), ChannelError>;
    fn recv(&self, timeout: Duration) -> Result<Vec<u8>, ChannelError>;
    fn health(&self) -> Health;        // Green/Yellow/Red
    fn stealth_score(&self) -> u8;     // 0=显眼 100=隐蔽，调度策略用
    fn fingerprint_resistance(&self) -> u8; // 抗 JA3/JA4/HTTP 指纹
}
```

**验收准则（C1）**：
- [ ] implant 同时维护 HTTPS + DNS-over-HTTPS + 域前置三条通道，单通道 sinkhole 后另外两条 30s 内接管
- [ ] JA3/JA4 指纹拟合到真实浏览器分布（chi-square 测试 p>0.05）
- [ ] beacon 时序经 jitter 拟合目标时区工作时段（KL 散度 < 0.2 vs 真实用户样本）
- [ ] DGA 域名池 ≥10000，单日切换 ≤5 个，sinkhole 抗性 ≥30 天

### C2. 跨平台 Implant

**现状**：`crates/implant-win`（PIC DLL，nightly + gnu target）是唯一作战 implant。`crates/agent-dev` 是 macOS std 测试桩，不是作战代码。

**目标**：抽象**平台无关核心 (implant-core)** + 平台特定后端，三平台共用协议层 / 命令分发 / 加密 / 任务循环。

```
crates/
├── implant-core/                 # 新：平台无关核心
│   └── src/
│       ├── lib.rs                # 入口、beacon loop、任务分发
│       ├── cmd.rs                # Command 变体（复用 protocol）
│       ├── crypto.rs             # 复用 nyx-protocol
│       ├── opsec.rs              # 跨平台 OPSEC 接口
│       └── platform.rs           # trait Platform（每平台实现）
├── implant-win/                  # 现有，重构为 Platform impl + Win 后端
├── implant-linux/                # 新：ELF so/executable，ptrace/proc 注入
├── implant-macos/                # 新：Mach-O dylib，task_for_pid/mach VM
└── evasion-kit/                  # 新：跨平台规避原语集合
    └── src/
        ├── linux/                # /proc 解析、seccomp bypass、ebpf hide
        ├── macos/                # amfid bypass、ES bypass、kext hook
        └── shared/               # 通用 sleep mask / anti-debug
```

**Platform trait**：
```rust
pub trait Platform {
    type Process;
    fn list_procs(&self) -> Vec<Self::Process>;
    fn inject(&self, target: &Self::Process, shellcode: &[u8]) -> Result<(), InjectError>;
    fn fs_read(&self, path: &str) -> Result<Vec<u8>, FsError>;
    // ... 全部 fs/exec/cred/net 原语
    fn opsec_floor(&self) -> OpSec;   // 该平台最小 OPSEC 配置
}
```

**验收准则（C2）**：
- [ ] Linux implant 在 Ubuntu 22.04 / RHEL 9 / Debian 12 上 production 运行，覆盖 systemd 服务 + cron 持久化
- [ ] macOS implant 在 macOS 13/14（Intel + Apple Silicon）上 production 运行，绕过 Gatekeeper + Notarization 检查（合法签名假设下）
- [ ] 三平台共用一份 `implant-core`，命令分发零平台分支代码（trait dispatch）
- [ ] 三平台均通过 EDR 盲化基线测试（Linux: auditd/eBPF hide; macOS: ES/Sysmon hide）

### C3. 投递与利用链（Delivery & Exploitation）

**现状**：零投递框架，零 exploit 代码。BYOVD 用 CVE-2019-16098（7 年公开）。

**目标**：分离**stager / loader / impl**三层，每层独立加密 + 反沙箱 + 反内存扫描。建立 N-day 利用链**框架**（不含 0day）。

```
crates/
├── stager/                       # 新：4KB 触发器，第二阶段按需拉取
│   └── src/
│       ├── shellcode/            # 平台原生 shellcode 模板
│       ├── anti_sandbox/         # 沙箱检测 + 自毁策略
│       └── fetch/                # 二阶段拉取（多通道回退）
├── loader/                       # 新：多阶段加载器
│   └── src/
│       ├── stages/               # 每阶段独立加密层
│       ├── reflective/           # 反射加载（已有 sRDI 工具为基础）
│       ├── early_bird/           # EarlyBird APC 注入
│       ├── module_stomp/         # 现有，移入
│       └── threadless/           # 现有，移入
├── exploit-framework/            # 新：N-day 利用框架（不含 0day）
│   └── src/
│       ├── lpe/                  # Win LPE 链（CVE-2021-1675 PrintNightmare / CVE-2023-36664 等）
│       ├── cred/                 # 凭据提权链
│       ├── chain/                # 多漏洞组合编排
│       └── payloads/             # 通用 payload 适配（→ stager）
└── payload-crypter/              # 新：payload 多态 / metamorphic 加密
```

**验收准则（C3）**：
- [ ] stager ≤8KB，stageless 模式下二阶段加密拉取，沙箱环境自动销毁
- [ ] 至少 1 条端到端 N-day LPE 链（如 PrintNightmare → SYSTEM），从普通用户到 SYSTEM 全自动
- [ ] payload 多态：同一 implant，每次构建产生不同字节序列（hash 不固定），VirusTotal 静态签名不可命中
- [ ] 反沙箱：在 Cuckoo / AnyRun / Joe Sandbox 默认配置下不触发真实行为分支

### C4. OPSEC / 反取证（Anti-Forensics）

**现状**：零反取证代码（`grep -ri "timestomp\|usn\|mft\|prefetch\|eventlog" crates/` → 零匹配）。

**目标**：全栈痕迹管理，按任务策略清理，并支持内存 only 路径（fileless 模式）。

```
crates/
├── anti-forensics/               # 新：痕迹清理套件
│   └── src/
│       ├── windows/
│       │   ├── timestomp.rs      # MFT $STANDARD_INFORMATION 时戳伪造
│       │   ├── usn.rs            # USN journal 删除（按 record ID 精确清除）
│       │   ├── prefetch.rs       # Prefetch 删除 / 替换
│       │   ├── eventlog.rs       # EventLog 按事件 ID 精确清除（不全清）
│       │   ├── shimcache.rs      # ShimCache / AmCache 清理
│       │   └── lnk_jumplist.rs   # LNK / JumpList 清理
│       ├── linux/                # utmp/wtmp/btmp/history/auditd 清理
│       ├── macos/                # unified log 选择性清理
│       └── policy.rs             # 策略：execution_only / full_clean / memory_only
├── memory-only/                  # 新：fileless 驻留路径
│   └── src/
│       ├── hollow.rs             # 进程空洞化（合法进程内存中驻留）
│       ├── lsass_inject.rs       # LSASS 空洞驻留
│       └── registry_transacted/  # Win10+ 事务注册表（不落盘）
└── anti-analysis/                # 新：检测取证工具自毁
    └── src/
        ├── detect.rs             # Volatility/KAPE/autopsy/F-Response 探测
        └── killswitch.rs         # 触发自毁
```

**验收准则（C4）**：
- [ ] `policy::FullClean` 执行后，KAPE 标准采集包中：USN/MFT/Prefetch/EventLog 相关条目可清（按策略）
- [ ] 内存 only 模式：implant 完全驻留 explorer.exe / lsass.exe 空洞，磁盘零落地文件
- [ ] 检测 Volatility / KAPE 进程启动 → 立即清关键内存 + 退出
- [ ] 时间戳伪造：MFT $STANDARD_INFORMATION 与 $FILE_NAME 一致性通过 forensic 工具校验

### C5. 横向移动与凭据操作（Lateral Movement）

**现状**：`postex.rs` 仅 4 个 token 原语。`grep -ri "kerberos\|dcsync\|golden\|s4u\|psexec\|wmi\|dcom" crates/` → 零匹配。

**目标**：Mimikatz + Impacket 级 AD 攻击套件，原生 Rust 实现（无外部依赖，避免 Mimikatz 签名）。

```
crates/
├── cred-kit/                     # 新：凭据提取套件
│   └── src/
│       ├── lsass.rs              # LSASS dump（mini/full/custom）+ 离线解析
│       ├── ntds.rs               # NTDS.dit 提取 + 解析
│       ├── dcsync.rs             # DCSync（DRSGetNCChanges）
│       ├── browsers.rs           # Chrome/Edge/Firefox 密码 + cookie
│       ├── rdp.rs                # RDP saved cred + Terminal Services
│       ├── wifi.rs               # WLAN profile 提取
│       ├── vault.rs              # Windows Vault / Credential Manager
│       └── password_mgr.rs       # 1Password/Bitwarden/Dashlane 内存抓取
├── kerberos-kit/                 # 新：Kerberos 攻击全家族
│   └── src/
│       ├── asn1.rs               # Kerberos ASN.1 编解码
│       ├── as_rep.rs             # AS-REP roasting
│       ├── kerberoast.rs         # Kerberoasting（TGS 离线破解）
│       ├── golden.rs             # Golden ticket（krbtgt hash）
│       ├── silver.rs             # Silver ticket（服务 hash）
│       ├── diamond.rs            # Diamond ticket（TGT 修饰）
│       ├── s4u.rs                # S4U2Self + S4U2Proxy（RBCD 滥用）
│       ├── unconstrained.rs      # 非约束委派滥用
│       └── pass_the_ticket.rs    # 票据传递
├── lateral-kit/                  # 新：横向移动协议套件
│   └── src/
│       ├── wmi.rs                # WMI exec（DCOM）
│       ├── dcom.rs               # MMC20 / ShellWindows / ShellBrowserWindow
│       ├── psexec.rs             # PsExec 风格（SVCCTL RPC）
│       ├── winrm.rs              # WinRM / PSRP
│       ├── smb_pipe.rs           # SMB named pipe impersonation
│       ├── pass_the_hash.rs      # NTLM hash 横向
│       └── ssh_agent/            # Linux SSH agent 劫持
├── ad-recon/                     # 新：AD 侦察
│   └── src/
│       ├── bloodhound.rs         # BloodHound 路径发现（图算法）
│       ├── acl_abuse.rs          # ACL 滥用链
│       ├── adminsdholder.rs      # AdminSDHolder
│       ├── gpo.rs                # GPO 滥用
│       └── trusted_domains.rs    # 林信任链
└── postex/                       # 现有，保留 token 原语
```

**验收准则（C5）**：
- [ ] 在标准 lab 域环境（goad / VulnerableAD / HackTheBox Forest），从普通域用户到 Enterprise Admin 全自动
- [ ] LSASS dump 真机：Defender ON 下 dump + 离线解析出 NTLM hash（绕过 LSASS PPL 假设 BYOVD 已加载）
- [ ] DCSync 在域控抓取 krbtgt hash，可铸造 Golden ticket 通过 PAC 验证
- [ ] Kerberoasting 提取 TGS，离线破解（hashcat 兼容格式）
- [ ] RBCD 滥用：从普通用户写 msDS-AllowedToActOnBehalfOfOtherIdentity → S4U 链 → 任意用户 impersonation

### C6. C2 韧性与协同（Server Federation）

**现状**：单 server，已有命名 operator + 哈希链审计（`crates/server/src/{operators,audit}.rs`）。

**目标**：分布式 team server 联邦，session 跨节点迁移，多 operator 协同锁。

```
crates/
├── server/                       # 现有，重构为联邦节点
│   └── src/
│       ├── federation/           # 新：节点间 Raft 一致性
│       ├── session_router.rs     # session → 节点路由（迁移 + failover）
│       └──协同锁/                # operator 操作互斥锁
├── team-server-cluster/          # 新：集群管理 CLI
├── topology-tracker/             # 新：目标资产拓扑追踪
│   └── src/
│       ├── graph.rs              # 资产关系图（主机/域/凭据/横向路径）
│       └── history.rs            # 资产变化时间线
└── pivot-mesh/                   # 现有 pivot.rs 扩展为双向 mesh
    └── src/
        ├── forward/              # 正向 SOCKS5（已有）
        ├── reverse/              # 反向 relay（已有）
        ├── airgap/               # 新：air-gap 跨网段（SMB pipe / Kerberos 委派穿越）
        └── protocol/             # 统一 mesh 协议
```

**验收准则（C6）**：
- [ ] 3 节点 team server 联邦，单节点 kill 后 implant 自动重连到健康节点，零 session 丢失
- [ ] 协同锁：两个 operator 同时操作同一目标，第二个被阻塞并提示（防抢操作）
- [ ] air-gap pivot：跨双网卡隔离网段，session 从内网段经 SMB pipe relay 到外网段
- [ ] 拓扑追踪：目标域资产变化（新主机/新凭据/新会话）实时反映在 GUI 拓扑视图

---

## 2. 工作量与人力估算

| 模块 | 估算人年 (PY) | 关键技能 | 外部依赖 |
|---|---|---|---|
| C1 流量生存性 | 4–5 | 网络协议、流量分析、域名运营 | 域名池预算、CDN 账号 |
| C2 跨平台（Linux + macOS） | 5–7 | 内核、Mach/ptrace、Rust no_std | macOS 硬件、签名证书 |
| C3 投递与利用链 | 3–4 | 漏洞研究、shellcode、加密 | N-day 公开漏洞（免费） |
| C4 反取证 | 2–3 | 取证工具链、文件系统 | 取证测试环境 |
| C5 横向移动 | 4–5 | AD、Kerberos、Windows RPC | lab 域环境 |
| C6 服务器联邦 | 3–4 | 分布式系统、Raft | 多节点测试环境 |
| **代码合计** | **21–28 PY** | | |
| 文档 / 测试 / 集成 | 4–6 PY | | |
| **总工程量** | **25–34 PY** | | |

**对照参考：**
- Cobalt Strike 4.x：~12 年迭代，估计累计 60–80 PY
- Sliver（开源）：~4 年，估计累计 15–20 PY（仅客户端 + Linux/Mac，无内核层）
- Brute Ratel C4：~3 年商业产品，估计 30–40 PY（窄而深）

**Nyx 当前累计估算**：~12–15 PY（基于 63k LOC + 真机验证深度）。意味着**到目标态需再投入 1.5–2× 当前工程量**。

---

## 3. 阶段化路线图

每阶段**必须可独立验收**，不依赖后续阶段。每阶段产出可作战的能力增量。

### M9 — 流量生存性 V1（C1 子集）· 目标 6 个月

**交付：** HTTPS + DNS-over-HTTPS 双通道 + jitter 拟合 + 域名池轮换。

| 子任务 | 验收 |
|---|---|
| `channel-mesh` crate + Channel trait | 单元测试 + 模拟单通道失效 failover |
| `channel-dns`（DoH 上行）| 真机 DNS 通道传输 1KB 数据往返 |
| `infra-dga` 域名池 + 轮换 | sinkhole 1 域名后 30s 切换到备份 |
| jitter 行为拟合（基于真实浏览器样本） | KL 散度 < 0.3 |

**依赖：** 域名池（≥50 域名预算）、DoH 公共解析器列表。

### M10 — 横向移动 V1（C5 子集）· 目标 5 个月

**交付：** LSASS dump + Kerberoasting + Pass-the-Hash + WMI/DCOM 横向。

| 子任务 | 验收 |
|---|---|
| `cred-kit::lsass`（含 PPL bypass 假设 BYOVD） | Defender ON 下 dump 出 NTLM |
| `kerberos-kit::{asn1, kerberoast}` | TGS 提取 + hashcat 格式离线破解 |
| `lateral-kit::{wmi, dcom, pass_the_hash}` | Win2019 域控上 SYSTEM shell 横向 |
| `ad-recon::bloodhound` 路径发现 | goad lab 自动出 DA 路径 |

**依赖：** goad / VulnerableAD lab 环境。

### M11 — 反取证 V1（C4 子集）· 目标 3 个月

**交付：** Windows 全栈痕迹清理 + 内存 only 路径。

| 子任务 | 验收 |
|---|---|
| `anti-forensics::windows::{timestomp,usn,prefetch,eventlog}` | KAPE 采集包对照清理前后 |
| `memory-only::hollow`（explorer.exe 空洞） | 磁盘零落地文件 |
| `anti-analysis::detect`（Volatility/KAPE 检测自毁） | 检测后 1s 内清关键内存退出 |

**依赖：** Volatility / KAPE / F-Response 测试套件。

### M12 — 跨平台 V1（C2 子集）· 目标 7 个月

**交付：** Linux production implant + implant-core 重构。

| 子任务 | 验收 |
|---|---|
| `implant-core` trait 抽象（Win 后端实现 trait） | Win implant 行为零回归 |
| `implant-linux`（ELF + systemd 持久化） | Ubuntu 22.04 / RHEL 9 production check-in |
| `evasion-kit::linux`（auditd/eBPF hide） | auditd 日志中无 implant 痕迹 |

**依赖：** Linux 测试机（多发行版）。

### M13 — 投递与利用链 V1（C3 子集）· 目标 4 个月

**交付：** stager 框架 + 1 条 N-day LPE 链。

| 子任务 | 验收 |
|---|---|
| `stager` ≤8KB + 沙箱自毁 | Cuckoo 默认配置下不触发真实分支 |
| `loader` 多阶段加密 | 每阶段独立解密，最终才出 implant |
| `exploit-framework::lpe`（PrintNightmare 或同级 N-day） | 普通用户 → SYSTEM 全自动 |
| `payload-crypter` 多态 | 同一 implant 三次构建 hash 不同 |

**依赖：** Cuckoo / AnyRun 沙箱测试。

### M14 — 服务器联邦 V1（C6 子集）· 目标 5 个月

**交付：** 3 节点联邦 + session 迁移 + 协同锁。

| 子任务 | 验收 |
|---|---|
| `server::federation` Raft 一致性 | 3 节点 quorum，1 节点 kill 零 session 丢失 |
| `session_router` failover | implant 自动重连到健康节点 |
| 协同锁 | 两 operator 抢同一目标，第二个阻塞 |

**依赖：** 多节点测试集群。

### M15 — macOS implant + 集成（C2 完整）· 目标 6 个月

**交付：** macOS production implant + 全支柱集成测试。

| 子任务 | 验收 |
|---|---|
| `implant-macos`（Mach-O dylib） | macOS 14 Intel + Apple Silicon check-in |
| `evasion-kit::macos`（amfid/ES bypass） | Endpoint Security 框架盲化 |
| 全支柱端到端集成 | lab 环境完整 kill chain 演练 |

**依赖：** macOS 硬件、Apple Developer 签名证书。

**累计 horizon：** M9 (6) + M10 (5) + M11 (3) + M12 (7) + M13 (4) + M14 (5) + M15 (6) ≈ **18–24 个月**（重叠并行）。

---

## 4. workspace 拓展蓝图

按阶段增量加入 `Cargo.toml [workspace].members`，每阶段保持 `cargo build --workspace` 绿。

**M9 后：**
```toml
members = [
    # ...existing 18 crates...
    "crates/channel-mesh",
    "crates/channel-https",
    "crates/channel-dns",
    "crates/infra-dga",
]
```

**M10 后：** 追加 `cred-kit / kerberos-kit / lateral-kit / ad-recon`。
**M11 后：** 追加 `anti-forensics / memory-only / anti-analysis`。
**M12 后：** 追加 `implant-core / implant-linux / evasion-kit`（implant-win 重构为 member）。
**M13 后：** 追加 `stager / loader / exploit-framework / payload-crypter`。
**M14 后：** 追加 `team-server-cluster / topology-tracker / pivot-mesh`。
**M15 后：** 追加 `implant-macos`。

每个新 crate 落地必须满足：
1. `cargo build -p <crate>` 绿
2. `cargo test -p <crate>` ≥ 10 测试
3. `cargo clippy -p <crate> -- -D warnings` 零警告
4. crate-level rustdoc 解释设计意图与 OPSEC 含义

---

## 5. 安全工程纪律（强制）

承接现有项目纪律（见 `STATUS.md` §0：哈希链审计、命名 operator、fuzz 1050 万输入、CI 全平台）：

1. **加密协议不可静默降级**：所有新通道必须用现有 `protocol::seal_dir` AEAD，禁止明文控制路径（哪怕是 ICMP 隧道，外层掩护，内层仍 AEAD）。
2. **零信任 operator**：每条任务下发必须可审计（哈希链不可破坏），federation 节点间通信双向 mTLS。
3. **OPSEC 默认 ON**：新 crate 的 OPSEC 相关 gate 默认 ARMED（参考 `STATUS.md` §3 的"默认 ON"原则），降级需显式编译期 cfg。
4. **fuzz 覆盖**：每个新协议解析点（Kerberos ASN.1 / SMB / RPC）必须配 cargo-fuzz harness，目标 ≥ 1000 万输入 0 panic。
5. **真机验证**：每个里程碑必须真机闭环验证（参考 §5d beacon loop 真机范式），不接受仅单元测试通过。
6. **不可归因工程**：编译器指纹抹除（custom panic handler / 移除 std panic 字符串）、payload 多态、运营资产与开发环境隔离。

---

## 6. 与现有事实源的关系

- **AUTHORITATIVE_FACTS_2026-07-18.md**：**当前代码事实的权威源**（描述"现在是什么"，数字优先级最高）
- **STATUS.md**：历史事实源（可能滞后，冲突时以 AUTHORITATIVE_FACTS 为准）
- **本文档**：目标架构与路线（描述"未来要成为什么"）
- 冲突时：AUTHORITATIVE_FACTS 描述现状胜出；本文档仅描述目标态。
- 每个里程碑完成后：在 STATUS.md / AUTHORITATIVE_FACTS 增量记录真机验证结果，本文档相应阶段标记 ✅ DONE。

---

## 7. 非目标与外部依赖（边界）

明确**本工程不交付**的部分（需独立预算 / 资产）：

### 7.1 0day 研发
本工程的 exploit-framework **只用 N-day 公开漏洞**。私藏 0day 储备是独立研发预算，单 0day 黑市价 $1–3M，不在本工程范围。

### 7.2 移动端 0click chain
iOS 0click（Pegasus 级）/ Android 0permission 驻留需独立移动安全研发团队，6–10 PY × 2 平台。本工程 M15 只交付 macOS implant（合法签名假设下），不交付 iOS。

### 7.3 网络设备 / 固件 implant
Cisco IOS XR / Juniper Junos / UEFI / BMC 植入不在本工程范围。需厂商 SDK / 硬件访问 / 固件逆向能力。

### 7.4 OT / SCADA / 工控
PLC 植入（Stuxnet 级）明确排除。这是物理破坏能力，超出红队 / 防御演练范围。

### 7.5 域名 / CDN / 基础设施运营
本工程交付**域名池管理代码**，但实际域名注册 / 预热 / 轮换 / CDN 账号是**运营预算**，不在代码交付物内。预估运营成本：域名池 ≥$5k/年、CDN ≥$10k/年、sinkhole 抗性测试 ≥$20k/年。

### 7.6 法律 / 合规授权
全部能力**仅限授权红队 / 国家授权安全研究**。任何国家级使用必须符合适用法律（中国《网络安全法》、相关授权框架）。本工程不提供任何形式的"未经授权使用"指导。

---

## 8. 验收准则总览（"达到国家级"的判定）

完成 M9–M15 全部里程碑，且：

- [ ] **C1 流量生存性**：3 异构通道在线，单通道 sinkhole 72h 不哑火
- [ ] **C2 平台广度**：Win + Linux + macOS 三平台 production implant
- [ ] **C3 投递**：stager + N-day LPE 链 + payload 多态
- [ ] **C4 OPSEC**：全栈痕迹清理 + 内存 only 路径 + 取证工具自毁
- [ ] **C5 横向**：标准 lab 域普通用户 → Enterprise Admin 全自动
- [ ] **C6 韧性**：3 节点联邦 + session 迁移 + 协同锁
- [ ] **工程纪律**：所有新 crate 通过 build / test / clippy / fuzz / 真机验证
- [ ] **审计**：哈希链不可破坏，operator 全任务可追溯

达到以上全部 → **达到"商业级高级威胁模拟器（ Tier-1 商业 C2 级）"水平**。

要达到"NSO / Equation Group 级国家级"，仍需：
- 移动端 0click chain（独立团队 + 0day）
- 网络设备 / 固件 implant（独立硬件能力）
- 0day 储备库（独立研发预算）
- 国家级域名 / CDN / sinkhole 抗性运营基础设施

这些超出本工程代码交付边界（见 §7）。

---

## 9. 立即可启动的下一步

按 ROI 排序（投入产出比，不按编号）：

1. **M10 横向移动 V1**（5 个月）— 当前最大作战短板，AD 环境裸奔。先做 `cred-kit::lsass` + `kerberos-kit::kerberoast` + `lateral-kit::wmi`。
2. **M9 流量生存性 V1**（6 个月）— 当前最大生存性短板，单点域名 sinkhole 即死。先做 `channel-mesh` + `channel-dns`。
3. **M11 反取证 V1**（3 个月）— 投入小见效快，2–3 PY 即可补齐基础痕迹清理。

建议**并行启动 M9 + M10**（不同团队 / 不同 agent），M11 串行在 M10 后（共享 Windows 真机环境）。

---

**文档维护：** 每个里程碑完成 → 更新本文档对应阶段状态 ✅ + STATUS.md 增量真机验证段。架构调整 → 直接修订本文档（不另起归档副本）。
