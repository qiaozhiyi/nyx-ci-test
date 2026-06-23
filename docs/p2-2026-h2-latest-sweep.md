# P2 — 2026 H2 最新情报扫描（Exa 网格化检索，2026-06-23）

> 19 组并行 Exa advanced 检索 + 4 个主源精读。**仅记录"对语料（5 个根文件 + `p2-*` + survey memory）的真正增量"**，已去重。授权红队研究。
> 同源续档：`p2-2026-research-addendum.md`、`p2-integration-analysis.md`、根目录 5 份研究文件。

---

## 0. 本轮最重要的认知更新

1. **EDR 中和出现"第三条路"——遥测饥饿（非 kill、非 blind）**：EDRChoker 用 QoS 把 EDR 进程带宽限到 8 bit/s，让 TLS 握手（3–10KB）超时，agent↔server 静默断连，**且 pacer.sys 在 WFP 之下，不留 EDRSilencer 那种 packet-block/drop 痕迹**。
2. **SSDT 作为"数据节"复活了**：在 VBS/HVCI 下 SSDT 不能 inline hook，但**数据节 hijack 仍可达内核执行**（exploitpack 2026-02；jmmicoli "Shadow SSDT Internals"）。被认定"已死"的 SSDT 以 data-only 形式回归。
3. **遥测完整性攻击（不是隐藏事件，是污染观测）**：SunnyDayBPF（eBPF）让事件照常发生、agent 照常读取，但在 syscall 返回后、agent 解析前**改写用户态 buffer** → 下游 SIEM/EDR 收到的数据≠真实事件。这是对"遥测即真相"假设的根本挑战。
4. **云 serverless 已成 C2 默认基础设施，且 SIEM 默认放行 CDN**：AsyncRAT 跑在 Cloudflare Workers（单账号 3 worker × 子域频道 = ~18 端点）+ R2 + IPFS。NDR 对抗的核心结论：**行为建模（beaconing 间隔/周期性）比解密更有效**，所以规避=抖动+合法域前置+低慢。
5. **HVCI 在 data-only 面前不是防御**：HVCIPwned（CVE-2024-35250）+ "Data-Only Gadgets"（UNDERCODE 2026-05）实证——HVCI/kCET/VBS 全部挡不住 data-only gadget 链。坐实语料"内核 tier 只能走数据节"的判断。

---

## A. 全新规避技术（语料未含）

### A1. EDRChoker — QoS 遥测饥饿（★ 全新品类）
- **源：** @TwoSevenOneT，2026-06-07；zerosalarium / lindensec / Securonix 三处报道。
- **机制：** `New-NetQosPolicy -AppPathNameMatchCondition <EDR.exe> -ThrottleRateActionBitsPerSecond 8`。QoS Packet Scheduler（`pacer.sys`）位于网络栈**比 WFP 更底层**（应用→tcpip.sys→**WFP**→…→pacer.sys→NDIS），所以**不触发** EDRSilencer/WFP 留下的 `packet-block`/`packet-drop` 事件（Elastic 有专门规则查 WFP）。
- **效果：** 8 bit/s 让现代 TLS 握手（证书链 3–8KB）必然 2–5s 超时 → agent 持续 timeout、静默断连。**不杀进程、不 block 包、无标准 IOC**。
- **检测面：** Defender 检出编译版 `Trojan:MSIL/EDRChoker.DA!MTB`，但**原生 PowerShell 几行版未检出**（行为检测缺口）。仅本地管理员。Defender 对 `MsMpEng.exe` 有自我保护（不能给它建防火墙规则——但 QoS 策略不受此限，这是关键绕过点）。
- **Nyx 落点：** operator-side 工具（admin），归入"EDR 中和"kit，与 EDRSilencer（WFP）、EDR-Freeze（WerFaultSecure）并列三条路。**比 WFP 路噪声更低**。

### A2. SunnyDayBPF — 遥测完整性欺骗（eBPF，★ 新概念）
- **源：** Azizcan Daştan，2026-05-08；github.com/azqzazq1/SunnyDayBPF + dev.to。
- **机制：** 不隐藏 syscall、不阻止事件。在 `read`-类 syscall **完成后**、监测 agent **解析/转发前**的时间窗，用 eBPF 改写 agent 用户态 buffer → 下游（SIEM/EDR/audit）收到的数据≠真实事件。"ground truth ≠ collected telemetry ≠ observed data"。
- **区别：** 传统规避=隐藏/阻止事件；SunnyDayBPF=**允许事件但污染观测**。对应语料里 Olaf Hartong "I'm in Your Logs Now" 的 ETW **forge** 哲学的 eBPF 实例化。
- **Nyx 落点：** 前沿研究（Linux eBPF 为主，Windows eBPF-for-Windows 同概念适用）。P2.2/P2.3——在 agent 解析窗污染 ETW consumer buffer，比 byte-patch/blind 更高阶。补语料 §6.1 的 eBPF 子vert 方向。

### A3. BYORWXDLL 注入
- **源：** meterpreter.org，2026-06-08。
- **机制：** 不 VirtualAlloc/Protect，而是把代码写进**已加载签名 DLL 内已存在的 RWX 区**（部分老 DLL/运行时残留 RWX 段）→ 零个"可执行私有内存"分配信号，遥测签名最少。
- **Nyx 落点：** ProcessInjectKit（P2.1c）的补充变体——module stomping 之外，先扫"已有 RWX 段"的签名 DLL。

### A4. SSDT 数据节 hijack（VBS/HVCI 下复活）
- **源：** exploitpack "SSDT Hijack Under VBS/HVCI"，2026-02-06；jmmicoli "Shadow SSDT Internals and Syscall Dispatch on Modern Windows"，2026-05。
- **机制：** inline SSDT hook 被 HVCI 杀，但**数据节重定向 SSDT 条目**（指向受信函数的 data-only 改写）可达内核执行/劫持 syscall 派发。
- **Nyx 落点：** P2.2 CallbackKit 的补充内核 vector；坐实"data-only 是 HVCI 下唯一路径"。

### A5. Data-Only Gadgets（绕 HVCI/kCET/VBS 全家）
- **源：** UNDERCODE TESTING，2026-05-13；HVCIPwned（CVE-2024-35250, xvalegendary）。
- **机制：** data-only gadget 链不碰返回地址/间接调用目标 → 同时绕 CET shadow stack + CFG + HVCI。HVCIPwned 实证 HVCI 对 data-only exploit **无防御**。
- **Nyx 落点：** 呼应语料 CFOP（协程帧）+ VIPER（syscall-guard 变量）。内核 tier 的理论基石。

### A6. DXE→Ring0 隐蔽内核手动映射
- **源：** 0rickyy. "From DXE to Ring 0"，2026-05-06。
- **机制：** 从 UEFI DXE（Driver Execution Environment）阶段手动映射驱动到内核，**绕过标准驱动加载路径**与 EDR/XDR 的加载监控。
- **Nyx 落点：** P2.2 内核 bootstrap 的 UEFI 持久化变体（long-term engagement），与 Windows Downdate、kd.exe LotLK、BTR 并列。

### A7. WerWolf — Silent Process Exit 的内存 BOF
- **源：** Kim Dvash，2026-04-13。
- **机制：** 把 Silent Process Exit 从 PS 脚本搬进**内存 BOF**，template-free BOF loader，不落盘；EDR 仍看不见。
- **Nyx 落点：** `bof.rs` 的 tradecraft 参考（Silent Process Exit 触发器 + 内存 BOF）。

### A8. 精度 module stomping / .reloc 段代码
- **toneillcodes 2026-06**：data-driven 多阶段模块选择管线，消除"突然映射陌生库"的高可见度噪声。
- **OXLOADER（Elastic 2026-06-19）**：把代码塞进 `.reloc` 段（合法工具链从不往 .reloc 写代码→静态红旗）。
- **Nyx 落点：** ProcessInjectKit 的 OpSec 细节——避免 .reloc 段，做精度选库。

---

## B. 新内核 CVE / 原语

| CVE / 原语 | 源 / 日期 | 意义 |
|---|---|---|
| **CVE-2026-23670** | SentinelOne 2026-04 | Windows **VBS Enclave 鉴权绕过** → enclave 内未授权执行。直接服务于 Mirage/BYOVE（P2.3）。 |
| **CVE-2026-45607** | SentinelOne 2026-06 | Windows **Hyper-V RCE**（guest→host 逃逸）。坐实 M-Trends "hypervisor 攻击上升"。 |
| **CVE-2026-32149** | SentinelOne 2026-04 | Windows **Hyper-V RCE**（同上）。 |
| **CVE-2024-35250** | HVCIPwned | HVCI 对 data-only 内核 exploit **无防御**（A5 基石）。 |
| **SSDT Shadow internals** | jmmicoli 2026-05 | 现代 Win syscall 派发 + Shadow SSDT 数据节利用面。 |
| **DKOM-2026 / HideProcessDKOM / eprocess-dkom-unlinking** | github 2026-01 | PG 回调移除 + EPROCESS 断链的现成 PoC 参考实现。 |
| **PatchGuard Peekaboo** | gm7.org 2026-03, gbhackers 2026-01 | 进程隐藏时序修复（语料已有，本轮加固确认）。 |

---

## C. 新 C2 / NDR 对抗（填补语料最薄的层）

### C1. AsyncRAT on Cloudflare Workers（Pattern 49，运营手册级）
- **源：** dugganusa "Pattern 49 — Snakes on a Worker"，2026-04-07。
- **架构：** 单 Cloudflare 账号 → 3 个 worker（`quiet-disk-62f9`/`shiny-darkness-5096`/`silent-frog-4440`，均为 CF 默认随机名）→ 每个 worker 多个子域频道（`atex`/`backup`/`data`/`ddos`/`malware`/`v3`）= **~18 活端点**。`data`=外泄、`backup`=冗余外泄、`malware`=二段下发、`ddos`=量级协调、`v3`=版本/受害队列路由。
- **关键洞察：** 攻击者从"被入侵主机"整体迁移到"CDN serverless"——因为**每个企业的 SIEM 都把 CDN 域名写进 allowlist**。35 个 IOC 跨 5 类平台原生基础设施（Cloudflare Workers/R2、IPFS、GitHub Pages、CloudFront），其中 2 个账号用真人姓名+出生年。IOC 自 2026-02-07 起可检索，**59 天未被下架**。
- **Nyx 落点：** `transport.rs` 的中继层设计——Cloudflare Worker 作 C2 前置，子域频道化（分阶段下发/外泄/协调）。直接补语料"C2/NDR 仍薄"的缺口。

### C2. Foxveil loader — Cloudflare + Discord + Netlify
- **源：** Cato Networks（Waizel/Buber/Kurtzberg），2026-02-11。
- 三平台混用做 C2 + 下发；Discord 当 staging/中继，Netlify 托管 payload。

### C3. Underminr — DNS 绕过隐藏 C2
- **源：** cipherssecurity，2026-05-25。
- DNS 库级漏洞让攻击者绕过 DNS 监控隐藏 C2 流量（DNS 隧道/隐蔽信道）。
- **Nyx 落点：** DNS 信标通道的规避参考（`pivot`/transport）。

### C4. NDR 已转向行为建模（规避要反过来）
- **源：** Vectra（John Mancini）"Why Modern C2 Detection Requires Behavioral Modeling, Not Decryption"，2026-06-08；ringsafe "Cloudflare-Fronted 2026"，2026-05-08。
- **结论：** NDR 不再指望解密（CDN/TLS），改查**beaconing 间隔、周期性、协议异常、host 发起的跨阶段行为**。
- **规避推论：** malleable C2（Phase 1 ✅）+ **大抖动 + 低慢 + 合法域前置**。固定周期信标必被建模抓。

### C5. Cloudflare 全家桶成默认基础设施
- Workers（C2）/ Pages / Tunnels / R2（钓鱼+外泄）。企业 allowlist 全放行。

---

## D. 新防御方检测器（规避必须知道——它们抓的是什么）

| 检测器 | 源 / 日期 | 抓什么 → 我们的规避要点 |
|---|---|---|
| **StackSentry** | Vith0r，2026-05-22 | BYOUD/unwind-spoof：监测 `.pdata`/`.xdata`/`.rdata`/`RUNTIME_FUNCTION`/动态 unwind 表的**时序变化**；`/byoud-trace` 观察改 unwind 元数据的 DLL 加载；`/shadow-stack` 捕获 CET 返回帧比对。→ 我们的 `stack.rs` BYOUD-Gap **必须零 .pdata 写**（gap 法本就如此），且不在敏感调用前改 unwind 表。 |
| **Sleep-Duck-Eye / Detect-SleepMask** | Olivaire，2025-12-03 | 通用调用栈完整性：SleepMask/ROP/VEH/加密栈/shadow-stack 绕过；针对 Ekko/SilentMoonWalker/Cronos。→ SleepmaskKit 验证靶机。 |
| **cet-spoofing-detection** | 0xjbb，2026-05-14 | 比对 CET 进程的 shadow stack vs 用户栈，抓栈伪造。→ BYOUD-Gap 是 leaf frame、不碰 shadow stack，本就 CET-clean。 |
| **K2** | titansoftwork，2026-05-20 | 内核驱动在 syscall 时检查**精确栈帧**，抓直接+间接 syscall。→ 印证 xacone-class，必须配 BYOUD-Gap。 |
| **HeathenEDR** | Heathen-Software，2026-03-25 | 高性能内核遥测 SDK——**自己造 EDR 做验证靶机**。 |
| **Elastic detection-rules 大改** | elastic/detection-rules，2026-03/05 | Windows 高危规则重写（#6028）；新增 PPID spoofing 检测（#6016）。→ postex 要注意 PPID/父进程一致性。 |
| Elastic `RtlLookupFunctionEntry(gap)==NULL` 启发式 | 语料已有 | 针对 LACUNA，2026-06 未商用部署。→ StackSentry 是更现实的当下威胁。 |

### EDR 钩子面情报（哪个产品钩哪些 API）
- **CrowdStrike**：330+ 函数；**SentinelOne**：50+ 高价值 API；**Cortex XDR**：**完全用内核回调，无用户态钩子**（不同检测模型，用户态 unhook 对它无效）。
- 工具：`hook_finder64.exe`（mr-un1k0d3r，starlog 2026-05）对比内存 vs 磁盘 ntdll，前 32 字节差异=被钩。

---

## E. 新真实威胁 tradecraft 参考实现

| 项目 | 源 / 日期 | 全链技术 | 对 Nyx 的价值 |
|---|---|---|---|
| **RedSun** | ACD421，2026-04-19 | 间接 syscall + ETW blind（`EtwEventWrite→xor rax,rax;ret`）+ AMSI HW-BP + **BYOVD `wsftprm.sys`（未上 blocklist）** + 内核杀 EDR + DKOM 回调 + Ekko sleep + module stomp | **当前可用未封锁驱动 `wsftprm.sys`**（BYOVD 选型硬情报）；全链参考 |
| **Qilin EDR killer** | Talos，2026-04-02 | 内存内核感知 loader；运行时 ETW 抑制；SEH/VEH 混淆控制流；删 EDR 回调（进程/线程/镜像加载）；全程内存执行 | 勒索团伙 EDR killer 解剖 |
| **Turla Kazuar v3** | r136a1 2026-01 / le0mx | COM 集成 + patchless HW-BP ETW/AMSI（DR0/DR1/DR7）+ AMSI `AMSI_RESULT` 栈操纵 + VBScript 下载 + HP 打印机驱动 sideload + COM 持久化 | `blind.rs` HW-BP patchless 的真实威胁实现 |
| **FudCrypt crypter** | ctrlaltintel 2026-04-19 | builder：间接 syscall + module stomp + threadless + fiber/callback 执行 + Ekko sleep + BCrypt AES-256-CBC | 商业 crypter 的运行时规避原语清单 |
| **BYOVD 工业化** | techtimes 2026-06-19 / ESET | 勒索团伙自建 BYOVD arsenal，478 受害者；GentleKiller 覆盖 400+ 进程/48 产品 | 证实 kit 模型 + operator 选驱动是正确方向 |

### BYOVD blocklist 态势（2026-06）
- Microsoft 受压要强化 BYOVD 防御（DarkReading 2026-02）；Vectra "有效签名≠安全"（2026-06-23）；MS 推荐驱动 block 规则 2026-05-03 更新。
- **blocklist 覆盖率**：反作弊驱动 90%+、安全遗留 70%、硬件工具 40-60%、法证 30-40%、**工业/SCADA <10%（蓝海）**。
- NDSS 2026 "Unveiling BYOVD Threats"（Monzani/Parata/Oliveri）——学术 BYOVD 研究。

---

## F. 语料项的新增确认/补强

- **LACUNA Chain = 7 组件**（Alzhrani，2026-06-20 披露）：BYOUD-Gap + Win32u NOP Gap Chain + ETW-Ti APC Window Attack + 加密 syscall 参数传递 + 栈可见性操纵 +（共 7）；**实测过 Elastic / Bitdefender / Kaspersky / Win11**；只留"行为关联"作最后防线。→ `stack.rs` 的权威参考（github.com/MazX0p/LACUNA-Chain）。
- **BYOUD 溯源**：klezVirus **Black Hat EUROPE 2025**（非 US）；原始 BYOUD 操纵 `UNWIND_INFO`（.pdata/.xdata）而非返回地址，CET-compliant。Gap 变体是 Alzhrani 后续。
- **BeaconGate / Crystal Mask / BUD 契约**（rastamouse 2026-04）：CS sleepmask 是 BOF/COFF，Beacon 显式调用它执行 BeaconGate 支持的 Win32 API；反射加载器经 **BUD（Beacon User Data）** 传内存契约。→ Nyx `SleepmaskKit` 接缝=gate 层。
- **InsomniacUnwinding 外科式**（kapla 2026-03-30）：只保 ~250B `UNWIND_INFO`（vs 全 .rdata ~6KB）+ PE 头 + .pdata，无需 call-stack spoof。

---

## G. 学术新源

- **NDSS 2026 "Unveiling BYOVD Threats: Malware's Use and Abuse of Kernel Drivers"**（Monzani, Parata, Oliveri et al.）。
- **NDSS 2026 "Breaking Isolation: Hypervisor Exploitation via Cross-Domain Attacks"**（Pan, Yiming et al.）= arXiv:2512.04260（语料已有，确认录用）。
- **ACM AsiaCCS 2025 "Can You Run My Code? Process Injection in Windows Malware"**。
- **ACM DOI 10.1145/3708821.3736206**。

---

## H. 对 Nyx 构建计划的影响（增量修订）

| 增量 | 影响 | 优先级 |
|---|---|---|
| **EDRChoker（QoS 饥饿）** | 新增 operator-side "EDR 中和 kit" 第三条路（与 WFP/EDR-Freeze 并列），噪声最低 | P2.2 |
| **SunnyDayBPF（遥测完整性）** | eBPF consumer-buffer 污染 = 比 blind/forge 更高阶；P2.3 研究 | P2.3 |
| **CVE-2026-23670（enclave 鉴权绕过）** | 给 Mirage/BYOVE 一个现成入口（不用自己找签名漏洞 enclave） | P2.3 |
| **CVE-2026-45607/32149（Hyper-V 逃逸）** | hypervisor tier 的现成向量（M-Trends 趋势） | P2.3 |
| **AsyncRAT-Cloudflare-Workers 手册** | `transport.rs` 加 Cloudflare Worker 中继 + 子域频道化；NDR 规避=大抖动+低慢 | **P2.x 新工作项**（C2/NDR） |
| **`wsftprm.sys` 未封锁** | BYOVD 选型当前可用驱动硬情报 | P2.2 |
| **StackSentry 检测器** | `stack.rs` BYOUD-Gap 验证靶机；且警示"不能在敏感调用前改 unwind 表" | P2.1a-ii 验证 |
| **Cortex XDR=纯内核回调** | 用户态 unhook/blind 对 Cortex 无效→对 Cortex 目标必须走内核 tier | 威胁模型 |

---

## I. 诚实的天花板更新（vs 语料 §防御天花板）

- **新增不可规避项：** NDR 行为建模（beaconing 周期性）——只能用抖动/低慢降低置信，不能消除；CDN 流量虽被 SIEM allowlist 放行，但高级 NDR（Vectra 类）做行为建模仍可能抓。
- **新增可利用项：** EDRChoker 的 pacer.sys 层、SunnyDayBPF 的观测窗——都是语料没有的新攻击面。
- **内核 tier 仍待 2026-08 BH/DC：** BTR 驱动细节 + 可能的新内核 LotLK。

## J. 本轮信息源（新增，去重）
EDRChoker（zerosalarium/lindensein/securonix 2026-06）· SunnyDayBPF（azqzazq1 2026-05）· BYORWXDLL（meterpreter 2026-06）· SSDT-VBS/HVCI（exploitpack 2026-02, jmmicoli 2026-05）· Data-Only Gadgets（UNDERCODE 2026-05）· HVCIPwned/CVE-2024-35250 · DXE→Ring0（0rickyy 2026-05）· WerWolf BOF（kimd15 2026-04）· OXLOADER（Elastic 2026-06）· FudCrypt（ctrlaltintel 2026-04）· RedSun（ACD421 2026-04）· Qilin EDR killer（Talos 2026-04）· Turla Kazuar v3（r136a1/le0mx 2026-01）· StackSentry（Vith0r 2026-05）· Sleep-Duck-Eye（Olivaire 2025-12）· cet-spoofing-detection（0xjbb 2026-05）· K2（titansoftwork 2026-05）· HeathenEDR（2026-03）· AsyncRAT-Cloudflare Pattern 49（dugganusa 2026-04）· Foxveil（Cato 2026-02）· Underminr DNS（cipherssecurity 2026-05）· Vectra behavioral C2（2026-06）· CVE-2026-23670/45607/32149（SentinelOne）· LACUNA 7-comp（0xmaz/cybernexora/gbhackers 2026-06）· BYOUD origin（klezVirus BHE 2025）· Crystal Mask/BUD（rastamouse 2026-04）· NDSS'26 BYOVD + Hypervisor Cross-Domain · BYOVD blocklist（DarkReading/Vectra/MS 2026-02..05）· EDR hook 情报（starlog/mr-un1k0d3r 2026-05）
