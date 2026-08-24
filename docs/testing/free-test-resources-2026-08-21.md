# 新功能免费测试资源调研（2026-08-21）

> **用途：** 为 2026-08-21 前沿对标改进八工作包（STATUS 第 15/16 条）的待验证项匹配零成本测试资源。
> **时效声明：** 免费政策随厂商调整，引用前以官网当前页面为准；本文所有政策描述均带来源链接。
> **关联：** [量化矩阵框架](edr-quant-matrix.md)（WP-B 的实测记录落点）。

## 1. 需求 → 资源映射

| 待测功能 | 测试需求 | 首选免费资源 | 备选 |
|---|---|---|---|
| WP-A FLS 注入（`nyx_selftest_inject_fls`） | 真 Windows x64（非 Prism 仿真）跑 rundll32 自测 | **GitHub hosted `windows-latest`**（已在用，Gate 3 有 smb_pipe_e2e 先例） | Win11 评估 VM（本地 Parallels/VMware） |
| WP-A FLS rundown 语义 | wine64 之外的真 Win32 FLS 回调 rundown | 同上；wine 行为不可信，必须真 Windows | — |
| WP-B EDR 量化矩阵实测 | "技术 × EDR × 告警量"，需要告警遥测可读 | **MDE 评估实验室**（预置机器 + 告警面板，免 onboard）→ 本机 Defender（`Get-MpThreatDetection` 已由 `edr_matrix_record.sh` 覆盖） | 免费第三方 EDR：OpenEDR / LimaCharlie free tier（见 §3） |
| WP-E extc2 impersonation | 真实出站 TLS 指纹校验 | **tls.peet.ws** 免费 API（CI 已有 `validate_ja3_live` 先例） | browserleaks.com/tls 人工核对 |
| WP-H sideloading 投递链 | Windows 宿主实际加载代理 DLL、观察转发解析与 implant 上线 | GitHub `windows-latest`（headless 足够验证加载/转发/上线） | Win11 评估 VM（交互观察 EDR 反应） |
| WP-G 多态增量 | 已随 `cargo test -p nyx-server` 覆盖 | 无需新资源 | — |
| WP-C 元数据整形 | profile/agent-dev/server 单测已覆盖；真流量形状观察需抓包 | 本地 loopback + Wireshark（免费） | — |
| ARM64/Prism 回归 | Win11 ARM64 + Prism x64 仿真 | 现有 Parallels VM 继续；**`windows-11-arm` hosted runner** 可作日常回归补充 | — |

## 2. 免费 Windows 运行环境

- **GitHub hosted runners**：标准 runner 对公开仓库免费且不限量；`windows-11-arm`（WoA）已全量开放给公开仓库，2026-01 起也进入私有仓库免费额度。([GitHub runners 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)、[WoA runner 公告](https://blogs.windows.com/windowsdeveloper/2025/04/14/github-actions-now-supports-windows-on-arm-runners-for-all-public-repos/)、[私有仓库 arm64 免费额度](https://github.blog/changelog/2026-01-29-arm64-standard-runners-are-now-available-in-private-repositories/))
  - 项目现状：BYOVD 真机加载、WFP selftest 之外的用户层自测均可搬上 hosted runner；**注意 hosted runner 无法做需要 Defender GUI 交互或长期驻留的演练**。
- **Microsoft 官方评估镜像**（本地虚拟化用，配合现有 Parallels）：
  - [Windows 11 Enterprise 90 天评估版](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise)（ISO，注册即下）；
  - [Windows 11 开发环境 VM](https://www.techzine.eu/news/devops/108059/microsoft-releases-free-windows-11-virtual-machines/)（Hyper-V/VMware/Parallels/VirtualBox 预建镜像，90 天免激活）；
  - [Win11 24H2 IoT LTSC 评估 ISO](https://memstechtips.com/download-windows-11-24h2-enterprise-ltsc-evaluation-iso-2/)（build 26100，90 天）。
  - 桌面虚拟化层：VMware Fusion/Workstation 现已对个人免费（[VMware 官网](https://www.vmware.com/products/desktop-hypervisor/workstation-and-fusion)），Parallels 继续可用。
- **云免费额度**（需要独立公网 Windows 时）：
  - [Azure 免费账户](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/create-free-services)：新账号 $200 额度 30 天 + B1s 750 小时/月×12 个月（[突发型 10% CPU 基线陷阱注意](https://bestusavps.com/deals/azure-free-trial/)）。
  - AWS Free Tier：EC2 t2/t3.micro 750 小时/月×12 个月（[AWS Free Tier 指南](https://theawstrainer.com/blog/aws-free-tier-guide-2025)）；**2025-07 起新账号免费套餐规则有变动**（[Amazon EC2 定价说明](https://cloudburn.io/blogs/aws/ec2/pricing)），开通前核对当前页面。
  - 用途边界：云端 Windows 适合 server 端 staging 与 WP-E 出站验证；**不建议**在云上跑攻击性载荷演练（厂商 ToS 风险），注入/投递链实测留在本地 VM 或 CI runner。

## 3. 免费 EDR / 告警遥测

- **Microsoft Defender for Endpoint 评估实验室**（[官方试用入口](https://learn.microsoft.com/en-us/defender-endpoint/api/get-domain-related-machines)（页面含 free trial 链接）；[社区实操指南](https://blog.sonnes.cloud/lets-create-a-free-lab-with-microsoft-defender-for-endpoint-and-simulate-some-ransomware-attacks-get-the-correct-free-trial/)）：试用租户内预置已 onboard 的测试机 + 完整告警面板，是 WP-B 矩阵"告警量"列对 MDE 行取数的最低成本路径——不用自己装 EDR，直接读告警计数。
- **本机 Defender**：`Get-MpThreatDetection`/`Get-MpThreat`/`Get-MpComputerStatus` 已由 `scripts/edr_matrix_record.sh` 自动化，Defender 行零新增成本。
- **第三方免费 EDR**（矩阵扩 EDR 维度时用）：
  - [OpenEDR（Xcitium）](https://www.xcitium.com/free-edr/)：开源、≤50 端点永久免费（[官网](https://www.openedr.com/)）；
  - [LimaCharlie](https://limacharlie.io/pricing)：全功能免费社区层（[EDR 页](https://limacharlie.io/use-cases/edr)），云端 SaaS 投递传感器，告警经其 API/Webhook 取数；
  - Elastic Security 免费层含基础端点检测规则（告警经 Kibana 可读），未在本次检索中逐条核实版本边界，用前核对官网订阅表。
- 诚实边界：免费层 EDR 的检测逻辑与付费企业版可能有差异，矩阵 `env_limit` 列应记"免费层"字样，不得外推到企业版结论。

## 4. 落地建议（按投入产出排序）

1. **零成本立即做**：给 CI 加一个 windows-latest job 跑 `nyx_selftest_inject_fls`（Gate 3 已有 windows 原生执行先例，只需 PS1 期望码已有条目），关闭 WP-A 最大的"真机未验"缺口。
2. **本周末可做**：Win11 评估 VM 装 OpenEDR 或 LimaCharlie 传感器，用 `edr_matrix_record.sh --no-trigger` 模式回填矩阵第一个非 Defender EDR 行。
3. **需要注册流程**：MDE 评估实验室试用租户（需公司邮箱注册试用），拿到后跑注入三件套 + FLS，读告警面板计数填矩阵。
4. **可选**：`windows-11-arm` runner 加入 CI 矩阵做 ARM64 日常回归（与 Parallels VM 互补，runner 无 GUI 交互）。

## 5. 不在本轮调研范围

- 真 EDR 企业版（CrowdStrike/SentinelOne 等）试用需销售对接，不属于自助免费资源。
- 云上 HVCI/内核验证：延续既有结论（HVCI-on 矩阵已决策放弃，STATUS 第 11 条）。
