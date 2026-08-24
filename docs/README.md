# Nyx 文档索引

## 当前执行口径

- [项目状态](STATUS.md)：当前能力边界、交付状态与文档生命周期。
- [工程化整改计划（2026 Q3）](design/NYX_REMEDIATION_PROGRAM_2026Q3.md)：当前整改目标、验收门禁与里程碑。
- [Nyx vs 前沿商业 C2 基准评测（2026-07-31）](design/BENCHMARK_FRONTIER_C2_2026-07-31.md)：2026-07-31 修复冲刺 + 2026-08-02 loader 波次（真实 Layer-2 反射加载 + 真机验证）后的权威当前状态对标（CS 4.13 / BRc4 Catalyst 2.6.3）。
- [ARM64 VM 全链路红队演练验证（2026-08-10）](testing/vm-arm64-verify-2026-08-10.md)：Parallels Win11 ARM64 + Prism x64 仿真（中文系统、Defender 实时保护 ON）下 generate-implant → beacon 回家 → 用户层任务面全绿、0 检出的端到端证据；含 LTO 常量折叠死 implant 根因修复记录。
- [DLL sideloading 投递链设计（WP-H）](design/SIDELOADING_DELIVERY.md)：宿主选择方法论 + 代理 DLL 生成工具（`tools/sideload-proxy/`）；工具链本机已验证，VM 投递链实测未完成。
- [前沿对标差距分析报告（2026-08-21）](research/frontier_gap_analysis_2026-08-21.md)：arXiv 前沿论文（AutoBypass/RX-INT 等）对 Nyx 技术选型的外部实证与 P0–P3 差距矩阵；对应改进已落 STATUS 第 15/16 条。
- [EDR 量化矩阵框架（WP-B）](testing/edr-quant-matrix.md)："技术 × EDR × 告警量"记录 schema + 采集脚本（`scripts/edr_matrix_record.sh`）；首版矩阵待 VM 实测。
- [新功能免费测试资源（2026-08-21）](testing/free-test-resources-2026-08-21.md)：八工作包待验证项 → 零成本资源映射（hosted runner / 评估 VM / 免费 EDR / MDE 评估实验室）与落地顺序。
- [注入后 VAD 一致性分析（WP-F）](research/vad-consistency-analysis.md)：四条注入路径对照 RX-INT 内核检测面的暴露面评估与实装建议 R1-R6。
- [载荷多态生成设计（WP-G）](design/NYX_POLYMORPHISM_DESIGN.md)：L1–L4 分层路线图；第一增量（配置块死区随机化 + 随机 PE overlay）已实装。

## 按用途查阅

| 目录 | 内容 | 使用方式 |
|---|---|---|
| `audits/` | 代码审计和事实快照 | 先看日期，再与当前代码和 CI 结果核对 |
| `design/` | 架构、产品和长期规划 | 用于决策；不代表已交付能力 |
| `testing/` | 测试策略、环境和验证记录 | 用于判断某个能力是否得到环境验证 |
| `research/` | 技术研究与资料汇总 | 仅作研究输入，不构成产品承诺 |
| `superpowers/specs/` | 历史设计规格 | 必须核对后续实现与审计结论 |
| `windows-api/` | 平台 API 参考 | 参考资料 |
| `trex/`、`bypass/` | 专项研究材料 | 需按 `STATUS.md` 的能力状态理解 |

## 文档规则

1. 涉及“已完成”“可用”或版本支持范围的表述，必须链接到代码、测试或验证记录。
2. 新设计文档需要写明状态、日期、范围、负责人和验收条件。
3. 旧审计与研究材料保留为历史证据，但不得覆盖当前状态口径。
4. 修改目录或文件名时，同时更新本索引和引用它的文档。
