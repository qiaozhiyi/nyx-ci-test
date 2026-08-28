# Nyx 载荷多态生成能力 — 分层设计与路线图

> **Date:** 2026-08-21；L1/L3 第一增量 2026-08-28
> **Status:** L2 已交付（server 侧生成期随机化）；L4 bursty timing 已交付；L1/L3 第一增量已交付（模板构建侧 `NYX_BUILD_SEED`：opt-level/codegen-units 轮换 + 不可执行 `.rdata` junk；**不触 fat LTO**）。可执行垃圾 / 源码重排仍为规划项。
> **Scope:** `generate-implant` 管线产物的静态指纹多样化。不改变 implant 功能、不触碰 wire 协议与加密原语。
> **依据:** `docs/research/frontier_gap_analysis_2026-08-21.md` §1.1（推断：无多态是与顶级形态的最大结构性差距）、§1.4（arXiv 2511.21764：8 种多态行为实测，多态行为化为有效方向）、§2 P2 行（implant_gen 结构性变异，长期项）。
> **原则:** 变异只动"死区"与构建参数，永不动功能语义；每批变异必须可被现有测试/自检套件验证功能等价。

---

## 1. 勘察结论：生成管线形态（2026-08-21 实读代码确认）

**管线是"预编译模板 + 生成期补丁"，不是每次重新 `cargo build`。** 这决定了多态注入层的落点。

```
CI / 本地（scripts/win_build.sh）
  cargo +nightly build -Z build-std=core,alloc,panic_abort --release
    → nyx_implant_win.dll（模板，.nyx_cfg 段为 0x41414141 + 0xAA 占位）
        │
        ▼  （模板文件随部署分发，server 启动时经 NYX_TEMPLATE 加载，
            crates/server/src/main.rs:189，validate_template_pe 只做粗校验）
team server `POST /api/generate-implant`
  （crates/server/src/implant_gen.rs::generate_implant）
  1. 克隆模板字节（内存中，无磁盘构建）
  2. 滑窗扫描定位 0x41414141+0xAA 占位符（locate_nyx_cfg_placeholder）
  3. 原地覆写 1024 字节 .nyx_cfg 段：per-implant X25519 密钥对、
     ChaCha20-Poly1305 加密配置（write_nyx_cfg_section）
  4. validate_patched_pe（偏移式校验：MZ/PE 签名/段 magic/data_len 边界）
  5. SHA-256 + 元数据入库，返回二进制
```

关键事实：

- **生成期是毫秒级内存补丁**（对齐 `NYX_IMPLANT_GENERATION_ARCHITECTURE.md` §2.1 决策 1："No Docker cargo build on server"）。任何需要重新编译的变异（L1/L3）都只能发生在**模板构建侧**（CI/本地），不能发生在生成期。
- **implant 侧只读 `.nyx_cfg` 段的前 86 + data_len 字节**（`crates/implant-tasks/src/config_placeholder.rs::load_runtime_config_unmask_keys`），段尾 `[86+data_len..1024]` 是死区。
- **既有 per-build 随机性先例**：`crates/implant-core/build.rs::bake_config` 每次构建重随机配置加密 key/nonce，使编译期配置密文每次构建不同（注释自述 "defeating static extractors/signature tools"）。多态能力不是从零起步，而是把这一思路系统化、分层化。
- **既有生成期随机性**：per-implant 密钥对与 nonce 本就是 OsRng 随机，因此两个不同 implant 的 `.nyx_cfg` 前 86+data_len 字节本就不同——但**同一 implant 的其余 ~160KB 模板字节完全相同**，这才是静态签名的主要攻击面。

---

## 2. 能力分层

### L1 — 编译参数变异（模板构建侧）

按种子轮换 `opt-level` / `codegen-units` / LTO 模式 / `panic` 策略，使不同批次模板在指令调度、函数内联、段布局层面结构性不同。

- **成本：** 低工程量（profile 配置轮换 + 构建脚本参数化），但验证成本高——每个参数组合都要过完整自检矩阵。
- **收益：** 中。改变 `.text` 字节级与结构级特征，对字节序列 YARA 规则与控制流图哈希有效。
- **检测侧证据：** 2511.21764 中"格式头调整/加壳"类静态变异对商业 AV 检出率的压制（AV 平均仅 34%）；AutoBypass（2608.01639）的多态生成闭环。
- **前置依赖：** 模板构建流水线参数化（`scripts/win_build.sh` + CI workflow）；`NYX_BUILD_SEED` 环境契约。
- **风险（高亮）：** ⚠️ **2026-08-10 fat LTO 常量折叠根因**（CHANGELOG b94a158）：fat LTO 会把 `NYX_CFG_PLACEHOLDER` 的读取常量折叠，吞掉服务器对 `.nyx_cfg` 段的链接后补丁，导致生成的 implant 全部回连编译期默认 127.0.0.1。现防线是 `black_box` + `nyx_selftest_cfgstage` 诊断导出。**L1 轮换 LTO 模式/opt-level 时，每个新参数组合都必须重跑 `nyx_selftest_cfgstage` 确认补丁链路存活**——这是 L1 的硬门禁，缺它不得合入。
- **第一增量（2026-08-28，模板构建侧）：** 可选环境变量 `NYX_BUILD_SEED`（u64，十进制或 `0x` 十六进制）。**未设置**时 `scripts/win_build.sh` 不导出任何 `CARGO_PROFILE_*`，行为与历史默认 profile 一致。**设置**后 `scripts/poly_seed.sh` 导出 `CARGO_PROFILE_RELEASE_OPT_LEVEL` ∈ {3,s,z} 与 `CARGO_PROFILE_RELEASE_CODEGEN_UNITS` ∈ {16,1}。**绝不**导出 `CARGO_PROFILE_RELEASE_LTO`（尤其禁止 fat）。映射实现于 `crates/config/src/poly.rs`（单测：两种子不同元组、seed 0 确定、非法 seed fail-closed）与 `scripts/poly_seed.sh`。每个新参数组合合入前必须过 `nyx_selftest_cfgstage`；本增量不增加全组合 CI 矩阵。`generate-implant` 仍是预编译模板补丁，不加 `cargo build`。

### L2 — 常量与配置块随机化（生成期，本轮交付）

在 server 补丁阶段随机化不承载功能的字节。

- **本轮已交付（第一增量，`crates/server/src/implant_gen.rs`）：**
  1. `.nyx_cfg` 段尾死区（`[86+data_len..1024]`）由全零填充改为 OsRng 随机填充——消除"段内固定偏移处 ~900 字节 0x00"这一签名锚点（`write_nyx_cfg_section`）。
  2. 补丁后追加随机长度（[128, 4224) 字节）随机内容 PE overlay——消除"同模板 ⇒ 同文件尺寸 + 同尾部字节"锚点（`append_random_overlay`）。overlay 位于最后一个 section 原始数据之后，Windows 加载器不映射，模板未签名（无证书表可失效），implant 不自读镜像，全部下游消费者（validate/SHA-256/入库）基于偏移或最终字节向量，**对补丁偏移定位零影响**。
- **成本：** 极低（纯 server 侧，std 环境，无 no_std 链风险）。
- **收益：** 低-中。保证同源码同请求两次生成的产物哈希必不同；对整文件哈希/尺寸签名有效，对段内 `.text` 内容签名无效。
- **检测侧证据：** 同 L1（静态变异压制 AV 层）；项目内先例为 implant-core 的 per-build key/nonce 重随机。
- **前置依赖：** 无（本轮即交付）。
- **风险：** 近零。唯一理论风险是 overlay 干扰补丁偏移定位——勘察确认补丁在 overlay 追加之前完成且全部偏移基于占位符扫描与段内偏移，不受影响；已有单元测试锁定（见 §4）。

### L3 — 代码重排与垃圾代码插入（源码级，高成本）

源码/中间表示级的函数重排、等价指令替换、垃圾基本块插入、不透明谓词。

- **成本：** 高。Rust 工具链下无成熟源码级变异生态；现实路径是 proc-macro/build.rs 生成垃圾项 + `#[link_section]` 垃圾段 + 条件编译重排，或引入外部二进制重写器（与"server 无工具链"决策冲突，只能在模板侧做）。
- **收益：** 中-高（对 `.text` 内容签名真正有效），但边际收益受 EDR 行为层压制（见 §3 诚实边界）。
- **检测侧证据：** 2511.21764 八行为中的"垃圾代码插入/控制流混淆"两项——在综合管线 ~92% 检出面前单独贡献有限。
- **前置依赖：** L1 的种子契约先行统一；垃圾代码必须通过 PIC/no_std 约束（不能引入 std 引用、不能破坏 `build-std` 链、不能引入可被静态识别为"死代码填充"的模板化模式——模板化垃圾本身会成为新签名）。
- **风险：** 中。垃圾代码若含可执行路径则扩大攻击面与崩溃面；若纯死代码则易被启发式标记。建议先做"垃圾数据段 + 编译期函数顺序扰动"这类不可执行变异，可执行垃圾后置。
- **第一增量（2026-08-28，不可执行 junk）：** `NYX_BUILD_SEED` 设置时 `nyx-implant-core` `build.rs` 生成 `#[used]` 只读 `.rdata` 字节 blob（splitmix64 确定性填充，打散 0x90/0xCC，避免自成 YARA）；cdylib 经 `nyx-implant-win` keep-alive 引用以免 LTO 丢段。未设置则省略静态，默认模板保持稳定。不新增可写/可执行 PE 段。可执行垃圾与不透明谓词仍后置。

### L4 — 多态行为化（运行时，与 WP-C 联动）

信标时序/profile 组合随机化：per-implant 的 sleep 分布形态、padding 长度分布、envelope 组合，使流量元数据形状跨 implant 去同质化。

- **成本：** 中。大部分原语已在：`implant-net/build.rs` 的 profile 烘焙（envelopes.rs）、WP-C 的 padding/`timing_baseline`；缺的是 per-implant 随机化组合与 server 侧下发。
- **收益：** 高——这是唯一对"流量元数据 ML 检测"有效的层。
- **检测侧证据：** 2511.21764 中"随机化 beacon 时序/协议模仿"两行为；Striking Back At Cobalt（2506.08922）证明仅内容层模仿不足、元数据形状是可检测残留（gap 分析 §1.3 同结论）。
- **前置依赖：** WP-C 的 padding/timing_baseline 落地；generate-implant 请求面扩展（per-implant 时序参数已在：sleep/jitter，缺分布形态参数）。
- **风险：** 低-中。随机化不当会产生"比基线更异常"的时序（如无 jitter 的固定间隔反而是 IOC——`check_request_fields` 已拒 sleep=0）。需 c2lint 配套校验随机化后的 profile 仍贴合目标基线。

---

## 3. 诚实边界（多态能力的上限）

- **多态只对静态签名层有效。** 对行为检测（EDR 遥测关联）、内存扫描（RX-INT 类 VAD/线程启发式）、流量元数据 ML（Striking Back At Cobalt 类）无直接效果——那些要靠 evasion 原语与 L4 行为整形，不在本工作包。
- **量化上限（2511.21764 实测）：** 8 种多态行为全开下，商业 AV 平均检出率仍 34%、YARA/Sigma 74%、**EDR 76%**、三层综合管线 ~92%（FPR 3.5%）。即多态做得再好，单一载荷穿过现代 EDR 的概率上限也就在 1/4 量级；多态的价值在于抬高防守方签名维护成本与拖慢 IoC 固化，不在于"免杀"。
- **L2 第一增量的具体边界：** 只改变段尾死区与文件尾 overlay；`.text`/`.rdata` 内容不变，同模板生成的所有 implant 的代码段仍然逐字节相同，段级 YARA 规则依然可写。真正破段级签名需要 L1（不同批次模板）与 L3。
- **变异可复现性是有意放弃的：** OsRng 驱动的生成期随机化不可复现，这是目标而非缺陷；但意味着产物哈希不能作为构建正确性的回归锚点——回归验证必须锚在功能等价（配置可解密、自检通过）而非字节一致。

---

## 4. 分阶段路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| 本轮（WP-G 第一增量） | L2：`.nyx_cfg` 尾随机化 + 随机 PE overlay（server 生成期）；本文档 | ✅ 已交付（`crates/server/src/implant_gen.rs`，单测 3 项） |
| 下一阶段 | L1：`NYX_BUILD_SEED` 驱动模板构建参数轮换；**门禁：每个参数组合过 `nyx_selftest_cfgstage`**（防 2026-08-10 LTO 根因回归） | ✅ 第一增量已交付（opt-level/codegen-units；不触 LTO；见 `crates/config/src/poly.rs` + `scripts/poly_seed.sh`） |
| 后续 | L4：per-implant 时序/padding 分布随机化，与 WP-C padding/timing_baseline 联动，c2lint 加元数据检查项 | ✅ bursty timing 已交付；分布形态扩展仍规划 |
| 长期（P2 原定位） | L3：源码级重排与垃圾插入，先做不可执行变异（垃圾数据段/函数顺序），可执行垃圾单独评审 | 🔄 不可执行 `.rdata` junk 已交付；可执行垃圾 / 源码重排仍规划 |

### 本轮验证（测试落点）

新增 `crates/server/src/implant_gen.rs::polymorphism_tests`（单测，随 `cargo test -p nyx-server` 自动跑，无需手动脚本——构建期冒烟不适用，因本轮无构建链改动）：

1. `two_generations_from_same_template_differ` — 同模板同请求两次生成，产物字节必不同（哈希差异断言）。
2. `patched_binary_still_valid_and_functional_region_deterministic` — 随机化后仍通过全部补丁后 PE 校验；功能区（段头 86B + 密文）逐字节确定，仅死区尾随机且非全零（功能等价断言）。
3. `overlay_preserves_prefix_and_varies` — overlay 不改前缀、长度落在 [128, 4224)、两次追加互不相同、头校验仍过。

功能等价由既有套件复跑覆盖：配置补丁/解密链路（端到端 `end_to_end.rs`）、envelope round-trip 等均未触碰。
