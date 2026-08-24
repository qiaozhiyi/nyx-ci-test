# Nyx DLL Sideloading 投递链设计（WP-H）

> **状态**：设计定稿 + 生成工具已实现并本机验证；**投递链未在 VM/真机对 AV/EDR 实测**。
> **日期**：2026-08-21
> **范围**：宿主选择方法论、代理 DLL 生成工具（`tools/sideload-proxy/`）、部署与检测面。不含 server 侧投递编排。
> **依据**：[frontier_gap_analysis §1.1 Table 12 与 §2 P3](../research/frontier_gap_analysis_2026-08-21.md)
> **负责人**：红队工程（WP-H）
> **验收条件**：① 工具 `cargo test` / `clippy -D warnings` 全绿；② 生成骨架 `x86_64-pc-windows-gnu` 交叉编译通过且导出表与原 DLL 一致（均已达成，见 §6）；③ VM 投递链实测（未做，遗留）。

---

## 1. 背景与依据

AutoBypass（arXiv 2608.01639）Table 12（**外部数据，Nyx 未复现**）：

| 投递上下文 | 总体成功率 | 对 Kaspersky |
|---|---|---|
| DLL sideloading | **52.3%** | **84.8%** |
| 独立 EXE | 37.4% | 11.2% |

机理：sideloading 让载荷在**已签名、信誉好的宿主进程**内执行，继承其信誉与行为基线；AV/EDR 对受信进程的加载行为告警阈值更高。

Nyx 现状：implant 已是 DLL 形态（`crates/implant-win` cdylib → `nyx_implant_win.dll`），server 侧生成管线见 `crates/server/src/implant_gen.rs`——**执行体不缺，缺的是投递链配套**。本工作包补齐"选宿主 → 生成代理 DLL → 部署"的文档与工具。

> 诚实标注：52.3%/84.8% 是论文跨 5 个 AV/EDR 聚合的统计数字，不代表任一具体宿主+代理组合的实测结果；Nyx 侧目前只有本机工具链验证（§6），无 EDR 对抗实测。

## 2. 宿主选择方法论

### 2.1 合格宿主的四个条件

1. **签名有效且信誉好**：Authenticode 有效，发布者信誉高（OS 组件、主流厂商）。签名为整个 sideloading 上下文提供信誉继承的来源。
2. **导入表静态引用目标 DLL**：宿主 IAT 直接 import 目标 DLL 的导出。**排除 delay-load 与运行时 `LoadLibrary`+`GetProcAddress` 动态解析**——delay-load 的 DLL 在延迟加载辅助函数里走自己的解析路径，劫持窗口与搜索行为不同；动态解析常带绝对路径或显式 System32 路径，不可控。
3. **不在已知 hijack blocklist**：Defender 与多家 EDR 维护已知滥用（宿主, DLL）对指纹（如 `winword.exe`+`wwlib.dll` 类经典组合）。命中即高危告警，信誉继承归零。
4. **搜索顺序可控**：宿主从应用目录加载目标 DLL（相对路径优先、未启用 SafeDllSearchMode 之外的硬化、非 KnownDLLs）。KnownDLLs 里的名字（`kernel32.dll` 等）永远从 System32 加载，**不可劫持**，直接排除。

### 2.2 两条路径

**人工审查**（一次一宿主，精确）：

- `dumpbin /dependents host.exe` / `objdump -p host.exe | grep "DLL Name"` 看静态导入；
- 查签名：`Get-AuthenticodeSignature`（Win）或 `osslsigncode verify`；
- 对照公开 hijack 清单（如 hijacklibs.net 类社区库）排除已知指纹对；
- 用 ProcMon 过滤 `NAME NOT FOUND` 确认宿主确实从应用目录搜索该 DLL。

**工具扫描**（批量初筛）：本仓库 `crates/nyx-loader/src/dll_probe.rs` 与 `tools/loader_probe_dll` 提供了 LoadLibrary 探针 + 导出枚举的先例（Windows 侧运行）；扫描器本体（批量遍历候选宿主、自动判定四条件）是后续工作项，本包未交付。

## 3. 投递链组装步骤

```text
① 选宿主         满足 §2.1 四条件
② 生成代理 DLL   nyx-sideload-proxy <原DLL> --out proxy_out/
                 → 交叉编译出与原 DLL 同名、全导出转发的代理
③ 植入触发       代理 DllMain 起线程 → 延时 → 加载同目录 implant DLL
④ 部署           <host dir>: host.exe + <原名>.dll(代理) + <原名去后缀>_orig.dll(真DLL)
                 + nyx_implant_win.dll
```

工具用法与生成物结构见 `tools/sideload-proxy/src/main.rs` 头部注释与生成 crate 的 README。核心约束：

- **代理必须占原 DLL 的名字与位置**，真 DLL 重命名（默认 `<stem>_orig.dll`）放同目录，作为转发目标。
- **转发覆盖全部导出**：漏一个导出，宿主解析该导入即失败（进程起不来 = 投递失败且暴露）。工具的导出解析覆盖具名导出、ordinal-only 导出、转发导出三类。

### 3.1 边界情况

- **ordinal-only 导出（NONAME）**：原 DLL 按序号导出、无名字。代理生成 `"_ord_N" = "real.#N" @N NONAME` 转发条目（语法已实测，见 §4）。goblin 的 `pe.exports` 只枚举具名导出会漏掉这类——这是工具自含解析器（`pe_exports.rs`）而不用 goblin 的直接原因。
- **原 DLL 自己就是转发导出**（导出 RVA 落在导出目录内，如 `api-ms-win-*` 转发层）：代理仍转发到原 DLL 的同名导出，Windows loader 支持链式转发（proxy.X → orig.X → kernel32.Y），无需特殊处理；解析器会把转发字符串识别出来供人工过目。
- **导出数为 0**：工具直接报错退出（代理无意义）。
- **版本化导出/复杂 def 语义**：极少数 DLL 依赖 def 文件的 `PRIVATE`、`DATA`（导出变量而非函数）等属性。当前生成器不保留 `DATA` 属性——导出变量的 DLL（如部分 `msvcrt` 数据导出）用纯转发会改变语义（转发对数据导出本身有效，但 `DATA` 标志丢失影响 `GetProcAddress` 之外的直接数据引用场景）。命中此类宿主请换目标。**这是推断边界，未实测。**

## 4. 转发机制选型（mingw 工具链）

候选与结论（`tools/sideload-proxy/src/generate.rs` 头部有同款记录）：

| 方案 | 结论 |
|---|---|
| **`.def` 转发条目（`name = real.name @ord`）** | **采用**。GNU ld（binutils deffilep）原生支持，生成真 forwarder RVA，loader 自行解析；零逐导出代码；ordinal-only 可用 `"real.#N"` 语法 |
| `#[no_mangle]` thunk stub 运行时 `GetProcAddress` + 尾调 | 否决：导出签名未知，需逐导出裸蹦床，脆弱且增大代码面 |
| `#[link]` / `/EXPORT:name=...` | 否决：MSVC 语法，GNU 工具链不支持 |

实测（mingw-w64 14，macOS 本机）记录的两个语法坑：

- `LIBRARY` 名必须加引号：`LIBRARY "proxy.dll"`（不带引号的点名语法错误）；
- ordinal 转发必须整体加引号：`"_ord_5" = "realdll.#5" @5 NONAME`。

`.def` 经生成 crate 的 `build.rs` 以 `cargo:rustc-link-arg=<abs path>` 传给链接器（cdylib 支持该指令）。

## 5. 检测面与限制

| 检测面 | 说明 | 缓解方向 |
|---|---|---|
| **已知 hijack 对被指纹化** | EDR 对 (宿主, DLL 名) 组合有静态/行为规则 | §2 选宿主时对照公开清单排除；优先选低知名度的自有软件宿主；定期重评（指纹库会更新） |
| **代理 DLL 无签名** | 目录里唯一未签名的 PE 就是代理 | 无法根治（自签反而更显眼）。靠宿主信誉继承 + 侧载上下文压低告警权重；投递后清理阶段可用 timestomp 降异常度 |
| **导出转发字符串是静态 IOC** | `.edata` 里明文 `real_stem.Func` 字符串，`strings` 即可见 | 转发目标名（`--real-name`）做成非常规名；对代理做整体加壳/加密装载（与 sRDI 链结合）是后续项；接受其作为已知残余 IOC |
| **代理比原 DLL 多一个 `DllMain` 导出** | rustc 在 windows-gnu 对 `#[no_mangle]` 符号强制 dllexport，无干净抑制手段（已验证） | 接受；或后处理 PE 删该名字表项（未实现，低优先） |
| **触发点只有 DllMain** | 纯链接器转发意味着宿主的导出调用**不经过我们的代码**， implant 触发只能挂 DllMain | 保守默认：PROCESS_ATTACH 起线程（loader lock 约束，线程在锁释放后才跑）→ 延时 → `LoadLibraryW` 同目录 implant。更隐蔽的"导出被调才触发"需要退回 thunk stub 方案，与转发机制互斥——取舍已定，文档在此 |

## 6. 验证状态

已验证（2026-08-21，macOS + mingw-w64 14.0.0）：

- `tools/sideload-proxy`：`cargo test` 7 项全绿（导出解析：具名/转发/洞/ordinal-only；def 渲染逐字节断言；骨架生成；CLI 冒烟）。
- `cargo clippy -- -D warnings` 无告警。
- 端到端交叉编译：以一个含具名导出 + ordinal-only 转发 + DllMain 的真实 DLL 为输入跑工具，生成 crate `cargo build --release --target x86_64-pc-windows-gnu` 通过；`objdump -p` 确认代理导出表与原 DLL 一致（4 导出、名称/ordinal 齐全、forwarder RVA 正确、NONAME 条目不具名）。

部分关闭（2026-08-24）：

- **投递链运行时实测（wine64 预冒烟 + 真 Windows loader CI）**：`tools/sideload-proxy/fixture/` 新增两阶段 fixture（`host_version.c` 静态导入 version.dll 走 named 转发；`ordlib.c/.def` + `host_ord.c` 走 ordinal-only 转发）。**wine64 双阶段 PASS**（named：转发调用返回真值 + DllMain 触发线程加载 fixture implant 落 marker，需 `WINEDLLOVERRIDES=version=n` 绕过 wine builtin 优先——真 Windows 的 version.dll 非 KnownDLL，不受影响；ordinal：`GetProcAddress(#1) -> 42` + marker）。真 Windows loader 复验由 `.github/workflows/windows-hosted-verify.yml` 的 `sideload-runtime` job 执行（手动 + 周定时），PASS 后本项升级为"已验证"。
- 对 AV/EDR 的告警观察仍在 `edr-matrix` job 维度另行记录（首版矩阵仅 Defender，见 edr-quant-matrix.md §3）。
- 仍未验证：批量宿主扫描器、投递编排（server 侧接线）。
