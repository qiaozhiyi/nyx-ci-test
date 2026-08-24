# 注入后 VAD 一致性离线分析（WP-F，2026-08-21）

> **用途：** 对照 RX-INT（arXiv 2508.03879）内核态实时检测模型，逐条审计 Nyx 四条注入路径在 VAD（虚拟地址描述符）元数据层面的残留暴露面，为后续实装工作包排优先级。纯文档分析，不改代码。
> **依据边界：** RX-INT 的技术细节以 `docs/research/frontier_gap_analysis_2026-08-21.md` §1.2 已转述的内容为限（线程创建监视 + 有状态 VAD 扫描 + 实时内存哈希，检测 module stomping / threadless injection / manual mapping，抗 TOCTOU）；凡超出该转述范围的检测器行为描述，均标注**【推断】**或**【待原文核对】**。代码事实全部带 `文件:行` 引用。

---

## 1. RX-INT 检测面摘要

### 1.1 论文已转述的检测器构成（论文依据：差距分析报告 §1.2）

RX-INT 是内核态实时内存威胁检测器，三个组件：

- **线程创建监视**：在内核回调层观察新线程的创建事件及其上下文。
- **有状态 VAD 扫描**：不是一次性快照，而是持续维护 VAD 元数据的状态视图——权限、类型、尺寸、背靠镜像关系的变化都在观察面内。"有状态"意味着权限的**历史翻转序列**本身是信号，翻回去不能消除记录。
- **实时内存哈希**：对内存页内容与磁盘上背靠镜像做实时哈希比对。

论文明确以 **module stomping / threadless injection / manual mapping** 为检测目标，且架构上**抗 TOCTOU**——"周期性扫描间隙清理现场"（扫描前还原、扫描后再注入）这类对抗对该架构无效。实测检出 PE-sieve 漏掉的手动映射区。

### 1.2 由三组件推导的 VAD 启发式清单（检测器看什么）

以下清单中标注【推断】的项是从"有状态 VAD 扫描 + 实时哈希"的能力描述推导出的具体启发式，论文转述未逐项列明，**待原文核对**：

| 启发式 | 内容 | 依据 |
|---|---|---|
| 权限异常 | MEM_PRIVATE / MEM_MAPPED 区域带 EXECUTE 权限，尤其 RWX；image 区段权限偏离 PE 头节表声明 | 【推断】 |
| 权限历史异常 | 同一区域出现 RX→RWX→RX 或 RW→RX 翻转序列（有状态扫描直接记录翻转事件本身） | 【推断，由"有状态"推导】 |
| 类型异常 | 可执行页的 VAD 类型为 Private（无背靠）或 Mapped（page-file section）而非 Image | 【推断，PE-sieve/Moneta 的同类启发式已在 inject.rs:11-28 模块头自述中确认】 |
| 尺寸异常 | 独立可执行区尺寸不对应任何已加载镜像的节布局；或远小于正常镜像映射的孤立可执行页 | 【推断】 |
| 背靠镜像一致性 | image-backed 区域的内存内容与磁盘文件哈希不一致（stomping 的直接靶心） | 论文转述：实时内存哈希 + 专门检测 module stomping |
| 线程创建上下文 | 新线程起始地址落在非 image 内存（private/mapped RX/RWX）、或远程线程创建后目标进程随即出现内存写入/权限变更 | 论文转述：线程创建监视；具体关联方式【推断】 |

### 1.3 哪些启发式是 Nyx 注入路径的靶心

差距分析报告 §1.2 已判定：Nyx 注入三件套（Module Stomping / ThreadlessInject / Pool Party）"正是该类内核检测器的靶心"。本文将该判断扩展至 2026-08-21 新增的第四条路径 FLS callback，并逐条给出 VAD 级分析（§2）。

**靶心映射总览：**

- **module_stomp** → 靶心是"背靠镜像一致性"（实时哈希对 stomped `.text` 直接命中）+ "权限历史异常"（RX→RWX→RX 翻转序列）。
- **threadless_inject（inject.rs 版）** → 靶心是"类型异常 + 权限异常"（private RWX 常驻不还原）。
- **pool_party_inject** → 靶心是"类型异常"（MEM_MAPPED 可执行 + 无文件名背靠）+ "权限异常"（RWX 常驻）。
- **fls_callback_inject** → 靶心是"类型异常"（private RX 可执行）+ "线程创建上下文"（两次 CreateRemoteThread）；权限历史（RW→RX）相对温和。

---

## 2. 逐路径 VAD 元数据形态分析

### 2.1 module_stomp（`crates/implant-tasks/src/inject.rs:532`）

**注入流程（代码事实）：**

1. `create_sacrificial(spawn_to)` 创建挂起的牺牲进程（inject.rs:152，CREATE_SUSPENDED）。
2. `stomp_and_resume`（inject.rs:572）：
   - Step 1：`CreateRemoteThread(LoadLibraryA, "xpsservices.dll")` 在目标内加载掩护 DLL——**硬编码**，inject.rs:581。
   - Step 2：远程读 PE 头解析掩护 DLL 的真实 `.text` 区域（`remote_text_region`，inject.rs:980）。
   - Step 3：`VirtualProtectEx` RX→RWX（inject.rs:590-592，prot 0x40）。
   - Step 4：`WriteProcessMemory` 覆写 `.text`（inject.rs:602）。stomp 窗口 = `min(vsize, 0x2000)`（inject.rs:1090，注释说明为防止 >8KiB shellcode 溢出到 `.rdata`/`.data` 的 CRITICAL-15 修复）。
   - Step 5：`VirtualProtectEx` RWX→RX 还原（inject.rs:606-612），返回值检查——v0.3.0 曾静默留下 RWX（"a louder EDR IOC than the original RX"）。
   - Step 6：`ResumeThread`（inject.rs:617）。

**注入后 VAD 形态：**

| 维度 | 状态 | 依据 |
|---|---|---|
| 名称 | 正常：`xpsservices.dll` 的 VAD 名称/路径与正常加载一致 | LoadLibrary 正常路径加载 |
| 类型 | **MEM_IMAGE** ✓ | image-backed 是 stomping 的核心价值（inject.rs:14-18） |
| 初始权限 | 正常：`.text` 由 loader 按节表映射为 RX | — |
| 权限翻转历史 | **RX→RWX→（写）→RWX→RX 还原发生过**；终态 RX 正常，但有状态扫描记录的是翻转序列本身 | inject.rs:590-612 |
| 背靠镜像一致性 | **`.text` 前 min(vsize, 0x2000) 字节与磁盘文件哈希不一致** | inject.rs:602 |

**RX-INT 有状态扫描 + 实时哈希下的暴露面：**

- 【残留 IOC · 高危】**实时哈希**：stomped `.text` 与磁盘 `xpsservices.dll` 的哈希不匹配，是论文明确点名的检测目标（module stomping）。RX 还原对此毫无缓解——哈希比对的是内容不是权限。模块头自述（inject.rs:23-26）已承认 PE-sieve 的 `.text` hash-mismatch 检测不可回避；RX-INT 把同一检测搬到内核实时路径。
- 【残留 IOC · 中危】**权限翻转序列**：RX→RWX→RX 对一个 image 区段是异常历史（正常 image `.text` 从不需 W 权限）。【推断】有状态 VAD 扫描若记录 protect 变更事件，终态还原不能消除该记录。但注意：翻转窗口很短（两次 VirtualProtectEx 之间只有一次 WPM），瞬时快照型扫描器大概率错过；这正是 RX-INT "有状态 + 抗 TOCTOU" 要解决的场景，故对该检测器应假设翻转被记录。
- 【已缓解】unbacked/private-executable 扫描（Moneta 主 IOC、PE-sieve unbacked 扫描）——inject.rs:21-22 明确这是设计目标且成立。
- 【不确定待实测】0x2000 窗口只覆写 `.text` 前 8KiB：剩余 `.text` 字节仍是原代码。一个只哈希"被修改页"的检测器照样命中（修改页哈希已变）；但若检测器抽样哈希（如只验入口点/节首），部分覆写与全覆写的命中率差异待实测。

### 2.2 threadless_inject（`crates/implant-tasks/src/inject.rs:1185`）

**注入流程（代码事实）：**

1. `NtAllocateVirtualMemory`（间接 syscall）在目标分配 **MEM_COMMIT|MEM_RESERVE、PAGE_EXECUTE_READWRITE（0x40）** 的私有区域（inject.rs:1226-1235）。
2. `NtWriteVirtualMemory` 写入 shellcode（inject.rs:1244-1253）。
3. `NtSuspendThread` 挂起目标主线程（inject.rs:1265）。
4. `NtGetContextThread` 取上下文（inject.rs:1285）。
5. **直接覆写 RIP = shellcode 地址**（inject.rs:1211）——v0.3.1 起为纯 RIP 劫持，DR0 HWBP 设置已移除（inject.rs:1201-1209 记录了 CRITICAL-16 的原因）。
6. `NtSetContextThread` + `NtResumeThread`（inject.rs:1321-1356）。

**注入后 VAD 形态：**

| 维度 | 状态 | 依据 |
|---|---|---|
| 名称 | 无（匿名私有区域） | — |
| 类型 | **MEM_PRIVATE** | NtAllocateVirtualMemory，inject.rs:1227 |
| 初始权限 | **RWX，且全程不还原** ——代码中无任何 VirtualProtect 后续调用 | inject.rs:1234（0x40），之后无 protect 调用 |
| 权限翻转历史 | 无翻转（一次分配即 RWX）——但这意味着 RWX 是**常驻**而非瞬时 | — |
| 背靠镜像一致性 | 无背靠（unbacked） | — |

**RX-INT 下的暴露面：**

- 【残留 IOC · 高危】**private RWX 常驻**：类型异常 + 权限异常双料命中，且因为是常驻（不像 stomp 的 RWX 是瞬时窗口），任何时刻的快照扫描都能看到。inject.rs:1168-1171 自述"Moneta may flag this as private executable"，并指出 PE-sieve 默认不扫 private RWX（除非 deep-scan）——但 RX-INT 是有状态内核扫描器，不应假设其等价于 PE-sieve 默认档。
- 【残留 IOC · 中危】**线程上下文异常**：主线程 RIP 指向 private 内存（非任何 image 区段）。论文的"线程创建监视"是否覆盖 RIP-落点审计【待原文核对】，但线程指令指针落在 unbacked 可执行页是经典启发式（已实装于多款扫描器）【推断】。
- 【残留 IOC · 低-中危】间接 syscall 使 RIP-of-syscall 留在 ntdll 内（用户态 hook 不可见），但对内核态 VAD 扫描无影响——VAD 元数据与 syscall 来源正交。
- 【已缓解】无任何 image `.text` 被修改 → 哈希比对干净（inject.rs:1168 "PE-sieve clean: no module .text is modified"）。这是相对 stomp 的明确优势。
- 【不确定待实测】shellcode 尺寸即区域尺寸（inject.rs:1225），一个尺寸恰等于 shellcode 长度对齐页的孤立 RWX 区在尺寸启发式下是否加权，待实测。

### 2.3 pool_party_inject（`crates/implant-tasks/src/tp.rs:312`）

**注入流程（代码事实）：**

1. `NtCreateSection`：**page-file-backed（SEC_COMMIT 0x8000000）、PAGE_EXECUTE_READWRITE（0x40）**、尺寸 = shellcode 长度页对齐（tp.rs:356-380）。
2. `NtMapViewOfSection` 双映射：implant 本地 writer 视图（tp.rs:384-412）+ 目标进程 reader 视图（tp.rs:426-453），**两侧均为 RWX（0x40）**。
3. 本地视图拷贝 shellcode（无 WriteProcessMemory，tp.rs:415-422），随即 unmap 本地视图（tp.rs:332）。
4. 执行投递走 `tp.rs` 版 `threadless_inject`（tp.rs:568）：劫持目标 worker-factory 句柄，**另分配一块 RWX stub 区**（`threadless_alloc_region`，tp.rs:688-709，0x40）写入伪造 `_TP_DIRECT`/`_TP_WORK`，经 `NtSetInformationWorkerFactory` 入队，由目标自有 `TppWorkerThread` 取出执行（tp.rs:282-300）。

**注入后 VAD 形态（目标进程内有两块新区域）：**

| 区域 | 类型 | 权限 | 背靠 |
|---|---|---|---|
| section 视图（shellcode） | **MEM_MAPPED**（非 Image、非 Private） | RWX 常驻，无降权代码 | page-file section，**无文件名** |
| stub 区（_TP_DIRECT/_TP_WORK） | MEM_PRIVATE | RWX 常驻 | 无 |

**RX-INT 下的暴露面：**

- 【残留 IOC · 高危】**MEM_MAPPED + 可执行 + 无文件背靠**：这是 manual mapping 的典型 VAD 指纹。SEC_COMMIT page-file-backed section 的视图在 VAD 里呈现为 mapped 类型但没有磁盘文件路径——一个"mapped 但无名字"的可执行区比 private 区更罕见（正常 mapped 区几乎都是非可执行的内存映射文件/共享内存）。论文实测检出 PE-sieve 漏掉的手动映射区，映射的正是此类形态。
- 【残留 IOC · 中危】**两块 RWX 常驻区**：section 视图与 stub 区均无降权（代码中无 VirtualProtect/NtProtect 调用）。"投递不用 VirtualAllocEx/WPM"（tp.rs:282-286）规避的是 **API 层遥测**（ETW/用户态 hook 对 VirtualAllocEx/WPM 的监控），对 VAD 元数据扫描无任何缓解——这是两个正交的检测面，必须在文档中讲清楚：Pool Party 的隐身收益在 syscall/API 层，VAD 层反而比 classic inject 更显眼（mapped vs private）。
- 【已缓解】无远程线程创建（tp.rs:300 "No remote thread is created"）→ 线程创建监视组件看不到 CreateRemoteThread 事件；执行来自目标自有线程池的既有线程。这直接削弱论文三组件之一的输入。
- 【已缓解】无 image `.text` 修改 → 哈希比对干净。
- 【不确定待实测】worker-factory 劫持（`hijack_worker_factory`，tp.rs:850）通过 `NtQuerySystemInformation` 句柄表扫描 + `DuplicateHandle` 完成，句柄复制事件在内核回调层的可见性待实测。

### 2.4 fls_callback_inject（`crates/implant-tasks/src/fls.rs:240`，2026-08-21 WP-A 新增）

**注入流程（代码事实）：**

1. `VirtualAllocEx` 分配 **PAGE_READWRITE（0x04）** 区域（shellcode + 36 字节触发 stub），fls.rs:255-263。
2. `WriteProcessMemory` 写 shellcode（fls.rs:273）。
3. `CreateRemoteThread(FlsAlloc, shellcode)` 在目标内注册 FLS 回调（fls.rs:308-344）。
4. 写入触发 stub（`FlsSetValue(index, shellcode)` + `ret`，fls.rs:281-282，编码见 fls.rs:406-428）。
5. `VirtualProtectEx` RW→RX（0x20），**返回值检查**（fls.rs:284-290）——明确不用 RWX："a private RWX region is the loudest allocation IOC"（fls.rs:23-26）。
6. `CreateRemoteThread(stub)`：stub 线程退出时 `RtlExitUserThread` 的 FLS rundown 触发回调 = shellcode（fls.rs:351-373）。

**注入后 VAD 形态：**

| 维度 | 状态 | 依据 |
|---|---|---|
| 名称 | 无（匿名私有区域） | — |
| 类型 | MEM_PRIVATE | fls.rs:255 |
| 初始权限 | **RW →（写）→ RX**：终态 RX，无 RWX 窗口 | fls.rs:260-261（0x04）、fls.rs:288（0x20） |
| 权限翻转历史 | RW→RX 一次翻转。比 stomp 的 RX→RWX→RX 温和得多——RW→RX 在合法场景存在（JIT、自解压 stub），非强信号 | 【推断】 |
| 背靠镜像一致性 | 无背靠（unbacked） | — |

**RX-INT 下的暴露面：**

- 【残留 IOC · 中危】**private RX 可执行**：无 RWX 是四条路径中权限面最干净的，但"unbacked 可执行页"仍是 RX-INT 检测目标（manual mapping/threadless 的同类指纹）。模块头自述（fls.rs:53-54）：Moneta deep-scan 仍可能 flag "private executable"，只是 RWX IOC 缺席。
- 【残留 IOC · 中危】**两次 CreateRemoteThread**（fls.rs:55-56 自述）：线程创建监视组件的直接输入。缓解点在于两次远程线程的起始地址分别是 kernel32!FlsAlloc（image 内，干净）和私有 stub（**unbacked 起始地址，异常**）——第二次创建才是靶心【推断】。
- 【残留 IOC · 新颖】**FLS 回调指针指向 private RX**：fls.rs:59-62 自述这是该技术的固有信号——审计 FLS 回调表找非 image 指针的 EDR 可命中；AutoBypass 的 14 告警实测说明被测 7 平台大多不做此审计。RX-INT 论文转述未提及 FLS 回调表审计，故对 RX-INT 本身此项记为【待原文核对】。
- 【已缓解】相对 threadless 的核心优势：无 `NtSuspendThread`/`NtGet|SetContextThread` 外线程上下文劫持链（fls.rs:57-58）——AutoBypass Table 11 中 threadless 56 告警 vs fls_callback 14 告警的主因。
- 【已缓解】无 image 修改 → 哈希干净。
- 【不确定待实测】线程退出 rundown 路径（RtlExitUserThread → FLS 回调）是否被内核态检测器关联到先前注入的 private RX 区，待实测。

### 2.5 四路径横向对比

| 路径 | 终态 VAD 类型/权限 | RWX 窗口 | image 哈希 | 线程创建事件 | 对 RX-INT 综合暴露 |
|---|---|---|---|---|---|
| module_stomp | Image / RX（正常终态） | 瞬时（RX→RWX→RX） | **不匹配** | 1× CreateRemoteThread | **哈希 + 权限历史双命中，最高** |
| threadless | Private / **RWX 常驻** | 常驻 | 干净 | 无远程线程，但有外线程 context 劫持 | 类型+权限常驻命中，高 |
| pool_party | **Mapped（无文件名）/ RWX 常驻** + Private RWX stub | 常驻 | 干净 | **无远程线程** | mapped 类型异常 + RWX 常驻，高；线程面最干净 |
| fls_callback | Private / RX | 无 | 干净 | 2× CreateRemoteThread（一次起始地址 unbacked） | 权限面最干净，类型+线程中危，相对最低 |

---

## 3. Stomping 目标选择策略盘点

### 3.1 现状（代码事实）

掩护 DLL **硬编码**为 `xpsservices.dll`，仅一处（inject.rs:581：`let cover_dll = b"xpsservices.dll\0"; // legit, signed, rarely used`）。选择理由写在行内注释：合法、微软签名、罕见使用（rarely used → 正常进程不会加载它，stomp 后不易因宿主自身引用 .text 而崩溃）。stomp 窗口 `min(vsize, 0x2000)`（inject.rs:1090）。

### 3.2 单目标硬编码的风险

- 【推断】**指纹化**：固定目标意味着固定的 IOC 组合（"notepad.exe 加载 xpsservices.dll 且 .text 被改"可写成一条 YARA/Sigma 式规则）。xpsservices.dll 本身是公开文献中 module stomping 的经典示例目标，防御侧对其作为 stomp 掩护的警觉度高于一般 DLL。
- 【推断】**罕见性是双刃剑**：`rarely used` 降低了崩溃风险，但也意味着"宿主进程加载 xpsservices.dll"这件事本身就是低频异常事件——在"该进程加载了与其正常行为无关的 DLL"这类加载上下文启发式下反而显眼。
- 【代码事实】当前无任何目标多样化、评分或按宿主进程定制的逻辑。

### 3.3 高启发分特征清单（stomping 目标选择的负向加权项）

以下为**笔者推断**（标注【推断】），依据是 §1.2 检测面与 stomping 检测的一般原理，非 RX-INT 原文：

会被加权的特征（应避免选作目标）：

1. **常驻高活动进程的核心系统 DLL**【推断】：ntdll/kernel32/kerberos 等被 EDR 完整性校验频率最高，.text 哈希比对大概率是常态开启的。
2. **被 AV/EDR 频繁做完整性校验的模块**【推断】：安全产品自身模块、已知被 patch 高频目标（amsi.dll、clr.dll）。
3. **被 EDR 用户态 hook 的模块**【推断】：stomp 覆写 .text 会顺带覆盖 EDR 注入的 hook 字节，可能触发 EDR 自检（hook 完整性校验）——不仅哈希不一致，还破坏了检测器自己的探针。
4. **.text 小于 shellcode 的 DLL**：代码事实层面的硬限制（inject.rs:599-601 直接报错拒绝），选型时必须预检 vsize。
5. **有自身完整性自检的模块**（DRM、反作弊组件）【推断】。

相对安全的方向（正向特征，同样【推断】）：

- 微软签名、体积大（.text ≫ 8KiB）、功能冷门但**加载上下文合理**的 DLL——即与宿主进程的业务有可信关联（如对 spoolsv 用打印相关 DLL），使"加载事件"本身不突兀。
- 多个候选目标轮换，避免单 IOC 固化。

---

## 4. Fluctuation 睡眠混淆对 VAD 扫描的缓解边界

### 4.1 机制（代码事实）

- `fluctuation::sleep`（`crates/implant-evasion/src/fluctuation.rs:41`）：睡眠期间将 implant `.text` 翻转为 **PAGE_NOACCESS**，唤醒时还原 RX（模块头 fluctuation.rs:1-2）。翻转由 PIC thunk 执行：Step 1 `NtProtectVirtualMemory(..., PAGE_NOACCESS=1)`（fluctuation_thunk.rs:132, 149），Step 3 还原 `PAGE_EXECUTE_READ=0x20`（fluctuation_thunk.rs:211, 228）。
- 数据面（config/key/token/BOF scratch/堆 slab）走 RC4 原地加密：`mem::mask`/`unmask`（mem.rs:196-217），加解密域为注册区域 + 分配器 slab（mem.rs:227-246）。

### 4.2 对"扫描时不可读"的缓解（有效）

PAGE_NOACCESS 窗口内，扫描器对 `.text` 的任何读取触发页错误——**内容层**的签名扫描/哈希比对在该窗口失效。这是 Fluctuation 对周期性内容扫描的正面对抗，差距分析报告 §1.2 已确认此收益。

### 4.3 对有状态 VAD 元数据启发式的无效边界

- 【代码事实 + 推断】**权限翻转历史**：每次睡眠周期产生一次 RX→NOACCESS→RX 翻转。对一个 image（或已 RX 化）区段做 NOACCESS 翻转，在"有状态 VAD 扫描"下是一个**反复出现、周期性的 protect 事件模式**——翻转频率与 beacon 周期同构。若检测器把 protect 事件纳入状态视图，睡眠混淆本身构成可检测的节律信号【推断，RX-INT 是否追踪 protect 事件历史待原文核对】。
- 【代码事实】**类型不变**：Fluctuation 不改 VAD 类型/尺寸/背靠关系。若 implant 本体落地在 private/mapped 可执行区（取决于投递方式），NOACCESS 翻转对类型异常启发式零缓解——区域依然是 unbacked 可执行区，只是暂时读不了。
- 【推断】**NOACCESS 本身是异常态**：正常进程的常驻代码页几乎从不处于 PAGE_NOACCESS。一个长期存在、周期性在 RX 与 NOACCESS 间翻转的可执行区，其**瞬态权限值**（扫描时刻恰好是 NOACCESS）同样偏离正常进程基线。
- 【代码事实】**`mask_text_and_heap`/`mask_heap_regions` 当前为 dormant**（mem.rs:254-261、325-330 自述零调用者，待 helper-thread 接线）：数据面 RC4 遮蔽目前只覆盖 `mask()`/`unmask()` 的注册区域路径（mem.rs:196-217），.text 内容加密（RX→RW→RC4→RX）未上线。即当前上线的是"权限翻转"版本，不是"内容加密"版本——内容层缓解依赖 NOACCESS 的不可读性，而非密文。

**结论：** Fluctuation 的有效域是"周期性内容扫描"这一检测类；对 RX-INT 的"有状态 VAD 元数据 + 实时哈希 + 线程监视"三组件，它既不改变 VAD 类型/背靠异常，也（在 protect 事件被记录的前提下）新增周期性翻转信号。两类检测的对抗必须分开评估，不能用"睡眠混淆已实装"推断 VAD 面已覆盖。

---

## 5. 实装建议清单（后续工作包候选，本轮不做）

| # | 建议 | 针对的暴露面 | 成本 | 前置依赖 |
|---|---|---|---|---|
| R1 | **注入后 VAD 自检工具**：VirtualQuery 全枚举 + 元数据一致性核对（类型/权限/名称/与 PE 头节表权限比对/.text 与磁盘哈希比对），先在 selftest/BOF 形态落地 | 全部四条路径的"看不见自己的 IOC"问题——当前代码只有防御性可读性探针（`bof.rs:85-113 vq_readable`、`bof-runner/src/shim.rs:74-109 is_readable`），无 VAD 元数据审查能力 | 低-中（纯本地 + VM 验证）；`.text` 哈希比对需要读磁盘文件 + PE 解析，可复用 `remote_text_region` 的解析逻辑 | 无硬依赖；建议作为一切后续 VAD 加固的度量工具先行 |
| R2 | **stomp 目标多元化 + 启发评分**：候选 DLL 池（按 §3.3 正负特征打分），按宿主进程上下文选目标；移除 `xpsservices.dll` 单点硬编码 | §3.2 指纹化风险；不解决哈希命中本身 | 低（纯本地数据 + 选择逻辑） | R1（选型效果需可度量）；候选池需实测各 DLL 的 vsize ≥ shellcode 尺寸 |
| R3 | **threadless/pool_party 的 RWX 降权**：投递完成后 private/mapped 区 RWX→RX（stomp 的 RX 还原纪律推广到另三条路径） | §2.2/§2.3 的"RWX 常驻"高危项——fls.rs 已证明 RW→RX 纪律可行 | 低（每条路径一次 NtProtectVirtualMemory/VirtualProtectEx 调用） | 无；但须验证 shellcode 不再需要自写（若 payload 有自修改段则降权时机需实测） |
| R4 | **stomp 窗口与 .text 全覆写策略评估**：0x2000 部分覆写 vs 全 .text 覆写（残余原代码填充/对齐）的哈希命中率对比实测 | §2.1 哈希 IOC 的窗口形态 | 中（需 VM + PE-sieve/RX-INT 类工具实测） | R1；实体 Windows VM |
| R5 | **pool_party section 类型伪装**：评估以命名文件 section（如合法数据文件映射）替代 page-file-backed SEC_COMMIT，消除"mapped 无文件名"指纹 | §2.3 mapped 类型异常 | 中（改动投递链 + 需落地诱饵文件） | R1；VM 实测 VAD 呈现 |
| R6 | **protect 事件面收敛评估**：量化 Fluctuation 周期性翻转在内核回调层的可见性，评估"内容加密替代权限翻转"（复活 mem.rs dormant 路径）的收益 | §4.3 翻转节律信号 | 中-大（helper-thread 接线 + 异常窗口工程，mem.rs 注释已标 CRIT-5 级别的硬件异常窗口问题） | R1 + VM；改动面大，排最后 |

**优先级排序理由：** R1 是一切后续项的度量基础（没有自检工具，所有加固都是盲改）；R2/R3 是纯本地、低成本、直接消除高危 IOC；R4-R6 需要 VM 实测或改动投递/睡眠链路，依赖 R1 的度量能力。

---

## 6. 证据与推断边界

**RX-INT 论文实测（来源：差距分析报告 §1.2 转述，未越出该范围）：**

- 内核态实时检测，三组件 = 线程创建监视 + 有状态 VAD 扫描 + 实时内存哈希。
- 检测目标明确包含 module stomping / threadless injection / manual mapping。
- 架构抗 TOCTOU；实测检出 PE-sieve 漏掉的手动映射区。
- 除此之外本文未引用论文任何其他内容；§1.2 启发式清单的逐项展开、§3.3 目标选择特征、§4.3 翻转节律均为推导。

**代码事实（带文件:行，已逐一核对源码）：**

- module_stomp 流程与硬编码目标：`crates/implant-tasks/src/inject.rs:532, 572-618, 581, 599-601, 1090`；检测面诚实分析 `inject.rs:11-28`。
- threadless_inject 流程与常驻 RWX：`inject.rs:1185, 1226-1235, 1244-1253, 1211`；v0.3.1 纯 RIP 劫持 `inject.rs:1201-1209`。
- hijack_main_thread：`inject.rs:462-509`（NtGet/SetContextThread + NtResumeThread，直调 ntdll 非间接 syscall，原因见 :455-461）。
- create_sacrificial / create_sacrificial_running：`inject.rs:152-156, 169-175`（FLS 路径需 RUNNING 进程的原因见 :158-164）。
- pool_party_inject section 投递：`crates/implant-tasks/src/tp.rs:312-334, 356-380, 426-453`；worker-factory dispatch 与 stub RWX 区 `tp.rs:568-616, 688-709`。
- fls_callback_inject 流程与 RW→RX 纪律：`crates/implant-tasks/src/fls.rs:240-299, 255-263, 284-290`；检测面自述 `fls.rs:52-62`。
- Fluctuation 机制：`crates/implant-evasion/src/fluctuation.rs:1-2, 41-58`；thunk 翻转 `fluctuation_thunk.rs:132, 149, 211, 228`；RC4 数据面 `mem.rs:196-217`；dormant 路径 `mem.rs:254-261, 325-330`。
- VAD 工具缺口：现有 VirtualQuery 用途均为防御性可读性探针——`crates/implant-tasks/src/bof.rs:85-113`（`vq_readable`，selftest 诊断专用）、`crates/bof-runner/src/shim.rs:74-109`（`is_readable`，`%s` 指针校验）。

**笔者推断（无外部证据，已就地标注【推断】）：**

- §1.2 启发式清单中标注【推断】的各项具体检测规则。
- stomp 目标的正负启发分特征（§3.3）。
- "protect 事件被有状态扫描记录"的假设及翻转节律可检测性（§2.1、§4.3）。
- 各路径在 RX-INT 下的相对危险度排序（§2.5）——基于 IOC 数量的定性比较，无量化实测。

**待原文核对：** RX-INT 是否审计线程 RIP 落点、是否追踪 protect 事件历史、是否审计 FLS 回调表、哈希比对是全区还是抽样。
