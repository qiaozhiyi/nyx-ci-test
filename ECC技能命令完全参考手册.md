# ECC 技能命令完全参考手册

> **Everything Claude Code** — 所有可用技能的简体中文详细说明
>
> 生成日期: 2026-07-11 | 技能总数: 300+

---

## 目录

1. [项目管理与流程](#1-项目管理与流程)
2. [Agent 系统架构](#2-agent-系统架构)
3. [前端开发](#3-前端开发)
4. [动效与视频](#4-动效与视频)
5. [后端开发](#5-后端开发)
6. [数据库与存储](#6-数据库与存储)
7. [运维与部署](#7-运维与部署)
8. [测试与质量](#8-测试与质量)
9. [安全与合规](#9-安全与合规)
10. [医疗健康](#10-医疗健康)
11. [网络工程](#11-网络工程)
12. [家庭网络](#12-家庭网络)
13. [研究分析](#13-研究分析)
14. [AI/ML 工程](#14-aiml-工程)
15. [移动开发](#15-移动开发)
16. [内容与写作](#16-内容与写作)
17. [商业与运营](#17-商业与运营)
18. [API 与集成](#18-api-与集成)
19. [开发工具与工作流](#19-开发工具与工作流)
20. [代码质量与审查](#20-代码质量与审查)
21. [探索与搜索](#21-探索与搜索)
22. [通信与协作](#22-通信与协作)
23. [终端与系统](#23-终端与系统)
24. [架构设计](#24-架构设计)
25. [其他](#25-其他)
26. [内置子 Agent 角色](#26-内置子-agent-角色)

---

## 1. 项目管理与流程

### `blueprint` — 工程蓝图
将一句话目标拆解为多会话、多 Agent 的工程设计蓝图。每步含自包含上下文简报，支持对抗性审查门禁、依赖图、并行步骤检测、反模式目录和计划变异协议。

**触发条件**: 用户请求复杂多 PR 任务的计划/蓝图/路线图，或描述需要多会话的工作。

### `plan-orchestrate` — 计划编排
读取计划文档，分解为步骤，从 ECC 目录设计每步的 Agent 链，输出即用型 `/orchestrate` 自定义提示。仅生成，不执行。

### `orch-add-feature` — 编排新增功能
端到端构建全新功能：研究→计划→TDD 实现→审查→门禁提交，每阶段委托匹配的 ECC Agent。

### `orch-fix-defect` — 编排修复缺陷
修复 Bug：复现为失败回归测试→修复→审查→门禁提交。

### `orch-change-feature` — 编排变更功能
将现有功能改为新行为：更新测试为新规格→修改实现→审查→门禁提交。

### `orch-refine-code` — 编排代码重构
行为保持型重构：确认测试绿→重构不改变行为→保持测试绿→审查→门禁提交。

### `orch-build-mvp` — 编排构建 MVP
从设计/SDD 文档启动 MVP：摄取文档→规划薄竖切片→搭建首条端到端切片→TDD 实现→审查→门禁提交。

### `orch-pipeline` — 编排共享管道
`orch-*` 系列的共享编排引擎。定义门禁式 Research-Plan-TDD-Review-Commit 管道、规模分类器、Agent 映射和两个人工门禁。

### `project-flow-ops` — 项目流程运维
GitHub + Linear 双轨执行流运维：分类 Issue 和 PR、链接活跃工作、保持 GitHub 公开面而 Linear 为内部执行层。

### `team-agent-orchestration` — 团队 Agent 编排
使用工作项、所有权、Agent Kanban、合并门禁和控制面板交接运行 Agent 小组的团队编排。

### `team-builder` — 团队构建器
交互式 Agent 挑选器，用于组合和派遣并行团队。

### `dmux-workflows` — dmux 多 Agent 工作流
使用 dmux（AI Agent 的 tmux 窗格管理器）进行多 Agent 编排。跨 Claude Code、Codex、OpenCode 等 Harness 的并行 Agent 工作流模式。

### `parallel-execution-optimizer` — 并行执行优化器
通过并行工作、并发 Agent、批量工具调用、隔离工作树或多条独立验证通道，在不损失正确性的前提下大幅加速任务。

### `dynamic-workflow-mode` — 动态工作流模式
为 Claude 动态工作流模式和其他自适应 Agent Harness 设计任务级 Harness、Eval 门禁和可复用技能提取。

---

## 2. Agent 系统架构

### `agent-architecture-audit` — Agent 架构审计
Agent 和 LLM 应用的全栈诊断。审计 12 层 Agent 栈：包装退化、内存污染、工具纪律失败、隐藏修复循环和渲染损坏。产出严重度排名的发现及代码优先修复。

### `agent-eval` — Agent 评估
编码 Agent 头对头对比（Claude Code、Aider、Codex 等），指标包括通过率、成本、时间和一致性。

### `agent-harness-construction` — Agent Harness 构建
设计和优化 AI Agent 动作空间、工具定义和观察格式化，以提高完成率。

### `agent-introspection-debugging` — Agent 自省调试
AI Agent 失败的结构化自调试工作流：捕获→诊断→受控恢复→自省报告。

### `agent-self-evaluation` — Agent 自我评估
非平凡任务完成后使用。Agent 在 5 个轴上自评输出——准确性、完整性、清晰度、可操作性、简洁性——每项附具体证据。产出结构化 1-5 评分卡及改进建议。

### `agentic-engineering` — Agentic 工程
以 Eval 优先执行、分解和成本感知模型路由进行 Agentic 工程。

### `agentic-os` — Agentic 操作系统
在 Claude Code 上构建持久多 Agent 操作系统。涵盖内核架构、专家 Agent、斜杠命令、基于文件的记忆、定时自动化和状态管理（无需外部数据库）。

### `autonomous-agent-harness` — 自主 Agent Harness
将 Claude Code 转化为完全自主的 Agent 系统：持久记忆、定时操作、计算机使用和任务队列。替代 Hermes、AutoGPT 等独立 Agent 框架。

### `autonomous-loops` — 自主循环
自主 Claude Code 循环的模式和架构——从简单顺序管道到 RFC 驱动的多 Agent DAG 系统。

### `continuous-agent-loop` — 持续 Agent 循环
带质量门禁、Eval 和恢复控制的持续自主 Agent 循环模式。

### `continuous-learning-v2` — 持续学习 v2
基于本能的学习系统：通过 Hook 观测会话，创建带置信度评分的原子本能，并进化为技能/命令/Agent。v2.1 增加项目范围本能以防止跨项目污染。

### `enterprise-agent-ops` — 企业 Agent 运维
运维长期 Agent 负载：可观测性、安全边界和生命周期管理。

### `eval-harness` — 评估 Harness
Claude Code 会话的正式评估框架，实现 Eval 驱动开发 (EDD) 原则。

### `gan-style-harness` — GAN 风格 Harness
受 Anthropic 2026 年 3 月 Harness 设计论文启发的 GAN 风格 Generator-Evaluator Agent Harness，用于自主构建高质量应用。

### `gateguard` — 门禁守卫
事实强制门禁：阻止 Edit/Write/Bash（包括 MultiEdit），要求具体调查（导入器、数据模式、用户指令）后才允许操作。比无门禁 Agent 可测量地提高输出质量 +2.25 分。

### `loop-design-check` — 循环设计检查
设计/审查目标导向 Agent 循环：检查五种失败模式 + 可判定性 + 边界 + fallback + judge 独立性 + 人类判断红线。补充机制层循环技能（autonomous-loops、continuous-agent-loop）未覆盖的判断层。

### `ralphinho-rfc-pipeline` — Ralphinho RFC 管道
RFC 驱动的多 Agent DAG 执行模式：质量门禁、合并队列和工作单元编排。

### `recursive-decision-ledger` — 递归决策账本
重复推出、标记决策过程、高维搜索、随机优化、局部最优探索、集成比较或带可见证据轨迹的递归推理。

### `santa-method` — Santa 方法
带收敛循环的多 Agent 对抗验证。两个独立审查 Agent 必须都通过才能交付输出。

### `cost-aware-llm-pipeline` — 成本感知 LLM 管道
LLM API 使用的成本优化模式：按任务复杂度路由模型、预算跟踪、重试逻辑和提示缓存。

### `context-budget` — 上下文预算
审计 Claude Code 上下文窗口消耗：Agent、技能、MCP 服务器和规则。识别膨胀、冗余组件，产出优先级 Token 节省建议。

### `token-budget-advisor` — Token 预算顾问
响应前为用户提供关于响应深度消耗的知情选择。控制响应长度、深度或 Token 预算。

---

## 3. 前端开发

### `react-patterns` — React 模式
React 18/19 模式：Hooks 纪律、Server/Client 组件边界、Suspense + Error Boundary、表单 Actions、数据获取、状态管理决策树和以无障碍为首的组合。

### `react-performance` — React 性能
React 和 Next.js 性能优化模式（源自 Vercel 工程最佳实践）。70+ 规则分 8 个优先级：瀑布流、打包体积、服务端、客户端获取、重渲染、渲染、JS 微性能、高级。

### `react-testing` — React 测试
React 组件测试：React Testing Library、Vitest/Jest、MSW 网络 mock、axe 无障碍断言，以及组件测试与 Playwright/Cypress E2E 的决策边界。

### `react-native-patterns` — React Native 模式
React Native 和 Expo 应用模式：Expo Router 导航、状态分离（server/client/route/form）、TanStack Query 数据获取 + Zod、高性能列表、NativeWind/StyleSheet 样式、原生 API 和安全存储。

### `vue-patterns` — Vue 模式
Vue.js 3 Composition API 模式：组件架构、响应式最佳实践、Pinia 状态管理、Vue Router 导航和 Nuxt SSR 模式。

### `angular-developer` — Angular 开发
生成 Angular 代码并提供架构指导。涵盖响应式（Signal、linkedSignal、resource）、表单、依赖注入、路由、SSR、无障碍（ARIA）、动画、样式（组件样式、Tailwind CSS）、测试和 CLI 工具。

### `nextjs-turbopack` — Next.js + Turbopack
Next.js 16+ 和 Turbopack：增量打包、FS 缓存、开发速度和何时使用 Turbopack vs webpack。

### `nuxt4-patterns` — Nuxt 4 模式
Nuxt 4 应用模式：水合安全、性能、路由规则、懒加载和使用 useFetch/useAsyncData 的 SSR 安全数据获取。

### `vite-patterns` — Vite 模式
Vite 构建工具模式：配置、插件、HMR、环境变量、代理设置、SSR、库模式、依赖预打包和构建优化。

### `frontend-patterns` — 前端通用模式
React、Next.js 的前端开发模式：状态管理、性能优化和 UI 最佳实践。

### `frontend-a11y` — 前端无障碍
React 和 Next.js 的无障碍模式：语义 HTML、ARIA 属性、表单标签、键盘导航、焦点管理和读屏器支持。构建任何交互式 UI 组件或表单时使用。

### `frontend-design-direction` — 前端设计方向
为生产 UI 工作设定 ECC 特定的前端设计方向。构建或改进网站、仪表盘、应用、组件、落地页、可视化工具时使用。

### `frontend-slides` — 前端幻灯片
从零创建动画丰富的 HTML 演示文稿，或转换 PowerPoint 文件。帮助非设计师通过视觉探索而非抽象选择发现其美学。

### `ui-demo` — UI 演示录制
使用 Playwright 录制精致的 UI 演示视频。产出 WebM 视频：可见光标、自然节奏和专业感。

### `ui-to-vue` — UI 转 Vue
UI 截图或设计导出批量转换为 Vue 3 组件，特别是配合 Vant、Element Plus 或 Ant Design Vue。

### `make-interfaces-feel-better` — 界面精致化
应用具体的设计工程细节使界面感觉精致：间距、排版、边框、阴影、动效、点击区域、图标、文本换行和交互状态。

### `design-system` — 设计系统
生成或审计设计系统，检查视觉一致性，审查涉及样式的 PR。

---

## 4. 动效与视频

### `motion-foundations` — 动效基础
React/Next.js 的动效 Token、弹簧预设、性能规则、设备适配、无障碍强制和 SSR 安全。使用 motion/react。基础层——所有其他动效技能依赖于此。

### `motion-patterns` — 动效模式
React/Next.js 的生产就绪动画模式：按钮、模态框、Toast、交错、页面过渡、退出动画、滚动和布局。构建于 motion-foundations Token 和弹簧之上。

### `motion-advanced` — 高级动效
React/Next.js 的高级动效模式：拖放、手势、文本动画、SVG 路径绘制、自定义 Hook、命令式序列 (useAnimate)、加载器和完整 API 决策树。

### `motion-ui` — UI 动效系统
React/Next.js 的生产就绪 UI 动效系统。实现动画、过渡或动效模式时使用。

### `video-editing` — 视频编辑
AI 辅助视频编辑工作流：从原始素材到 FFmpeg、Remotion、ElevenLabs、fal.ai 再到 Descript/CapCut 的最终润色。

### `remotion-video-creation` — Remotion 视频创建
React 视频创建最佳实践。29 条领域特定规则涵盖 3D、动画、音频、字幕、图表、过渡等。

### `fal-ai-media` — fal.ai 媒体生成
通过 fal.ai MCP 的统一媒体生成——图片、视频和音频。涵盖文生图、文/图生视频、文生语音和视频转音频。

### `manim-video` — Manim 视频
为技术概念、图表、系统图和产品演示构建可复用的 Manim 动画解释器。

### `taste` — 品味/创意方向
音乐视频和短片编辑的创意方向层。提取命名流派美学词汇、情绪+色彩+光线系统和节拍同步编辑语法。

---

## 5. 后端开发

### Java / Kotlin 生态

#### `springboot-patterns` — Spring Boot 模式
Spring Boot 架构模式：REST API 设计、分层服务、数据访问、缓存、异步处理和日志。

#### `springboot-security` — Spring Boot 安全
Spring Security 最佳实践：认证/授权、JWT/OIDC、RBAC、输入验证、CSRF、密钥管理、请求头和限流。

#### `springboot-tdd` — Spring Boot TDD
测试驱动开发：JUnit 5、Mockito、MockMvc、Testcontainers 和 JaCoCo。新增功能、修 Bug 或重构时使用。

#### `springboot-verification` — Spring Boot 验证
验证循环：构建、静态分析、测试+覆盖率、安全扫描和发布/PR 前的差异审查。

#### `quarkus-patterns` — Quarkus 模式
Quarkus 3.x LTS 架构模式：Camel 消息、RESTful API 设计、CDI 服务、Panache 数据访问和异步处理。

#### `quarkus-security` — Quarkus 安全
Quarkus 安全最佳实践：认证/授权、JWT/OIDC、RBAC、CSRF、密钥管理和依赖安全。

#### `quarkus-tdd` — Quarkus TDD
测试驱动开发：JUnit 5、Mockito、REST Assured、Camel 测试和 JaCoCo。

#### `quarkus-verification` — Quarkus 验证
验证循环：构建、静态分析、测试+覆盖率、安全扫描、原生编译和差异审查。

#### `kotlin-patterns` — Kotlin 模式
惯用 Kotlin 模式：协程、空安全、DSL 构建器，构建健壮可维护的 Kotlin 应用。

#### `kotlin-testing` — Kotlin 测试
测试模式：Kotest、MockK、协程测试、属性测试和 Kover 覆盖率。遵循 TDD 方法论。

#### `kotlin-coroutines-flows` — Kotlin 协程与 Flow
协程和 Flow 模式：结构化并发、Flow 操作符、StateFlow、错误处理和测试。

#### `kotlin-ktor-patterns` — Ktor 模式
Ktor 服务器模式：路由 DSL、插件、认证、Koin DI、kotlinx.serialization、WebSocket 和 testApplication 测试。

#### `kotlin-exposed-patterns` — Exposed ORM 模式
JetBrains Exposed ORM 模式：DSL 查询、DAO 模式、事务、HikariCP 连接池、Flyway 迁移和仓库模式。

#### `jpa-patterns` — JPA 模式
JPA/Hibernate 模式：实体设计、关系映射、查询优化、事务、审计、索引、分页和连接池。

#### `java-coding-standards` — Java 编码标准
Spring Boot 和 Quarkus 服务的 Java 编码标准：命名、不可变性、Optional、Stream、异常、泛型、CDI、响应式和项目布局。

#### `android-clean-architecture` — Android Clean Architecture
Android 和 KMP 项目的 Clean Architecture：模块结构、依赖规则、UseCase、Repository 和数据层模式。

#### `compose-multiplatform-patterns` — Compose Multiplatform 模式
Compose Multiplatform 和 Jetpack Compose：状态管理、导航、主题、性能和平台特定 UI。

#### `dart-flutter-patterns` — Dart/Flutter 模式
生产就绪模式：空安全、不可变状态、异步组合、Widget 架构、流行状态管理框架（BLoC、Riverpod、Provider）、GoRouter 导航、Dio 网络、Freezed 代码生成和 Clean Architecture。

### Python 生态

#### `python-patterns` — Python 模式
Pythonic 惯用法、PEP 8 标准、类型提示和最佳实践。

#### `python-testing` — Python 测试
测试策略：pytest、TDD 方法论、fixtures、mock、参数化和覆盖率要求。

#### `django-patterns` — Django 模式
Django 架构模式：REST API (DRF)、ORM 最佳实践、缓存、信号、中间件和生产级 Django 应用。

#### `django-security` — Django 安全
安全最佳实践：认证、授权、CSRF 保护、SQL 注入防护、XSS 防护和安全部署配置。

#### `django-tdd` — Django TDD
测试策略：pytest-django、TDD 方法论、factory_boy、mock、覆盖率和 DRF API 测试。

#### `django-verification` — Django 验证
验证循环：迁移检查、lint、测试+覆盖率、安全扫描和部署就绪检查。

#### `django-celery` — Django + Celery
异步任务模式：配置、任务设计、Beat 调度、重试、Canvas 工作流、监控和测试。

#### `fastapi-patterns` — FastAPI 模式
最佳实践：项目结构、Pydantic v2 模式、依赖注入、异步处理器、认证、授权、事务服务层和 httpx + pytest 测试。

### Go / Rust / C++ / C# / F# / .NET

#### `golang-patterns` — Go 模式
惯用 Go 模式：错误处理、并发、接口和最佳实践。

#### `golang-testing` — Go 测试
测试模式：表驱动测试、子测试、基准、Fuzzing 和覆盖率。

#### `rust-patterns` — Rust 模式
惯用 Rust 模式：所有权、生命周期、Error Handling、Trait、并发和最佳实践。

#### `rust-testing` — Rust 测试
测试模式：单元测试、集成测试、异步测试、属性测试、mock 和覆盖率。

#### `cpp-coding-standards` — C++ 编码标准
基于 C++ Core Guidelines 的编码标准。现代、安全、惯用 C++。

#### `cpp-testing` — C++ 测试
测试模式：GoogleTest、CTest、诊断失败或 Flaky 测试、添加覆盖率/Sanitizer。

#### `csharp-testing` — C# 测试
.NET 测试模式：xUnit、FluentAssertions、mock、集成测试和测试组织最佳实践。

#### `fsharp-testing` — F# 测试
测试模式：xUnit、FsUnit、Unquote、FsCheck 属性测试、集成测试。

#### `dotnet-patterns` — .NET 模式
惯用 C# 和 .NET 模式：约定、DI、async/await 和最佳实践。

#### `nodejs-keccak256` — Node.js Keccak-256
防止 JavaScript/TypeScript 中的 Ethereum 哈希 Bug。Node 的 sha3-256 是 NIST SHA3 而非 Ethereum Keccak-256，会静默破坏选择器、签名、存储槽和地址派生。

### PHP / Laravel

#### `laravel-patterns` — Laravel 模式
架构模式：路由/控制器、Eloquent ORM、服务层、队列、事件、缓存和 API 资源。

#### `laravel-security` — Laravel 安全
安全最佳实践：认证、授权、Eloquent 安全、CSRF、XSS 防护、API 安全和安全部署配置。

#### `laravel-tdd` — Laravel TDD
测试策略：PHPUnit、Pest、模型工厂、HTTP 测试、Sanctum 认证测试、mock 和覆盖率。

#### `laravel-verification` — Laravel 验证
验证循环：env 检查、lint、静态分析、测试+覆盖率、安全扫描和部署就绪。

#### `laravel-plugin-discovery` — Laravel 插件发现
通过 LaraPlugins.io MCP 发现和评估 Laravel 包。

### 其他后端框架

#### `nestjs-patterns` — NestJS 模式
架构模式：模块、控制器、Provider、DTO 验证、Guard、拦截器、配置和生产级 TypeScript 后端。

#### `tinystruct-patterns` — tinystruct 模式
tinystruct Java 框架专家指导：Application 类、@Action 路由、单元测试、HTTP/CLI 双模式、内置 HTTP 服务器、事件系统、JSON Builder/Builders、数据库持久化、POJO 生成、SSE、文件上传和外部 HTTP 网络。

#### `backend-patterns` — 后端通用模式
后端架构模式：API 设计、数据库优化和服务端最佳实践（Node.js、Express、Next.js API 路由）。

---

## 6. 数据库与存储

### `postgres-patterns` — PostgreSQL 模式
查询优化、Schema 设计、索引和安全。基于 Supabase 最佳实践。

### `mysql-patterns` — MySQL 模式
MySQL/MariaDB Schema、查询、索引、事务、复制和连接池模式。

### `clickhouse-io` — ClickHouse
数据库模式、查询优化、分析和高性能分析工作负载的数据工程最佳实践。

### `redis-patterns` — Redis 模式
数据结构模式、缓存策略、分布式锁、限流、Pub/Sub 和连接管理。

### `prisma-patterns` — Prisma ORM 模式
TypeScript 后端的 Prisma ORM 模式：Schema 设计、查询优化、事务、分页和关键陷阱（updateMany 返回 count 而非记录、$transaction 超时、migrate dev 重置数据库、批量写入跳过 @updatedAt、Serverless 连接耗尽）。

### `database-migrations` — 数据库迁移
最佳实践：Schema 变更、数据迁移、回滚和 PostgreSQL/MySQL 及常见 ORM（Prisma、Drizzle、Kysely、Django、TypeORM、golang-migrate）的零停机部署。

### `content-hash-cache-pattern` — 内容哈希缓存
使用 SHA-256 内容哈希缓存昂贵文件处理结果：路径无关、自动失效、服务层分离。

---

## 7. 运维与部署

### `docker-patterns` — Docker 模式
Docker 和 Docker Compose 模式：本地开发、容器安全、网络、卷策略和多服务编排。

### `kubernetes-patterns` — Kubernetes 模式
工作负载模式、资源管理、RBAC、探针、自动扩缩容、ConfigMap/Secret 处理和生产级 kubectl 调试。

### `deployment-patterns` — 部署模式
部署工作流、CI/CD 管道模式、Docker 容器化、健康检查、回滚策略和生产就绪清单。

### `uncloud` — Uncloud 集群管理
管理 Uncloud 集群：部署服务、配置 Caddy 入口、添加静态代理路由、发布端口、扩缩容、检查日志、管理机器和卷。

### `flox-environments` — Flox 环境
使用 Flox 创建可复现的跨平台（macOS/Linux）开发环境。安装系统级依赖、固定包版本、运行本地服务（PostgreSQL、Redis、Kafka）、一键入职开发者。

### `bun-runtime` — Bun 运行时
Bun 作为运行时、包管理器、打包器和测试运行器。何时选择 Bun vs Node、迁移说明和 Vercel 支持。

### `canary-watch` — 金丝雀监控
部署后监控和验证已部署 URL：检查 HTTP 端点、SSE 流、静态资源、控制台错误和部署/合并/依赖升级后的性能回归。冒烟/金丝雀/部署后验证。

### `production-audit` — 生产审计
已发布应用的生产就绪本地证据审计：发布前审查、合并后检查、"生产会坏在哪"问题——不发送仓库数据到外部审计服务。

---

## 8. 测试与质量

### `tdd-workflow` — TDD 工作流
编写新功能、修复 Bug 或重构代码时使用。强制测试驱动开发，80%+ 覆盖率（单元+集成+E2E）。

### `e2e-testing` — E2E 测试
Playwright E2E 测试模式：页面对象模型、配置、CI/CD 集成、工件管理和 Flaky 测试策略。

### `windows-desktop-e2e` — Windows 桌面 E2E
Windows 原生桌面应用 E2E 测试：pywinauto 和 Windows UI Automation（WPF、WinForms、Win32/MFC、Qt）。

### `browser-qa` — 浏览器 QA
部署功能后使用浏览器自动化进行自动化视觉测试和 UI 交互验证。

### `ai-regression-testing` — AI 回归测试
AI 辅助开发的回归测试策略：无数据库依赖的沙箱模式 API 测试、自动 Bug 检查工作流和捕获 AI 盲点的模式。

### `benchmark` — 基准测试
测量性能基线、检测 PR 前后的回归、对比技术栈替代方案。

### `benchmark-optimization-loop` — 基准优化循环
通过重复实测，让代码更快、尝试多方案、递归优化延迟/吞吐/成本。

### `codehealth-mcp` — 代码健康 MCP
CodeScene 实时结构化代码健康：编辑前审查、分数增量验证、PR 门禁。

### `plankton-code-quality` — Plankton 代码质量
Plankton 写时质量强制：每次文件编辑自动格式化、Lint 和 Claude 驱动修复（通过 Hook）。

### `verification-loop` — 验证循环
Claude Code 会话的综合验证系统。

### `security-review` — 安全审查
添加认证、处理用户输入、使用密钥、创建 API 端点或实现支付/敏感功能时使用。综合安全清单和模式。

### `security-scan` — 安全扫描
使用 AgentShield 扫描 Claude Code 配置（`.claude/` 目录）的安全漏洞、错误配置和注入风险。

### `security-bounty-hunter` — 安全赏金猎人
在仓库中寻找可被利用的、值得赏金的安全问题。关注符合真实报告条件的远程可达漏洞，而非嘈杂的本地发现。

### `silent-failure-hunter` — 静默失败猎人
审查代码中的静默失败、吞掉的错误、不良 Fallback 和缺失的错误传播。

### `click-path-audit` — 点击路径审计
追踪每个面向用户的按钮/触控点通过其完整状态变更序列，找到功能各自工作但互相抵消、产生错误最终状态、或使 UI 处于不一致状态的 Bug。

### `pr-test-analyzer` — PR 测试分析器
审查 PR 的测试覆盖质量和完整性，强调行为覆盖和真实 Bug 预防。

---

## 9. 安全与合规

### `defi-amm-security` — DeFi AMM 安全
Solidity AMM 合约、流动性池和交换流的安全清单。涵盖重入、CEI 排序、捐赠/通胀攻击、预言机操纵、滑点、管理员控制和整数数学。

### `evm-token-decimals` — EVM 代币精度
防止跨 EVM 链的静默精度不匹配 Bug。涵盖运行时精度查找、链感知缓存、跨链代币精度漂移和机器人/仪表盘/DeFi 工具的安全标准化。

### `llm-trading-agent-security` — LLM 交易 Agent 安全
具有钱包或交易权限的自主交易 Agent 的安全模式。涵盖提示注入、支出限制、预发送模拟、熔断、MEV 保护和密钥处理。

### `hipaa-compliance` — HIPAA 合规
HIPAA 特定入口：医疗隐私和安全工作。PHI 处理、覆盖实体、BAA、泄露态势和 US 医疗合规要求。

### `healthcare-phi-compliance` — 医疗 PHI 合规
医疗应用的 PHI/PII 合规模式。数据分类、访问控制、审计追踪、加密和常见泄露向量。

### `healthcare-eval-harness` — 医疗评估 Harness
医疗应用部署的患者安全评估 Harness。CDSS 准确性、PHI 暴露、临床工作流完整性和集成合规的自动测试套件。

### `safety-guard` — 安全守卫
防止生产系统或自主 Agent 运行时的破坏性操作。

---

## 10. 医疗健康

### `healthcare-cdss-patterns` — 临床决策支持模式
CDSS 开发模式：药物相互作用检查、剂量验证、临床评分（NEWS2、qSOFA）、警报严重度分类和 EMR 工作流集成。

### `healthcare-emr-patterns` — EMR 开发模式
EMR/EHR 开发模式：临床安全、就诊工作流、处方生成、CDSS 集成和医疗数据录入的无障碍优先 UI。

---

## 11. 网络工程

### `cisco-ios-patterns` — Cisco IOS 模式
Cisco IOS 和 IOS-XE 审查模式：show 命令、配置层级、通配掩码、ACL 放置、接口卫生和安全变更窗口验证。

### `netmiko-ssh-automation` — Netmiko SSH 自动化
安全 Python Netmiko 模式：只读采集、有界批量 SSH、TextFSM 解析、守卫式配置变更、超时和网络自动化错误处理。

### `network-bgp-diagnostics` — BGP 诊断
仅诊断的 BGP 故障排除模式：邻居状态、路由交换、前缀策略、AS 路径检查和安全证据采集。

### `network-config-validation` — 网络配置验证
路由器和交换机配置的部署前检查：危险命令、重复地址、子网重叠、过时引用、管理面风险和 IOS 风格安全卫生。

### `network-interface-health` — 接口健康诊断
诊断接口错误、丢弃、CRC、双工不匹配、抖动、速度协商问题和路由器/交换机/Linux 主机的计数器趋势。

---

## 12. 家庭网络

### `homelab-network-setup` — 家庭网络规划
网关、交换机、AP、IP 范围、DHCP 预留、DNS、布线的实用家庭/家庭实验网络规划及常见初学者错误。

### `homelab-vlan-segmentation` — VLAN 分段
使用 UniFi、pfSense/OPNsense 和 MikroTik 对 IoT、访客、信任和服务器流量进行 VLAN 分段：交换机 Trunk 配置、防火墙规则和无线 SSID 映射。

### `homelab-wireguard-vpn` — WireGuard VPN
WireGuard VPN 服务器设置、Peer 配置、密钥生成、分流 vs 全隧道路由和移动/笔记本客户端远程访问家庭网络。

### `homelab-pihole-dns` — Pi-hole DNS
Pi-hole 安装、阻止列表管理、DoH 设置、DHCP 集成、本地 DNS 记录和家庭网络的 DNS 解析故障排除。

### `homelab-network-readiness` — 网络就绪清单
路由器/防火墙/DHCP/VPN 配置变更前的家庭实验 VLAN 分段、本地 DNS 过滤和 WireGuard 远程访问就绪清单。

---

## 13. 研究分析

### `deep-research` — 深度研究
使用 firecrawl 和 exa MCP 的多源深度研究。搜索网络、综合发现并提供带来源归属的引用报告。

### `literature-review` — 文献综述
学术、生物医学、技术和科学主题的系统文献综述工作流：搜索规划、来源筛选、综合、引用检查和证据日志。

### `pubmed-database` — PubMed 数据库
PubMed 和 NCBI E-utilities 搜索工作流：MeSH 查询、PMID 查找、引用检索和 API 驱动的文献监控。

### `uspto-database` — USPTO 数据库
USPTO 专利和商标数据工作流：官方记录查找、PatentSearch 查询、TSDR 检查、转让数据和可复现 IP 研究日志。

### `exa-search` — Exa 搜索
通过 Exa MCP 的神经搜索：Web、代码和公司研究。Web 搜索、代码示例、公司情报、人员查找或 AI 驱动的深度研究。

### `documentation-lookup` — 文档查找
通过 Context7 MCP 使用最新库和框架文档，而非训练数据。设置问题、API 参考、代码示例或用户提及框架名称时激活。

### `research-ops` — 研究运维
ECC 的证据优先现状研究工作流：新鲜事实、对比、增强或基于当前公共证据和提供的本地上下文的推荐。

### `market-research` — 市场研究
市场研究、竞争分析、投资者尽职调查和行业情报：带来源归属和决策导向摘要。

### `competitive-platform-analysis` — 竞品平台分析
竞品格局范围界定：识别、分类和评分过滤竞品集。

### `benchmark-methodology` — 基准方法论
在竞争平台分析产生分层竞品集后使用。九个加权维度评分：定位、声音、视觉工艺、报价包装、证据、企业就绪、思想领导力、定价、客户战略张力。

### `competitive-report-structure` — 竞品报告结构
在基准方法论产生评分竞品档案卡后使用。组装决策级报告：格局图、竞品档案、基准矩阵、空白分析和战略建议。

### `prediction-market-oracle-research` — 预测市场 Oracle 研究
将预测市场作为产品、Agent、仪表盘和企业决策情报的数据源或 Oracle 信号进行研究。

### `ito-market-intelligence` — Itô 市场情报
研究预测市场事件、场所、标底、流动性和新闻背景。

### `ito-basket-compare` — Itô 篮对比
将 Itô 预测市场篮与用户的知识库、组合笔记、金融背景进行对比。

### `ito-trade-planner` — Itô 交易规划器
构建非咨询预测市场交易规划工作表。

### `ito-data-atlas-agent` — Itô 数据图集 Agent
设计后台 Data Atlas 风格 Agent：篮研究、市场发现、参数起草和人机协同编辑。

### `prediction-market-risk-review` — 预测市场风险审查
审查预测市场、篮、Oracle 和交易 Agent 工作流：合规、安全、数据质量、隐私和执行风险。

### `scholar-evaluation` — 学术评估
论文、提案、文献综述、方法部分、证据质量、引用支持和研究写作反馈的结构化评估。

### `gget` — 基因组查询
gget CLI 和 Python 工作流：快速基因组数据库查询、序列查找、BLAST 风格搜索、富集检查和可复现生物信息学证据日志。

---

## 14. AI/ML 工程

### `pytorch-patterns` — PyTorch 模式
深度学习模式和最佳实践：训练管道、模型架构和数据加载。

### `ml-adoption-playbook` — ML 采用方法论
AI Agent 和软件工程师将机器学习算法添加到现有非 ML 代码库的端到端方法论。涵盖问题框架、数据就绪、架构建模和基线模型集成。

### `mle-workflow` — MLE 工作流
生产机器学习工程工作流：数据合约、可复现训练、模型评估、部署、监控和回滚。

### `recsys-pipeline-architect` — 推荐系统管道
使用六阶段 Source→Hydrator→Filter→Scorer→Selector→SideEffect 框架设计可组合的推荐、排名和 Feed 管道。

### `foundation-models-on-device` — 设备端基础模型
Apple FoundationModels 框架：设备端 LLM——文本生成、@Generable 引导生成、工具调用和 iOS 26+ 快照流。

### `data-scraper-agent` — 数据采集 Agent
构建全自动 AI 驱动数据采集 Agent：定时抓取、免费 LLM 增强（Gemini Flash）、结果存储 Notion/Sheets/Supabase、从用户反馈学习。GitHub Actions 100% 免费运行。

### `data-throughput-accelerator` — 数据吞吐加速
大量数据摄取/回填/导出/ETL/仓库加载/清单追赶/表同步大幅加速，同时保持数据正确性。

### `latency-critical-systems` — 低延迟系统
实时仪表盘、市场数据、流式 Agent、执行网关、队列、缓存或 HFT 类基础设施的延迟关键系统模式。

---

## 15. 移动开发

### `swiftui-patterns` — SwiftUI 模式
SwiftUI 架构模式：@Observable 状态管理、视图组合、导航、性能优化和现代 iOS/macOS UI 最佳实践。

### `swift-concurrency-6-2` — Swift 6.2 并发
Swift 6.2 亲和并发：默认单线程、@concurrent 显式后台卸载、主 Actor 类型的隔离适配。

### `swift-protocol-di-testing` — Swift 协议 DI 测试
基于协议的依赖注入：使用聚焦协议和 Swift Testing mock 文件系统、网络和外部 API。

### `swift-actor-persistence` — Swift Actor 持久化
使用 Actor 的线程安全数据持久化：内存缓存+文件后备存储，设计消除数据竞争。

### `ios-icon-gen` — iOS 图标生成
从 SF Symbols (5000+ Apple 原生) 或 Iconify API (275k+ 开源图标，200+ 集合) 生成 Xcode Asset Catalog 的 PNG 图片集。

### `liquid-glass-design` — Liquid Glass 设计
iOS 26 Liquid Glass 设计系统：动态玻璃材质+模糊+反射+交互变形，适用于 SwiftUI、UIKit 和 WidgetKit。

---

## 16. 内容与写作

### `article-writing` — 文章写作
撰写文章、指南、博客文章、教程、通讯期刊和其他长文内容。基于提供的示例或品牌指南使用独特声音。

### `brand-voice` — 品牌声音
从真实帖子、文章、发布说明、文档或网站文案构建来源派生的写作风格档案，然后跨内容、外联和社交工作流复用。

### `brand-discovery` — 品牌发现
通过结构化多会话访谈发现或阐明品牌身份。涵盖目的、定位、受众、个性、声音、叙事和创始人-品牌张力，使用 Laddering、5 Whys 和投射技术。

### `content-engine` — 内容引擎
为 X、LinkedIn、TikTok、YouTube、Newsletter 和复用型多平台活动创建平台原生内容系统。

### `crosspost` — 跨平台分发
跨 X、LinkedIn、Threads 和 Bluesky 的多平台内容分发。永不在不同平台发布相同内容。

### `social-publisher` — 社交发布
通过 SocialClaw 跨 13 个平台的 Agent 驱动排期和发布：X、LinkedIn、Instagram、Facebook Pages、TikTok、Discord、Telegram、YouTube、Reddit、WordPress、Pinterest。

### `seo` — SEO
审计、规划和实施 SEO 改进：技术 SEO、页面优化、结构化数据、Core Web Vitals 和内容策略。

---

## 17. 商业与运营

### `customer-billing-ops` — 客户计费运营
客户计费工作流：订阅、退款、流失分类、计费门户恢复和计划分析（Stripe）。

### `finance-billing-ops` — 财务计费运营
ECC 的证据优先收入、定价、退款、团队计费和计费模型真相工作流。

### `investor-materials` — 投资人材料
创建和更新 Pitch Deck、一页摘要、投资人备忘录、加速器申请、财务模型和融资材料。

### `investor-outreach` — 投资人外联
起草冷邮件、暖介绍、跟进、更新邮件和投资人沟通。

### `marketing-campaign` — 营销活动
端到端营销活动规划和执行：受众研究、定位、活动角度定义、落地页文案、邮件序列、社交帖子、广告文案、短视频脚本和内容日历。

### `lead-intelligence` — 线索情报
AI 原生线索情报和外联管道：信号评分、互评、暖路径发现、来源派生声音建模和跨渠道外联。

### `carrier-relationship-management` — 承运商关系管理
管理承运商组合、谈判运费、跟踪承运商绩效、分配货运和维护战略承运商关系。含评分卡框架、RFP 流程、市场情报和合规审查。

### `customs-trade-compliance` — 海关贸易合规
海关文档、关税分类、关税优化、受限方筛选和跨司法管辖区监管合规。含 HS 分类逻辑、Incoterms 应用、FTA 利用和处罚缓解。

### `energy-procurement` — 能源采购
电力和天然气采购、关税优化、需求管理、可再生 PPA 评估和多设施能源成本管理。含市场结构分析、对冲策略、负荷分析和可持续性报告框架。

### `inventory-demand-planning` — 需求计划
需求预测、安全库存优化、补货计划和促销提升估算。含预测方法选择、ABC/XYZ 分析、季节过渡管理和供应商谈判框架。

### `logistics-exception-management` — 物流异常管理
货运异常处理、货物延误、损坏、丢失和承运商争议。含升级协议、承运商特定行为、索赔流程和判断框架。

### `production-scheduling` — 生产调度
离散和批量制造的生产调度、工序排序、线平衡、换型优化和瓶颈解决。含 TOC/DBR、SMED、OEE 分析、中断响应框架和 ERP/MES 交互模式。

### `quality-nonconformance` — 质量不合格
受监管制造中的质量控制、不合格调查、根因分析、纠正措施和供应商质量管理。含 NCR 生命周期管理、CAPA 系统、SPC 解释和审计方法论。

### `returns-reverse-logistics` — 退货逆向物流
退货授权、接收和检查、处置决策、退款处理、欺诈检测和保修索赔管理。含分级框架、处置经济学、欺诈模式识别和供应商追索流程。

---

## 18. API 与集成

### `api-connector-builder` — API 连接器构建器
通过精确匹配目标仓库现有集成模式构建新 API 连接器或提供者。添加一个集成而不发明第二种架构时使用。

### `api-design` — API 设计
REST API 设计模式：资源命名、状态码、分页、过滤、错误响应、版本控制和限流。

### `mcp-server-patterns` — MCP 服务器模式
使用 Node/TypeScript SDK 构建 MCP 服务器：工具、资源、提示、Zod 验证、stdio vs 流式 HTTP。

### `agent-payment-x402` — Agent x402 支付
为 AI Agent 添加 x402 支付执行：每任务预算、支出控制和非托管钱包。支持 Base（agentwallet-sdk）和 X Layer（OKX Payments/OKX Agent Payments Protocol）。

### `mailtrap-email-integration` — Mailtrap 邮件集成
通过 Mailtrap Email API 集成事务邮件发送：沙箱测试、域名验证和 API 认证。

### `google-workspace-ops` — Google Workspace 运维
跨 Google Drive、Docs、Sheets 和 Slides 作为一个工作流表面操作：计划、跟踪器、演示文稿和共享文档。

---

## 19. 开发工具与工作流

### `git-workflow` — Git 工作流
分支策略、提交约定、merge vs rebase、冲突解决和协作开发最佳实践。

### `github-ops` — GitHub 运营
仓库运营、自动化和管理：Issue 分类、PR 管理、CI/CD 运营、发布管理、安全监控（gh CLI）。

### `jira-integration` — Jira 集成
检索 Jira 工单、分析需求、更新工单状态、添加评论或转换 Issue。通过 MCP 或直接 REST 调用提供 Jira API 模式。

### `code-tour` — 代码导览
创建 CodeTour `.tour` 文件：角色目标、步骤式导览、真实文件和行锚点。用于入职导览、架构导览、PR 导览、RCA 导览和结构化"解释如何工作"请求。

### `codebase-onboarding` — 代码库入职
分析陌生代码库并生成结构化入职指南：架构图、关键入口点、约定和入门 CLAUDE.md。

### `architecture-decision-records` — 架构决策记录
捕获 Claude Code 会话期间的架构决策为结构化 ADR。自动检测决策时刻、记录上下文、考虑的替代方案和理由。

### `inherit-legacy-style` — 继承遗留风格
遗留项目风格继承技能。将 AI 编码 Agent 入职手写遗留项目时使用，防止"风格漂移"。

### `intent-driven-development` — 意图驱动开发
将模糊或高影响的产品和工程变更转化为可范围化、可验证的验收标准，在实现之前或同时进行。

### `product-capability` — 产品能力
将 PRD 意图、路线图要求或产品讨论转化为实现就绪的能力计划：暴露约束、不变量、接口和未解决决策。

### `product-lens` — 产品透镜
在构建前验证"为什么"：运行产品诊断和方向压力测试。

### `generating-python-installer` — Python 安装包生成
商业级 Python Windows 安装包：Nuitka 极限编译、dist 瘦身、DLL 足迹分析和 Inno Setup 打包。

### `nutrient-document-processing` — Nutrient 文档处理
使用 Nutrient DWS API 处理、转换、OCR、提取、编辑、签名和填充文档（PDF、DOCX、XLSX、PPTX、HTML 和图片）。

### `opensource-pipeline` — 开源管道
Fork→净化→打包私有项目以安全公开发布。链式 3 个 Agent（Forker、Sanitizer、Packager）。

### `hermes-imports` — Hermes 导入
将本地 Hermes 操作工作流转换为净化 ECC 技能和发布包工件。

### `visa-doc-translate` — 签证文档翻译
将签证申请文档（图片）翻译为英文并创建双语 PDF。

### `perl-patterns` — Perl 模式
现代 Perl 5.36+ 惯用法、最佳实践和约定。

### `perl-security` — Perl 安全
综合 Perl 安全：污点模式、输入验证、安全进程执行、DBI 参数化查询、Web 安全和 perlcritic 安全策略。

### `perl-testing` — Perl 测试
测试模式：Test2::V0、Test::More、prove 运行器、mock、Devel::Cover 覆盖率和 TDD 方法论。

---

## 20. 代码质量与审查

### `flutter-dart-code-review` — Flutter/Dart 代码审查
库无关的 Flutter/Dart 代码审查清单：Widget 最佳实践、状态管理模式、Dart 惯用法、性能、无障碍、安全和 Clean Architecture。

### `coding-standards` — 编码标准
跨项目基线编码约定：命名、可读性、不可变性和代码质量审查。

### `config-gc` — 配置垃圾回收
定期扫描 `~/.claude`（技能、记忆、Hook、权限、MCP 服务器、缓存）的冗余、过时、孤立或低价值项，然后引导用户确认删除清理。

### `configure-ecc` — 配置 ECC
ECC 交互式安装器：引导用户选择和安装技能和规则到用户级或项目级目录，验证路径，可选优化已安装文件。

### `rules-distill` — 规则蒸馏
扫描技能提取跨领域原则并将其蒸馏为规则——追加、修订或创建新规则文件。

### `skill-scout` — 技能搜索
在创建新技能之前搜索现有本地、市场、GitHub 和 Web 技能来源。

### `skill-stocktake` — 技能盘点
审计 Claude 技能和命令的质量。支持快速扫描（仅变更技能）和完整盘点模式。

### `skill-comply` — 技能合规
可视化技能、规则和 Agent 定义是否实际被遵循：自动生成 3 个提示严格级别的场景、运行 Agent、分类行为序列并报告合规率。

### `repo-scan` — 仓库扫描
跨技术栈源码资产审计：分类每个文件、检测嵌入式第三方库、交付每个模块的四级可操作判定及交互式 HTML 报告。

### `workspace-surface-audit` — 工作区表面审计
审计活跃仓库、MCP 服务器、插件、连接器、环境表面和 Harness 设置，然后推荐最高价值的 ECC 原生技能、Hook、Agent 和操作工作流。

### `ecc-guide` — ECC 指南
通过读取实时仓库表面引导用户了解 ECC 当前的 Agent、技能、命令、Hook、规则、安装配置和项目入职。

### `ecc-recipes` — ECC 配方
将描述的工作流映射到正确的 ECC 命令组及运行顺序和停止条件。在平面命令目录上添加分组+运行顺序+停止层次。

### `ecc-tools-cost-audit` — ECC 工具成本审计
ECC 工具消耗和计费审计的证据优先工作流：调查失控 PR 创建、配额绕过、高价模型泄漏、重复作业或 ECC 工具仓库的 GitHub App 成本激增。

### `automation-audit-ops` — 自动化审计运维
ECC 的证据优先自动化清单和重叠审计工作流：哪些作业、Hook、连接器、MCP 服务器或包装器是活跃/损坏/冗余/缺失的。

### `hookify-rules` — Hookify 规则
创建 Hookify 规则、编写 Hook 规则、配置 Hookify 或需要 Hookify 规则语法和模式指导。

### `delivery-gate` — 交付门禁
Stop Hook：阻止 Claude 在质量检查通过前结束。检测合理化模式、过时学习日志和低磁盘空间。通过机械强制学习捕获习惯补充自我审计。

### `growth-log` — 成长日志
复杂任务、失败后或审查所学内容时使用。教如何编写提取可复用模式的成长日志——而非日记条目。

### `search-first` — 搜索优先
先搜索后编码工作流。在编写自定义代码前搜索现有工具、库和模式。调用 Researcher Agent。

### `strategic-compact` — 战略压缩
建议在逻辑间隔手动压缩上下文，以在任务阶段中保持上下文而非任意自动压缩。

---

## 21. 探索与搜索

### `blender-motion-state-inspection` — Blender 运动状态检查
检查 Blender 角色、绑定、姿势、动画重定向、地面接触、朝向方向或模型与运动对齐（仅截图不够时）。

### `openclaw-persona-forge` — OpenClaw 角色锻造
为 OpenClaw AI Agent 锻造完整龙虾灵魂方案。根据用户偏好或随机抽卡输出身份定位、灵魂描述 (SOUL.md)、角色化底线规则、名字和头像生图提示词。

### `x-api` — X/Twitter API
X/Twitter API 集成：发帖、线程、读取时间线、搜索和分析。涵盖 OAuth 认证模式、速率限制和平台原生内容发布。

### `knowledge-ops` — 知识库运维
跨多个存储层的知识库管理、摄取、同步和检索：本地文件、MCP 内存、向量存储、Git 仓库。

### `cost-tracking` — 成本跟踪
从本地 ECC 成本跟踪器指标日志跟踪和报告 Claude Code Token 使用、支出和预算。

### `prompt-optimizer` — 提示优化器
分析原始提示、识别意图和差距、匹配 ECC 组件（技能/命令/Agent/Hook），并输出即用优化提示。仅顾问角色——永不执行任务本身。

---

## 22. 通信与协作

### `email-ops` — 邮件运维
ECC 的证据优先邮箱分类、起草、发送验证和已发送邮件安全跟进工作流。

### `messages-ops` — 消息运维
ECC 的证据优先实时消息工作流：读取短信/DM、恢复一次性验证码、回复前检查线程、或证明实际检查了哪个消息源。

### `unified-notifications-ops` — 统一通知运维
跨 GitHub、Linear、桌面提醒、Hook 和连接的通信表面作为 ECC 原生工作流操作通知。

### `connections-optimizer` — 人脉优化器
重组 X 和 LinkedIn 网络：审查优先修剪、添加/关注推荐和频道特定暖外联。

### `social-graph-ranker` — 社交图谱排名器
跨 X 和 LinkedIn 的加权社交图谱排名：暖介绍发现、桥接评分和网络缺口分析。

---

## 23. 终端与系统

### `terminal-ops` — 终端运维
ECC 的证据优先仓库执行工作流：命令运行、仓库检查、CI 失败调试或窄修复推送及执行和验证的确切证明。

### `nanoclaw-repl` — NanoClaw REPL
操作和扩展 NanoClaw v2，ECC 的零依赖会话感知 REPL（构建于 `claude -p`）。

### `regex-vs-llm-structured-text` — 正则 vs LLM 结构化文本
在解析结构化文本时选择正则还是 LLM 的决策框架——从正则开始，仅对低置信度边缘情况添加 LLM。

---

## 24. 架构设计

### `hexagonal-architecture` — 六边形架构
设计、实现和重构 Ports & Adapters 系统：清晰领域边界、依赖反转和跨 TypeScript、Java、Kotlin 和 Go 服务的可测试用例编排。

### `error-handling` — 错误处理
跨 TypeScript、Python 和 Go 的健壮错误处理模式。涵盖类型化错误、错误边界、重试、熔断和面向用户的错误消息。

### `api-design` — API 设计
REST API 设计模式：资源命名、状态码、分页、过滤、错误响应、版本控制和限流（生产 API）。

---

## 25. 其他

### `agent-sort` — Agent 排序
为特定仓库构建证据驱动的 ECC 安装计划：将技能、命令、规则、Hook 和附加组件分类为 DAILY vs LIBRARY 桶。

### `council` — 委员会
为模糊决策、权衡和 go/no-go 调用召开四声部委员会。当存在多条有效路径且需要结构化分歧后再做选择时使用。

### `blender-motion-state-inspection` — Blender 动作状态检查
检查 Blender 角色、绑定、姿势、动画重定向、地面接触、朝向方向或模型与动作对齐（仅截图不够时）。

### `openclaw-persona-forge` — OpenClaw 角色锻造
为 OpenClaw AI Agent 锻造完整龙虾灵魂方案。根据用户偏好或随机抽卡输出身份定位、灵魂描述、角色化底线规则、名字和头像生图提示词。（中文）

### `x-api` — X/Twitter API
X/Twitter API 集成：发帖、线程、读取时间线、搜索和分析。涵盖 OAuth 认证模式、速率限制和平台原生内容发布。

### `google-workspace-ops` — Google Workspace 运维
跨 Google Drive、Docs、Sheets 和 Slides 运维。

### `knowledge-ops` — 知识库运维
跨多个存储层的知识库管理、摄取、同步和检索：本地文件、MCP 内存、向量存储、Git 仓库。

---

## 26. 内置子 Agent 角色

通过 `task` 工具可调用的专业子 Agent（部分只读用于调研，其余可编辑）：

### 调研类（只读）

| Agent | 说明 |
|---|---|
| `architect` | 软件架构师——系统设计、可扩展性和技术决策 |
| `code-explorer` | 代码探索者——追踪执行路径、映射架构层 |
| `planner` | 规划专家——复杂功能和重构的计划制定 |
| `scout` | 快速侦察——压缩上下文，批量搜索，发现阶段专用 |
| `comment-analyzer` | 注释分析——代码注释准确性/完整性/可维护性 |
| `conversation-analyzer` | 对话分析——从对话转录发现值得 Hook 预防的行为 |
| `docs-lookup` | 文档查找——Context7 MCP 获取最新库/框架文档 |
| `healthcare-reviewer` | 医疗代码审查——临床安全/CDSS 准确性/PHI 合规 |
| `homelab-architect` | 家庭网络架构师——从硬件清单设计网络计划 |
| `librarian` | 图书管理员——阅读源码研究外部库和 API |
| `network-architect` | 网络架构师——企业/多站点网络架构设计 |
| `network-config-reviewer` | 网络配置审查——路由器/交换机配置安全审查 |
| `type-design-analyzer` | 类型设计分析——封装/不变量表达/有用性/强制分析 |

### 审查类

| Agent | 说明 |
|---|---|
| `code-reviewer` | 通用代码审查——质量/安全/可维护性 |
| `security-reviewer` | 安全审查——用户输入/认证/API/密钥/OWASP Top 10 |
| `python-reviewer` | Python 审查——PEP 8/惯用法/类型提示/安全/性能 |
| `react-reviewer` | React 审查——Hook 正确性/性能/Server-Client 边界/无障碍 |
| `vue-reviewer` | Vue 审查——Composition API/响应式陷阱/组件架构/安全 |
| `typescript-reviewer` | TS/JS 审查——类型安全/异步正确性/安全/惯用模式 |
| `go-reviewer` | Go 审查——惯用 Go/并发/错误处理/性能 |
| `rust-reviewer` | Rust 审查——所有权/生命周期/unsafe/惯用模式 |
| `java-reviewer` | Java 审查——Spring Boot/Quarkus 自动检测 |
| `kotlin-reviewer` | Kotlin 审查——协程安全/Compose/Clean Architecture |
| `swift-reviewer` | Swift 审查——协议导向/ARC/并发/惯用模式 |
| `csharp-reviewer` | C# 审查——.NET 约定/异步/nullable/安全 |
| `cpp-reviewer` | C++ 审查——内存安全/现代 C++/并发/性能 |
| `fsharp-reviewer` | F# 审查——函数惯用法/类型安全/模式匹配 |
| `php-reviewer` | PHP 审查——PSR-12/类型系统/Eloquent/安全 |
| `django-reviewer` | Django 审查——ORM 正确性/DRF/迁移安全/安全配置 |
| `fastapi-reviewer` | FastAPI 审查——异步/DI/Pydantic/安全/OpenAPI |
| `flutter-reviewer` | Flutter/Dart 审查——Widget/状态管理/性能/无障碍 |
| `database-reviewer` | 数据库专家——PostgreSQL 查询优化/Schema/安全 |
| `mle-reviewer` | MLE 审查——数据合约/特征管道/训练/评估/服务 |
| `network-troubleshooter` | 网络故障排除——OSI 层诊断/根因分析 |

### 构建修复类

| Agent | 说明 |
|---|---|
| `build-error-resolver` | 通用构建错误修复 |
| `react-build-resolver` | React 构建修复——Vite/Webpack/Next.js/CRA |
| `go-build-resolver` | Go 构建修复——build/vet/linter |
| `rust-build-resolver` | Rust 构建修复——cargo/borrow checker |
| `java-build-resolver` | Java 构建修复——Maven/Gradle/Spring Boot/Quarkus |
| `kotlin-build-resolver` | Kotlin 构建修复——Gradle/编译器 |
| `swift-build-resolver` | Swift 构建修复——Xcode/SPM/代码签名 |
| `dart-build-resolver` | Dart/Flutter 构建修复——analyze/pub/编译 |
| `django-build-resolver` | Django 构建修复——pip/Poetry/迁移/import |
| `cpp-build-resolver` | C++ 构建修复——CMake/链接/模板错误 |
| `pytorch-build-resolver` | PyTorch 运行时修复——张量/设备/梯度/DataLoader |

### 执行类

| Agent | 说明 |
|---|---|
| `task` | 通用子 Agent——完全能力委托多步任务 |
| `tdd-guide` | TDD 引导——强制先写测试，80%+ 覆盖率 |
| `e2e-runner` | E2E 测试——Playwright 自动化 |
| `performance-optimizer` | 性能优化——瓶颈识别/打包体积/内存泄漏 |
| `code-simplifier` | 代码简化——清晰性/一致性/可维护性 |
| `refactor-cleaner` | 死代码清理——knip/depcheck/ts-prune |
| `doc-updater` | 文档更新——CODEMAPS/README/指南 |
| `spec-miner` | Spec 提取——从现有代码提取行为 Spec |
| `designer` | UI/UX 设计实现/审查 |
| `marketing-agent` | 营销策略和文案 |
| `loop-operator` | 自主循环运维——监控和干预 |
| `harness-optimizer` | Harness 配置优化——可靠性/成本/吞吐 |

### GAN 多 Agent 构建

| Agent | 说明 |
|---|---|
| `gan-planner` | 规划——一句话提示→完整产品规格（功能/冲刺/评估标准/设计方向） |
| `gan-generator` | 生成器——按规格实现功能，读取评估反馈迭代 |
| `gan-evaluator` | 评估器——Playwright 测试、评分、反馈 |

### 开源管道

| Agent | 说明 |
|---|---|
| `opensource-forker` | Fork——复制文件、剥离密钥和 PII |
| `opensource-sanitizer` | 净化验证——扫描 20+ 模式、PASS/FAIL 报告 |
| `opensource-packager` | 打包——CLAUDE.md/setup.sh/README/LICENSE/CONTRIBUTING |

### 特殊

| Agent | 说明 |
|---|---|
| `sonic` | 低推理 Agent——纯机械更新或数据采集 |
| `agent-evaluator` | Agent 输出评估——5 轴质量评分 |
| `a11y-architect` | 无障碍架构师——WCAG 2.2 合规 |
| `chief-of-staff` | 通讯幕僚长——邮件/Slack/LINE 分类和回复 |
| `silent-failure-hunter` | 静默失败猎人——审查吞掉的错误 |
| `pr-test-analyzer` | PR 测试分析——行为覆盖和 Bug 预防 |
| `seo-specialist` | SEO 专家——技术审计/结构化数据/Core Web Vitals |
| `harmonyos-app-resolver` | 鸿蒙应用开发——ArkTS/ArkUI V2 |

---

## 附录：可用 MCP 服务器

当前会话可用：

| MCP 服务器 | 工具数 | 说明 |
|---|---|---|
| `ecc:chrome-devtools` | 29 | Chrome DevTools 协议——浏览器自动化、调试、性能分析 |
| `node_repl` | 3 | 持久 Node.js REPL——JavaScript 执行环境 |
| `web-reader` | 1 | Web 内容读取器 |
| `web-search-prime` | 1 | Web 搜索 |
| `zai-mcp-server` | 8 | Zai MCP 服务器 |
| `zread` | 3 | GitHub 仓库读取——结构/文件/文档搜索 |

---

> **提示**: 所有技能均通过自然语言描述触发，无需精确命令。直接告诉 Claude Code 你想做什么，它会自动匹配最合适的技能和 Agent 组合。
