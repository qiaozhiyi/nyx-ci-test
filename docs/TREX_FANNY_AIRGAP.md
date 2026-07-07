# T-REX vs Fanny · 空气间隙跨越能力对比

> **制定:** 2026-07-07 · **参考:** Equation Group Fanny (2008) · ESET Jumping the Air Gap (2021) · ACM Bridgeware Survey (2023) · Hak5 Keystroke Reflection (2026) · APT37 Ruby Jumper (2026)

---

## 0. Fanny 蠕虫核心能力回顾（Equation Group / NSA TAO）

Fanny 是 Equation Group 在 2008 年部署的空气间隙跨越蠕虫。其核心设计是 **USB 双向隐蔽信道**：

| 能力 | Fanny 实现 | T-REX v2 计划 |
|------|-----------|--------------|
| **USB 隐蔽存储** | FAT16/32 原始分区上的 1MB 隐藏区域，自定义 FAT 驱动，RC4 加密 | ❌ 缺失 |
| **空气间隙跨越** | USB 插入 → 自动感染 → 收集数据 → USB 拔出 → 插入联网主机 → 外传 | ❌ 缺失 |
| **双向隐蔽信道** | 命令通过 USB 下发到气隙主机，数据通过 USB 回传 | ❌ 缺失 |
| **网络拓扑映射** | 扫描气隙网络 → 构建主机列表 → 存储在 USB 隐藏区 | ❌ 缺失 |
| **LNK 漏洞自动运行** | CVE-2010-2568 (Stuxnet LNK) 实现插入即执行 | ⚠️ 现代 Windows 已禁用 AutoRun |
| **系统信息收集** | OS 版本、补丁、主机名、用户名、进程列表 | ✅ T-REX T0-T3 已覆盖 |
| **内核提权** | 两个本地提权漏洞 | ⚠️ 需 N-day LPE 集成 |
| **RC4 加密** | 硬编码密钥 | ✅ X25519+ML-KEM-1024 混合 |
| **自毁** | 无 | ✅ T-REX v2 计划中 |

---

## 1. T-REX 需要补齐的 Fanny 能力

### 1.1 USB 隐蔽存储层（Fanny 的核心创新）

**Fanny 做法:** 在 FAT16/32 USB 驱动器的原始分区上创建 1MB 隐藏区域——绕过文件系统，直接读写原始扇区。自定义 FAT 驱动读写，操作系统完全不可见。

**T-REX 2026 升级:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    T-REX USB Hidden Storage v2                   │
│                                                                  │
│  方案 A: 原始扇区隐藏（Fanny 模式）                                │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ FAT32/NTFS Volume                                            │ │
│  │ ┌─────────┐ ┌─────────────────┐ ┌──────────────────────────┐ │ │
│  │ │  Boot   │ │  FAT / MFT      │ │  正常文件区域              │ │ │
│  │ │  Sector │ │  Tables          │ │  (可见)                   │ │ │
│  │ └─────────┘ └─────────────────┘ └──────────────────────────┘ │ │
│  │                                                               │ │
│  │  ▼ 最后 2048 扇区 (1MB) ▼                                     │ │
│  │ ┌───────────────────────────────────────────────────────────┐ │ │
│  │ │  T-REX Hidden Area (1 MB)                                  │ │ │
│  │ │  ┌──────────┬──────────────┬────────────────────────────┐ │ │ │
│  │ │  │ Magic    │  Report #1   │  Report #2   ...           │ │ │ │
│  │ │  │ 0x54524558│ (encrypted)  │  (encrypted)               │ │ │ │
│  │ │  │ ("TREX") │              │                            │ │ │ │
│  │ │  └──────────┴──────────────┴────────────────────────────┘ │ │ │
│  │ └───────────────────────────────────────────────────────────┘ │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  方案 B: NTFS Alternate Data Stream (仅 NTFS)                     │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  正常文件: report.docx (0 bytes)                             │ │
│  │  ADS 隐藏: report.docx:trex.dat (加密报告)                    │ │
│  │  优点: 无需原始扇区访问，`dir /r` 不可见（需特殊工具）         │ │
│  │  缺点: NTFS-only, 某些 EDR 监控 ADS 创建                     │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  方案 C: 自定义文件系统 + 隐藏卷（2026 升级）                      │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │  USB 插入 → T-REX 检测 → 在未分配空间中创建微型 ext4 分区     │ │
│  │  → 挂载为隐藏卷 → 加密读写 → USB 拔出 → 分区对 OS 不可见     │ │
│  │  优点: 完全不可见，跨文件系统                                   │ │
│  │  实现: `NtCreateFile("\\\\.\\PhysicalDriveX")` 直写磁盘       │ │
│  └─────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 空气间隙双向信道

```
                    ┌─────────────────────────────────┐
                    │     T-REX Air-Gap Bridging       │
                    │                                  │
  互联网 ←──────────┼──────────────────────────────┐   │
  (C2 服务器)        │                              │   │
                    │  ┌──────────────────────┐    │   │
                    │  │  Phase 1: 联网主机    │    │   │
                    │  │                      │    │   │
                    │  │  T-REX Probe 注入    │    │   │
                    │  │  ↓                    │    │   │
                    │  │  监控 USB 插入事件   │    │   │
                    │  │  ↓                    │    │   │
                    │  │  USB 插入 → 感染    │    │   │
                    │  │  写入隐蔽存储:       │    │   │
                    │  │  - 侦察模块 DLL     │    │   │
                    │  │  - 任务配置文件     │    │   │
                    │  │  - ML-KEM 公钥      │    │   │
                    │  └──────────┬───────────┘    │   │
                    │             │                 │   │
                    │     ┌───────▼───────────┐     │   │
                    │     │   USB 物理移动     │     │   │
                    │     └───────┬───────────┘     │   │
                    │             │                 │   │
                    │  ┌──────────▼───────────┐     │   │
                    │  │  Phase 2: 气隙主机    │     │   │
                    │  │                      │     │   │
                    │  │  USB 插入 (手动)     │     │   │
                    │  │  ↓                    │     │   │
                    │  │  T-REX 自动检测      │     │   │
                    │  │  隐蔽存储 → 加载 DLL │     │   │
                    │  │  ↓                    │     │   │
                    │  │  执行侦察:            │     │   │
                    │  │  - 网络拓扑扫描      │     │   │
                    │  │  - 主机信息收集      │     │   │
                    │  │  - EDR/AV 探测       │     │   │
                    │  │  - 文件枚举          │     │   │
                    │  │  ↓                    │     │   │
                    │  │  加密报告 → 隐蔽存储 │     │   │
                    │  └──────────┬───────────┘     │   │
                    │             │                 │   │
                    │     ┌───────▼───────────┐     │   │
                    │     │   USB 物理移动     │     │   │
                    │     │   (返回路径)       │     │   │
                    │     └───────┬───────────┘     │   │
                    │             │                 │   │
                    │  ┌──────────▼───────────┐     │   │
                    │  │  Phase 3: 联网主机    │     │   │
                    │  │                      │     │   │
                    │  │  T-REX 检测加密报告  │     │   │
                    │  │  ↓                    │     │   │
                    │  │  外传到 C2 (网络)    │     │   │
                    │  │  ↓                    │     │   │
                    │  │  自毁                 │     │   │
                    │  └──────────────────────┘     │   │
                    └─────────────────────────────────┘
```

### 1.3 空气间隙网络拓扑映射

> **Fanny 做法:** 扫描气隙网络 → 构建可达主机列表 → 存储在 USB 隐蔽区 → 带回联网主机

**T-REX 2026 升级:**

| 技术 | 协议 | 零流量？ | 检测风险 |
|------|------|---------|---------|
| **被动嗅探** | ARP / NDP / CDP / LLDP / SSDP / DHCP | ✅ 完全被动 | 零 |
| **LLMNR 投毒** | LLMNR / NBT-NS / mDNS 响应欺骗 | ⚠️ 主动 | 中等 |
| **WPAD 劫持** | WPAD DHCP Inform + PAC 注入 | ⚠️ 主动 | 中等 |
| **TTL 路由追踪** | ICMP TTL 递增 (Screamer 2026 模式) | ⚠️ 主动 | 低 |
| **NetBIOS 浏览** | NetServerEnum / NetShareEnum | ⚠️ 主动 | 低 |
| **LDAP 匿名查询** | `(objectClass=computer)` 无认证 | ⚠️ 主动 | 极低 |

```rust
// trex/modules/airgap/recon.rs

pub struct AirGapRecon {
    pub discovered_hosts: Vec<DiscoveredHost>,
    pub network_segments: Vec<NetworkSegment>,
    pub gateway_paths: Vec<GatewayPath>,
}

impl AirGapRecon {
    /// Passive: sniff ARP/NDP/mDNS/DHCP from the wire
    fn passive_sniff(&mut self, interface: &Interface, duration_secs: u32);

    /// Active: TTL-based topology discovery (Screamer 2026)
    fn ttl_discovery(&mut self, start_subnet: Ipv4Addr);

    /// Active: LLMNR/NBT-NS query → map Windows hosts
    fn llmnr_probe(&mut self, target_subnets: &[Ipv4Addr]);

    /// Active: LDAP anonymous bind → enumerate domain computers
    fn ldap_enum_computers(&mut self, domain_controller: &str);

    /// Encrypt + store to USB hidden storage
    fn persist_to_usb(&self, usb_handle: &UsbHiddenStorage);
}
```

### 1.4 2026 年空气间隙外传新手段

| 信道 | 带宽 | 距离 | 隐蔽性 | 硬件要求 |
|------|------|------|--------|---------|
| **USB 隐蔽存储** (Fanny 经典) | 无限 (受 USB 容量限制) | 物理传输 | ★★★★★ | USB 端口 |
| **超声声波** (18-24 kHz) | ~20 bit/s | 15米 | ★★★★☆ | 扬声器/麦克风 |
| **LED 光信号** (HDD/键盘 LED) | ~4000 bit/s (HDD LED) | 视线 | ★★★☆☆ | 光传感器/摄像头 |
| **电磁辐射** (TEMPEST) | ~100 bit/s | 2米 | ★★★★★ | SDR 接收器 |
| **PIXHELL 像素噪声** (2024) | ~5 bit/s | 2米 | ★★★★☆ | LCD 屏幕 |
| **BadUSB HID 反射** (2026) | ~200 byte/s | 零 (同机) | ★★★★★ | 无需额外硬件 |
| **xLED 路由器 LED** (2024) | ~1 bit/s | 视线 | ★★★★☆ | 网络设备 LED |

**T-REX 应集成的 2026 空气间隙外传信道:**

```
优先级:
  1. USB 隐蔽存储 —— 最可靠，带宽无限，Fanny 验证 15 年
  2. BadUSB HID 反射 —— 无需额外硬件，利用 Caps/Num/Scroll 锁键 LED
  3. 超声声波 —— 如果气隙主机有扬声器+麦克风
  4. HDD LED 光信号 —— 如果气隙主机有 HDD LED
```

### 1.5 BadUSB / HID 键盘反射（2026 前沿）

> **Hak5 Keystroke Reflection (2026):** 利用 Caps/Num/Scroll 锁键 LED 状态作为隐蔽外传信道。无需 USB 大容量存储暴露。

**攻击流程:**
1. T-REX 在气隙主机上运行
2. 将侦察报告编码为 Caps/Num/Scroll 锁键序列
3. 模拟键盘 HID 设备 → 发送编码的锁键按键
4. 外部 Rubber Ducky / Arduino 监听 USB HID OUT endpoint
5. 解码锁键状态 → 恢复侦察报告 → 存储在外部设备

**T-REX 实现:**
```rust
// trex/modules/airgap/hid_exfil.rs

/// Encode report bytes into lock-key toggle sequence.
/// Each byte = 8 bits → 8 CapsLock toggles.
/// Bandwidth: ~200 bytes/sec (25 toggles/sec × 1 bit/toggle)
pub fn encode_to_lock_keys(data: &[u8]) -> Vec<LockKeyToggle> {
    let mut toggles = Vec::new();
    for &byte in data {
        for bit in 0..8 {
            toggles.push(if (byte >> bit) & 1 == 1 {
                LockKeyToggle::CapsLockOn
            } else {
                LockKeyToggle::CapsLockOff
            });
        }
    }
    toggles
}

/// Send via SendInput API (simulate keyboard input)
pub fn transmit_via_send_input(toggles: &[LockKeyToggle]) {
    for toggle in toggles {
        let mut input = INPUT { type_: INPUT_KEYBOARD, ... };
        input.ki.wVk = VK_CAPITAL;
        input.ki.dwFlags = match toggle {
            LockKeyToggle::CapsLockOn => 0,
            LockKeyToggle::CapsLockOff => KEYEVENTF_KEYUP,
        };
        unsafe { SendInput(1, &input, size_of::<INPUT>()) };
    }
}
```

---

## 2. T-REX 空气间隙能力升级清单

```
P8e. USB 隐蔽存储层 (3 周)
  ├── 原始扇区读写: \\\\.\\PhysicalDriveX → 末尾 2048 扇区
  ├── NTFS ADS: CreateFileW("file:trex.dat")
  ├── 自定义 FAT 驱动: 直接写 FAT 表 + 魔数标记
  ├── 加密: X25519+ML-KEM-1024 混合 → 隐蔽区数据
  └── 防检测: 避开 $UsnJrnl / $LogFile / MFT 记录

P8f. 空气间隙双向桥接 (2 周)
  ├── USB 插入检测: RegisterDeviceNotification(DBT_DEVICEARRIVAL)
  ├── 自动感染: 写入 DLL + 隐蔽存储到 USB
  ├── Phase 2 检测: USB 上存在报告文件 → 自动外传
  └── 任务传递: C2 → 联网主机 → USB → 气隙主机

P8g. 气隙网络拓扑映射 (2 周)
  ├── 被动嗅探: ARP/NDP/mDNS/DHCP/LLMNR/NBT-NS
  ├── TTL 路由追踪: Screamer 2026 模式
  ├── LDAP 匿名枚举: (objectClass=computer)
  ├── NetBIOS 浏览: NetServerEnum/NetShareEnum
  └── 拓扑可视化: DOT 格式输出

P8h. 2026 空气间隙外传信道 (2 周)
  ├── BadUSB HID 键盘反射 (优先级最高)
  ├── 超声声波外传 (18-24 kHz, 15m 范围)
  ├── HDD LED 光信号 (4000 bit/s)
  └── 信道自动选择: 根据可用硬件选择最优信道

P8i. 自毁 + USB 痕迹清除 (1 周)
  ├── USB 隐蔽区归零 → 扇区覆写 (3-pass)
  ├── MFT 条目覆盖
  ├── USN Journal 清理
  └── 自毁序列 (内存 + 磁盘)
```

---

## 3. Fanny vs T-REX 最终对比

| 能力 | Fanny (2008) | T-REX v2 (目标) | 升级 |
|------|-------------|----------------|------|
| **USB 隐蔽存储** | FAT 原始扇区, RC4 | 多模式 (扇区/ADS/隐藏卷), ML-KEM | ✅ |
| **空气间隙跨越** | USB 双向 | USB + 超声 + LED + HID | ✅✅✅ |
| **网络拓扑映射** | 基本扫描 | 被动嗅探 + TTL + LDAP + LLMNR | ✅✅ |
| **自动运行** | LNK 漏洞 | USB 插入检测 + 自动 DLL 加载 | ✅ |
| **系统侦察** | OS/补丁/进程 | 25 EDR 厂商 + CET/HVCI/CFG/mitigation | ✅✅ |
| **加密** | RC4 硬编码密钥 | X25519 + ML-KEM-1024 + ChaCha20 | ✅✅✅ |
| **自毁** | 无 | 5 步自毁 + USB 扇区覆写 | ✅✅ |
| **反取证** | 无 | USNJ/Prefetch/EventLog/MFT/Amcache | ✅✅ |
| **隐蔽外传** | 仅 USB | DoH/QUIC/MASQUE/DeadDrop + USB | ✅✅✅ |
| **载荷变形** | 无 | LLVM IR pass + 三编译目标 | ✅✅ |
| **后量子** | 无 | NIST FIPS 203/204/205/206 CNSA 2.0 | ✅✅✅ |
