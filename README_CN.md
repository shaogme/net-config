# NetConfig

[English](README.md)

NetConfig 是一个用 Rust 编写的轻量级、高性能、跨平台网络接口拓扑分析命令行工具。它可以在 Windows、Linux 和 macOS 系统上检索、解析和精细排版对齐网络接口的完整拓扑结构和配置详情。

与普通网络工具不同，NetConfig 能够利用系统原生路由表指标和 API，智能识别系统的主网卡接口（即负责当前互联网流量的默认网卡），并以极具可读性的树状终端结构或结构化的 JSON 格式进行输出。

## 功能特性

- 智能主网卡识别：自动检测活动网关，并根据操作系统路由指标与 API 解析出最优的默认主网卡接口。
- 协议栈分配来源检测：按地址保留手动配置、DHCPv4、DHCPv6、路由器通告、SLAAC、其他和未知来源；同一接口存在多种来源时标记为混合 (Mixed)，不会把缺少证据误报为静态。
- 完整的网络接口信息：
  - 运行状态：已启用 (Up)、未启用 (Down)、测试中 (Testing) 或未知 (Unknown)。
  - 物理介质/接口类型：以太网、无线局域网 (Wi-Fi)、本地环回、虚拟网卡/网桥、隧道/VPN 以及其他类型。
  - 物理地址：MAC 地址的自动检测与格式化。
  - 速率与吞吐量：链路速度自动换算（Gbps、Mbps、Kbps）及实时的网络流量统计（接收和发送的字节数与数据包数）。
- 深入的 IP 拓扑解析：完整解析单个网卡上绑定的多个 IPv4 和 IPv6 地址配置，包括子网掩码、前缀长度、接口路由、下一跳及地址级配置来源。
- 系统 DNS 诊断：独立采集系统解析配置，并为每个 DNS 服务器保留接口归属（可能未知）、来源和 `available/none/unavailable` 状态。
- 灵活的输出格式：
  - 精美格式化的终端树状文本对齐排版。
  - 结构化的 JSON 序列化输出，便于 Shell 管道脚本调用及自动化运维。
- 内置多语言支持：支持英文和中文。可自动检测系统环境语言，也支持通过命令行参数手动切换。内置东亚宽字符宽度精确计算，确保中文字符在终端中完美对齐。
- 轻量级与安全：零复杂的外部运行时依赖，完全依托 Rust 内存安全特性与原生系统调用。

## 平台实现原理

NetConfig 深度集成各操作系统的原生底层 API，以保障最高的效率与准确性：

- Windows：调用 IP 助手 (IP Helper / IPHLPAPI) API。通过 GetBestInterface 传入模拟外部 IP 以确定当前主网卡索引；使用 GetAdaptersAddresses 提取单播 IP 的 PrefixOrigin/SuffixOrigin，分别表达 DHCP、手动、路由器通告和 SLAAC，适配器 DHCP 标志不再覆盖地址级未知结果；DNS 作为带适配器归属的系统级结果输出。
- Linux：解析 /proc/net/route 和 /proc/net/ipv6_route 路由文件，保留目的前缀、下一跳、接口名和 Metric，并据此找出主网卡。使用 libc::getifaddrs 遍历 IP 地址和掩码列表，仅将租约中明确出现的地址标为 DHCP，IPv6 内核隐私/SLAAC 标志作为 SLAAC 证据，其他缺少证据的地址保留 Unknown。从 /sys/class/net/<interface>/ 目录下的虚拟文件中读取网卡状态、物理类型、链路速度、MAC 地址和流量统计。DNS 按 systemd-resolved、NetworkManager、resolv.conf 回退顺序采集，并保留来源和接口归属。
- macOS：通过 netstat -rn 读取 IPv4/IPv6 完整路由表，并以 route get default 与 route get -inet6 default 作为回退，保留 link-local 网关作用域和接口归属。使用 networksetup -listallhardwareports 区分物理端口介质。按接口缓存 ipconfig 的 DHCP/DHCPv6 探测，并从 ifconfig 的 autoconf/temporary 标志识别 SLAAC；没有证据时返回 Unknown。通过 libc::getifaddrs 提取 IP 信息，从 AF_LINK 套接字结构中提取 MAC 地址、物理速度和网络吞吐。DNS 优先解析 scutil --dns，失败时记录 resolv.conf 回退来源。

## 安装与编译

### 一键快速运行

您可以使用以下一行命令，自动检测系统架构并下载最新版本的二进制文件到当前目录：

**Linux**:
```bash
curl -sSL https://github.com/shaogme/net-config/releases/latest/download/net-config-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/;s/arm64/arm64/') -o net-config && chmod +x net-config && ./net-config
```

**macOS**:
```bash
curl -sSL https://github.com/shaogme/net-config/releases/latest/download/net-config-macos-$(uname -m | sed 's/x86_64/amd64/;s/arm64/arm64/') -o net-config && chmod +x net-config && ./net-config
```

**Windows (PowerShell)**:
```powershell
$arch = if ($env:PROCESSOR_ARCHITECTURE -match 'ARM|arch64') { 'arm64' } else { 'amd64' }; Invoke-WebRequest -Uri "https://github.com/shaogme/net-config/releases/latest/download/net-config-windows-$arch.exe" -OutFile "net-config.exe"; .\net-config.exe
```

### 预编译二进制程序

可以在 GitHub Releases 中直接下载适用于各平台的预编译程序：

- Linux:
  - AMD64 (64位 Intel/AMD 平台): net-config-linux-amd64
  - ARM64 (64位 ARM 平台): net-config-linux-arm64
- macOS:
  - AMD64 (64位 Intel 平台): net-config-macos-amd64
  - ARM64 (64位 Apple Silicon 平台): net-config-macos-arm64
- Windows:
  - AMD64 (64位 Intel/AMD 平台): net-config-windows-amd64.exe
  - ARM64 (64位 ARM 平台): net-config-windows-arm64.exe

### 从源码编译

要从源码编译 NetConfig，请确保您的系统中已安装标准 Rust 开发工具链：

```bash
git clone https://github.com/shaogme/net-config.git
cd net-config
cargo build --release
```

编译生成的二进制文件将保存在 target/release/net-config（Windows 下为 target/release/net-config.exe）。

## 命令行用法

```text
用法: net-config [options]

选项:
  -a, --all      显示所有网卡接口信息（默认仅显示主/默认网卡）
  -j, --json     以 JSON 格式输出结果
  -h, --help     显示帮助信息
  -l, --lang     手动指定语言，支持 'zh' (中文) 或 'en' (英文)
```

### 终端文本输出示例

以下为英文本地化时的控制台输出效果：

```text
==================================================================
 NetConfig - Cross-Platform Network Interface Topology Tool
==================================================================

[Primary Interface]
--------------------------------------------------
 Interface Name: en0
 Description   : en0
 Status        : Up
 Type          : Wi-Fi
 Allocation    : Mixed
 Link Speed    : 1.20 Gbps
 MAC Address   : 00:00:5E:00:53:01
 IPv4 Config   :
   [1] Address    : 192.168.1.100
       Subnet Mask: 255.255.255.0 (Prefix /24)
       Allocation : DHCPv4
 IPv6 Config   :
   [1] Address    : fe80::1000:2000:3000:4000
       Prefix Len : /64
       Allocation : Other
 Routes        :
   [1] Destination: Default
       Gateway    : 192.168.1.1
       Interface  : en0
       Metric     : 100
   [2] Destination: fe80::/64
       Gateway    : On-link / None
       Interface  : en0
       Metric     : 256
 Statistics    :
    ├── Received (Rx)   : 1.20 GiB (900000 packets)
    └── Transmitted (Tx): 320.50 MiB (250000 packets)

[System DNS]
 DNS Servers   :
   [1] Address    : 1.1.1.1
       Interface  : en0
       Source     : scutil

==================================================================
```

### JSON 输出示例

```json
{
  "primary": {
    "name": "en0",
    "description": "en0",
    "mac_address": "00:00:5E:00:53:01",
    "ipv4_addresses": [
      {
        "address": "192.168.1.100",
        "netmask": "255.255.255.0",
        "prefix_len": 24,
        "allocation": "dhcpv4"
      }
    ],
    "ipv6_addresses": [
      {
        "address": "fe80::1000:2000:3000:4000",
        "prefix_len": 64,
        "allocation": "other"
      }
    ],
    "routes": [
      {
        "family": "ipv4",
        "destination": "0.0.0.0",
        "prefix_len": 0,
        "gateway": "192.168.1.1",
        "gateway_scope": null,
        "interface": "en0",
        "metric": 100,
        "is_default": true
      },
      {
        "family": "ipv6",
        "destination": "fe80::",
        "prefix_len": 64,
        "gateway": null,
        "gateway_scope": null,
        "interface": "en0",
        "metric": 256,
        "is_default": false
      }
    ],
    "status": "Up",
    "interface_type": "WiFi",
    "allocation": "mixed",
    "link_speed": 1200000000,
    "statistics": {
      "rx_bytes": 1288490188,
      "tx_bytes": 336068608,
      "rx_packets": 900000,
      "tx_packets": 250000
    }
  },
  "other": [],
  "dns": {
    "status": "available",
    "servers": [
      {
        "address": "1.1.1.1",
        "interface": "en0",
        "source": "scutil"
      },
      {
        "address": "8.8.8.8",
        "interface": null,
        "source": "scutil"
      }
    ]
  }
}
```

## 开发者说明

对于有定制开发需求的用户，项目已提供基于 Docker 与 Nix 的一致性 Linux 开发环境。关于环境启动、SSH 远程连接及基准测试等详细步骤，请参见 README_DEV.md。

## 开源协议

本项目采用双重开源协议授权：

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
