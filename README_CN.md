# NetConfig

[English](README.md)

NetConfig 是一个用 Rust 编写的轻量级、高性能、跨平台网络接口拓扑分析命令行工具。它可以在 Windows、Linux 和 macOS 系统上检索、解析和精细排版对齐网络接口的完整拓扑结构和配置详情。

与普通网络工具不同，NetConfig 能够利用系统原生路由表指标和 API，智能识别系统的主网卡接口（即负责当前互联网流量的默认网卡），并以极具可读性的树状终端结构或结构化的 JSON 格式进行输出。

## 功能特性

- 智能主网卡识别：自动检测活动网关，并根据操作系统路由指标与 API 解析出最优的默认主网卡接口。
- 完整的网络接口信息：
  - 运行状态：已启用 (Up)、未启用 (Down)、测试中 (Testing) 或未知 (Unknown)。
  - 物理介质/接口类型：以太网、无线局域网 (Wi-Fi)、本地环回、虚拟网卡/网桥、隧道/VPN 以及其他类型。
  - 物理地址：MAC 地址的自动检测与格式化。
  - 速率与吞吐量：链路速度自动换算（Gbps、Mbps、Kbps）及实时的网络流量统计（接收和发送的字节数与数据包数）。
- 深入的 IP 拓扑解析：完整解析单个网卡上绑定的多个 IPv4 和 IPv6 地址配置，包括子网掩码、前缀长度和网关路径。
- 系统 DNS 诊断：自动提取系统当前处于活动状态的 DNS 服务器列表并进行关联展示。
- 灵活的输出格式：
  - 精美格式化的终端树状文本对齐排版。
  - 结构化的 JSON 序列化输出，便于 Shell 管道脚本调用及自动化运维。
- 内置多语言支持：支持英文和中文。可自动检测系统环境语言，也支持通过命令行参数手动切换。内置东亚宽字符宽度精确计算，确保中文字符在终端中完美对齐。
- 轻量级与安全：零复杂的外部运行时依赖，完全依托 Rust 内存安全特性与原生系统调用。

## 平台实现原理

NetConfig 深度集成各操作系统的原生底层 API，以保障最高的效率与准确性：

- Windows：调用 IP 助手 (IP Helper / IPHLPAPI) API。通过 GetBestInterface 传入模拟外部 IP 以确定当前主网卡索引；使用 GetAdaptersAddresses 接口一次性提取网络适配器、单播 IP 列表、前缀长度、网关和 DNS 服务器信息；通过 GetIfEntry2 获取物理网速和流量吞吐统计。
- Linux：解析 /proc/net/route 和 /proc/net/ipv6_route 路由文件，分析 Metric 路由权重以找出默认网关及对应的主网卡。使用 libc::getifaddrs 遍历 IP 地址和掩码列表。从 /sys/class/net/<interface>/ 目录下的虚拟文件中读取网卡状态、物理类型、链路速度、MAC 地址和流量统计。解析 /etc/resolv.conf 文件获取系统 DNS。
- macOS：通过运行 route get default 与 route get -inet6 default 命令并解析输出，智能确定主网卡名称及其网关。使用 networksetup -listallhardwareports 区分物理端口介质。通过 libc::getifaddrs 提取 IP 信息，从 AF_LINK 套接字结构中提取 MAC 地址、物理速度和网络吞吐。解析 /etc/resolv.conf 文件获取系统 DNS。

## 安装与编译

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
git clone https://github.com/your-username/net-config.git
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
 Link Speed    : 1.20 Gbps
 MAC Address   : 00:00:5E:00:53:01
 IPv4 Config   :
   [1] Address    : 192.168.1.100
       Subnet Mask: 255.255.255.0 (Prefix /24)
       Gateway    : 192.168.1.1
 IPv6 Config   :
   [1] Address    : fe80::1000:2000:3000:4000
       Prefix Len : /64
       Gateway    : fe80::1
 DNS Servers   :
   ├── 1.1.1.1
   └── 8.8.8.8
 Statistics    :
   ├── Received (Rx)   : 1.20 GiB (900000 packets)
   └── Transmitted (Tx): 320.50 MiB (250000 packets)

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
        "gateways": [
          "192.168.1.1"
        ]
      }
    ],
    "ipv6_addresses": [
      {
        "address": "fe80::1000:2000:3000:4000",
        "prefix_len": 64,
        "gateways": [
          "fe80::1"
        ]
      }
    ],
    "status": "Up",
    "interface_type": "WiFi",
    "link_speed": 1200000000,
    "dns_servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "statistics": {
      "rx_bytes": 1288490188,
      "tx_bytes": 336068608,
      "rx_packets": 900000,
      "tx_packets": 250000
    }
  },
  "other": []
}
```

## 开发者说明

对于有定制开发需求的用户，项目已提供基于 Docker 与 Nix 的一致性 Linux 开发环境。关于环境启动、SSH 远程连接及基准测试等详细步骤，请参见 README_DEV.md。

## 开源协议

本项目采用双重开源协议授权：

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
