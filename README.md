# NetConfig

[简体中文](README_CN.md)

NetConfig is a lightweight, high-performance, cross-platform command-line tool written in Rust. It retrieves, parses, and aligns comprehensive network interface topology and configuration details across Windows, Linux, and macOS. 

Unlike standard tools, NetConfig intelligently identifies the primary network interface (responsible for active internet traffic) using native routing metrics and presents the details in a highly structured, tree-like terminal layout or in structured JSON.

## Features

- Primary Interface Auto-Detection: Automatically resolves the active gateway and primary network interface based on OS routing metrics and system APIs.
- Comprehensive Interface Data:
  - Network state: Up, Down, Testing, or Unknown.
  - Physical medium: Ethernet, Wi-Fi, Loopback, Virtual/Bridge, Tunnel/VPN, and others.
  - Hardware addresses: MAC address detection and formatting.
  - Performance data: Active link speed (Gbps, Mbps, Kbps) and real-time traffic statistics (both received and transmitted bytes/packets).
- Deep IP Topology: Fully parses multiple IPv4 and IPv6 bindings, subnet masks, prefix lengths, and corresponding gateway paths.
- System DNS Diagnostics: Resolves and associates active system DNS servers.
- Flexible Outputs:
  - Polished terminal layout with clean tree-like text alignments.
  - Structured, pretty-printed JSON output for easy shell piping and automation.
- Built-in Internationalization: Supports English and Chinese. Automatically detects the system language or allows manual overrides. Uses custom string width calculations to ensure perfect alignment for double-width East Asian characters in the terminal.
- Lightweight & Safe: Zero complex external runtime dependencies; leverages memory-safe Rust and native OS system calls.

## Platform Implementations

NetConfig relies on native operating system APIs for maximum performance and accuracy:

- Windows: Uses the IP Helper (IPHLPAPI) library. Resolves the primary interface via GetBestInterface using a mock target IP address. Extracts adapters, unicast IPs, prefixes, gateways, and DNS servers using GetAdaptersAddresses. Queries traffic throughput statistics and hardware speeds using GetIfEntry2.
- Linux: Parses /proc/net/route and /proc/net/ipv6_route to evaluate routing metrics and find the primary gateway. Queries system interfaces and IP details using libc::getifaddrs. Retrieves interface operational state, media type, link speed, MAC address, and traffic counters directly from /sys/class/net/<interface>/. Parses /etc/resolv.conf for DNS.
- macOS: Detects the active interface by running route get default and route get -inet6 default and parsing the gateway. Uses networksetup -listallhardwareports to distinguish physical media. Uses libc::getifaddrs to list IP bindings, and parses AF_LINK for MAC addresses and hardware metrics. Parses /etc/resolv.conf for DNS.

## Installation

### Precompiled Binaries

Precompiled binaries for various platforms are available in the GitHub Releases:

- Linux:
  - AMD64 (64-bit Intel/AMD): net-config-linux-amd64
  - ARM64 (64-bit ARM): net-config-linux-arm64
- macOS:
  - AMD64 (64-bit Intel): net-config-macos-amd64
  - ARM64 (64-bit Apple Silicon): net-config-macos-arm64
- Windows:
  - AMD64 (64-bit Intel/AMD): net-config-windows-amd64.exe
  - ARM64 (64-bit ARM): net-config-windows-arm64.exe

### Building from Source

To build NetConfig from source, you need a standard Rust toolchain installed:

```bash
git clone https://github.com/your-username/net-config.git
cd net-config
cargo build --release
```

The compiled binary will be located at target/release/net-config (or target/release/net-config.exe on Windows).

## Usage

```text
Usage: net-config [options]

Options:
  -a, --all      Show all network interfaces (default shows primary/default interface only)
  -j, --json     Output results in JSON format
  -h, --help     Show help information
  -l, --lang     Specify language, 'zh' (Chinese) or 'en' (English)
```

### CLI Output Example

Below is an example of the text representation in English:

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

### JSON Output Example

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

## Development

For developers, a pre-configured Docker-based Linux environment with Nix package manager is available. Refer to README_DEV.md for startup options, remote SSH connections, and benchmarking details.

## License

This project is dual-licensed under:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
