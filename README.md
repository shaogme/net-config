# NetConfig

[简体中文](README_CN.md)

NetConfig is a lightweight, high-performance, cross-platform command-line tool written in Rust. It retrieves, parses, and aligns comprehensive network interface topology and configuration details across Windows, Linux, and macOS. 

Unlike standard tools, NetConfig intelligently identifies the primary network interface (responsible for active internet traffic) using native routing metrics and presents the details in a highly structured, tree-like terminal layout or in structured JSON.

## Features

- Primary Interface Auto-Detection: Automatically resolves the active gateway and primary network interface based on OS routing metrics and system APIs.
- Protocol Stack Allocation Sources: Preserves Manual, DHCPv4, DHCPv6, Router Advertisement, SLAAC, Other, and Unknown at address level; interfaces with multiple sources are reported as Mixed instead of being inferred as Static.
- Comprehensive Interface Data:
  - Network state: Up, Down, Testing, or Unknown.
  - Physical medium: Ethernet, Wi-Fi, Loopback, Virtual/Bridge, Tunnel/VPN, and others.
  - Hardware addresses: MAC address detection and formatting.
  - Performance data: Active link speed (Gbps, Mbps, Kbps) and real-time traffic statistics (both received and transmitted bytes/packets).
- Deep IP Topology: Fully parses multiple IPv4 and IPv6 bindings, subnet masks, prefix lengths, interface routes, next hops, and address-level allocation sources.
- System DNS Diagnostics: Collects DNS as an independent system result with server source, optional interface association, and available/none/unavailable status.
- Flexible Outputs:
  - Polished terminal layout with clean tree-like text alignments.
  - Structured, pretty-printed JSON output for easy shell piping and automation.
- Built-in Internationalization: Supports English and Chinese. Automatically detects the system language or allows manual overrides. Uses Unicode Standard Annex #11 width rules for terminal alignment, including combining marks and emoji sequences.
- Lightweight & Safe: Uses a small, verified Unicode width dependency together with memory-safe Rust and native OS system calls.

## Platform Implementations

NetConfig relies on native operating system APIs for maximum performance and accuracy:

- Windows: Uses the IP Helper (IPHLPAPI) library. Resolves the primary interface via GetBestInterface using a mock target IP address. Extracts unicast PrefixOrigin/SuffixOrigin values with GetAdaptersAddresses to distinguish DHCP, Manual, Router Advertisement, and SLAAC without using the adapter DHCP flag as an address-level fallback; DNS is emitted as an interface-associated system result.
- Linux: Parses /proc/net/route and /proc/net/ipv6_route to retain destination prefixes, next hops, interface names, and routing metrics. Queries system interfaces and IP details using libc::getifaddrs. Marks only addresses explicitly present in system DHCP leases as DHCP, uses IPv6 privacy/SLAAC flags as SLAAC evidence, and leaves unsupported inferences Unknown. Retrieves interface operational state, media type, link speed, MAC address, and traffic counters directly from /sys/class/net/<interface>/. Collects DNS from systemd-resolved, NetworkManager, and finally resolv.conf while preserving source and interface scope.
- macOS: Reads complete IPv4 and IPv6 route tables with netstat -rn and uses route get default as a fallback, preserving link-local gateway scopes and interface associations. Uses networksetup -listallhardwareports to distinguish physical media. Caches per-interface ipconfig DHCP/DHCPv6 probes and reads ifconfig autoconf/temporary flags for SLAAC; unsupported inferences remain Unknown. Uses libc::getifaddrs to list IP bindings, and parses AF_LINK for MAC addresses and hardware metrics. Uses scutil --dns first and records resolv.conf as an explicit fallback source.

## Installation

### Quick Install & Run

You can use the following one-line commands to automatically detect your system architecture, download the latest precompiled binary, and run it instantly:

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
git clone https://github.com/shaogme/net-config.git
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

## Development

For developers, a pre-configured Docker-based Linux environment with Nix package manager is available. Refer to README_DEV.md for startup options, remote SSH connections, and benchmarking details.

## License

This project is dual-licensed under:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)
