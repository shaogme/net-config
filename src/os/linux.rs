use crate::shared::{
    InterfaceStats, InterfaceStatus, InterfaceType, Ipv4Info, Ipv6Info, NetworkInterface,
    NetworkInterfaces,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

struct LinuxRouteV4 {
    iface: String,
    gateway: Ipv4Addr,
    metric: u32,
    is_default: bool,
}

fn parse_ipv4_routes() -> Vec<LinuxRouteV4> {
    let mut routes = Vec::new();
    if let Ok(file) = File::open("/proc/net/route") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1) {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 8 {
                    let iface = parts[0].to_string();
                    let dest_hex = parts[1];
                    let gateway_hex = parts[2];
                    let metric_str = parts[6];

                    if let (Ok(dest), Ok(gateway), Ok(metric)) = (
                        u32::from_str_radix(dest_hex, 16),
                        u32::from_str_radix(gateway_hex, 16),
                        u32::from_str_radix(metric_str, 10),
                    ) {
                        let gw_bytes = gateway.to_ne_bytes();
                        let gw_ip = Ipv4Addr::from(gw_bytes);

                        routes.push(LinuxRouteV4 {
                            iface,
                            gateway: gw_ip,
                            metric,
                            is_default: dest == 0,
                        });
                    }
                }
            }
        }
    }
    routes
}

struct LinuxRouteV6 {
    iface: String,
    gateway: Ipv6Addr,
    metric: u32,
    is_default: bool,
}

fn parse_hex_to_ipv6(hex_str: &str) -> Result<Ipv6Addr, String> {
    if hex_str.len() != 32 {
        return Err("Invalid hex length for IPv6".to_string());
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex_str[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16).map_err(|e| e.to_string())?;
    }
    Ok(Ipv6Addr::from(bytes))
}

fn parse_ipv6_routes() -> Vec<LinuxRouteV6> {
    let mut routes = Vec::new();
    if let Ok(file) = File::open("/proc/net/ipv6_route") {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let dest_hex = parts[0];
                    let prefix_hex = parts[1];
                    let next_hop_hex = parts[4];
                    let metric_hex = parts[5];
                    let iface = parts[9].to_string();

                    if dest_hex.len() == 32 && next_hop_hex.len() == 32 {
                        let is_default =
                            dest_hex == "00000000000000000000000000000000" && prefix_hex == "00";

                        if let (Ok(gateway), Ok(metric)) = (
                            parse_hex_to_ipv6(next_hop_hex),
                            u32::from_str_radix(metric_hex, 16),
                        ) {
                            routes.push(LinuxRouteV6 {
                                iface,
                                gateway,
                                metric,
                                is_default,
                            });
                        }
                    }
                }
            }
        }
    }
    routes
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, String> {
    // 1. 获取默认路由及网关列表
    let v4_routes = parse_ipv4_routes();
    let v6_routes = parse_ipv6_routes();

    // 找出 Metric 最小且网关有效的默认路由作为主网卡接口
    let primary_v4_iface = v4_routes
        .iter()
        .filter(|r| r.is_default && r.gateway != Ipv4Addr::UNSPECIFIED)
        .min_by_key(|r| r.metric)
        .map(|r| r.iface.clone());

    let primary_v6_iface = v6_routes
        .iter()
        .filter(|r| r.is_default && r.gateway != Ipv6Addr::UNSPECIFIED)
        .min_by_key(|r| r.metric)
        .map(|r| r.iface.clone());

    let primary_iface = primary_v4_iface.or(primary_v6_iface);

    // 2. 调用 getifaddrs
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    let res = unsafe { libc::getifaddrs(&mut ifap) };
    if res != 0 {
        return Err("getifaddrs failed".to_string());
    }

    let mut interface_map: std::collections::HashMap<String, NetworkInterface> =
        std::collections::HashMap::new();

    let mut current = ifap;
    while !current.is_null() {
        let ifa = unsafe { &*current };

        let ifa_name = if !ifa.ifa_name.is_null() {
            unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned()
        } else {
            current = ifa.ifa_next;
            continue;
        };

        if !ifa.ifa_addr.is_null() {
            let sa_family = unsafe { (*ifa.ifa_addr).sa_family } as i32;

            if sa_family == libc::AF_INET {
                let sock_in = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let ip_bytes = sock_in.sin_addr.s_addr.to_ne_bytes();
                let ip = Ipv4Addr::from(ip_bytes);

                let mut netmask = Ipv4Addr::new(255, 255, 255, 0);
                let mut prefix_len = 24;
                if !ifa.ifa_netmask.is_null() {
                    let mask_in = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                    let mask_bytes = mask_in.sin_addr.s_addr.to_ne_bytes();
                    netmask = Ipv4Addr::from(mask_bytes);
                    let mask_u32 = u32::from_ne_bytes(mask_bytes);
                    prefix_len = mask_u32.count_ones() as u8;
                }

                // 收集绑定在该网卡上的有效网关
                let gateways = v4_routes
                    .iter()
                    .filter(|r| r.iface == ifa_name && r.gateway != Ipv4Addr::UNSPECIFIED)
                    .map(|r| r.gateway)
                    .collect::<Vec<Ipv4Addr>>();

                let ipv4_info = Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    gateways,
                };

                let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;
                let entry =
                    interface_map
                        .entry(ifa_name.clone())
                        .or_insert_with(|| NetworkInterface {
                            name: ifa_name.clone(),
                            description: ifa_name.clone(),
                            mac_address: None,
                            ipv4_addresses: Vec::new(),
                            ipv6_addresses: Vec::new(),
                            status: if is_up {
                                InterfaceStatus::Up
                            } else {
                                InterfaceStatus::Down
                            },
                            interface_type: InterfaceType::Unknown,
                            link_speed: None,
                            dns_servers: Vec::new(),
                            statistics: None,
                        });
                entry.ipv4_addresses.push(ipv4_info);
            } else if sa_family == libc::AF_INET6 {
                let sock_in6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                let ip_bytes = sock_in6.sin6_addr.s6_addr;
                let ip = Ipv6Addr::from(ip_bytes);

                let mut prefix_len = 64;
                if !ifa.ifa_netmask.is_null() {
                    let mask_in6 = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in6) };
                    let mask_bytes = mask_in6.sin6_addr.s6_addr;
                    prefix_len = mask_bytes.iter().map(|b| b.count_ones()).sum::<u32>() as u8;
                }

                let gateways = v6_routes
                    .iter()
                    .filter(|r| r.iface == ifa_name && r.gateway != Ipv6Addr::UNSPECIFIED)
                    .map(|r| r.gateway)
                    .collect::<Vec<Ipv6Addr>>();

                let ipv6_info = Ipv6Info {
                    address: ip,
                    prefix_len,
                    gateways,
                };

                let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;
                let entry =
                    interface_map
                        .entry(ifa_name.clone())
                        .or_insert_with(|| NetworkInterface {
                            name: ifa_name.clone(),
                            description: ifa_name.clone(),
                            mac_address: None,
                            ipv4_addresses: Vec::new(),
                            ipv6_addresses: Vec::new(),
                            status: if is_up {
                                InterfaceStatus::Up
                            } else {
                                InterfaceStatus::Down
                            },
                            interface_type: InterfaceType::Unknown,
                            link_speed: None,
                            dns_servers: Vec::new(),
                            statistics: None,
                        });
                entry.ipv6_addresses.push(ipv6_info);
            }
        }
        current = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };

    // 辅助函数：读取流量统计
    fn read_stat_file(iface: &str, file: &str) -> Option<u64> {
        let path = format!("/sys/class/net/{}/statistics/{}", iface, file);
        if let Ok(mut f) = File::open(&path) {
            let mut content = String::new();
            if std::io::Read::read_to_string(&mut f, &mut content).is_ok() {
                return content.trim().parse::<u64>().ok();
            }
        }
        None
    }

    // 后处理：读取状态、类型、速度与流量统计
    for (name, interface) in &mut interface_map {
        // 1. 读取 MAC 地址
        let mac_path = format!("/sys/class/net/{}/address", name);
        if let Ok(mut file) = File::open(&mac_path) {
            let mut mac_str = String::new();
            if std::io::Read::read_to_string(&mut file, &mut mac_str).is_ok() {
                let formatted = mac_str.trim().to_uppercase();
                if !formatted.is_empty() && formatted != "00:00:00:00:00:00" {
                    interface.mac_address = Some(formatted);
                }
            }
        }

        // 2. 状态覆盖 (operstate)
        let operstate_path = format!("/sys/class/net/{}/operstate", name);
        if let Ok(mut file) = File::open(&operstate_path) {
            let mut state_str = String::new();
            if std::io::Read::read_to_string(&mut file, &mut state_str).is_ok() {
                match state_str.trim() {
                    "up" => interface.status = InterfaceStatus::Up,
                    "down" => interface.status = InterfaceStatus::Down,
                    "testing" => interface.status = InterfaceStatus::Testing,
                    _ => {}
                }
            }
        }

        // 3. 确定网卡类型
        let itype;
        if name == "lo" {
            itype = InterfaceType::Loopback;
        } else {
            let type_path = format!("/sys/class/net/{}/type", name);
            let mut arp_type = 0u32;
            if let Ok(mut file) = File::open(&type_path) {
                let mut type_str = String::new();
                if std::io::Read::read_to_string(&mut file, &mut type_str).is_ok() {
                    if let Ok(val) = type_str.trim().parse::<u32>() {
                        arp_type = val;
                    }
                }
            }

            match arp_type {
                772 => itype = InterfaceType::Loopback,
                801 | 802 => itype = InterfaceType::WiFi,
                1 => {
                    let device_path = format!("/sys/class/net/{}/device", name);
                    let is_virtual = !std::path::Path::new(&device_path).exists();
                    let lower_name = name.to_lowercase();
                    if is_virtual
                        || lower_name.contains("docker")
                        || lower_name.contains("veth")
                        || lower_name.contains("br-")
                        || lower_name.contains("virbr")
                    {
                        if lower_name.contains("tun")
                            || lower_name.contains("tap")
                            || lower_name.contains("wg")
                        {
                            itype = InterfaceType::Tunnel;
                        } else {
                            itype = InterfaceType::Virtual;
                        }
                    } else {
                        itype = InterfaceType::Ethernet;
                    }
                }
                _ => {
                    let lower_name = name.to_lowercase();
                    if lower_name.contains("tun")
                        || lower_name.contains("tap")
                        || lower_name.contains("wg")
                    {
                        itype = InterfaceType::Tunnel;
                    } else if lower_name.contains("docker")
                        || lower_name.contains("veth")
                        || lower_name.contains("br-")
                    {
                        itype = InterfaceType::Virtual;
                    } else {
                        itype = InterfaceType::Other;
                    }
                }
            }
        }
        interface.interface_type = itype;

        // 4. 链路速度
        let speed_path = format!("/sys/class/net/{}/speed", name);
        if let Ok(mut file) = File::open(&speed_path) {
            let mut speed_str = String::new();
            if std::io::Read::read_to_string(&mut file, &mut speed_str).is_ok() {
                if let Ok(speed_val) = speed_str.trim().parse::<i64>() {
                    if speed_val > 0 {
                        interface.link_speed = Some((speed_val as u64) * 1_000_000);
                    }
                }
            }
        }

        // 5. 流量吞吐统计
        if let (Some(rx_bytes), Some(tx_bytes), Some(rx_packets), Some(tx_packets)) = (
            read_stat_file(name, "rx_bytes"),
            read_stat_file(name, "tx_bytes"),
            read_stat_file(name, "rx_packets"),
            read_stat_file(name, "tx_packets"),
        ) {
            interface.statistics = Some(InterfaceStats {
                rx_bytes,
                tx_bytes,
                rx_packets,
                tx_packets,
            });
        }
    }

    let mut primary: Option<NetworkInterface> = None;
    let mut other: Vec<NetworkInterface> = Vec::new();

    for iface in interface_map.into_values() {
        let is_pri = primary_iface.as_ref().map_or(false, |p| p == &iface.name);
        if is_pri && primary.is_none() {
            primary = Some(iface);
        } else {
            other.push(iface);
        }
    }

    // 保底：若无主网卡，选择第一个非环回有IP绑定的网卡作为 primary
    if primary.is_none() {
        if let Some(pos) = other.iter().position(|i| {
            i.name != "lo" && (!i.ipv4_addresses.is_empty() || !i.ipv6_addresses.is_empty())
        }) {
            primary = Some(other.remove(pos));
        }
    }

    // 6. 解析并分配全局 DNS 给主网卡
    fn parse_dns_servers() -> Vec<IpAddr> {
        let mut dns = Vec::new();
        if let Ok(file) = File::open("/etc/resolv.conf") {
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if let Ok(line) = line {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0] == "nameserver" {
                        if let Ok(ip) = parts[1].parse::<IpAddr>() {
                            dns.push(ip);
                        }
                    }
                }
            }
        }
        dns
    }

    let dns_list = parse_dns_servers();
    if let Some(ref mut pri) = primary {
        pri.dns_servers = dns_list;
    }

    Ok(NetworkInterfaces { primary, other })
}
