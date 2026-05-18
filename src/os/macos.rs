use std::ptr;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::fs::File;
use std::io::{BufRead, BufReader};
use crate::shared::{
    NetworkInterfaces, NetworkInterface, Ipv4Info, Ipv6Info,
    InterfaceStatus, InterfaceType, InterfaceStats,
};

/// 解析 IPv4 默认路由 (执行 route get default)
fn get_macos_default_route_v4() -> Option<(String, Ipv4Addr)> {
    let output = std::process::Command::new("route")
        .args(["get", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let mut interface = None;
    let mut gateway = None;
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0] == "interface:" {
                interface = Some(parts[1].to_string());
            } else if parts[0] == "gateway:" {
                if let Ok(ip) = parts[1].parse::<Ipv4Addr>() {
                    gateway = Some(ip);
                }
            }
        }
    }
    match (interface, gateway) {
        (Some(iface), Some(gw)) => Some((iface, gw)),
        _ => None,
    }
}

/// 解析 IPv6 默认路由 (执行 route get -inet6 default)
fn get_macos_default_route_v6() -> Option<(String, Ipv6Addr)> {
    let output = std::process::Command::new("route")
        .args(["get", "-inet6", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let mut interface = None;
    let mut gateway = None;
    for line in s.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if parts[0] == "interface:" {
                interface = Some(parts[1].to_string());
            } else if parts[0] == "gateway:" {
                if let Ok(ip) = parts[1].parse::<Ipv6Addr>() {
                    gateway = Some(ip);
                }
            }
        }
    }
    match (interface, gateway) {
        (Some(iface), Some(gw)) => Some((iface, gw)),
        _ => None,
    }
}

/// 解析物理端口设备映射 (执行 networksetup -listallhardwareports)
fn get_macos_interface_types() -> std::collections::HashMap<String, InterfaceType> {
    let mut types = std::collections::HashMap::new();
    if let Ok(output) = std::process::Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
    {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout);
            let mut current_port = String::new();
            for line in s.lines() {
                let line = line.trim();
                if line.starts_with("Hardware Port:") {
                    current_port = line.trim_start_matches("Hardware Port:").trim().to_string();
                } else if line.starts_with("Device:") {
                    let device = line.trim_start_matches("Device:").trim().to_string();
                    if !device.is_empty() && !current_port.is_empty() {
                        let itype = if current_port.contains("Wi-Fi") {
                            InterfaceType::WiFi
                        } else if current_port.contains("Ethernet") || current_port.contains("Thunderbolt") {
                            InterfaceType::Ethernet
                        } else if current_port.contains("Bridge") {
                            InterfaceType::Virtual
                        } else {
                            InterfaceType::Other
                        };
                        types.insert(device, itype);
                    }
                }
            }
        }
    }
    types
}

/// 解析全局 DNS 配置
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

/// macOS 下获取所有网卡信息的统一实现
pub fn get_network_interfaces() -> Result<NetworkInterfaces, String> {
    // 1. 获取全局路由与默认网关信息
    let default_v4 = get_macos_default_route_v4();
    let default_v6 = get_macos_default_route_v6();

    let primary_v4_iface = default_v4.as_ref().map(|(iface, _)| iface.clone());
    let primary_v6_iface = default_v6.as_ref().map(|(iface, _)| iface.clone());
    let primary_iface = primary_v4_iface.or(primary_v6_iface);

    // 2. 加载硬件端口物理映射
    let hardware_types = get_macos_interface_types();

    // 3. 遍历 getifaddrs 链表
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    let res = unsafe { libc::getifaddrs(&mut ifap) };
    if res != 0 {
        return Err("getifaddrs failed".to_string());
    }

    let mut interface_map: std::collections::HashMap<String, NetworkInterface> = std::collections::HashMap::new();

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

                let mut gateways = Vec::new();
                if let Some((ref iface, gw)) = default_v4 {
                    if iface == &ifa_name {
                        gateways.push(gw);
                    }
                }

                let ipv4_info = Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    gateways,
                };

                let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;
                let entry = interface_map.entry(ifa_name.clone()).or_insert_with(|| NetworkInterface {
                    name: ifa_name.clone(),
                    description: ifa_name.clone(),
                    mac_address: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    status: if is_up { InterfaceStatus::Up } else { InterfaceStatus::Down },
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

                let mut gateways = Vec::new();
                if let Some((ref iface, gw)) = default_v6 {
                    if iface == &ifa_name {
                        gateways.push(gw);
                    }
                }

                let ipv6_info = Ipv6Info {
                    address: ip,
                    prefix_len,
                    gateways,
                };

                let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;
                let entry = interface_map.entry(ifa_name.clone()).or_insert_with(|| NetworkInterface {
                    name: ifa_name.clone(),
                    description: ifa_name.clone(),
                    mac_address: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    status: if is_up { InterfaceStatus::Up } else { InterfaceStatus::Down },
                    interface_type: InterfaceType::Unknown,
                    link_speed: None,
                    dns_servers: Vec::new(),
                    statistics: None,
                });
                entry.ipv6_addresses.push(ipv6_info);

            } else if sa_family == libc::AF_LINK {
                // macOS 下 AF_LINK 对应数据链路层，用于获取 MAC 地址和流量统计
                let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                let sdl_alen = sdl.sdl_alen as usize;
                let sdl_nlen = sdl.sdl_nlen as usize;

                let mut mac_address = None;
                if sdl_alen == 6 {
                    let mut mac_bytes = [0u8; 6];
                    for i in 0..6 {
                        mac_bytes[i] = sdl.sdl_data[sdl_nlen + i] as u8;
                    }
                    let formatted = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]
                    );
                    if formatted != "00:00:00:00:00:00" {
                        mac_address = Some(formatted);
                    }
                }

                // 从 if_data 中解析流量数据和接口物理网速
                let mut statistics = None;
                let mut link_speed = None;
                if !ifa.ifa_data.is_null() {
                    let data = unsafe { &*(ifa.ifa_data as *const libc::if_data) };
                    statistics = Some(InterfaceStats {
                        rx_bytes: data.ifi_ibytes as u64,
                        tx_bytes: data.ifi_obytes as u64,
                        rx_packets: data.ifi_ipackets as u64,
                        tx_packets: data.ifi_opackets as u64,
                    });
                    if data.ifi_baudrate > 0 {
                        link_speed = Some(data.ifi_baudrate as u64);
                    }
                }

                let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;
                let entry = interface_map.entry(ifa_name.clone()).or_insert_with(|| NetworkInterface {
                    name: ifa_name.clone(),
                    description: ifa_name.clone(),
                    mac_address: None,
                    ipv4_addresses: Vec::new(),
                    ipv6_addresses: Vec::new(),
                    status: if is_up { InterfaceStatus::Up } else { InterfaceStatus::Down },
                    interface_type: InterfaceType::Unknown,
                    link_speed: None,
                    dns_servers: Vec::new(),
                    statistics: None,
                });

                if mac_address.is_some() {
                    entry.mac_address = mac_address;
                }
                if statistics.is_some() {
                    entry.statistics = statistics;
                }
                if link_speed.is_some() {
                    entry.link_speed = link_speed;
                }
            }
        }
        current = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };

    // 4. 后处理：精细化接口类型分类与映射
    for (name, interface) in &mut interface_map {
        let itype;
        if name.starts_with("lo") {
            itype = InterfaceType::Loopback;
        } else if let Some(t) = hardware_types.get(name) {
            itype = *t;
        } else {
            let lower_name = name.to_lowercase();
            if lower_name.contains("utun")
                || lower_name.contains("gif")
                || lower_name.contains("stf")
                || lower_name.contains("ppp")
            {
                itype = InterfaceType::Tunnel;
            } else if lower_name.contains("bridge") {
                itype = InterfaceType::Virtual;
            } else if lower_name.contains("en") {
                itype = InterfaceType::Ethernet;
            } else {
                itype = InterfaceType::Other;
            }
        }
        interface.interface_type = itype;
    }

    // 分离主网卡与辅助网卡
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

    // 保底：若无主网卡，选择第一个非环回且绑定了IP地址的网卡
    if primary.is_none() {
        if let Some(pos) = other.iter().position(|i| {
            !i.name.starts_with("lo") && (!i.ipv4_addresses.is_empty() || !i.ipv6_addresses.is_empty())
        }) {
            primary = Some(other.remove(pos));
        }
    }

    // 5. 分配全局 DNS 信息给主网卡
    let dns_list = parse_dns_servers();
    if let Some(ref mut pri) = primary {
        pri.dns_servers = dns_list;
    }

    Ok(NetworkInterfaces { primary, other })
}
