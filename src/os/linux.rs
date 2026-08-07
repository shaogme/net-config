use crate::shared::{
    AddressFamily, InterfaceStats, InterfaceStatus, InterfaceType, IpAllocation, Ipv4Info,
    Ipv6Info, NetworkInterface, NetworkInterfaces, Route,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

struct LinuxRouteV4 {
    iface: String,
    destination: Ipv4Addr,
    prefix_len: u8,
    gateway: Option<Ipv4Addr>,
    metric: u32,
    is_default: bool,
}

impl LinuxRouteV4 {
    fn to_route(&self) -> Route {
        Route {
            family: AddressFamily::Ipv4,
            destination: self.destination.into(),
            prefix_len: self.prefix_len,
            gateway: self.gateway.map(IpAddr::V4),
            gateway_scope: None,
            interface: self.iface.clone(),
            metric: Some(self.metric),
            is_default: self.is_default,
        }
    }
}

fn parse_ipv4_route_line(line: &str) -> Option<LinuxRouteV4> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return None;
    }

    let destination_raw = u32::from_str_radix(parts[1], 16).ok()?;
    let gateway_raw = u32::from_str_radix(parts[2], 16).ok()?;
    let metric = parts[6].parse::<u32>().ok()?;
    let mask_raw = u32::from_str_radix(parts[7], 16).ok()?;
    let destination = Ipv4Addr::from(destination_raw.to_ne_bytes());
    let gateway = Ipv4Addr::from(gateway_raw.to_ne_bytes());

    Some(LinuxRouteV4 {
        iface: parts[0].to_string(),
        destination,
        prefix_len: mask_raw.count_ones() as u8,
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        metric,
        is_default: destination.is_unspecified() && mask_raw == 0,
    })
}

fn parse_ipv4_routes() -> Vec<LinuxRouteV4> {
    let mut routes = Vec::new();
    if let Ok(file) = File::open("/proc/net/route") {
        let reader = BufReader::new(file);
        for line in reader.lines().skip(1).map_while(Result::ok) {
            if let Some(route) = parse_ipv4_route_line(&line) {
                routes.push(route);
            }
        }
    }
    routes
}

struct LinuxRouteV6 {
    iface: String,
    destination: Ipv6Addr,
    prefix_len: u8,
    gateway: Option<Ipv6Addr>,
    metric: u32,
    is_default: bool,
}

impl LinuxRouteV6 {
    fn to_route(&self) -> Route {
        let gateway_scope = self
            .gateway
            .filter(|address| address.is_unicast_link_local())
            .map(|_| self.iface.clone());

        Route {
            family: AddressFamily::Ipv6,
            destination: self.destination.into(),
            prefix_len: self.prefix_len,
            gateway: self.gateway.map(IpAddr::V6),
            gateway_scope,
            interface: self.iface.clone(),
            metric: Some(self.metric),
            is_default: self.is_default,
        }
    }
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

fn parse_ipv6_route_line(line: &str) -> Option<LinuxRouteV6> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let destination = parse_hex_to_ipv6(parts[0]).ok()?;
    let prefix_len = u8::from_str_radix(parts[1], 16).ok()?;
    if prefix_len > 128 {
        return None;
    }
    let gateway = parse_hex_to_ipv6(parts[4]).ok()?;
    let metric = u32::from_str_radix(parts[5], 16).ok()?;

    Some(LinuxRouteV6 {
        iface: parts[9].to_string(),
        destination,
        prefix_len,
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        metric,
        is_default: destination.is_unspecified() && prefix_len == 0,
    })
}

fn parse_ipv6_routes() -> Vec<LinuxRouteV6> {
    let mut routes = Vec::new();
    if let Ok(file) = File::open("/proc/net/ipv6_route") {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            if let Some(route) = parse_ipv6_route_line(&line) {
                routes.push(route);
            }
        }
    }
    routes
}

fn is_dhcp_interface_linux(iface: &str) -> bool {
    if iface == "lo" {
        return false;
    }
    if std::path::Path::new("/run/systemd/netif/leases").exists() {
        if let Ok(entries) = std::fs::read_dir("/run/systemd/netif/leases") {
            for entry in entries.flatten() {
                if let Ok(content) = std::fs::read_to_string(entry.path()) {
                    if content.contains(&format!("INTERFACE={}", iface)) {
                        return true;
                    }
                }
            }
        }
    }
    let nm_paths = [
        format!("/var/lib/NetworkManager/dhclient-{}.lease", iface),
        format!("/var/lib/NetworkManager/dhclient6-{}.lease", iface),
        format!("/var/lib/dhcp/dhclient-{}.leases", iface),
        format!("/var/lib/dhcpcd/{}.lease", iface),
    ];
    for path in &nm_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_path = entry.path().join("cmdline");
            if pid_path.exists() {
                if let Ok(cmdline) = std::fs::read_to_string(pid_path) {
                    if (cmdline.contains("dhclient")
                        || cmdline.contains("dhcpcd")
                        || cmdline.contains("udhcpc"))
                        && cmdline.contains(iface)
                    {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn parse_ipv6_permanent_map() -> std::collections::HashMap<(String, Ipv6Addr), bool> {
    let mut map = std::collections::HashMap::new();
    if let Ok(file) = File::open("/proc/net/if_inet6") {
        let reader = BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                if let (Ok(ip), Ok(flags)) = (
                    parse_hex_to_ipv6(parts[0]),
                    u32::from_str_radix(parts[4], 16),
                ) {
                    let iface = parts[5].to_string();
                    let is_permanent = (flags & 0x80) != 0;
                    map.insert((iface, ip), is_permanent);
                }
            }
        }
    }
    map
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, String> {
    // 1. 获取默认路由及网关列表
    let v4_routes = parse_ipv4_routes();
    let v6_routes = parse_ipv6_routes();
    let v6_perm_map = parse_ipv6_permanent_map();

    // 找出 Metric 最小的默认路由作为主网卡接口；点对点默认路由可以没有网关。
    let primary_v4_iface = v4_routes
        .iter()
        .filter(|r| r.is_default)
        .min_by_key(|r| (r.metric, r.iface.as_str()))
        .map(|r| r.iface.clone());

    let primary_v6_iface = v6_routes
        .iter()
        .filter(|r| r.is_default)
        .min_by_key(|r| (r.metric, r.iface.as_str()))
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

                let is_dhcp = is_dhcp_interface_linux(&ifa_name);
                let alloc = if ifa_name == "lo" {
                    IpAllocation::Static
                } else if is_dhcp {
                    IpAllocation::Dynamic
                } else {
                    IpAllocation::Static
                };

                let ipv4_info = Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    allocation: alloc,
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
                            routes: Vec::new(),
                            status: if is_up {
                                InterfaceStatus::Up
                            } else {
                                InterfaceStatus::Down
                            },
                            interface_type: InterfaceType::Unknown,
                            allocation: IpAllocation::Unknown,
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

                let is_dhcp = is_dhcp_interface_linux(&ifa_name);
                let alloc = if ifa_name == "lo" {
                    IpAllocation::Static
                } else if let Some(&is_perm) = v6_perm_map.get(&(ifa_name.clone(), ip)) {
                    if is_perm {
                        IpAllocation::Static
                    } else {
                        IpAllocation::Dynamic
                    }
                } else if is_dhcp {
                    IpAllocation::Dynamic
                } else {
                    IpAllocation::Static
                };

                let ipv6_info = Ipv6Info {
                    address: ip,
                    prefix_len,
                    allocation: alloc,
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
                            routes: Vec::new(),
                            status: if is_up {
                                InterfaceStatus::Up
                            } else {
                                InterfaceStatus::Down
                            },
                            interface_type: InterfaceType::Unknown,
                            allocation: IpAllocation::Unknown,
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

        // 将路由挂在接口上，而不是复制到该接口的每个 IP 地址。
        interface.routes = v4_routes
            .iter()
            .filter(|route| route.iface == *name)
            .map(LinuxRouteV4::to_route)
            .chain(
                v6_routes
                    .iter()
                    .filter(|route| route.iface == *name)
                    .map(LinuxRouteV6::to_route),
            )
            .collect();
        crate::shared::sort_routes(&mut interface.routes);

        // 6. 确定网卡协议栈/IP 分配方式
        let is_dhcp = is_dhcp_interface_linux(name);
        let has_dynamic = interface
            .ipv4_addresses
            .iter()
            .any(|a| a.allocation == IpAllocation::Dynamic)
            || interface
                .ipv6_addresses
                .iter()
                .any(|a| a.allocation == IpAllocation::Dynamic);
        interface.allocation = if name == "lo" {
            IpAllocation::Static
        } else if is_dhcp || has_dynamic {
            IpAllocation::Dynamic
        } else if !interface.ipv4_addresses.is_empty() || !interface.ipv6_addresses.is_empty() {
            IpAllocation::Static
        } else {
            IpAllocation::Unknown
        };
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

    // 7. 解析并分配全局 DNS 给主网卡
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_default_route_without_gateway() {
        let route = parse_ipv4_route_line("ppp0 00000000 00000000 0000 0 0 10 00000000 0 0 0")
            .expect("default route should parse");

        assert_eq!(route.destination, Ipv4Addr::UNSPECIFIED);
        assert_eq!(route.prefix_len, 0);
        assert_eq!(route.gateway, None);
        assert!(route.is_default);
        assert_eq!(route.to_route().gateway, None);
    }

    #[test]
    fn parses_ipv4_network_and_gateway_separately() {
        let route = parse_ipv4_route_line("eth0 0000A8C0 0100A8C0 0003 0 0 100 0000FFFF 0 0 0")
            .expect("IPv4 route should parse");

        assert_eq!(route.destination, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(route.prefix_len, 16);
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!route.is_default);
    }

    #[test]
    fn parses_ipv6_route_and_preserves_interface_scope() {
        let route = parse_ipv6_route_line(
            "20010db8000000000000000000000000 40 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000010 00000000 00000000 00000001 eth0",
        )
        .expect("IPv6 route should parse");

        assert_eq!(
            route.destination,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(route.prefix_len, 64);
        assert_eq!(
            route.gateway,
            Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(route.to_route().gateway_scope, Some("eth0".to_string()));
    }
}
