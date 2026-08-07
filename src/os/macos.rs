use crate::shared::{
    AddressFamily, InterfaceStats, InterfaceStatus, InterfaceType, IpAllocation, Ipv4Info,
    Ipv6Info, NetworkError, NetworkInterface, NetworkInterfaces, Route, select_primary_interface,
    sort_interfaces, sort_routes,
};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

fn check_is_dhcp_macos(iface: &str) -> Result<bool, NetworkError> {
    if iface.starts_with("lo") {
        return Ok(false);
    }
    let output = std::process::Command::new("ipconfig")
        .args(["getpacket", iface])
        .output()
        .map_err(|source| NetworkError::command_spawn("ipconfig", &["getpacket", iface], source))?;
    if output.status.success() && !output.stdout.is_empty() {
        let s = String::from_utf8_lossy(&output.stdout);
        if s.contains("op =") || s.contains("yiaddr") || s.contains("server_identifier") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_ipv4_destination(value: &str, flags: &str) -> Option<(Ipv4Addr, u8)> {
    if value == "default" {
        return Some((Ipv4Addr::UNSPECIFIED, 0));
    }

    let (address_part, prefix_len) = if let Some((address, prefix)) = value.split_once('/') {
        (address, Some(prefix.parse::<u8>().ok()?))
    } else {
        (value, None)
    };
    let mut octets = address_part
        .split('.')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    if prefix_len.is_some_and(|prefix| prefix > 32) {
        return None;
    }

    let inferred_prefix = if flags.contains('H') {
        32
    } else {
        (octets.len() * 8) as u8
    };
    while octets.len() < 4 {
        octets.push(0);
    }

    Some((
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
        prefix_len.unwrap_or(inferred_prefix),
    ))
}

fn parse_scoped_ipv6(value: &str) -> Option<(Ipv6Addr, Option<String>)> {
    let value = value.split_once('/').map_or(value, |(address, _)| address);
    let (address_part, scope) = value
        .split_once('%')
        .map(|(address, scope)| (address, Some(scope.to_string())))
        .unwrap_or((value, None));
    let address = address_part.parse::<Ipv6Addr>().ok()?;
    Some((address, scope))
}

fn is_link_layer_address(value: &str) -> bool {
    let octets: Vec<&str> = value.split(':').collect();
    octets.len() == 6
        && octets
            .iter()
            .all(|octet| (1..=2).contains(&octet.len()) && u8::from_str_radix(octet, 16).is_ok())
}

fn parse_ipv6_destination(value: &str, _flags: &str) -> Option<(Ipv6Addr, u8, Option<String>)> {
    if value == "default" {
        return Some((Ipv6Addr::UNSPECIFIED, 0, None));
    }

    let (address_part, prefix_len) = if let Some((address, prefix)) = value.split_once('/') {
        (address, Some(prefix.parse::<u8>().ok()?))
    } else {
        (value, None)
    };
    let (address, scope) = parse_scoped_ipv6(address_part)?;
    if prefix_len.is_some_and(|prefix| prefix > 128) {
        return None;
    }
    Some((address, prefix_len.unwrap_or(128), scope))
}

fn parse_macos_route_line(
    line: &str,
    family: AddressFamily,
) -> Result<Option<Route>, NetworkError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 || parts[0] == "Destination" {
        return Ok(None);
    }

    let flags = parts[2];
    let interface = parts[3];
    let (destination, prefix_len, destination_scope) = match family {
        AddressFamily::Ipv4 => {
            let (address, prefix_len) = parse_ipv4_destination(parts[0], flags)
                .ok_or_else(|| NetworkError::parse("macOS IPv4 route destination", parts[0]))?;
            (IpAddr::V4(address), prefix_len, None)
        }
        AddressFamily::Ipv6 => {
            let (address, prefix_len, scope) = parse_ipv6_destination(parts[0], flags)
                .ok_or_else(|| NetworkError::parse("macOS IPv6 route destination", parts[0]))?;
            (IpAddr::V6(address), prefix_len, scope)
        }
    };

    let (gateway, gateway_scope) = match family {
        AddressFamily::Ipv4 => match parts[1].parse::<Ipv4Addr>() {
            Ok(address) => (
                (!address.is_unspecified()).then_some(IpAddr::V4(address)),
                None,
            ),
            Err(_) if parts[1].starts_with("link#") || is_link_layer_address(parts[1]) => {
                (None, None)
            }
            Err(_) => {
                return Err(NetworkError::parse("macOS IPv4 route gateway", parts[1]));
            }
        },
        AddressFamily::Ipv6 => match parse_scoped_ipv6(parts[1]) {
            Some((address, scope)) if !address.is_unspecified() => {
                let scope = scope.or(destination_scope).or_else(|| {
                    address
                        .is_unicast_link_local()
                        .then(|| interface.to_string())
                });
                (Some(IpAddr::V6(address)), scope)
            }
            Some(_) => (None, None),
            None if parts[1].starts_with("link#") || is_link_layer_address(parts[1]) => {
                (None, None)
            }
            None => {
                return Err(NetworkError::parse("macOS IPv6 route gateway", parts[1]));
            }
        },
    };

    Ok(Some(Route {
        family,
        destination,
        prefix_len,
        gateway,
        gateway_scope,
        interface: interface.to_string(),
        metric: None,
        is_default: destination.is_unspecified() && prefix_len == 0,
    }))
}

fn parse_macos_route_table(
    output: &str,
    family: AddressFamily,
) -> Result<Vec<Route>, NetworkError> {
    let mut routes = Vec::new();
    for line in output.lines() {
        if let Some(route) = parse_macos_route_line(line, family)? {
            routes.push(route);
        }
    }
    Ok(routes)
}

fn get_macos_route_table(
    family_name: &str,
    family: AddressFamily,
) -> Result<Vec<Route>, NetworkError> {
    let args = ["-rn", "-f", family_name];
    let output = std::process::Command::new("netstat").args(args).output();
    let output = output.map_err(|source| NetworkError::command_spawn("netstat", &args, source))?;
    if !output.status.success() {
        return Err(NetworkError::command_failed(
            "netstat",
            &args,
            output.status,
            &output.stderr,
        ));
    }
    parse_macos_route_table(&String::from_utf8_lossy(&output.stdout), family)
}

/// 解析 IPv4 默认路由 (执行 route get default)
fn get_macos_default_route_v4() -> Result<Option<Route>, NetworkError> {
    let args = ["get", "default"];
    let output = std::process::Command::new("route")
        .args(args)
        .output()
        .map_err(|source| NetworkError::command_spawn("route", &args, source))?;
    if !output.status.success() {
        return Ok(None);
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
                let ip = parts[1].parse::<Ipv4Addr>().map_err(|_| {
                    NetworkError::parse("macOS IPv4 default route gateway", parts[1])
                })?;
                gateway = Some(ip);
            }
        }
    }
    let interface = interface
        .ok_or_else(|| NetworkError::parse("macOS IPv4 default route interface", s.trim()))?;
    Ok(Some(Route {
        family: AddressFamily::Ipv4,
        destination: Ipv4Addr::UNSPECIFIED.into(),
        prefix_len: 0,
        gateway: gateway
            .filter(|address| !address.is_unspecified())
            .map(IpAddr::V4),
        gateway_scope: None,
        interface,
        metric: None,
        is_default: true,
    }))
}

/// 解析 IPv6 默认路由 (执行 route get -inet6 default)
fn get_macos_default_route_v6() -> Result<Option<Route>, NetworkError> {
    let args = ["get", "-inet6", "default"];
    let output = std::process::Command::new("route")
        .args(args)
        .output()
        .map_err(|source| NetworkError::command_spawn("route", &args, source))?;
    if !output.status.success() {
        return Ok(None);
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
                let parsed = parse_scoped_ipv6(parts[1]).ok_or_else(|| {
                    NetworkError::parse("macOS IPv6 default route gateway", parts[1])
                })?;
                gateway = Some(parsed);
            }
        }
    }
    let interface = interface
        .ok_or_else(|| NetworkError::parse("macOS IPv6 default route interface", s.trim()))?;
    let (gateway, explicit_scope) = gateway.unwrap_or((Ipv6Addr::UNSPECIFIED, None));
    let gateway = (!gateway.is_unspecified()).then_some(IpAddr::V6(gateway));
    let gateway_scope = explicit_scope.or_else(|| {
        gateway.and_then(|address| match address {
            IpAddr::V6(address) if address.is_unicast_link_local() => Some(interface.clone()),
            _ => None,
        })
    });
    Ok(Some(Route {
        family: AddressFamily::Ipv6,
        destination: Ipv6Addr::UNSPECIFIED.into(),
        prefix_len: 0,
        gateway,
        gateway_scope,
        interface,
        metric: None,
        is_default: true,
    }))
}

/// 解析物理端口设备映射 (执行 networksetup -listallhardwareports)
fn get_macos_interface_types()
-> Result<std::collections::HashMap<String, InterfaceType>, NetworkError> {
    let mut types = std::collections::HashMap::new();
    let args = ["-listallhardwareports"];
    let output = std::process::Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .map_err(|source| NetworkError::command_spawn("networksetup", &args, source))?;
    if !output.status.success() {
        return Err(NetworkError::command_failed(
            "networksetup",
            &args,
            output.status,
            &output.stderr,
        ));
    }

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
                } else if current_port.contains("Ethernet") || current_port.contains("Thunderbolt")
                {
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
    Ok(types)
}

/// 解析全局 DNS 配置
fn parse_dns_servers() -> Result<Vec<IpAddr>, NetworkError> {
    const PATH: &str = "/etc/resolv.conf";
    let mut dns = Vec::new();
    let file = File::open(PATH)
        .map_err(|source| NetworkError::io("read DNS configuration", PATH, source))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line =
            line.map_err(|source| NetworkError::io("read DNS configuration", PATH, source))?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "nameserver" {
            let ip = parts[1]
                .parse::<IpAddr>()
                .map_err(|_| NetworkError::parse("macOS DNS nameserver address", parts[1]))?;
            dns.push(ip);
        }
    }
    Ok(dns)
}

/// macOS 下获取所有网卡信息的统一实现
pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    // 1. 获取路由表；netstat 提供完整路由，route get 作为默认路由回退。
    let mut routes = get_macos_route_table("inet", AddressFamily::Ipv4)?;
    if !routes.iter().any(|route| route.is_default)
        && let Some(route) = get_macos_default_route_v4()?
    {
        routes.push(route);
    }

    let mut v6_routes = get_macos_route_table("inet6", AddressFamily::Ipv6)?;
    if !v6_routes.iter().any(|route| route.is_default)
        && let Some(route) = get_macos_default_route_v6()?
    {
        v6_routes.push(route);
    }
    routes.extend(v6_routes);
    sort_routes(&mut routes);

    // 2. 加载硬件端口物理映射
    let hardware_types = get_macos_interface_types()?;

    // 3. 遍历 getifaddrs 链表
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    let res = unsafe { libc::getifaddrs(&mut ifap) };
    if res != 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .map_or(0, |value| value as u32);
        return Err(NetworkError::api("getifaddrs", code));
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

                let is_dhcp = match check_is_dhcp_macos(&ifa_name) {
                    Ok(value) => value,
                    Err(error) => {
                        unsafe { libc::freeifaddrs(ifap) };
                        return Err(error);
                    }
                };
                let alloc = if ifa_name.starts_with("lo") {
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

                let is_dhcp = match check_is_dhcp_macos(&ifa_name) {
                    Ok(value) => value,
                    Err(error) => {
                        unsafe { libc::freeifaddrs(ifap) };
                        return Err(error);
                    }
                };
                let alloc = if ifa_name.starts_with("lo") {
                    IpAllocation::Static
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
            } else if sa_family == libc::AF_LINK {
                // macOS 下 AF_LINK 对应数据链路层，用于获取 MAC 地址和流量统计
                let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                let sdl_alen = sdl.sdl_alen as usize;
                let sdl_nlen = sdl.sdl_nlen as usize;

                let mut mac_address = None;
                if sdl_alen == 6 {
                    let mut mac_bytes = [0u8; 6];
                    for (i, byte) in mac_bytes.iter_mut().enumerate() {
                        *byte = sdl.sdl_data[sdl_nlen + i] as u8;
                    }
                    let formatted = format!(
                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                        mac_bytes[0],
                        mac_bytes[1],
                        mac_bytes[2],
                        mac_bytes[3],
                        mac_bytes[4],
                        mac_bytes[5]
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

    if !ifap.is_null() {
        unsafe { libc::freeifaddrs(ifap) };
    }

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

        interface.routes = routes
            .iter()
            .filter(|route| route.interface == *name)
            .cloned()
            .collect();
        sort_routes(&mut interface.routes);

        let is_dhcp = check_is_dhcp_macos(name)?;
        let has_dynamic = interface
            .ipv4_addresses
            .iter()
            .any(|a| a.allocation == IpAllocation::Dynamic)
            || interface
                .ipv6_addresses
                .iter()
                .any(|a| a.allocation == IpAllocation::Dynamic);
        interface.allocation = if name.starts_with("lo") {
            IpAllocation::Static
        } else if is_dhcp || has_dynamic {
            IpAllocation::Dynamic
        } else if !interface.ipv4_addresses.is_empty() || !interface.ipv6_addresses.is_empty() {
            IpAllocation::Static
        } else {
            IpAllocation::Unknown
        };
    }

    let mut interfaces: Vec<NetworkInterface> = interface_map.into_values().collect();
    sort_interfaces(&mut interfaces);
    let mut primary = select_primary_interface(&interfaces).map(|index| interfaces.remove(index));
    let other = interfaces;

    // 5. 分配全局 DNS 信息给主网卡
    let dns_list = parse_dns_servers()?;
    if let Some(ref mut pri) = primary {
        pri.dns_servers = dns_list;
    }

    Ok(NetworkInterfaces { primary, other })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_default_and_direct_routes() {
        let routes = parse_macos_route_table(
            "Destination Gateway Flags Netif Expire\ndefault 192.168.1.1 UGSc en0\n192.168.1/24 link#6 UCS en0",
            AddressFamily::Ipv4,
        )
        .expect("route table parsing should not fail");

        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(routes[0].prefix_len, 0);
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(routes[1].gateway, None);
        assert!(!routes[1].is_default);
    }

    #[test]
    fn treats_mac_gateway_as_a_direct_route() {
        let routes = parse_macos_route_table(
            "Destination Gateway Flags Netif Expire\n192.168.1/24 1:0:5e:0:0:fb UCS en0",
            AddressFamily::Ipv4,
        )
        .expect("route table parsing should not fail");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].gateway, None);
        assert!(!routes[0].is_default);
    }

    #[test]
    fn parses_ipv6_link_local_gateway_scope() {
        let routes = parse_macos_route_table(
            "Destination Gateway Flags Netif Expire\ndefault fe80::1%en0 UGcg en0",
            AddressFamily::Ipv6,
        )
        .expect("route table parsing should not fail");

        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(routes[0].prefix_len, 0);
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(routes[0].gateway_scope, Some("en0".to_string()));
    }
}
