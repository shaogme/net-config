mod ffi;

use crate::shared::{
    AddressFamily, DnsConfiguration, DnsServer, DnsSource, InterfaceStatus, InterfaceType,
    IpAllocation, Ipv4Info, Ipv6Info, NetworkError, NetworkInterface, NetworkInterfaces, Route,
    aggregate_allocations, parse_resolv_conf, select_primary_interface, sort_interfaces,
    sort_routes,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

#[derive(Debug, Default)]
struct MacosAllocationEvidence {
    dhcpv4_addresses: HashSet<Ipv4Addr>,
    dhcpv6_addresses: HashSet<Ipv6Addr>,
    slaac_addresses: HashSet<Ipv6Addr>,
}

fn parse_macos_dhcp_addresses(output: &str, ipv6: bool) -> HashSet<IpAddr> {
    let mut addresses = HashSet::new();
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let is_address = if ipv6 {
            key.contains("iaaddr") || key.contains("ia address") || key == "address"
        } else {
            key == "yiaddr"
        };
        if !is_address {
            continue;
        }
        let value = value
            .trim()
            .trim_matches(|character: char| matches!(character, ';' | ',' | '"' | '\''));
        if ipv6 {
            if let Some((address, _)) = parse_scoped_ipv6(value) {
                addresses.insert(IpAddr::V6(address));
            }
        } else if let Ok(address) = value.parse::<Ipv4Addr>() {
            addresses.insert(IpAddr::V4(address));
        }
    }
    addresses
}

fn probe_macos_dhcp(iface: &str, ipv6: bool) -> HashSet<IpAddr> {
    let args = if ipv6 {
        ["getv6packet", iface]
    } else {
        ["getpacket", iface]
    };
    let Ok(output) = Command::new("ipconfig").args(args).output() else {
        return HashSet::new();
    };
    if !output.status.success() || output.stdout.is_empty() {
        return HashSet::new();
    }
    parse_macos_dhcp_addresses(&String::from_utf8_lossy(&output.stdout), ipv6)
}

fn parse_macos_slaac_addresses(output: &str) -> HashSet<Ipv6Addr> {
    let mut addresses = HashSet::new();
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "inet6" {
            continue;
        }
        let address = parts[1]
            .split_once('%')
            .map_or(parts[1], |(address, _)| address);
        if let Ok(address) = address.parse::<Ipv6Addr>()
            && parts
                .iter()
                .any(|part| *part == "autoconf" || *part == "temporary")
        {
            addresses.insert(address);
        }
    }
    addresses
}

fn collect_macos_allocation_evidence(iface: &str) -> MacosAllocationEvidence {
    if iface.starts_with("lo") {
        return MacosAllocationEvidence::default();
    }
    let slaac_addresses = Command::new("ifconfig")
        .arg(iface)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_macos_slaac_addresses(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default();
    let dhcpv4_addresses = probe_macos_dhcp(iface, false)
        .into_iter()
        .filter_map(|address| match address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .collect();
    let dhcpv6_addresses = probe_macos_dhcp(iface, true)
        .into_iter()
        .filter_map(|address| match address {
            IpAddr::V4(_) => None,
            IpAddr::V6(address) => Some(address),
        })
        .collect();
    MacosAllocationEvidence {
        dhcpv4_addresses,
        dhcpv6_addresses,
        slaac_addresses,
    }
}

fn macos_ipv4_allocation(
    interface: &str,
    address: Ipv4Addr,
    evidence: Option<&MacosAllocationEvidence>,
) -> IpAllocation {
    if interface.starts_with("lo") {
        IpAllocation::Other
    } else if evidence.is_some_and(|value| value.dhcpv4_addresses.contains(&address)) {
        IpAllocation::Dhcpv4
    } else {
        IpAllocation::Unknown
    }
}

fn macos_ipv6_allocation(
    interface: &str,
    address: Ipv6Addr,
    evidence: Option<&MacosAllocationEvidence>,
) -> IpAllocation {
    if interface.starts_with("lo") || address.is_unicast_link_local() {
        IpAllocation::Other
    } else if evidence.is_some_and(|value| value.dhcpv6_addresses.contains(&address)) {
        IpAllocation::Dhcpv6
    } else if evidence.is_some_and(|value| value.slaac_addresses.contains(&address)) {
        IpAllocation::Slaac
    } else {
        IpAllocation::Unknown
    }
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

fn parse_scutil_dns(output: &str) -> Vec<DnsServer> {
    let mut servers = Vec::new();
    let mut resolver_interface = None;
    let mut resolver_servers = Vec::new();

    let flush_resolver = |servers: &mut Vec<DnsServer>,
                          resolver_interface: &Option<String>,
                          resolver_servers: &mut Vec<IpAddr>| {
        servers.extend(resolver_servers.drain(..).map(|address| DnsServer {
            address,
            interface: resolver_interface.clone(),
            source: DnsSource::Scutil,
        }));
    };

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") {
            flush_resolver(&mut servers, &resolver_interface, &mut resolver_servers);
            resolver_interface = None;
        } else if let Some(value) = trimmed.strip_prefix("nameserver[")
            && let Some((_, value)) = value.split_once(':')
            && let Ok(address) = value.trim().parse::<IpAddr>()
        {
            resolver_servers.push(address);
        } else if let Some(value) = trimmed.strip_prefix("if_index")
            && let Some((_, interface)) = value.trim().split_once('(')
        {
            resolver_interface = interface.strip_suffix(')').map(str::to_string);
        }
    }
    flush_resolver(&mut servers, &resolver_interface, &mut resolver_servers);
    servers
}

fn collect_macos_dns() -> DnsConfiguration {
    if let Ok(output) = Command::new("scutil").args(["--dns"]).output()
        && output.status.success()
    {
        let servers = parse_scutil_dns(&String::from_utf8_lossy(&output.stdout));
        if !servers.is_empty() {
            return DnsConfiguration::from_servers(servers);
        }
    }

    match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(contents) => match parse_resolv_conf(&contents, DnsSource::ResolvConf) {
            Ok(servers) => DnsConfiguration::from_servers(servers),
            Err(_) => DnsConfiguration::unavailable(),
        },
        Err(_) => DnsConfiguration::unavailable(),
    }
}

fn empty_macos_interface(name: &str, is_up: bool) -> NetworkInterface {
    NetworkInterface {
        name: name.to_string(),
        description: name.to_string(),
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
        statistics: None,
    }
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

    // 3. 由 FFI 适配层验证 getifaddrs 链表和 sockaddr 布局。
    let records = ffi::get_ifaddrs_records()?;
    let mut interface_map: HashMap<String, NetworkInterface> = HashMap::new();

    for record in records {
        let name = record.name;
        let is_up = (record.flags & libc::IFF_UP as u32) != 0;
        let address = record.address;
        let netmask = record.netmask;
        let link_data = record.link_data;

        match address {
            Some(ffi::MacosAddress::Ipv4(ip)) => {
                let (netmask, prefix_len) = match netmask {
                    Some(ffi::MacosAddress::Ipv4(mask)) => {
                        let bytes = mask.octets();
                        (mask, u32::from_ne_bytes(bytes).count_ones() as u8)
                    }
                    _ => (Ipv4Addr::new(255, 255, 255, 0), 24),
                };
                let entry = interface_map
                    .entry(name.clone())
                    .or_insert_with(|| empty_macos_interface(&name, is_up));
                entry.ipv4_addresses.push(Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    allocation: IpAllocation::Unknown,
                });
            }
            Some(ffi::MacosAddress::Ipv6(ip)) => {
                let prefix_len = match netmask {
                    Some(ffi::MacosAddress::Ipv6(mask)) => {
                        mask.octets()
                            .iter()
                            .map(|byte| byte.count_ones())
                            .sum::<u32>() as u8
                    }
                    _ => 64,
                };
                let entry = interface_map
                    .entry(name.clone())
                    .or_insert_with(|| empty_macos_interface(&name, is_up));
                entry.ipv6_addresses.push(Ipv6Info {
                    address: ip,
                    prefix_len,
                    allocation: IpAllocation::Unknown,
                });
            }
            Some(ffi::MacosAddress::Link) => {
                let entry = interface_map
                    .entry(name.clone())
                    .or_insert_with(|| empty_macos_interface(&name, is_up));
                if let Some(link_data) = link_data {
                    if let Some(mac_bytes) = link_data.mac_address {
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
                            entry.mac_address = Some(formatted);
                        }
                    }
                    if link_data.statistics.is_some() {
                        entry.statistics = link_data.statistics;
                    }
                    if link_data.link_speed.is_some() {
                        entry.link_speed = link_data.link_speed;
                    }
                }
            }
            None => {}
        }
    }

    // 地址遍历完成后按接口生成一次分配证据；后处理只读取这份缓存。
    let allocation_evidence: HashMap<String, MacosAllocationEvidence> = interface_map
        .iter()
        .filter(|(name, interface)| {
            !name.starts_with("lo")
                && (!interface.ipv4_addresses.is_empty() || !interface.ipv6_addresses.is_empty())
        })
        .map(|(name, _)| (name.clone(), collect_macos_allocation_evidence(name)))
        .collect();

    // 4. 后处理：精细化接口类型分类与映射
    for (name, interface) in &mut interface_map {
        let evidence = allocation_evidence.get(name);
        for address in &mut interface.ipv4_addresses {
            address.allocation = macos_ipv4_allocation(name, address.address, evidence);
        }
        for address in &mut interface.ipv6_addresses {
            address.allocation = macos_ipv6_allocation(name, address.address, evidence);
        }

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

        interface.allocation = aggregate_allocations(
            interface
                .ipv4_addresses
                .iter()
                .map(|address| address.allocation)
                .chain(
                    interface
                        .ipv6_addresses
                        .iter()
                        .map(|address| address.allocation),
                ),
        );
    }

    let mut interfaces: Vec<NetworkInterface> = interface_map.into_values().collect();
    sort_interfaces(&mut interfaces);
    let primary = select_primary_interface(&interfaces).map(|index| interfaces.remove(index));
    let other = interfaces;

    let dns = collect_macos_dns();

    Ok(NetworkInterfaces {
        primary,
        other,
        dns,
    })
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

    #[test]
    fn parses_scutil_dns_resolver_interface() {
        let servers = parse_scutil_dns(
            "DNS configuration\nresolver #1\n  nameserver[0] : 192.0.2.53\n  if_index : 4 (en0)\nresolver #2\n  nameserver[0] : 2001:db8::53\n",
        );

        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].interface.as_deref(), Some("en0"));
        assert_eq!(servers[1].interface, None);
        assert!(
            servers
                .iter()
                .all(|server| server.source == DnsSource::Scutil)
        );
    }

    #[test]
    fn parses_macos_slaac_flags_by_address() {
        let addresses = parse_macos_slaac_addresses(
            "en0: flags=8863<UP>\n\tinet6 2001:db8::10 prefixlen 64 autoconf secured\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n",
        );

        assert!(addresses.contains(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)));
        assert!(!addresses.contains(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn parses_macos_dhcp_lease_address_only() {
        let addresses = parse_macos_dhcp_addresses(
            "op = BOOTREPLY\nyiaddr = 192.0.2.10\nserver_identifier = 192.0.2.1\n",
            false,
        );

        assert_eq!(addresses.len(), 1);
        assert!(addresses.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    }

    #[test]
    fn classifies_addresses_from_cached_macos_evidence() {
        let mut evidence = MacosAllocationEvidence::default();
        evidence
            .dhcpv4_addresses
            .insert(Ipv4Addr::new(192, 0, 2, 10));
        evidence
            .slaac_addresses
            .insert(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10));

        assert_eq!(
            macos_ipv4_allocation("en0", Ipv4Addr::new(192, 0, 2, 10), Some(&evidence),),
            IpAllocation::Dhcpv4
        );
        assert_eq!(
            macos_ipv6_allocation(
                "en0",
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10),
                Some(&evidence),
            ),
            IpAllocation::Slaac
        );
        assert_eq!(
            macos_ipv6_allocation(
                "en0",
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
                Some(&evidence),
            ),
            IpAllocation::Other
        );
    }
}
