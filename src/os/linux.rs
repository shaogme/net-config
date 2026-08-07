use crate::shared::{
    AddressFamily, DnsConfiguration, DnsServer, DnsSource, InterfaceStats, InterfaceStatus,
    InterfaceType, IpAllocation, Ipv4Info, Ipv6Info, NetworkError, NetworkInterface,
    NetworkInterfaces, Route, aggregate_allocations, parse_resolv_conf, select_primary_interface,
    sort_interfaces, sort_routes,
};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;
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

fn parse_ipv4_route_line(line: &str) -> Result<Option<LinuxRouteV4>, NetworkError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 8 {
        return Ok(None);
    }

    let destination_raw = u32::from_str_radix(parts[1], 16)
        .map_err(|_| NetworkError::parse("Linux IPv4 route destination", parts[1]))?;
    let gateway_raw = u32::from_str_radix(parts[2], 16)
        .map_err(|_| NetworkError::parse("Linux IPv4 route gateway", parts[2]))?;
    let metric = parts[6]
        .parse::<u32>()
        .map_err(|_| NetworkError::parse("Linux IPv4 route metric", parts[6]))?;
    let mask_raw = u32::from_str_radix(parts[7], 16)
        .map_err(|_| NetworkError::parse("Linux IPv4 route netmask", parts[7]))?;
    let destination = Ipv4Addr::from(destination_raw.to_ne_bytes());
    let gateway = Ipv4Addr::from(gateway_raw.to_ne_bytes());

    Ok(Some(LinuxRouteV4 {
        iface: parts[0].to_string(),
        destination,
        prefix_len: mask_raw.count_ones() as u8,
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        metric,
        is_default: destination.is_unspecified() && mask_raw == 0,
    }))
}

fn parse_ipv4_routes() -> Result<Vec<LinuxRouteV4>, NetworkError> {
    const PATH: &str = "/proc/net/route";
    let mut routes = Vec::new();
    let file = File::open(PATH)
        .map_err(|source| NetworkError::io("read IPv4 route table", PATH, source))?;
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line =
            line.map_err(|source| NetworkError::io("read IPv4 route table", PATH, source))?;
        if let Some(route) = parse_ipv4_route_line(&line)? {
            routes.push(route);
        }
    }
    Ok(routes)
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

fn parse_hex_to_ipv6(hex_str: &str) -> Result<Ipv6Addr, NetworkError> {
    if hex_str.len() != 32 {
        return Err(NetworkError::parse(
            "Linux IPv6 hexadecimal address length",
            hex_str,
        ));
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        let byte_str = &hex_str[i * 2..i * 2 + 2];
        bytes[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| NetworkError::parse("Linux IPv6 hexadecimal address", byte_str))?;
    }
    Ok(Ipv6Addr::from(bytes))
}

fn parse_ipv6_route_line(line: &str) -> Result<Option<LinuxRouteV6>, NetworkError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return Ok(None);
    }

    let destination = parse_hex_to_ipv6(parts[0])?;
    let prefix_len = u8::from_str_radix(parts[1], 16)
        .map_err(|_| NetworkError::parse("Linux IPv6 route prefix length", parts[1]))?;
    if prefix_len > 128 {
        return Err(NetworkError::parse(
            "Linux IPv6 route prefix length",
            parts[1],
        ));
    }
    let gateway = parse_hex_to_ipv6(parts[4])?;
    let metric = u32::from_str_radix(parts[5], 16)
        .map_err(|_| NetworkError::parse("Linux IPv6 route metric", parts[5]))?;

    Ok(Some(LinuxRouteV6 {
        iface: parts[9].to_string(),
        destination,
        prefix_len,
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        metric,
        is_default: destination.is_unspecified() && prefix_len == 0,
    }))
}

fn parse_ipv6_routes() -> Result<Vec<LinuxRouteV6>, NetworkError> {
    const PATH: &str = "/proc/net/ipv6_route";
    let mut routes = Vec::new();
    let file = File::open(PATH)
        .map_err(|source| NetworkError::io("read IPv6 route table", PATH, source))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line =
            line.map_err(|source| NetworkError::io("read IPv6 route table", PATH, source))?;
        if let Some(route) = parse_ipv6_route_line(&line)? {
            routes.push(route);
        }
    }
    Ok(routes)
}

#[derive(Debug, Default)]
struct LinuxDhcpEvidence {
    ipv4_addresses: HashSet<Ipv4Addr>,
    ipv6_addresses: HashSet<Ipv6Addr>,
    ipv4_interfaces: HashSet<String>,
    ipv6_interfaces: HashSet<String>,
}

fn parse_lease_addresses(content: &str) -> (HashSet<Ipv4Addr>, HashSet<Ipv6Addr>) {
    let mut ipv4_addresses = HashSet::new();
    let mut ipv6_addresses = HashSet::new();
    for token in content.split(|character: char| {
        character.is_whitespace() || matches!(character, ';' | ',' | '"' | '\'' | '{' | '}')
    }) {
        let token = token.rsplit_once('=').map_or(token, |(_, value)| value);
        let token = token.split_once('/').map_or(token, |(address, _)| address);
        if let Ok(address) = token.parse::<IpAddr>() {
            match address {
                IpAddr::V4(address) => {
                    ipv4_addresses.insert(address);
                }
                IpAddr::V6(address) => {
                    ipv6_addresses.insert(address);
                }
            }
        }
    }
    (ipv4_addresses, ipv6_addresses)
}

fn lease_interface(path: &Path, content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| {
            line.strip_prefix("INTERFACE=")
                .or_else(|| line.strip_prefix("interface-name:"))
                .map(|value| value.trim().to_string())
        })
        .or_else(|| {
            let file_name = path.file_name()?.to_str()?;
            let name = file_name
                .strip_prefix("dhclient6-")
                .or_else(|| file_name.strip_prefix("dhclient-"))
                .or_else(|| file_name.strip_suffix(".lease"))
                .or_else(|| file_name.strip_suffix(".leases"))?;
            let name = name
                .strip_suffix(".lease")
                .or_else(|| name.strip_suffix(".leases"))
                .unwrap_or(name);
            (!name.is_empty()).then(|| name.to_string())
        })
}

fn add_linux_lease_evidence(path: &Path, evidence: &mut HashMap<String, LinuxDhcpEvidence>) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Some(interface) = lease_interface(path, &content) else {
        return;
    };
    let (ipv4_addresses, ipv6_addresses) = parse_lease_addresses(&content);
    if ipv4_addresses.is_empty() && ipv6_addresses.is_empty() {
        return;
    }
    let entry = evidence.entry(interface).or_default();
    entry.ipv4_addresses.extend(ipv4_addresses);
    entry.ipv6_addresses.extend(ipv6_addresses);
}

fn add_linux_dhcp_process_evidence(content: &[u8], evidence: &mut LinuxDhcpEvidence) {
    let mut tokens = content
        .split(|byte| *byte == 0)
        .filter(|token| !token.is_empty());
    let Some(command) = tokens.next() else {
        return;
    };
    let Ok(command) = std::str::from_utf8(command) else {
        return;
    };
    let Some(command) = Path::new(command).file_name() else {
        return;
    };
    let command = command.to_string_lossy();
    let (ipv4, ipv6) = match command.as_ref() {
        "dhclient" | "udhcpc" => (true, false),
        "dhcp6c" => (false, true),
        "dhcpcd" => (true, true),
        _ => return,
    };

    for token in tokens {
        let Ok(interface) = std::str::from_utf8(token) else {
            continue;
        };
        if interface.is_empty()
            || interface.starts_with('-')
            || interface.contains('/')
            || interface.contains('=')
            || interface.parse::<IpAddr>().is_ok()
        {
            continue;
        }
        if ipv4 {
            evidence.ipv4_interfaces.insert(interface.to_string());
        }
        if ipv6 {
            evidence.ipv6_interfaces.insert(interface.to_string());
        }
    }
}

fn collect_linux_dhcp_process_evidence(evidence: &mut LinuxDhcpEvidence) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if file_name.to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        let path = entry.path().join("cmdline");
        if let Ok(content) = std::fs::read(path) {
            add_linux_dhcp_process_evidence(&content, evidence);
        }
    }
}

fn collect_linux_dhcp_evidence() -> HashMap<String, LinuxDhcpEvidence> {
    let mut evidence = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/run/systemd/netif/leases") {
        for entry in entries.flatten() {
            add_linux_lease_evidence(&entry.path(), &mut evidence);
        }
    }

    if let Ok(entries) = std::fs::read_dir("/var/lib/NetworkManager") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with("dhclient-") || file_name.starts_with("dhclient6-") {
                add_linux_lease_evidence(&entry.path(), &mut evidence);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/var/lib/dhcp") {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with("dhclient-") {
                add_linux_lease_evidence(&entry.path(), &mut evidence);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir("/var/lib/dhcpcd") {
        for entry in entries.flatten() {
            add_linux_lease_evidence(&entry.path(), &mut evidence);
        }
    }

    let mut process_evidence = LinuxDhcpEvidence::default();
    collect_linux_dhcp_process_evidence(&mut process_evidence);
    for interface in process_evidence
        .ipv4_interfaces
        .iter()
        .chain(process_evidence.ipv6_interfaces.iter())
    {
        let entry = evidence.entry(interface.clone()).or_default();
        if process_evidence.ipv4_interfaces.contains(interface) {
            entry.ipv4_interfaces.insert(interface.clone());
        }
        if process_evidence.ipv6_interfaces.contains(interface) {
            entry.ipv6_interfaces.insert(interface.clone());
        }
    }
    evidence
}

fn parse_ipv6_flags_map() -> Result<HashMap<(String, Ipv6Addr), u32>, NetworkError> {
    const PATH: &str = "/proc/net/if_inet6";
    let mut map = HashMap::new();
    let file = File::open(PATH)
        .map_err(|source| NetworkError::io("read IPv6 interface table", PATH, source))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line =
            line.map_err(|source| NetworkError::io("read IPv6 interface table", PATH, source))?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            let ip = parse_hex_to_ipv6(parts[0])?;
            let flags = u32::from_str_radix(parts[4], 16)
                .map_err(|_| NetworkError::parse("Linux IPv6 interface flags", parts[4]))?;
            let iface = parts[5].to_string();
            map.insert((iface, ip), flags);
        }
    }
    Ok(map)
}

fn linux_ipv6_allocation(
    interface: &str,
    address: Ipv6Addr,
    flags: Option<u32>,
    evidence: Option<&LinuxDhcpEvidence>,
) -> IpAllocation {
    if interface.starts_with("lo") {
        return IpAllocation::Other;
    }
    if address.is_unicast_link_local() {
        return IpAllocation::Other;
    }
    if evidence.is_some_and(|value| value.ipv6_addresses.contains(&address)) {
        return IpAllocation::Dhcpv6;
    }
    if evidence.is_some_and(|value| value.ipv6_interfaces.contains(interface)) {
        return IpAllocation::Dhcpv6;
    }

    const IFA_F_TEMPORARY: u32 = 0x01;
    const IFA_F_MANAGETEMPADDR: u32 = 0x100;
    const IFA_F_STABLE_PRIVACY: u32 = 0x800;
    if flags.is_some_and(|value| {
        value & (IFA_F_TEMPORARY | IFA_F_MANAGETEMPADDR | IFA_F_STABLE_PRIVACY) != 0
    }) {
        IpAllocation::Slaac
    } else {
        IpAllocation::Unknown
    }
}

fn parse_resolvectl_dns(output: &str) -> Vec<DnsServer> {
    let mut servers = Vec::new();
    let mut interface = None;
    let mut reading_servers = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed == "Global" {
            interface = None;
            reading_servers = false;
        } else if let Some(rest) = trimmed.strip_prefix("Link ") {
            interface = rest
                .split_once('(')
                .and_then(|(_, rest)| rest.strip_suffix(')'))
                .map(str::to_string);
            reading_servers = false;
        } else if let Some(value) = trimmed.strip_prefix("DNS Servers:") {
            for token in value.split_whitespace() {
                if let Ok(address) = token.parse::<IpAddr>() {
                    servers.push(DnsServer {
                        address,
                        interface: interface.clone(),
                        source: DnsSource::SystemdResolved,
                    });
                }
            }
            reading_servers = true;
        } else if reading_servers && let Ok(address) = trimmed.parse::<IpAddr>() {
            servers.push(DnsServer {
                address,
                interface: interface.clone(),
                source: DnsSource::SystemdResolved,
            });
        } else if trimmed.starts_with("Current DNS Server:") || trimmed.contains(':') {
            reading_servers = false;
        }
    }
    servers
}

fn parse_nmcli_dns(output: &str) -> Vec<DnsServer> {
    let mut servers = Vec::new();
    let mut interface = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        if key == "GENERAL.DEVICE" {
            interface = (!value.is_empty() && value != "--").then(|| value.to_string());
        } else if key.starts_with("IP4.DNS") || key.starts_with("IP6.DNS") {
            let value = value.replace("\\:", ":");
            if let Ok(address) = value.parse::<IpAddr>() {
                servers.push(DnsServer {
                    address,
                    interface: interface.clone(),
                    source: DnsSource::NetworkManager,
                });
            }
        }
    }
    servers
}

fn read_linux_dns_file(
    path: &str,
    source: DnsSource,
) -> Result<Option<Vec<DnsServer>>, NetworkError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => parse_resolv_conf(&contents, source).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source_error) => Err(NetworkError::io(
            "read DNS configuration",
            path,
            source_error,
        )),
    }
}

fn collect_linux_dns() -> DnsConfiguration {
    if let Ok(output) = Command::new("resolvectl").args(["dns"]).output()
        && output.status.success()
    {
        let servers = parse_resolvectl_dns(&String::from_utf8_lossy(&output.stdout));
        if !servers.is_empty() {
            return DnsConfiguration::from_servers(servers);
        }
    }

    if let Ok(Some(servers)) = read_linux_dns_file(
        "/run/systemd/resolve/resolv.conf",
        DnsSource::SystemdResolved,
    ) && !servers.is_empty()
    {
        return DnsConfiguration::from_servers(servers);
    }

    if let Ok(output) = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "GENERAL.DEVICE,IP4.DNS,IP6.DNS",
            "device",
            "show",
        ])
        .output()
        && output.status.success()
    {
        let servers = parse_nmcli_dns(&String::from_utf8_lossy(&output.stdout));
        if !servers.is_empty() {
            return DnsConfiguration::from_servers(servers);
        }
    }

    match read_linux_dns_file("/etc/resolv.conf", DnsSource::ResolvConf) {
        Ok(Some(servers)) => DnsConfiguration::from_servers(servers),
        Ok(None) | Err(_) => DnsConfiguration::unavailable(),
    }
}

fn empty_linux_interface(name: &str, is_up: bool) -> NetworkInterface {
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

pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    // 1. 获取默认路由及网关列表
    let v4_routes = parse_ipv4_routes()?;
    let v6_routes = parse_ipv6_routes()?;
    let v6_flags_map = parse_ipv6_flags_map()?;
    let dhcp_evidence = collect_linux_dhcp_evidence();

    // 2. 调用 getifaddrs
    let mut ifap: *mut libc::ifaddrs = ptr::null_mut();
    let res = unsafe { libc::getifaddrs(&mut ifap) };
    if res != 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .map_or(0, |value| value as u32);
        return Err(NetworkError::api("getifaddrs", code));
    }
    let mut interface_map: HashMap<String, NetworkInterface> = HashMap::new();

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
            let is_up = (ifa.ifa_flags as u32 & libc::IFF_UP as u32) != 0;

            if sa_family == libc::AF_PACKET {
                // AF_PACKET 可覆盖没有 IPv4/IPv6 地址的接口，后处理再补充链路信息。
                interface_map
                    .entry(ifa_name.clone())
                    .or_insert_with(|| empty_linux_interface(&ifa_name, is_up));
            } else if sa_family == libc::AF_INET {
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

                let alloc = if ifa_name.starts_with("lo") {
                    IpAllocation::Other
                } else if dhcp_evidence
                    .get(&ifa_name)
                    .is_some_and(|value| value.ipv4_addresses.contains(&ip))
                    || dhcp_evidence
                        .get(&ifa_name)
                        .is_some_and(|value| value.ipv4_interfaces.contains(&ifa_name))
                {
                    IpAllocation::Dhcpv4
                } else {
                    IpAllocation::Unknown
                };

                let ipv4_info = Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    allocation: alloc,
                };

                let entry = interface_map
                    .entry(ifa_name.clone())
                    .or_insert_with(|| empty_linux_interface(&ifa_name, is_up));
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

                let alloc = linux_ipv6_allocation(
                    &ifa_name,
                    ip,
                    v6_flags_map.get(&(ifa_name.clone(), ip)).copied(),
                    dhcp_evidence.get(&ifa_name),
                );

                let ipv6_info = Ipv6Info {
                    address: ip,
                    prefix_len,
                    allocation: alloc,
                };

                let entry = interface_map
                    .entry(ifa_name.clone())
                    .or_insert_with(|| empty_linux_interface(&ifa_name, is_up));
                entry.ipv6_addresses.push(ipv6_info);
            }
        }
        current = ifa.ifa_next;
    }

    if !ifap.is_null() {
        unsafe { libc::freeifaddrs(ifap) };
    }

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
                if std::io::Read::read_to_string(&mut file, &mut type_str).is_ok()
                    && let Ok(val) = type_str.trim().parse::<u32>()
                {
                    arp_type = val;
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
            if std::io::Read::read_to_string(&mut file, &mut speed_str).is_ok()
                && let Ok(speed_val) = speed_str.trim().parse::<i64>()
                && speed_val > 0
            {
                interface.link_speed = Some((speed_val as u64) * 1_000_000);
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
        sort_routes(&mut interface.routes);

        // 6. 按地址级证据聚合接口配置来源。
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

    let dns = collect_linux_dns();

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
    fn parses_ipv4_default_route_without_gateway() {
        let route = parse_ipv4_route_line("ppp0 00000000 00000000 0000 0 0 10 00000000 0 0 0")
            .expect("route parsing should not fail")
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
            .expect("route parsing should not fail")
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
        .expect("route parsing should not fail")
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

    #[test]
    fn parses_dhcp_lease_addresses_by_family() {
        let (ipv4, ipv6) = parse_lease_addresses(
            "ADDRESS=192.0.2.10\nfixed-address 192.0.2.10; iaaddr 2001:db8::10/64; option routers 192.0.2.1;",
        );

        assert!(ipv4.contains(&Ipv4Addr::new(192, 0, 2, 10)));
        assert!(ipv6.contains(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)));
    }

    #[test]
    fn parses_dhcp_process_interface_snapshot_once() {
        let mut evidence = LinuxDhcpEvidence::default();
        add_linux_dhcp_process_evidence(b"/sbin/dhcpcd\0-q\0eth0\0", &mut evidence);

        assert!(evidence.ipv4_interfaces.contains("eth0"));
        assert!(evidence.ipv6_interfaces.contains("eth0"));
    }

    #[test]
    fn parses_resolvectl_and_nmcli_interface_sources() {
        let resolvectl = parse_resolvectl_dns(
            "Global\n       DNS Servers: 192.0.2.53\nLink 2 (eth0)\n       DNS Servers: 2001:db8::53\n",
        );
        assert_eq!(resolvectl.len(), 2);
        assert!(resolvectl[0].interface.is_none());
        assert_eq!(resolvectl[1].interface.as_deref(), Some("eth0"));

        let nmcli = parse_nmcli_dns(
            "GENERAL.DEVICE:eth0\nIP4.DNS[1]:192.0.2.53\nIP6.DNS[1]:2001\\:db8\\:\\:53\n",
        );
        assert_eq!(nmcli.len(), 2);
        assert!(nmcli.iter().all(|server| {
            server.interface.as_deref() == Some("eth0")
                && server.source == DnsSource::NetworkManager
        }));
    }
}
