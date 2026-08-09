mod netlink;

use crate::shared::{
    AddressFamily, DnsConfiguration, DnsServer, DnsSource, InterfaceBuilder, InterfaceStats,
    InterfaceStatus, InterfaceType, IpAllocation, Ipv4Info, Ipv6Info, NetworkError,
    NetworkInterface, NetworkInterfaces, Route, normalize_interfaces, parse_resolv_conf,
};
use netlink::{
    AddressFact, IFAPROT_KERNEL_LL, IFAPROT_KERNEL_LO, IFAPROT_KERNEL_RA, LinkFact,
    NetlinkSnapshot, RTPROT_DHCP, RouteFact,
};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::Command;

const IFF_UP_FLAG: u32 = 0x1;

const IFA_F_SECONDARY: u32 = 0x01;
const IFA_F_TEMPORARY: u32 = IFA_F_SECONDARY;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_F_MANAGETEMPADDR: u32 = 0x100;
const IFA_F_STABLE_PRIVACY: u32 = 0x800;
const IFA_F_DYNAMIC: u32 = 0x8000;

const IF_OPER_DOWN: u8 = 2;
const IF_OPER_TESTING: u8 = 4;
const IF_OPER_UP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxAddressMethod {
    Dhcp,
    Manual,
    Auto,
    Other,
}

#[derive(Debug, Default, Clone, Copy)]
struct LinuxInterfaceMethods {
    ipv4: Option<LinuxAddressMethod>,
    ipv6: Option<LinuxAddressMethod>,
}

#[derive(Debug, Default)]
struct LinuxDhcpEvidence {
    ipv4_addresses: HashSet<Ipv4Addr>,
    ipv6_addresses: HashSet<Ipv6Addr>,
    ipv4_interfaces: HashSet<String>,
    ipv6_interfaces: HashSet<String>,
}

fn set_interface_method(
    methods: &mut HashMap<String, LinuxInterfaceMethods>,
    interface: &str,
    family: &str,
    method: LinuxAddressMethod,
) {
    let entry = methods.entry(interface.to_string()).or_default();
    if family == "inet" {
        entry.ipv4 = Some(method);
    } else {
        entry.ipv6 = Some(method);
    }
}

fn parse_ifupdown_method(family: &str, method: &str) -> Option<LinuxAddressMethod> {
    match (family, method) {
        ("inet", "dhcp") => Some(LinuxAddressMethod::Dhcp),
        ("inet", "static") => Some(LinuxAddressMethod::Manual),
        ("inet", "manual") => Some(LinuxAddressMethod::Other),
        ("inet6", "dhcp") => Some(LinuxAddressMethod::Dhcp),
        ("inet6", "static") => Some(LinuxAddressMethod::Manual),
        ("inet6", "auto") => Some(LinuxAddressMethod::Auto),
        ("inet6", "manual") => Some(LinuxAddressMethod::Other),
        _ => None,
    }
}

fn parse_ifupdown_config(contents: &str) -> HashMap<String, LinuxInterfaceMethods> {
    let mut methods = HashMap::new();
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 || parts[0] != "iface" {
            continue;
        }
        if let Some(method) = parse_ifupdown_method(parts[2], parts[3]) {
            set_interface_method(&mut methods, parts[1], parts[2], method);
        }
    }
    methods
}

fn parse_nmcli_method(value: &str, ipv6: bool) -> Option<LinuxAddressMethod> {
    match (ipv6, value) {
        (_, "auto") if ipv6 => Some(LinuxAddressMethod::Auto),
        (_, "auto") => Some(LinuxAddressMethod::Dhcp),
        (_, "dhcp") => Some(LinuxAddressMethod::Dhcp),
        (_, "manual") => Some(LinuxAddressMethod::Manual),
        (_, "disabled" | "link-local" | "shared" | "ipv4ll") => Some(LinuxAddressMethod::Other),
        _ => None,
    }
}

fn parse_nmcli_allocation_methods(output: &str) -> HashMap<String, LinuxInterfaceMethods> {
    let mut methods = HashMap::new();
    let mut interface = None;
    for line in output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if key == "GENERAL.DEVICE" {
            interface = (!value.is_empty() && value != "--").then(|| value.to_string());
            continue;
        }
        let Some(interface_name) = interface.as_deref() else {
            continue;
        };
        if key == "IP4.METHOD" {
            if let Some(method) = parse_nmcli_method(value, false) {
                set_interface_method(&mut methods, interface_name, "inet", method);
            }
        } else if key == "IP6.METHOD"
            && let Some(method) = parse_nmcli_method(value, true)
        {
            set_interface_method(&mut methods, interface_name, "inet6", method);
        }
    }
    methods
}

fn merge_interface_methods(
    target: &mut HashMap<String, LinuxInterfaceMethods>,
    source: HashMap<String, LinuxInterfaceMethods>,
) {
    for (interface, methods) in source {
        let entry = target.entry(interface).or_default();
        if methods.ipv4.is_some() {
            entry.ipv4 = methods.ipv4;
        }
        if methods.ipv6.is_some() {
            entry.ipv6 = methods.ipv6;
        }
    }
}

fn collect_linux_interface_methods() -> HashMap<String, LinuxInterfaceMethods> {
    let mut methods = HashMap::new();
    if let Ok(contents) = std::fs::read_to_string("/etc/network/interfaces") {
        merge_interface_methods(&mut methods, parse_ifupdown_config(&contents));
    }
    if let Ok(entries) = std::fs::read_dir("/etc/network/interfaces.d") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Ok(contents) = std::fs::read_to_string(path)
            {
                merge_interface_methods(&mut methods, parse_ifupdown_config(&contents));
            }
        }
    }
    if let Ok(output) = Command::new("nmcli")
        .args([
            "-t",
            "-f",
            "GENERAL.DEVICE,IP4.METHOD,IP6.METHOD",
            "device",
            "show",
        ])
        .output()
        && output.status.success()
    {
        merge_interface_methods(
            &mut methods,
            parse_nmcli_allocation_methods(&String::from_utf8_lossy(&output.stdout)),
        );
    }
    methods
}

fn parse_address_token(value: &str) -> Option<IpAddr> {
    let value = value
        .trim()
        .trim_matches(|character: char| matches!(character, ';' | ',' | '"' | '\''));
    let value = value.split_once('/').map_or(value, |(address, _)| address);
    value.parse::<IpAddr>().ok()
}

fn parse_lease_addresses(content: &str) -> (HashSet<Ipv4Addr>, HashSet<Ipv6Addr>) {
    let mut ipv4_addresses = HashSet::new();
    let mut ipv6_addresses = HashSet::new();
    for line in content.lines() {
        let line = line.trim();
        let value = line
            .strip_prefix("fixed-address")
            .or_else(|| line.strip_prefix("iaaddr"))
            .or_else(|| line.strip_prefix("ADDRESS="))
            .or_else(|| line.strip_prefix("address="))
            .or_else(|| line.strip_prefix("ip_address="));
        let Some(value) = value else {
            continue;
        };
        let Some(address) = value.split_whitespace().find_map(parse_address_token) else {
            continue;
        };
        match address {
            IpAddr::V4(address) => {
                ipv4_addresses.insert(address);
            }
            IpAddr::V6(address) => {
                ipv6_addresses.insert(address);
            }
        }
    }
    (ipv4_addresses, ipv6_addresses)
}

fn lease_interface(path: &Path, content: &str, links: &HashMap<u32, LinkFact>) -> Option<String> {
    content
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if let Some(value) = line.strip_prefix("INTERFACE=") {
                return Some(value.trim().to_string());
            }
            if let Some(value) = line.strip_prefix("interface-name:") {
                return Some(value.trim().to_string());
            }
            line.strip_prefix("interface")
                .and_then(|value| value.split_whitespace().next())
                .map(|value| value.trim_matches(|character| matches!(character, '"' | ';')))
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            content.lines().find_map(|line| {
                let value = line.trim().strip_prefix("IFINDEX=")?.trim();
                let index = value.parse::<u32>().ok()?;
                links.get(&index).map(|link| link.name.clone())
            })
        })
        .or_else(|| {
            let file_name = path.file_name()?.to_str()?;
            if let Ok(ifindex) = file_name.parse::<u32>()
                && let Some(link) = links.get(&ifindex)
            {
                return Some(link.name.clone());
            }
            None
        })
        .or_else(|| {
            let file_name = path.file_name()?.to_str()?;
            let name = file_name
                .strip_prefix("dhclient6-")
                .or_else(|| file_name.strip_prefix("dhclient-"))
                .or_else(|| file_name.strip_prefix("dhclient6."))
                .or_else(|| file_name.strip_prefix("dhclient."))
                .or_else(|| file_name.strip_suffix(".lease"))
                .or_else(|| file_name.strip_suffix(".leases"))?;
            let name = name
                .strip_suffix(".lease")
                .or_else(|| name.strip_suffix(".leases"))
                .unwrap_or(name);
            (!name.is_empty() && name != "dhclient").then(|| name.to_string())
        })
}

fn add_linux_lease_evidence(
    path: &Path,
    links: &HashMap<u32, LinkFact>,
    evidence: &mut HashMap<String, LinuxDhcpEvidence>,
) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Some(interface) = lease_interface(path, &content, links) else {
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

fn collect_linux_dhcp_evidence(
    links: &HashMap<u32, LinkFact>,
) -> HashMap<String, LinuxDhcpEvidence> {
    let mut evidence = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/run/systemd/netif/leases") {
        for entry in entries.flatten() {
            add_linux_lease_evidence(&entry.path(), links, &mut evidence);
        }
    }

    for directory in [
        "/var/lib/NetworkManager",
        "/var/lib/dhcp",
        "/var/lib/dhcpcd",
    ] {
        if let Ok(entries) = std::fs::read_dir(directory) {
            for entry in entries.flatten() {
                let file_name = entry.file_name().to_string_lossy().into_owned();
                let is_lease = file_name.starts_with("dhclient")
                    || file_name.ends_with(".lease")
                    || file_name.ends_with(".leases");
                if is_lease {
                    add_linux_lease_evidence(&entry.path(), links, &mut evidence);
                }
            }
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

fn linux_ipv4_allocation(
    interface: &str,
    address: Ipv4Addr,
    fact: &AddressFact,
    evidence: Option<&LinuxDhcpEvidence>,
    methods: Option<&LinuxInterfaceMethods>,
) -> IpAllocation {
    if interface.starts_with("lo") {
        IpAllocation::Other
    } else if evidence.is_some_and(|value| {
        value.ipv4_addresses.contains(&address) || value.ipv4_interfaces.contains(interface)
    }) || methods.is_some_and(|value| value.ipv4 == Some(LinuxAddressMethod::Dhcp))
    {
        IpAllocation::Dhcpv4
    } else if methods.is_some_and(|value| value.ipv4 == Some(LinuxAddressMethod::Manual))
        || fact.flags & IFA_F_PERMANENT != 0 && fact.flags & IFA_F_DYNAMIC == 0
    {
        IpAllocation::Manual
    } else {
        IpAllocation::Unknown
    }
}

fn linux_ipv6_allocation(
    interface: &str,
    fact: &AddressFact,
    evidence: Option<&LinuxDhcpEvidence>,
    methods: Option<&LinuxInterfaceMethods>,
) -> IpAllocation {
    let IpAddr::V6(address) = fact.address else {
        return IpAllocation::Unknown;
    };
    if interface.starts_with("lo") || address.is_unicast_link_local() {
        return IpAllocation::Other;
    }
    if evidence.is_some_and(|value| value.ipv6_addresses.contains(&address))
        || evidence.is_some_and(|value| value.ipv6_interfaces.contains(interface))
        || methods.is_some_and(|value| value.ipv6 == Some(LinuxAddressMethod::Dhcp))
    {
        return IpAllocation::Dhcpv6;
    }
    if methods.is_some_and(|value| value.ipv6 == Some(LinuxAddressMethod::Manual))
        || fact.flags & IFA_F_PERMANENT != 0 && fact.protocol != IFAPROT_KERNEL_RA
    {
        return IpAllocation::Manual;
    }

    let privacy_flags = IFA_F_TEMPORARY | IFA_F_MANAGETEMPADDR | IFA_F_STABLE_PRIVACY;
    let has_managed_lifetime = fact
        .preferred_lifetime
        .is_some_and(|lifetime| lifetime != u32::MAX)
        || fact
            .valid_lifetime
            .is_some_and(|lifetime| lifetime != u32::MAX);
    let has_slaac_flags =
        fact.flags & privacy_flags != 0 || fact.scope == 0 && has_managed_lifetime;
    if methods.is_some_and(|value| value.ipv6 == Some(LinuxAddressMethod::Auto))
        || fact.protocol == IFAPROT_KERNEL_RA && has_slaac_flags
    {
        return IpAllocation::Slaac;
    }
    if fact.protocol == IFAPROT_KERNEL_RA {
        return IpAllocation::RouterAdvertisement;
    }
    if fact.protocol == IFAPROT_KERNEL_LO || fact.protocol == IFAPROT_KERNEL_LL {
        return IpAllocation::Other;
    }
    IpAllocation::Unknown
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LinuxInterfaceFacts {
    arp_type: Option<u32>,
    wireless: bool,
    has_device: bool,
    has_driver: bool,
    driver_name: Option<String>,
    tunnel_marker: bool,
    bridge_marker: bool,
    vlan_marker: bool,
}

fn read_linux_interface_facts(name: &str) -> LinuxInterfaceFacts {
    let base = Path::new("/sys/class/net").join(name);
    let arp_type = std::fs::read_to_string(base.join("type"))
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok());
    let driver_name = std::fs::read_link(base.join("device/driver"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|value| value.to_string_lossy().into_owned())
        });

    LinuxInterfaceFacts {
        arp_type,
        wireless: base.join("wireless").exists(),
        has_device: base.join("device").exists(),
        has_driver: driver_name.is_some(),
        driver_name,
        tunnel_marker: base.join("tun_flags").exists(),
        bridge_marker: base.join("bridge").exists(),
        vlan_marker: base.join("vlan").exists(),
    }
}

fn linux_interface_type(name: &str, facts: &LinuxInterfaceFacts) -> InterfaceType {
    const ARPHRD_ETHER: u32 = 1;
    const ARPHRD_PPP: u32 = 512;
    const ARPHRD_LOOPBACK: u32 = 772;
    const ARPHRD_IEEE80211: u32 = 801;
    const ARPHRD_IEEE80211_PRISM: u32 = 802;
    const ARPHRD_TUNNEL: u32 = 768;
    const ARPHRD_TUNNEL6: u32 = 769;
    const ARPHRD_SIT: u32 = 776;
    const ARPHRD_IPGRE: u32 = 778;
    const ARPHRD_IP6GRE: u32 = 823;
    const ARPHRD_6LOWPAN: u32 = 825;

    if facts.wireless
        || matches!(
            facts.arp_type,
            Some(ARPHRD_IEEE80211 | ARPHRD_IEEE80211_PRISM)
        )
    {
        return InterfaceType::WiFi;
    }
    if facts.tunnel_marker
        || matches!(
            facts.arp_type,
            Some(
                ARPHRD_PPP
                    | ARPHRD_TUNNEL
                    | ARPHRD_TUNNEL6
                    | ARPHRD_SIT
                    | ARPHRD_IPGRE
                    | ARPHRD_IP6GRE
            )
        )
    {
        return InterfaceType::Tunnel;
    }
    if facts.arp_type == Some(ARPHRD_LOOPBACK) || name == "lo" {
        return InterfaceType::Loopback;
    }
    if facts.bridge_marker
        || facts.vlan_marker
        || matches!(facts.driver_name.as_deref(), Some("wireguard" | "dummy"))
    {
        return InterfaceType::Virtual;
    }
    if facts.arp_type == Some(ARPHRD_ETHER) && facts.has_device && facts.has_driver {
        return InterfaceType::Ethernet;
    }
    if facts.arp_type == Some(ARPHRD_6LOWPAN) {
        return InterfaceType::Other;
    }
    InterfaceType::Unknown
}

fn linux_interface_type_with_link(
    name: &str,
    facts: &LinuxInterfaceFacts,
    link: &LinkFact,
) -> InterfaceType {
    match link.kind.as_deref() {
        Some("bridge" | "dummy" | "vlan" | "macvlan" | "macvtap" | "wireguard") => {
            InterfaceType::Virtual
        }
        Some("tun" | "tap" | "gre" | "gretap" | "ipip" | "sit" | "vti") => InterfaceType::Tunnel,
        _ => linux_interface_type(name, facts),
    }
}

fn interface_status(link: &LinkFact) -> InterfaceStatus {
    match link.operstate {
        Some(IF_OPER_UP) => InterfaceStatus::Up,
        Some(IF_OPER_TESTING) => InterfaceStatus::Testing,
        Some(IF_OPER_DOWN) => InterfaceStatus::Down,
        _ if link.flags & IFF_UP_FLAG != 0 => InterfaceStatus::Up,
        _ => InterfaceStatus::Unknown,
    }
}

fn ipv4_netmask(prefix_len: u8) -> Ipv4Addr {
    let value = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(value.to_be_bytes())
}

fn route_from_fact(route: &RouteFact, interface: &str) -> Route {
    let gateway_scope = route.gateway.and_then(|gateway| match gateway {
        IpAddr::V6(address) if address.is_unicast_link_local() => Some(interface.to_string()),
        _ => None,
    });
    Route {
        family: route.family,
        destination: route.destination,
        prefix_len: route.prefix_len,
        gateway: route.gateway,
        gateway_scope,
        interface: interface.to_string(),
        metric: route.metric,
        is_default: route.destination.is_unspecified() && route.prefix_len == 0,
    }
}

fn read_stat_file(iface: &str, file: &str) -> Option<u64> {
    let path = format!("/sys/class/net/{iface}/statistics/{file}");
    let mut file = File::open(path).ok()?;
    let mut content = String::new();
    std::io::Read::read_to_string(&mut file, &mut content).ok()?;
    content.trim().parse::<u64>().ok()
}

fn read_sysfs_statistics(name: &str) -> Option<InterfaceStats> {
    Some(InterfaceStats {
        rx_bytes: read_stat_file(name, "rx_bytes")?,
        tx_bytes: read_stat_file(name, "tx_bytes")?,
        rx_packets: read_stat_file(name, "rx_packets")?,
        tx_packets: read_stat_file(name, "tx_packets")?,
    })
}

fn set_linux_speed(interface: &mut InterfaceBuilder, name: &str) {
    let path = format!("/sys/class/net/{name}/speed");
    if let Ok(contents) = std::fs::read_to_string(path)
        && let Ok(speed) = contents.trim().parse::<i64>()
        && speed > 0
    {
        interface.set_link_speed(speed as u64 * 1_000_000);
    }
}

fn set_linux_mac(interface: &mut InterfaceBuilder, name: &str, link: &LinkFact) {
    if let Some(mac_address) = &link.mac_address {
        interface.set_mac_address(mac_address.clone());
        return;
    }
    let path = format!("/sys/class/net/{name}/address");
    if let Ok(contents) = std::fs::read_to_string(path) {
        let mac_address = contents.trim().to_uppercase();
        if !mac_address.is_empty() && mac_address != "00:00:00:00:00:00" {
            interface.set_mac_address(mac_address);
        }
    }
}

fn add_linux_address(
    interface: &mut InterfaceBuilder,
    name: &str,
    fact: &AddressFact,
    evidence: Option<&LinuxDhcpEvidence>,
    methods: Option<&LinuxInterfaceMethods>,
) {
    match (fact.family, fact.address) {
        (AddressFamily::Ipv4, IpAddr::V4(address)) => interface.add_ipv4_address(Ipv4Info {
            address,
            netmask: ipv4_netmask(fact.prefix_len),
            prefix_len: fact.prefix_len,
            allocation: linux_ipv4_allocation(name, address, fact, evidence, methods),
        }),
        (AddressFamily::Ipv6, IpAddr::V6(address)) => interface.add_ipv6_address(Ipv6Info {
            address,
            prefix_len: fact.prefix_len,
            allocation: linux_ipv6_allocation(name, fact, evidence, methods),
        }),
        _ => {}
    }
}

fn build_linux_interfaces(
    snapshot: NetlinkSnapshot,
    dhcp_evidence: HashMap<String, LinuxDhcpEvidence>,
    methods: HashMap<String, LinuxInterfaceMethods>,
) -> Vec<NetworkInterface> {
    let mut builders = HashMap::new();
    let mut routes_by_interface: HashMap<u32, Vec<Route>> = HashMap::new();
    for link in snapshot.links.values() {
        let mut facts = read_linux_interface_facts(&link.name);
        if facts.arp_type.is_none() {
            facts.arp_type = Some(u32::from(link.arp_type));
        }
        let mut interface = InterfaceBuilder::new(&link.name, &link.name, interface_status(link));
        interface.set_interface_type(linux_interface_type_with_link(&link.name, &facts, link));
        set_linux_mac(&mut interface, &link.name, link);
        set_linux_speed(&mut interface, &link.name);
        if let Some(statistics) = link
            .statistics
            .or_else(|| read_sysfs_statistics(&link.name))
        {
            interface.set_statistics(statistics);
        }
        builders.insert(link.ifindex, interface);
    }

    for address in &snapshot.addresses {
        let Some(link) = snapshot.links.get(&address.ifindex) else {
            continue;
        };
        let Some(interface) = builders.get_mut(&address.ifindex) else {
            continue;
        };
        add_linux_address(
            interface,
            &link.name,
            address,
            dhcp_evidence.get(&link.name),
            methods.get(&link.name),
        );
    }

    for route in &snapshot.routes {
        let Some(link) = snapshot.links.get(&route.ifindex) else {
            continue;
        };
        routes_by_interface
            .entry(route.ifindex)
            .or_default()
            .push(route_from_fact(route, &link.name));
    }

    builders
        .into_iter()
        .map(|(ifindex, mut interface)| {
            interface.set_routes(routes_by_interface.remove(&ifindex).unwrap_or_default());
            interface.build()
        })
        .collect()
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    let snapshot = netlink::collect()?;
    let mut dhcp_evidence = collect_linux_dhcp_evidence(&snapshot.links);
    for route in &snapshot.routes {
        if route.protocol != RTPROT_DHCP {
            continue;
        }
        let Some(link) = snapshot.links.get(&route.ifindex) else {
            continue;
        };
        let evidence = dhcp_evidence.entry(link.name.clone()).or_default();
        match route.family {
            AddressFamily::Ipv4 => {
                evidence.ipv4_interfaces.insert(link.name.clone());
            }
            AddressFamily::Ipv6 => {
                evidence.ipv6_interfaces.insert(link.name.clone());
            }
        }
    }
    let methods = collect_linux_interface_methods();
    let interfaces = build_linux_interfaces(snapshot, dhcp_evidence, methods);
    Ok(normalize_interfaces(interfaces, collect_linux_dns()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn address_fact(address: IpAddr, flags: u32, protocol: u8) -> AddressFact {
        AddressFact {
            ifindex: 2,
            family: match address {
                IpAddr::V4(_) => AddressFamily::Ipv4,
                IpAddr::V6(_) => AddressFamily::Ipv6,
            },
            address,
            prefix_len: 64,
            scope: 0,
            flags,
            protocol,
            preferred_lifetime: None,
            valid_lifetime: None,
        }
    }

    #[test]
    fn parses_ifupdown_methods_for_both_families() {
        let methods = parse_ifupdown_config(
            "iface enp0s3 inet dhcp\niface enp0s3 inet6 auto\niface enp0s8 inet static\n",
        );
        assert_eq!(methods["enp0s3"].ipv4, Some(LinuxAddressMethod::Dhcp));
        assert_eq!(methods["enp0s3"].ipv6, Some(LinuxAddressMethod::Auto));
        assert_eq!(methods["enp0s8"].ipv4, Some(LinuxAddressMethod::Manual));
    }

    #[test]
    fn parses_nmcli_methods_without_confusing_ipv4_and_ipv6_auto() {
        let methods = parse_nmcli_allocation_methods(
            "GENERAL.DEVICE:enp0s3\nIP4.METHOD:auto\nIP6.METHOD:auto\n",
        );
        assert_eq!(methods["enp0s3"].ipv4, Some(LinuxAddressMethod::Dhcp));
        assert_eq!(methods["enp0s3"].ipv6, Some(LinuxAddressMethod::Auto));
    }

    #[test]
    fn parses_isc_lease_only_from_address_fields() {
        let (ipv4, ipv6) = parse_lease_addresses(
            "lease 192.0.2.10 {\n interface \"enp0s3\";\n fixed-address 192.0.2.10;\n option routers 192.0.2.1;\n}\niaaddr 2001:db8::10/64;",
        );
        assert!(ipv4.contains(&Ipv4Addr::new(192, 0, 2, 10)));
        assert!(!ipv4.contains(&Ipv4Addr::new(192, 0, 2, 1)));
        assert!(ipv6.contains(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10)));
    }

    #[test]
    fn maps_systemd_networkd_numeric_lease_name_by_ifindex() {
        let links = HashMap::from([(
            2,
            LinkFact {
                ifindex: 2,
                name: "enp0s3".to_string(),
                arp_type: 1,
                flags: IFF_UP_FLAG,
                operstate: Some(IF_OPER_UP),
                mac_address: None,
                kind: None,
                statistics: None,
            },
        )]);
        let interface = lease_interface(Path::new("2"), "ADDRESS=10.0.2.4/24\n", &links);
        assert_eq!(interface.as_deref(), Some("enp0s3"));
    }

    #[test]
    fn classifies_fixture_addresses_from_rtnetlink_and_config_evidence() {
        let mut evidence = LinuxDhcpEvidence::default();
        let methods = LinuxInterfaceMethods {
            ipv6: Some(LinuxAddressMethod::Auto),
            ..LinuxInterfaceMethods::default()
        };
        let ipv4 = address_fact(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 4)), IFA_F_DYNAMIC, 0);
        let ipv6 = address_fact(
            IpAddr::V6(Ipv6Addr::new(
                0xfd12, 0, 0, 0x254, 0xa00, 0x27ff, 0xfe14, 0xa34d,
            )),
            IFA_F_MANAGETEMPADDR,
            IFAPROT_KERNEL_RA,
        );
        let link_local = address_fact(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            0,
            IFAPROT_KERNEL_LL,
        );
        evidence.ipv4_addresses.insert(Ipv4Addr::new(10, 0, 2, 4));

        assert_eq!(
            linux_ipv4_allocation(
                "enp0s3",
                Ipv4Addr::new(10, 0, 2, 4),
                &ipv4,
                Some(&evidence),
                Some(&methods)
            ),
            IpAllocation::Dhcpv4
        );
        assert_eq!(
            linux_ipv6_allocation("enp0s3", &ipv6, Some(&evidence), Some(&methods)),
            IpAllocation::Slaac
        );
        assert_eq!(
            linux_ipv6_allocation("enp0s3", &link_local, Some(&evidence), Some(&methods)),
            IpAllocation::Other
        );
    }

    #[test]
    fn classifies_ifupdown_static_address_as_manual() {
        let fact = address_fact(IpAddr::V4(Ipv4Addr::new(192, 168, 56, 10)), 0, 0);
        let methods = LinuxInterfaceMethods {
            ipv4: Some(LinuxAddressMethod::Manual),
            ipv6: None,
        };
        assert_eq!(
            linux_ipv4_allocation(
                "enp0s8",
                Ipv4Addr::new(192, 168, 56, 10),
                &fact,
                None,
                Some(&methods),
            ),
            IpAllocation::Manual
        );
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

    #[test]
    fn classifies_wireless_from_sysfs_marker_before_arp_type() {
        let facts = LinuxInterfaceFacts {
            arp_type: Some(1),
            wireless: true,
            has_device: true,
            has_driver: true,
            ..LinuxInterfaceFacts::default()
        };
        assert_eq!(linux_interface_type("vendor0", &facts), InterfaceType::WiFi);
    }

    #[test]
    fn does_not_guess_ethernet_or_virtual_from_missing_evidence() {
        let facts = LinuxInterfaceFacts {
            arp_type: Some(1),
            ..LinuxInterfaceFacts::default()
        };
        assert_eq!(
            linux_interface_type("vendor0", &facts),
            InterfaceType::Unknown
        );
        assert_eq!(
            linux_interface_type("docker0", &facts),
            InterfaceType::Unknown
        );
    }

    #[test]
    fn classifies_virtual_and_tunnel_from_sysfs_or_arp_fields() {
        let bridge = LinuxInterfaceFacts {
            arp_type: Some(1),
            bridge_marker: true,
            ..LinuxInterfaceFacts::default()
        };
        let tunnel = LinuxInterfaceFacts {
            arp_type: Some(768),
            ..LinuxInterfaceFacts::default()
        };
        assert_eq!(
            linux_interface_type("bridge0", &bridge),
            InterfaceType::Virtual
        );
        assert_eq!(
            linux_interface_type("interface0", &tunnel),
            InterfaceType::Tunnel
        );
    }
}
