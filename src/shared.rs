use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{fmt, io, path::PathBuf, process::ExitStatus};

/// 物理/虚拟接口运行状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum InterfaceStatus {
    Up,
    Down,
    Testing,
    Unknown,
}

/// 网卡物理介质/接口类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum InterfaceType {
    Ethernet,
    WiFi,
    Loopback,
    Virtual,
    Tunnel,
    Other,
    Unknown,
}

/// IP 地址的配置来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpAllocation {
    /// 手动配置的地址。
    Manual,
    /// DHCPv4 分配的地址。
    Dhcpv4,
    /// DHCPv6 分配的地址。
    Dhcpv6,
    /// 路由器通告提供的前缀或地址来源。
    RouterAdvertisement,
    /// 由 SLAAC 生成的地址。
    Slaac,
    /// 平台明确报告但无法映射到上述来源的地址。
    Other,
    /// 没有足够证据判断来源。
    Unknown,
    /// 同一接口上的地址使用了多个来源，或同时存在已知和未知来源。
    Mixed,
}

/// 根据地址级结果聚合接口级配置来源。
///
/// 空地址列表和只有未知来源的地址都返回 `Unknown`。只有所有地址来源完全
/// 相同才返回该来源；任何来源差异（包括已知来源与未知来源并存）都返回
/// `Mixed`，避免把部分证据误报成整个接口的单一配置方式。
pub fn aggregate_allocations<I>(allocations: I) -> IpAllocation
where
    I: IntoIterator<Item = IpAllocation>,
{
    let unique: BTreeSet<IpAllocation> = allocations.into_iter().collect();
    match unique.len() {
        0 => IpAllocation::Unknown,
        1 => unique
            .iter()
            .next()
            .copied()
            .unwrap_or(IpAllocation::Unknown),
        _ => IpAllocation::Mixed,
    }
}

/// 路由使用的地址族
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

/// 与某个网络接口关联的路由
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// 地址族
    pub family: AddressFamily,
    /// 目的网络地址
    pub destination: IpAddr,
    /// 目的网络前缀长度
    pub prefix_len: u8,
    /// 下一跳地址；直连或点对点路由可能没有下一跳
    pub gateway: Option<IpAddr>,
    /// IPv6 link-local 下一跳的作用域接口
    pub gateway_scope: Option<String>,
    /// 路由所属接口名称
    pub interface: String,
    /// 路由 metric；平台未提供时为 None
    pub metric: Option<u32>,
    /// 是否为默认路由
    pub is_default: bool,
}

/// 按稳定规则排序路由，避免 HashMap 或平台 API 顺序泄漏到输出。
pub fn sort_routes(routes: &mut [Route]) {
    routes.sort_by(|left, right| {
        left.family
            .cmp(&right.family)
            .then_with(|| left.destination.cmp(&right.destination))
            .then_with(|| left.prefix_len.cmp(&right.prefix_len))
            .then_with(|| left.metric.cmp(&right.metric))
            .then_with(|| left.gateway.cmp(&right.gateway))
            .then_with(|| left.interface.cmp(&right.interface))
    });
}

/// 按接口名称排序，避免平台 API 或 HashMap 的遍历顺序泄漏到输出。
pub fn sort_interfaces(interfaces: &mut [NetworkInterface]) {
    interfaces.sort_by(|left, right| left.name.cmp(&right.name));
}

/// 选择主接口并返回其在输入切片中的索引。
///
/// 有效默认路由优先于无路由接口；同类候选再依次比较默认路由 metric、
/// 接口状态、是否为环回、接口类型和名称。没有默认路由时，只考虑非环回且
/// 至少绑定一个 IP 地址的接口，避免无地址接口被错误地选为主接口。
pub fn select_primary_interface(interfaces: &[NetworkInterface]) -> Option<usize> {
    let has_default_route = interfaces.iter().any(interface_has_default_route);
    interfaces
        .iter()
        .enumerate()
        .filter(|(_, interface)| {
            if has_default_route {
                interface_has_default_route(interface)
            } else {
                !is_loopback_interface(interface) && interface_has_addresses(interface)
            }
        })
        .min_by(|(_, left), (_, right)| {
            primary_interface_key(left).cmp(&primary_interface_key(right))
        })
        .map(|(index, _)| index)
}

fn interface_has_default_route(interface: &NetworkInterface) -> bool {
    interface.routes.iter().any(|route| {
        route.interface == interface.name
            && route.is_default
            && route.destination.is_unspecified()
            && route.prefix_len == 0
    })
}

fn interface_has_addresses(interface: &NetworkInterface) -> bool {
    !interface.ipv4_addresses.is_empty() || !interface.ipv6_addresses.is_empty()
}

fn is_loopback_interface(interface: &NetworkInterface) -> bool {
    interface.interface_type == InterfaceType::Loopback || interface.name.starts_with("lo")
}

fn primary_interface_key(interface: &NetworkInterface) -> (u8, u32, u8, u8, u8, &str) {
    let default_route = interface
        .routes
        .iter()
        .filter(|route| {
            route.interface == interface.name
                && route.is_default
                && route.destination.is_unspecified()
                && route.prefix_len == 0
        })
        .min_by_key(|route| route.metric.unwrap_or(u32::MAX));

    (
        u8::from(default_route.is_none()),
        default_route
            .and_then(|route| route.metric)
            .unwrap_or(u32::MAX),
        interface_status_rank(interface.status),
        u8::from(is_loopback_interface(interface)),
        interface_type_rank(interface.interface_type),
        interface.name.as_str(),
    )
}

fn interface_status_rank(status: InterfaceStatus) -> u8 {
    match status {
        InterfaceStatus::Up => 0,
        InterfaceStatus::Testing => 1,
        InterfaceStatus::Unknown => 2,
        InterfaceStatus::Down => 3,
    }
}

fn interface_type_rank(interface_type: InterfaceType) -> u8 {
    match interface_type {
        InterfaceType::Ethernet => 0,
        InterfaceType::WiFi => 1,
        InterfaceType::Other => 2,
        InterfaceType::Unknown => 3,
        InterfaceType::Virtual => 4,
        InterfaceType::Tunnel => 5,
        InterfaceType::Loopback => 6,
    }
}

/// 流量数据吞吐统计
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// 系统网卡状态汇总（显式分离主网卡与其他网卡）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaces {
    /// 主网卡（可能不存在）
    pub primary: Option<NetworkInterface>,
    /// 其他网卡列表
    pub other: Vec<NetworkInterface>,
    /// 系统级 DNS 解析配置，不属于某一个主网卡。
    pub dns: DnsConfiguration,
}

/// DNS 配置的采集状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsStatus {
    /// 至少采集到一个 DNS 服务器。
    Available,
    /// 权威来源可访问，但没有配置 DNS 服务器。
    None,
    /// 当前环境无法读取任何 DNS 配置来源。
    Unavailable,
}

/// 系统级 DNS 解析配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfiguration {
    pub status: DnsStatus,
    pub servers: Vec<DnsServer>,
}

impl DnsConfiguration {
    pub fn from_servers(mut servers: Vec<DnsServer>) -> Self {
        sort_dns_servers(&mut servers);
        servers.dedup();
        let status = if servers.is_empty() {
            DnsStatus::None
        } else {
            DnsStatus::Available
        };
        Self { status, servers }
    }

    #[allow(dead_code)]
    pub fn unavailable() -> Self {
        Self {
            status: DnsStatus::Unavailable,
            servers: Vec::new(),
        }
    }
}

/// DNS 服务器及其可选的接口归属和采集来源。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsServer {
    pub address: IpAddr,
    pub interface: Option<String>,
    pub source: DnsSource,
}

/// DNS 配置来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSource {
    SystemdResolved,
    NetworkManager,
    ResolvConf,
    Scutil,
    WindowsAdapter,
}

/// 解析 resolv.conf 风格文本中的 nameserver 行。
#[allow(dead_code)]
pub fn parse_resolv_conf(
    contents: &str,
    source: DnsSource,
) -> Result<Vec<DnsServer>, NetworkError> {
    let mut servers = Vec::new();
    for line in contents.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[0] == "nameserver" {
            let address = parts[1]
                .parse::<IpAddr>()
                .map_err(|_| NetworkError::parse("DNS nameserver address", parts[1]))?;
            servers.push(DnsServer {
                address,
                interface: None,
                source,
            });
        }
    }
    Ok(servers)
}

/// 按接口、来源和地址稳定排序 DNS 服务器。
pub fn sort_dns_servers(servers: &mut [DnsServer]) {
    servers.sort_by(|left, right| {
        left.interface
            .cmp(&right.interface)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.address.cmp(&right.address))
    });
}

/// 网卡（网络接口）信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// 网卡名称（如 Linux 下的 "eth0" 或 Windows 下的 GUID "{...}"）
    pub name: String,
    /// 网卡友好描述（如 "Intel(R) Ethernet Connection" 或 Linux 下的别名）
    pub description: String,
    /// MAC 地址（格式化为 "XX:XX:XX:XX:XX:XX"）
    pub mac_address: Option<String>,
    /// IPv4 绑定列表（IP、子网掩码）
    pub ipv4_addresses: Vec<Ipv4Info>,
    /// IPv6 绑定列表（IP、前缀长度）
    pub ipv6_addresses: Vec<Ipv6Info>,
    /// 与该接口关联的路由列表
    pub routes: Vec<Route>,
    /// 接口状态
    pub status: InterfaceStatus,
    /// 接口类型
    pub interface_type: InterfaceType,
    /// 由所有地址级来源聚合得到的接口级配置来源。
    pub allocation: IpAllocation,
    /// 链路速度（单位：bps，例如 1000000000 表示 1 Gbps，None 表示未知或不可用）
    pub link_speed: Option<u64>,
    /// 流量统计数据（发送/接收字节数等）
    pub statistics: Option<InterfaceStats>,
}

/// 用于将平台原始数据合并为统一接口模型的构造器。
#[derive(Debug)]
pub struct InterfaceBuilder {
    interface: NetworkInterface,
}

impl InterfaceBuilder {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        status: InterfaceStatus,
    ) -> Self {
        Self {
            interface: NetworkInterface {
                name: name.into(),
                description: description.into(),
                mac_address: None,
                ipv4_addresses: Vec::new(),
                ipv6_addresses: Vec::new(),
                routes: Vec::new(),
                status,
                interface_type: InterfaceType::Unknown,
                allocation: IpAllocation::Unknown,
                link_speed: None,
                statistics: None,
            },
        }
    }

    #[allow(dead_code)]
    pub fn interface_type(&self) -> InterfaceType {
        self.interface.interface_type
    }

    pub fn set_interface_type(&mut self, interface_type: InterfaceType) {
        self.interface.interface_type = interface_type;
    }

    #[allow(dead_code)]
    pub fn set_status(&mut self, status: InterfaceStatus) {
        self.interface.status = status;
    }

    pub fn add_ipv4_address(&mut self, address: Ipv4Info) {
        self.interface.ipv4_addresses.push(address);
    }

    pub fn add_ipv6_address(&mut self, address: Ipv6Info) {
        self.interface.ipv6_addresses.push(address);
    }

    #[allow(dead_code)]
    pub fn ipv4_addresses(&self) -> &[Ipv4Info] {
        &self.interface.ipv4_addresses
    }

    #[allow(dead_code)]
    pub fn ipv4_addresses_mut(&mut self) -> &mut [Ipv4Info] {
        &mut self.interface.ipv4_addresses
    }

    #[allow(dead_code)]
    pub fn ipv6_addresses(&self) -> &[Ipv6Info] {
        &self.interface.ipv6_addresses
    }

    #[allow(dead_code)]
    pub fn ipv6_addresses_mut(&mut self) -> &mut [Ipv6Info] {
        &mut self.interface.ipv6_addresses
    }

    #[allow(dead_code)]
    pub fn has_addresses(&self) -> bool {
        !self.interface.ipv4_addresses.is_empty() || !self.interface.ipv6_addresses.is_empty()
    }

    pub fn set_mac_address(&mut self, mac_address: String) {
        self.interface.mac_address = Some(mac_address);
    }

    pub fn set_link_speed(&mut self, link_speed: u64) {
        self.interface.link_speed = Some(link_speed);
    }

    pub fn set_statistics(&mut self, statistics: InterfaceStats) {
        self.interface.statistics = Some(statistics);
    }

    pub fn set_routes(&mut self, routes: Vec<Route>) {
        self.interface.routes = routes;
    }

    pub fn build(mut self) -> NetworkInterface {
        normalize_interface(&mut self.interface);
        self.interface
    }
}

fn normalize_interface(interface: &mut NetworkInterface) {
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

/// 将平台构造的接口统一排序，并按共享规则选择主接口。
pub fn normalize_interfaces(
    mut interfaces: Vec<NetworkInterface>,
    dns: DnsConfiguration,
) -> NetworkInterfaces {
    for interface in &mut interfaces {
        normalize_interface(interface);
    }
    sort_interfaces(&mut interfaces);
    let primary = select_primary_interface(&interfaces).map(|index| interfaces.remove(index));

    NetworkInterfaces {
        primary,
        other: interfaces,
        dns,
    }
}

/// IPv4 地址与相关路由信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Info {
    /// IPv4 地址
    pub address: Ipv4Addr,
    /// 子网掩码（如 255.255.255.0）
    pub netmask: Ipv4Addr,
    /// 前缀长度（如 24）
    pub prefix_len: u8,
    /// IP 地址的配置来源。
    pub allocation: IpAllocation,
}

/// IPv6 地址与相关路由信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Info {
    /// IPv6 地址
    pub address: Ipv6Addr,
    /// 前缀长度（如 64）
    pub prefix_len: u8,
    /// IP 地址的配置来源。
    pub allocation: IpAllocation,
}

/// 网络采集过程中的结构化错误。
///
/// 采集器保留故障阶段和平台上下文，CLI 只在最外层将其转换为用户可读文本。
#[allow(dead_code)]
#[derive(Debug)]
pub enum NetworkError {
    /// 原生系统 API 返回了失败码。
    Api { operation: String, code: u32 },
    /// 读取系统文件或其他 IO 资源失败。
    Io {
        operation: String,
        path: PathBuf,
        source: io::Error,
    },
    /// 外部命令无法启动或以失败状态退出。
    Command {
        command: String,
        args: Vec<String>,
        status: Option<i32>,
        stderr: String,
        source: Option<io::Error>,
    },
    /// 系统 API 或系统文件的内容不符合预期格式。
    Parse { context: String, value: String },
    /// 当前平台或运行环境不提供所需能力。
    Unsupported { platform: String, feature: String },
    /// 违反了采集器对系统 API 数据的内部假设。
    Invariant { context: String },
}

#[allow(dead_code)]
impl NetworkError {
    pub fn api(operation: impl Into<String>, code: u32) -> Self {
        Self::Api {
            operation: operation.into(),
            code,
        }
    }

    pub fn io(operation: impl Into<String>, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation: operation.into(),
            path: path.into(),
            source,
        }
    }

    pub fn command_spawn(command: &str, args: &[&str], source: io::Error) -> Self {
        Self::Command {
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            status: None,
            stderr: String::new(),
            source: Some(source),
        }
    }

    pub fn command_failed(command: &str, args: &[&str], status: ExitStatus, stderr: &[u8]) -> Self {
        Self::Command {
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            status: status.code(),
            stderr: String::from_utf8_lossy(stderr).trim().to_string(),
            source: None,
        }
    }

    pub fn parse(context: impl Into<String>, value: impl Into<String>) -> Self {
        Self::Parse {
            context: context.into(),
            value: value.into(),
        }
    }

    pub fn unsupported(platform: impl Into<String>, feature: impl Into<String>) -> Self {
        Self::Unsupported {
            platform: platform.into(),
            feature: feature.into(),
        }
    }

    pub fn invariant(context: impl Into<String>) -> Self {
        Self::Invariant {
            context: context.into(),
        }
    }

    /// 稳定的机器可识别错误类别。
    pub fn code(&self) -> &'static str {
        match self {
            Self::Api { .. } => "api",
            Self::Io { .. } => "io",
            Self::Command { .. } => "command",
            Self::Parse { .. } => "parse",
            Self::Unsupported { .. } => "unsupported",
            Self::Invariant { .. } => "invariant",
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api { operation, code } => {
                write!(formatter, "{} failed with error code {}", operation, code)
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{} failed for {}: {}",
                operation,
                path.display(),
                source
            ),
            Self::Command {
                command,
                args,
                status,
                stderr,
                source,
            } => {
                let command_line = if args.is_empty() {
                    command.clone()
                } else {
                    format!("{} {}", command, args.join(" "))
                };
                if let Some(source) = source {
                    write!(formatter, "failed to run {}: {}", command_line, source)
                } else if let Some(status) = status {
                    if stderr.is_empty() {
                        write!(
                            formatter,
                            "command {} exited with status {}",
                            command_line, status
                        )
                    } else {
                        write!(
                            formatter,
                            "command {} exited with status {}: {}",
                            command_line, status, stderr
                        )
                    }
                } else {
                    write!(formatter, "command {} failed", command_line)
                }
            }
            Self::Parse { context, value } => {
                write!(formatter, "failed to parse {}: {:?}", context, value)
            }
            Self::Unsupported { platform, feature } => {
                write!(formatter, "{} is unsupported on {}", feature, platform)
            }
            Self::Invariant { context } => {
                write!(formatter, "internal invariant failed: {}", context)
            }
        }
    }
}

impl std::error::Error for NetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Command {
                source: Some(source),
                ..
            } => Some(source),
            _ => None,
        }
    }
}

/// 跨平台获取所有网卡信息的统一 API
pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    {
        crate::os::get_network_interfaces()
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(NetworkError::unsupported(
            std::env::consts::OS,
            "network interface collection",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_interface(
        name: &str,
        status: InterfaceStatus,
        interface_type: InterfaceType,
        address: Option<Ipv4Addr>,
        routes: Vec<Route>,
    ) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            description: name.to_string(),
            mac_address: None,
            ipv4_addresses: address
                .into_iter()
                .map(|address| Ipv4Info {
                    address,
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    prefix_len: 24,
                    allocation: IpAllocation::Unknown,
                })
                .collect(),
            ipv6_addresses: Vec::new(),
            routes,
            status,
            interface_type,
            allocation: IpAllocation::Unknown,
            link_speed: None,
            statistics: None,
        }
    }

    fn default_route(interface: &str, metric: Option<u32>) -> Route {
        Route {
            family: AddressFamily::Ipv4,
            destination: Ipv4Addr::UNSPECIFIED.into(),
            prefix_len: 0,
            gateway: None,
            gateway_scope: None,
            interface: interface.to_string(),
            metric,
            is_default: true,
        }
    }

    #[test]
    fn test_get_network_interfaces() {
        let res = get_network_interfaces();
        assert!(res.is_ok(), "获取网卡信息失败: {:?}", res.err());

        let interfaces = res.unwrap();

        // 验证主网卡（如果存在）的字段完整性
        if let Some(ref primary) = interfaces.primary {
            assert!(!primary.name.is_empty(), "主网卡名称不能为空");
            assert!(!primary.description.is_empty(), "主网卡描述不能为空");

            // 验证 MAC 地址格式（如果存在）
            if let Some(ref mac) = primary.mac_address {
                assert!(
                    mac.contains(':') || mac.is_empty(),
                    "MAC 地址格式可能不正确: {}",
                    mac
                );
            }
        }

        // 验证其他网卡的字段完整性
        for iface in &interfaces.other {
            assert!(!iface.name.is_empty(), "网卡名称不能为空");
            assert!(!iface.description.is_empty(), "网卡描述不能为空");
        }
    }

    #[test]
    fn test_serialization() {
        let res = get_network_interfaces();
        if let Ok(interfaces) = res {
            let json_res = serde_json::to_string(&interfaces);
            assert!(json_res.is_ok(), "序列化网络接口数据失败");
        }
    }

    #[test]
    fn network_error_keeps_category_and_context() {
        let error = NetworkError::io(
            "read route table",
            "/proc/net/route",
            io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"),
        );

        assert_eq!(error.code(), "io");
        assert!(error.to_string().contains("/proc/net/route"));
        assert!(error.to_string().contains("permission denied"));

        let error = NetworkError::parse("IPv6 route prefix", "129");
        assert_eq!(error.code(), "parse");
        assert!(error.to_string().contains("IPv6 route prefix"));

        let error = NetworkError::unsupported("test", "network interface collection");
        assert_eq!(error.code(), "unsupported");
    }

    #[test]
    fn primary_selection_prefers_default_route_metric() {
        let interfaces = vec![
            test_interface(
                "eth0",
                InterfaceStatus::Up,
                InterfaceType::Ethernet,
                Some(Ipv4Addr::new(192, 168, 1, 2)),
                vec![default_route("eth0", Some(200))],
            ),
            test_interface(
                "wlan0",
                InterfaceStatus::Down,
                InterfaceType::WiFi,
                Some(Ipv4Addr::new(192, 168, 1, 3)),
                vec![default_route("wlan0", Some(100))],
            ),
        ];

        assert_eq!(select_primary_interface(&interfaces), Some(1));
    }

    #[test]
    fn primary_selection_without_default_route_is_deterministic() {
        let mut interfaces = vec![
            test_interface(
                "zeta0",
                InterfaceStatus::Up,
                InterfaceType::Ethernet,
                Some(Ipv4Addr::new(192, 168, 1, 2)),
                Vec::new(),
            ),
            test_interface(
                "alpha0",
                InterfaceStatus::Up,
                InterfaceType::Ethernet,
                Some(Ipv4Addr::new(192, 168, 1, 3)),
                Vec::new(),
            ),
        ];

        sort_interfaces(&mut interfaces);

        assert_eq!(interfaces[0].name, "alpha0");
        assert_eq!(select_primary_interface(&interfaces), Some(0));
    }

    #[test]
    fn primary_selection_ignores_no_address_interfaces_without_routes() {
        let interfaces = vec![
            test_interface(
                "eth0",
                InterfaceStatus::Up,
                InterfaceType::Ethernet,
                Some(Ipv4Addr::new(192, 168, 1, 2)),
                Vec::new(),
            ),
            test_interface(
                "eth1",
                InterfaceStatus::Up,
                InterfaceType::Ethernet,
                None,
                Vec::new(),
            ),
        ];

        assert_eq!(select_primary_interface(&interfaces), Some(0));
    }

    #[test]
    fn allocation_aggregation_preserves_mixed_sources() {
        assert_eq!(
            aggregate_allocations([IpAllocation::Dhcpv4, IpAllocation::Dhcpv4]),
            IpAllocation::Dhcpv4
        );
        assert_eq!(
            aggregate_allocations([IpAllocation::Dhcpv4, IpAllocation::Manual]),
            IpAllocation::Mixed
        );
        assert_eq!(
            aggregate_allocations([IpAllocation::Dhcpv4, IpAllocation::Unknown]),
            IpAllocation::Mixed
        );
        assert_eq!(aggregate_allocations([]), IpAllocation::Unknown);
    }

    #[test]
    fn interface_builder_aggregates_addresses_and_sorts_routes() {
        let mut builder = InterfaceBuilder::new("eth0", "Ethernet", InterfaceStatus::Up);
        builder.add_ipv4_address(Ipv4Info {
            address: Ipv4Addr::new(192, 0, 2, 10),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            prefix_len: 24,
            allocation: IpAllocation::Dhcpv4,
        });
        builder.add_ipv6_address(Ipv6Info {
            address: Ipv6Addr::LOCALHOST,
            prefix_len: 128,
            allocation: IpAllocation::Manual,
        });
        builder.set_routes(vec![default_route("eth0", Some(100))]);

        let interface = builder.build();

        assert_eq!(interface.allocation, IpAllocation::Mixed);
        assert_eq!(interface.routes.len(), 1);
        assert!(interface.routes[0].is_default);
    }

    #[test]
    fn parses_dns_without_assigning_an_interface() {
        let servers = parse_resolv_conf(
            "nameserver 192.0.2.53\nnameserver 2001:db8::53\n",
            DnsSource::ResolvConf,
        )
        .expect("DNS configuration should parse");

        assert_eq!(servers.len(), 2);
        assert!(servers.iter().all(|server| server.interface.is_none()));
        assert!(
            servers
                .iter()
                .all(|server| server.source == DnsSource::ResolvConf)
        );
    }
}
