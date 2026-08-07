use serde::{Deserialize, Serialize};
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

/// IP 地址/协议栈配置分配方式（静态/动态）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum IpAllocation {
    /// 动态分配 (DHCP / SLAAC)
    Dynamic,
    /// 静态分配 (手动指定)
    Static,
    /// 未知
    Unknown,
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
    /// 协议栈/IP 地址分配模式（静态/动态/未知）
    pub allocation: IpAllocation,
    /// 链路速度（单位：bps，例如 1000000000 表示 1 Gbps，None 表示未知或不可用）
    pub link_speed: Option<u64>,
    /// DNS 服务器列表
    pub dns_servers: Vec<IpAddr>,
    /// 流量统计数据（发送/接收字节数等）
    pub statistics: Option<InterfaceStats>,
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
    /// IP 分配方式（动态/静态/未知）
    pub allocation: IpAllocation,
}

/// IPv6 地址与相关路由信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Info {
    /// IPv6 地址
    pub address: Ipv6Addr,
    /// 前缀长度（如 64）
    pub prefix_len: u8,
    /// IP 分配方式（动态/静态/未知）
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
}
