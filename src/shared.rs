use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    /// IPv4 绑定列表（IP、子网掩码、网关）
    pub ipv4_addresses: Vec<Ipv4Info>,
    /// IPv6 绑定列表（IP、前缀长度、网关）
    pub ipv6_addresses: Vec<Ipv6Info>,
    /// 接口状态
    pub status: InterfaceStatus,
    /// 接口类型
    pub interface_type: InterfaceType,
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
    /// 该网卡关联的网关列表
    pub gateways: Vec<Ipv4Addr>,
}

/// IPv6 地址与相关路由信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Info {
    /// IPv6 地址
    pub address: Ipv6Addr,
    /// 前缀长度（如 64）
    pub prefix_len: u8,
    /// 该网卡关联的网关列表
    pub gateways: Vec<Ipv6Addr>,
}

/// 跨平台获取所有网卡信息的统一 API
pub fn get_network_interfaces() -> Result<NetworkInterfaces, String> {
    std::cfg_select! {
        target_os = "windows" => crate::os::get_network_interfaces(),
        target_os = "linux" => crate::os::get_network_interfaces(),
        target_os = "macos" => crate::os::get_network_interfaces(),
        _ => compile_error!("Unsupported operating system")
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
}
