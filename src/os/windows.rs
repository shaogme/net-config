use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetBestInterface, GetIpForwardTable2,
    IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};

use crate::shared::{
    AddressFamily, InterfaceStats, InterfaceStatus, InterfaceType, IpAllocation, Ipv4Info,
    Ipv6Info, NetworkError, NetworkInterface, NetworkInterfaces, Route, select_primary_interface,
    sort_interfaces, sort_routes,
};
use std::net::IpAddr;

struct WindowsRoute {
    interface_index: u32,
    family: AddressFamily,
    destination: IpAddr,
    prefix_len: u8,
    gateway: Option<IpAddr>,
    gateway_scope: Option<String>,
    metric: u32,
    is_default: bool,
}

impl WindowsRoute {
    fn clone_for_interface(&self, interface: &str) -> Route {
        let gateway_scope = self.gateway_scope.clone().or_else(|| match self.gateway {
            Some(IpAddr::V6(address)) if address.is_unicast_link_local() => {
                Some(self.interface_index.to_string())
            }
            _ => None,
        });

        Route {
            family: self.family,
            destination: self.destination,
            prefix_len: self.prefix_len,
            gateway: self.gateway,
            gateway_scope,
            interface: interface.to_string(),
            metric: Some(self.metric),
            is_default: self.is_default,
        }
    }
}

fn sockaddr_inet_to_ip(address: &SOCKADDR_INET) -> Option<(AddressFamily, IpAddr, Option<u32>)> {
    let family = unsafe { address.si_family };
    match family {
        AF_INET => {
            let sockaddr = unsafe { address.Ipv4 };
            let value = unsafe { sockaddr.sin_addr.S_un.S_addr };
            Some((
                AddressFamily::Ipv4,
                IpAddr::V4(Ipv4Addr::from(value.to_ne_bytes())),
                None,
            ))
        }
        AF_INET6 => {
            let sockaddr = unsafe { address.Ipv6 };
            let value = unsafe { sockaddr.sin6_addr.u.Byte };
            let scope_id = unsafe { sockaddr.Anonymous.sin6_scope_id };
            Some((
                AddressFamily::Ipv6,
                IpAddr::V6(Ipv6Addr::from(value)),
                (scope_id != 0).then_some(scope_id),
            ))
        }
        _ => None,
    }
}

fn normalize_gateway(address: IpAddr) -> Option<IpAddr> {
    (!address.is_unspecified()).then_some(address)
}

fn get_windows_routes() -> Result<Vec<WindowsRoute>, NetworkError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if result != ERROR_SUCCESS {
        return Err(NetworkError::api("GetIpForwardTable2", result));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }

    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut routes = Vec::with_capacity(count);

    for row in rows {
        if let Some((family, destination, _)) = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix) {
            let prefix_len = row.DestinationPrefix.PrefixLength;
            let next_hop = sockaddr_inet_to_ip(&row.NextHop);
            let gateway = next_hop
                .filter(|(next_family, _, _)| *next_family == family)
                .map(|(_, address, _)| address)
                .and_then(normalize_gateway);
            let gateway_scope = next_hop
                .filter(|(next_family, _, _)| *next_family == family)
                .and_then(|(_, address, scope_id)| {
                    normalize_gateway(address).and(scope_id.map(|scope| scope.to_string()))
                });

            routes.push(WindowsRoute {
                interface_index: row.InterfaceIndex,
                family,
                destination,
                prefix_len,
                gateway,
                gateway_scope,
                metric: row.Metric,
                is_default: destination.is_unspecified() && prefix_len == 0,
            });
        }
    }

    unsafe { FreeMibTable(table as *const _) };
    Ok(routes)
}

/// 计算 IPv4 前缀对应的子网掩码
fn prefix_to_ipv4_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        Ipv4Addr::new(0, 0, 0, 0)
    } else if prefix >= 32 {
        Ipv4Addr::new(255, 255, 255, 255)
    } else {
        let mask = !((1u32 << (32 - prefix)) - 1);
        Ipv4Addr::from(mask)
    }
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    // 1. 获取主网卡接口索引 (GetBestInterface)
    let mut best_index = 0u32;
    // 传入 8.8.8.8 的大端表示 (0x08080808) 探测最优网络接口
    let has_best_interface =
        unsafe { GetBestInterface(0x08080808, &mut best_index) } == ERROR_SUCCESS;

    // 2. 获取完整路由表。适配器上的 gateway 列表不包含目的前缀和 metric，
    // 不能用于建立可靠的地址到网关关系。
    let routes = get_windows_routes()?;

    // 3. 准备缓冲区以调用 GetAdaptersAddresses
    let mut buf_len = 15000;
    let mut buf = vec![0u8; buf_len as usize];
    let family = AF_UNSPEC as u32;

    let mut res = unsafe {
        GetAdaptersAddresses(
            family,
            0,
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if res == ERROR_BUFFER_OVERFLOW {
        buf.resize(buf_len as usize, 0);
        res = unsafe {
            GetAdaptersAddresses(
                family,
                0,
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
    }

    if res != ERROR_SUCCESS {
        return Err(NetworkError::api("GetAdaptersAddresses", res));
    }

    let mut primary: Option<NetworkInterface> = None;
    let mut other: Vec<NetworkInterface> = Vec::new();

    let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;

    while !current.is_null() {
        let adapter = unsafe { &*current };

        // 提取适配器的唯一名称 (GUID)
        let name = if !adapter.AdapterName.is_null() {
            unsafe { std::ffi::CStr::from_ptr(adapter.AdapterName as *const i8) }
                .to_string_lossy()
                .into_owned()
        } else {
            return Err(NetworkError::invariant(
                "GetAdaptersAddresses returned an adapter without AdapterName",
            ));
        };

        // 提取适配器的友好描述名称
        let description = if !adapter.FriendlyName.is_null() {
            let mut len = 0;
            while unsafe { *adapter.FriendlyName.add(len) } != 0 {
                len += 1;
            }
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            String::from_utf16_lossy(slice)
        } else {
            String::new()
        };

        // 提取 MAC 地址
        let mac_address = if adapter.PhysicalAddressLength > 0 {
            let len = adapter.PhysicalAddressLength as usize;
            if len > adapter.PhysicalAddress.len() {
                return Err(NetworkError::invariant(format!(
                    "adapter {} reported a physical address length of {}",
                    name, len
                )));
            }
            let mac_bytes = &adapter.PhysicalAddress[..len];
            let mac_str = mac_bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<String>>()
                .join(":");
            Some(mac_str)
        } else {
            None
        };

        // 判定是否为主网卡
        let is_primary = has_best_interface
            && (unsafe { adapter.Anonymous1.Anonymous.IfIndex } == best_index
                || adapter.Ipv6IfIndex == best_index);

        let interface_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let mut interface_routes = routes
            .iter()
            .filter(|route| {
                (route.family == AddressFamily::Ipv4 && route.interface_index == interface_index)
                    || (route.family == AddressFamily::Ipv6
                        && adapter.Ipv6IfIndex != 0
                        && route.interface_index == adapter.Ipv6IfIndex)
            })
            .map(|route| route.clone_for_interface(&name))
            .collect::<Vec<Route>>();
        sort_routes(&mut interface_routes);

        let mut ipv4_addresses = Vec::new();
        let mut ipv6_addresses = Vec::new();

        // 3. 提取单播 IP 地址列表
        let mut unicast_ptr = adapter.FirstUnicastAddress;
        while !unicast_ptr.is_null() {
            let unicast = unsafe { &*unicast_ptr };
            let lp_sockaddr = unicast.Address.lpSockaddr;

            if !lp_sockaddr.is_null() {
                let sa_family = unsafe { (*lp_sockaddr).sa_family };
                let prefix_origin = unicast.PrefixOrigin;
                let is_dhcp_adapter = (unsafe { adapter.Anonymous2.Flags } & 0x0004) != 0;

                let alloc = match prefix_origin {
                    1 => IpAllocation::Static,
                    3 | 4 => IpAllocation::Dynamic,
                    _ => {
                        if is_dhcp_adapter {
                            IpAllocation::Dynamic
                        } else {
                            IpAllocation::Static
                        }
                    }
                };

                if sa_family as u32 == AF_INET as u32 {
                    let sock_in = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN) };
                    // 提取 IPv4 地址字节
                    let s_addr = unsafe { sock_in.sin_addr.S_un.S_addr };
                    let ip_bytes = s_addr.to_ne_bytes();
                    let ip = Ipv4Addr::from(ip_bytes);

                    let prefix_len = unicast.OnLinkPrefixLength;
                    let netmask = prefix_to_ipv4_mask(prefix_len);

                    ipv4_addresses.push(Ipv4Info {
                        address: ip,
                        netmask,
                        prefix_len,
                        allocation: alloc,
                    });
                } else if sa_family as u32 == AF_INET6 as u32 {
                    let sock_in6 = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN6) };
                    // 提取 IPv6 地址字节
                    let ip_bytes = unsafe { sock_in6.sin6_addr.u.Byte };
                    let ip = Ipv6Addr::from(ip_bytes);
                    let prefix_len = unicast.OnLinkPrefixLength;

                    ipv6_addresses.push(Ipv6Info {
                        address: ip,
                        prefix_len,
                        allocation: alloc,
                    });
                }
            }
            unicast_ptr = unicast.Next;
        }

        // 4. 确定接口状态
        let status = match adapter.OperStatus {
            1 => InterfaceStatus::Up,
            2 => InterfaceStatus::Down,
            3 => InterfaceStatus::Testing,
            _ => InterfaceStatus::Unknown,
        };

        // 确定接口类型
        let lower_desc = description.to_lowercase();
        let lower_name = name.to_lowercase();
        let is_virtual = lower_desc.contains("virtual")
            || lower_desc.contains("vpn")
            || lower_desc.contains("wsl")
            || lower_desc.contains("docker")
            || lower_desc.contains("tap")
            || lower_desc.contains("hyper-v")
            || lower_desc.contains("loopback")
            || lower_name.contains("loopback")
            || lower_desc.contains("zerotier")
            || lower_desc.contains("wireguard");

        let interface_type = match adapter.IfType {
            24 => InterfaceType::Loopback,
            71 => InterfaceType::WiFi,
            131 => InterfaceType::Tunnel,
            _ => {
                if is_virtual {
                    InterfaceType::Virtual
                } else if adapter.IfType == 6 {
                    InterfaceType::Ethernet
                } else {
                    InterfaceType::Other
                }
            }
        };

        // 确定链路速度
        let raw_speed = adapter.TransmitLinkSpeed.max(adapter.ReceiveLinkSpeed);
        let link_speed = if raw_speed > 0 && raw_speed != u64::MAX {
            Some(raw_speed)
        } else {
            None
        };

        // 提取 DNS 服务器地址
        let mut dns_servers = Vec::new();
        let mut dns_ptr = adapter.FirstDnsServerAddress;
        while !dns_ptr.is_null() {
            let dns_addr = unsafe { &*dns_ptr };
            let lp_sockaddr = dns_addr.Address.lpSockaddr;
            if !lp_sockaddr.is_null() {
                let sa_family = unsafe { (*lp_sockaddr).sa_family };
                if sa_family as u32 == AF_INET as u32 {
                    let sock_in = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN) };
                    let s_addr = unsafe { sock_in.sin_addr.S_un.S_addr };
                    let ip_bytes = s_addr.to_ne_bytes();
                    dns_servers.push(IpAddr::V4(Ipv4Addr::from(ip_bytes)));
                } else if sa_family as u32 == AF_INET6 as u32 {
                    let sock_in6 = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN6) };
                    let ip_bytes = unsafe { sock_in6.sin6_addr.u.Byte };
                    dns_servers.push(IpAddr::V6(Ipv6Addr::from(ip_bytes)));
                }
            }
            dns_ptr = dns_addr.Next;
        }

        // 提取流量统计数据 (GetIfEntry2)
        use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let statistics = if unsafe { GetIfEntry2(&mut row) } == 0 {
            Some(InterfaceStats {
                rx_bytes: row.InOctets,
                tx_bytes: row.OutOctets,
                rx_packets: row.InUcastPkts + row.InNUcastPkts,
                tx_packets: row.OutUcastPkts + row.OutNUcastPkts,
            })
        } else {
            None
        };

        let is_dhcp_enabled = (unsafe { adapter.Anonymous2.Flags } & 0x0004) != 0;
        let has_dynamic_ip = ipv4_addresses
            .iter()
            .any(|i| i.allocation == IpAllocation::Dynamic)
            || ipv6_addresses
                .iter()
                .any(|i| i.allocation == IpAllocation::Dynamic);
        let allocation = if is_dhcp_enabled || has_dynamic_ip {
            IpAllocation::Dynamic
        } else if !ipv4_addresses.is_empty() || !ipv6_addresses.is_empty() {
            IpAllocation::Static
        } else {
            IpAllocation::Unknown
        };

        let iface = NetworkInterface {
            name,
            description,
            mac_address,
            ipv4_addresses,
            ipv6_addresses,
            routes: interface_routes,
            status,
            interface_type,
            allocation,
            link_speed,
            dns_servers,
            statistics,
        };

        if is_primary && primary.is_none() {
            primary = Some(iface);
        } else {
            other.push(iface);
        }

        current = adapter.Next;
    }

    sort_interfaces(&mut other);
    if primary.is_none()
        && let Some(index) = select_primary_interface(&other)
    {
        primary = Some(other.remove(index));
    }

    Ok(NetworkInterfaces { primary, other })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_gateway_is_not_exposed() {
        assert_eq!(normalize_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None);
        assert_eq!(normalize_gateway(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None);
        assert_eq!(
            normalize_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }
}
