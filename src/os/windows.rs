mod ffi;

use std::net::{IpAddr, Ipv4Addr};

use crate::shared::{
    AddressFamily, DnsConfiguration, DnsServer, DnsSource, InterfaceStatus, InterfaceType,
    IpAllocation, Ipv4Info, Ipv6Info, NetworkError, NetworkInterface, NetworkInterfaces, Route,
    aggregate_allocations, select_primary_interface, sort_interfaces, sort_routes,
};

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

fn normalize_gateway(address: IpAddr) -> Option<IpAddr> {
    (!address.is_unspecified()).then_some(address)
}

fn get_windows_routes() -> Result<Vec<WindowsRoute>, NetworkError> {
    let rows = ffi::get_forward_rows()?;
    let mut routes = Vec::with_capacity(rows.len());

    for row in rows {
        if let Some((family, destination, _)) =
            ffi::sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix)
        {
            let prefix_len = row.DestinationPrefix.PrefixLength;
            let max_prefix_len = match family {
                AddressFamily::Ipv4 => 32,
                AddressFamily::Ipv6 => 128,
            };
            if prefix_len > max_prefix_len {
                return Err(NetworkError::invariant(format!(
                    "GetIpForwardTable2 returned an invalid prefix length {}",
                    prefix_len
                )));
            }
            let next_hop = ffi::sockaddr_inet_to_ip(&row.NextHop);
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

fn windows_ip_allocation(
    family: AddressFamily,
    prefix_origin: i32,
    suffix_origin: i32,
) -> IpAllocation {
    match prefix_origin {
        0 | 2 => IpAllocation::Other,
        1 => IpAllocation::Manual,
        3 => match family {
            AddressFamily::Ipv4 => IpAllocation::Dhcpv4,
            AddressFamily::Ipv6 => IpAllocation::Dhcpv6,
        },
        4 if family == AddressFamily::Ipv6 && matches!(suffix_origin, 4 | 5) => IpAllocation::Slaac,
        4 => IpAllocation::RouterAdvertisement,
        _ => IpAllocation::Unknown,
    }
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    // 1. 获取主网卡接口索引 (GetBestInterface)
    // 传入 8.8.8.8 的大端表示 (0x08080808) 探测最优网络接口
    let best_index = ffi::get_best_interface();

    // 2. 获取完整路由表。适配器上的 gateway 列表不包含目的前缀和 metric，
    // 不能用于建立可靠的地址到网关关系。
    let routes = get_windows_routes()?;

    // 3. 由 FFI 适配层负责缓冲区扩容、边界和链表解析。
    let adapters = ffi::get_adapters()?;

    let mut primary: Option<NetworkInterface> = None;
    let mut other: Vec<NetworkInterface> = Vec::new();
    let mut dns_servers = Vec::new();

    for adapter in adapters {
        let name = adapter.name;
        let description = adapter.description;

        let mac_address = if let Some(mac_bytes) = adapter.mac_address {
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
        let is_primary = best_index.is_some_and(|best_index| {
            adapter.interface_index == best_index || adapter.ipv6_interface_index == best_index
        });

        let interface_index = adapter.interface_index;
        let mut interface_routes = routes
            .iter()
            .filter(|route| {
                (route.family == AddressFamily::Ipv4 && route.interface_index == interface_index)
                    || (route.family == AddressFamily::Ipv6
                        && adapter.ipv6_interface_index != 0
                        && route.interface_index == adapter.ipv6_interface_index)
            })
            .map(|route| route.clone_for_interface(&name))
            .collect::<Vec<Route>>();
        sort_routes(&mut interface_routes);

        let mut ipv4_addresses = Vec::new();
        let mut ipv6_addresses = Vec::new();

        // 3. 提取已由 FFI 适配层验证过的单播 IP 地址列表。
        for unicast in adapter.unicast_addresses {
            let Some(address) = unicast.address else {
                continue;
            };
            let family = address.family;
            let alloc = windows_ip_allocation(family, unicast.prefix_origin, unicast.suffix_origin);

            if family == AddressFamily::Ipv4 {
                let IpAddr::V4(ip) = address.address else {
                    continue;
                };
                let prefix_len = unicast.prefix_len;
                let netmask = prefix_to_ipv4_mask(prefix_len);

                ipv4_addresses.push(Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    allocation: alloc,
                });
            } else if let IpAddr::V6(ip) = address.address {
                let prefix_len = unicast.prefix_len;
                ipv6_addresses.push(Ipv6Info {
                    address: ip,
                    prefix_len,
                    allocation: alloc,
                });
            }
        }

        // 4. 确定接口状态
        let status = match adapter.oper_status {
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

        let interface_type = match adapter.interface_type {
            24 => InterfaceType::Loopback,
            71 => InterfaceType::WiFi,
            131 => InterfaceType::Tunnel,
            _ => {
                if is_virtual {
                    InterfaceType::Virtual
                } else if adapter.interface_type == 6 {
                    InterfaceType::Ethernet
                } else {
                    InterfaceType::Other
                }
            }
        };

        // 确定链路速度
        let raw_speed = adapter.transmit_link_speed.max(adapter.receive_link_speed);
        let link_speed = if raw_speed > 0 && raw_speed != u64::MAX {
            Some(raw_speed)
        } else {
            None
        };

        // 提取已由 FFI 适配层验证过的 DNS 服务器地址。
        for dns_addr in adapter.dns_servers {
            if dns_addr.family == AddressFamily::Ipv4 {
                if let IpAddr::V4(address) = dns_addr.address {
                    dns_servers.push(DnsServer {
                        address: IpAddr::V4(address),
                        interface: Some(name.clone()),
                        source: DnsSource::WindowsAdapter,
                    });
                }
            } else if let IpAddr::V6(address) = dns_addr.address {
                dns_servers.push(DnsServer {
                    address: IpAddr::V6(address),
                    interface: Some(name.clone()),
                    source: DnsSource::WindowsAdapter,
                });
            }
        }

        // 提取流量统计数据 (GetIfEntry2)
        let statistics = ffi::get_interface_stats(interface_index);

        let allocation = aggregate_allocations(
            ipv4_addresses
                .iter()
                .map(|address| address.allocation)
                .chain(ipv6_addresses.iter().map(|address| address.allocation)),
        );

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
            statistics,
        };

        if is_primary && primary.is_none() {
            primary = Some(iface);
        } else {
            other.push(iface);
        }
    }

    sort_interfaces(&mut other);
    if primary.is_none()
        && let Some(index) = select_primary_interface(&other)
    {
        primary = Some(other.remove(index));
    }

    let dns = DnsConfiguration::from_servers(dns_servers);
    Ok(NetworkInterfaces {
        primary,
        other,
        dns,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn unspecified_gateway_is_not_exposed() {
        assert_eq!(normalize_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), None);
        assert_eq!(normalize_gateway(IpAddr::V6(Ipv6Addr::UNSPECIFIED)), None);
        assert_eq!(
            normalize_gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn maps_windows_address_origins_without_adapter_fallback() {
        assert_eq!(
            windows_ip_allocation(AddressFamily::Ipv4, 3, 0),
            IpAllocation::Dhcpv4
        );
        assert_eq!(
            windows_ip_allocation(AddressFamily::Ipv6, 3, 0),
            IpAllocation::Dhcpv6
        );
        assert_eq!(
            windows_ip_allocation(AddressFamily::Ipv6, 4, 5),
            IpAllocation::Slaac
        );
        assert_eq!(
            windows_ip_allocation(AddressFamily::Ipv6, 4, 1),
            IpAllocation::RouterAdvertisement
        );
        assert_eq!(
            windows_ip_allocation(AddressFamily::Ipv4, 5, 0),
            IpAllocation::Unknown
        );
    }
}
