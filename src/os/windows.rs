mod ffi;

use std::net::{IpAddr, Ipv4Addr};

use crate::shared::{
    AddressFamily, DnsConfiguration, DnsServer, DnsSource, InterfaceBuilder, InterfaceStatus,
    InterfaceType, IpAllocation, Ipv4Info, Ipv6Info, NetworkError, NetworkInterfaces, Route,
    normalize_interfaces,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_FAST, IF_TYPE_FASTETHER, IF_TYPE_FASTETHER_FX,
    IF_TYPE_GIGABITETHERNET, IF_TYPE_IEEE8023AD_LAG, IF_TYPE_IEEE80211, IF_TYPE_L2_VLAN,
    IF_TYPE_L3_IPVLAN, IF_TYPE_L3_IPXVLAN, IF_TYPE_OTHER, IF_TYPE_PPP, IF_TYPE_PROP_VIRTUAL,
    IF_TYPE_SLIP, IF_TYPE_SOFTWARE_LOOPBACK, IF_TYPE_TUNNEL, IF_TYPE_VIRTUALIPADDRESS,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    NdisMedium802_3, NdisMediumLoopback, NdisMediumNative802_11, NdisMediumTunnel,
    NdisMediumWirelessWan, NdisPhysicalMedium802_3, NdisPhysicalMediumNative802_11,
    NdisPhysicalMediumWirelessLan, NdisPhysicalMediumWirelessWan, TUNNEL_TYPE_NONE,
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

fn windows_interface_type(
    if_type: u32,
    tunnel_type: i32,
    media_type: Option<i32>,
    physical_medium_type: Option<i32>,
) -> InterfaceType {
    if if_type == IF_TYPE_SOFTWARE_LOOPBACK || media_type == Some(NdisMediumLoopback) {
        return InterfaceType::Loopback;
    }
    if if_type == IF_TYPE_TUNNEL
        || if_type == IF_TYPE_PPP
        || if_type == IF_TYPE_SLIP
        || tunnel_type != TUNNEL_TYPE_NONE
        || media_type == Some(NdisMediumTunnel)
    {
        return InterfaceType::Tunnel;
    }
    if matches!(
        if_type,
        IF_TYPE_PROP_VIRTUAL
            | IF_TYPE_VIRTUALIPADDRESS
            | IF_TYPE_L2_VLAN
            | IF_TYPE_L3_IPVLAN
            | IF_TYPE_L3_IPXVLAN
    ) {
        return InterfaceType::Virtual;
    }
    if if_type == IF_TYPE_IEEE80211
        || media_type == Some(NdisMediumNative802_11)
        || physical_medium_type.is_some_and(|value| {
            value == NdisPhysicalMediumNative802_11 || value == NdisPhysicalMediumWirelessLan
        })
    {
        return InterfaceType::WiFi;
    }
    if media_type == Some(NdisMediumWirelessWan)
        || physical_medium_type == Some(NdisPhysicalMediumWirelessWan)
    {
        return InterfaceType::Other;
    }
    if matches!(
        if_type,
        IF_TYPE_ETHERNET_CSMACD
            | IF_TYPE_FAST
            | IF_TYPE_FASTETHER
            | IF_TYPE_FASTETHER_FX
            | IF_TYPE_GIGABITETHERNET
            | IF_TYPE_IEEE8023AD_LAG
    ) || media_type == Some(NdisMedium802_3)
        || physical_medium_type == Some(NdisPhysicalMedium802_3)
    {
        return InterfaceType::Ethernet;
    }
    if if_type == IF_TYPE_OTHER {
        return InterfaceType::Other;
    }

    InterfaceType::Unknown
}

pub fn get_network_interfaces() -> Result<NetworkInterfaces, NetworkError> {
    // 1. 获取完整路由表。适配器上的 gateway 列表不包含目的前缀和 metric，
    // 不能用于建立可靠的地址到网关关系。
    let routes = get_windows_routes()?;

    // 2. 由 FFI 适配层负责缓冲区扩容、边界和链表解析。
    let adapters = ffi::get_adapters()?;

    let mut interfaces = Vec::new();
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

        let interface_index = adapter.interface_index;
        let details = ffi::get_interface_details(interface_index);
        let interface_routes = routes
            .iter()
            .filter(|route| {
                (route.family == AddressFamily::Ipv4 && route.interface_index == interface_index)
                    || (route.family == AddressFamily::Ipv6
                        && adapter.ipv6_interface_index != 0
                        && route.interface_index == adapter.ipv6_interface_index)
            })
            .map(|route| route.clone_for_interface(&name))
            .collect::<Vec<Route>>();
        let interface_type = windows_interface_type(
            details.map_or(adapter.interface_type, |value| value.interface_type),
            details.map_or(adapter.tunnel_type, |value| value.tunnel_type),
            details.map(|value| value.media_type),
            details.map(|value| value.physical_medium_type),
        );

        // 3. 提取已由 FFI 适配层验证过的单播 IP 地址列表。
        let status = match adapter.oper_status {
            1 => InterfaceStatus::Up,
            2 => InterfaceStatus::Down,
            3 => InterfaceStatus::Testing,
            _ => InterfaceStatus::Unknown,
        };
        let mut builder = InterfaceBuilder::new(name.clone(), description, status);
        builder.set_interface_type(interface_type);
        if let Some(mac_address) = mac_address {
            builder.set_mac_address(mac_address);
        }

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

                builder.add_ipv4_address(Ipv4Info {
                    address: ip,
                    netmask,
                    prefix_len,
                    allocation: alloc,
                });
            } else if let IpAddr::V6(ip) = address.address {
                let prefix_len = unicast.prefix_len;
                builder.add_ipv6_address(Ipv6Info {
                    address: ip,
                    prefix_len,
                    allocation: alloc,
                });
            }
        }

        // 4. 确定链路速度
        let raw_speed = adapter.transmit_link_speed.max(adapter.receive_link_speed);
        let link_speed = if raw_speed > 0 && raw_speed != u64::MAX {
            Some(raw_speed)
        } else {
            None
        };
        if let Some(link_speed) = link_speed {
            builder.set_link_speed(link_speed);
        }

        // 5. 提取已由 FFI 适配层验证过的 DNS 服务器地址。
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

        // 6. 提取由 GetIfEntry2 返回的统计数据。
        if let Some(details) = details {
            builder.set_statistics(details.statistics);
        }

        builder.set_routes(interface_routes);
        interfaces.push(builder.build());
    }

    let dns = DnsConfiguration::from_servers(dns_servers);
    Ok(normalize_interfaces(interfaces, dns))
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

    #[test]
    fn classifies_windows_interfaces_from_iftype_tunnel_and_media() {
        use windows_sys::Win32::NetworkManagement::Ndis::TUNNEL_TYPE_DIRECT;

        assert_eq!(
            windows_interface_type(IF_TYPE_IEEE80211, TUNNEL_TYPE_NONE, None, None),
            InterfaceType::WiFi
        );
        assert_eq!(
            windows_interface_type(IF_TYPE_OTHER, TUNNEL_TYPE_DIRECT, None, None),
            InterfaceType::Tunnel
        );
        assert_eq!(
            windows_interface_type(IF_TYPE_PROP_VIRTUAL, TUNNEL_TYPE_NONE, None, None),
            InterfaceType::Virtual
        );
        assert_eq!(
            windows_interface_type(
                IF_TYPE_OTHER,
                TUNNEL_TYPE_NONE,
                None,
                Some(NdisPhysicalMediumWirelessLan),
            ),
            InterfaceType::WiFi
        );
        assert_eq!(
            windows_interface_type(999, TUNNEL_TYPE_NONE, None, None),
            InterfaceType::Unknown
        );
    }
}
