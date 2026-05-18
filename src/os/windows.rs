use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GetAdaptersAddresses, GetBestInterface, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

use crate::shared::{
    InterfaceStats, InterfaceStatus, InterfaceType, Ipv4Info, Ipv6Info, NetworkInterface,
    NetworkInterfaces,
};
use std::net::IpAddr;

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

pub fn get_network_interfaces() -> Result<NetworkInterfaces, String> {
    // 1. 获取主网卡接口索引 (GetBestInterface)
    let mut best_index = 0u32;
    // 传入 8.8.8.8 的大端表示 (0x08080808) 探测最优网络接口
    let has_best_interface =
        unsafe { GetBestInterface(0x08080808, &mut best_index) } == ERROR_SUCCESS;

    // 2. 准备缓冲区以调用 GetAdaptersAddresses
    let mut buf_len = 15000;
    let mut buf = vec![0u8; buf_len as usize];
    let family = AF_UNSPEC as u32;

    let mut res = unsafe {
        GetAdaptersAddresses(
            family,
            GAA_FLAG_INCLUDE_GATEWAYS,
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
                GAA_FLAG_INCLUDE_GATEWAYS,
                ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
    }

    if res != ERROR_SUCCESS {
        return Err(format!(
            "GetAdaptersAddresses failed with error code {}",
            res
        ));
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
            String::new()
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

        let mut ipv4_addresses = Vec::new();
        let mut ipv6_addresses = Vec::new();

        // 3. 提取单播 IP 地址列表
        let mut unicast_ptr = adapter.FirstUnicastAddress;
        while !unicast_ptr.is_null() {
            let unicast = unsafe { &*unicast_ptr };
            let lp_sockaddr = unicast.Address.lpSockaddr;

            if !lp_sockaddr.is_null() {
                let sa_family = unsafe { (*lp_sockaddr).sa_family };

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
                        gateways: Vec::new(),
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
                        gateways: Vec::new(),
                    });
                }
            }
            unicast_ptr = unicast.Next;
        }

        // 4. 提取网关地址列表
        let mut gateways_ipv4 = Vec::new();
        let mut gateways_ipv6 = Vec::new();

        let mut gateway_ptr = adapter.FirstGatewayAddress;
        while !gateway_ptr.is_null() {
            let gateway = unsafe { &*gateway_ptr };
            let lp_sockaddr = gateway.Address.lpSockaddr;

            if !lp_sockaddr.is_null() {
                let sa_family = unsafe { (*lp_sockaddr).sa_family };

                if sa_family as u32 == AF_INET as u32 {
                    let sock_in = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN) };
                    let s_addr = unsafe { sock_in.sin_addr.S_un.S_addr };
                    let ip_bytes = s_addr.to_ne_bytes();
                    let ip = Ipv4Addr::from(ip_bytes);
                    gateways_ipv4.push(ip);
                } else if sa_family as u32 == AF_INET6 as u32 {
                    let sock_in6 = unsafe { &*(lp_sockaddr as *const SOCKADDR_IN6) };
                    let ip_bytes = unsafe { sock_in6.sin6_addr.u.Byte };
                    let ip = Ipv6Addr::from(ip_bytes);
                    gateways_ipv6.push(ip);
                }
            }
            gateway_ptr = gateway.Next;
        }

        // 5. 将获取到的网关绑定到各 IP 配置上
        for ip_info in &mut ipv4_addresses {
            ip_info.gateways = gateways_ipv4.clone();
        }
        for ip_info in &mut ipv6_addresses {
            ip_info.gateways = gateways_ipv6.clone();
        }

        // 确定接口状态
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

        let iface = NetworkInterface {
            name,
            description,
            mac_address,
            ipv4_addresses,
            ipv6_addresses,
            status,
            interface_type,
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

    // 保底：若无主网卡，选择第一个非环回有IP绑定的网卡作为 primary
    if primary.is_none()
        && let Some(pos) = other.iter().position(|i| {
            !i.description.to_lowercase().contains("loopback")
                && (!i.ipv4_addresses.is_empty() || !i.ipv6_addresses.is_empty())
        })
    {
        primary = Some(other.remove(pos));
    }

    Ok(NetworkInterfaces { primary, other })
}
