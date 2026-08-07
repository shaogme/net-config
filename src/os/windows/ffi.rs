use crate::shared::{AddressFamily, InterfaceStats, NetworkError};
use std::collections::HashSet;
use std::mem::{align_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfEntry2, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET, SOCKET_ADDRESS,
};

#[cfg(test)]
use windows_sys::Win32::Networking::WinSock::SOCKADDR;

const INITIAL_ADAPTER_BUFFER_SIZE: usize = 15_000;
const MAX_ADAPTER_BUFFER_SIZE: usize = 16 * 1024 * 1024;
const MAX_ADAPTER_BUFFER_ATTEMPTS: usize = 8;
const MAX_FORWARD_ROUTE_ENTRIES: usize = 100_000;
const MAX_STRING_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(super) struct ParsedSocketAddress {
    pub(super) family: AddressFamily,
    pub(super) address: IpAddr,
}

pub(super) struct UnicastData {
    pub(super) address: Option<ParsedSocketAddress>,
    pub(super) prefix_origin: i32,
    pub(super) suffix_origin: i32,
    pub(super) prefix_len: u8,
}

pub(super) struct AdapterData {
    pub(super) name: String,
    pub(super) description: String,
    pub(super) mac_address: Option<Vec<u8>>,
    pub(super) interface_index: u32,
    pub(super) ipv6_interface_index: u32,
    pub(super) unicast_addresses: Vec<UnicastData>,
    pub(super) dns_servers: Vec<ParsedSocketAddress>,
    pub(super) oper_status: i32,
    pub(super) interface_type: u32,
    pub(super) tunnel_type: i32,
    pub(super) transmit_link_speed: u64,
    pub(super) receive_link_speed: u64,
}

#[derive(Clone, Copy)]
pub(super) struct InterfaceDetails {
    pub(super) statistics: InterfaceStats,
    pub(super) interface_type: u32,
    pub(super) tunnel_type: i32,
    pub(super) media_type: i32,
    pub(super) physical_medium_type: i32,
}

pub(super) fn get_interface_details(interface_index: u32) -> Option<InterfaceDetails> {
    let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
    row.InterfaceIndex = interface_index;
    let result = unsafe { GetIfEntry2(&mut row) };
    if result != ERROR_SUCCESS {
        return None;
    }

    Some(InterfaceDetails {
        statistics: InterfaceStats {
            rx_bytes: row.InOctets,
            tx_bytes: row.OutOctets,
            rx_packets: row.InUcastPkts.saturating_add(row.InNUcastPkts),
            tx_packets: row.OutUcastPkts.saturating_add(row.OutNUcastPkts),
        },
        interface_type: row.Type,
        tunnel_type: row.TunnelType,
        media_type: row.MediaType,
        physical_medium_type: row.PhysicalMediumType,
    })
}

struct ForwardTable(*mut MIB_IPFORWARD_TABLE2);

impl Drop for ForwardTable {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0 as *const _) };
        }
    }
}

pub(super) fn get_forward_rows() -> Result<Vec<MIB_IPFORWARD_ROW2>, NetworkError> {
    let mut table = ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if result != ERROR_SUCCESS {
        return Err(NetworkError::api("GetIpForwardTable2", result));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }

    let _table_guard = ForwardTable(table);
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_FORWARD_ROUTE_ENTRIES {
        return Err(NetworkError::invariant(format!(
            "GetIpForwardTable2 returned {} entries",
            count
        )));
    }

    let rows = unsafe { slice::from_raw_parts((*table).Table.as_ptr(), count) };
    Ok(rows.to_vec())
}

pub(super) fn sockaddr_inet_to_ip(
    address: &SOCKADDR_INET,
) -> Option<(AddressFamily, IpAddr, Option<u32>)> {
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

struct AdapterBuffer {
    storage: Vec<u64>,
}

impl AdapterBuffer {
    fn load() -> Result<Self, NetworkError> {
        let mut requested_size = INITIAL_ADAPTER_BUFFER_SIZE;

        for _ in 0..MAX_ADAPTER_BUFFER_ATTEMPTS {
            let word_count = requested_size
                .checked_add(size_of::<u64>() - 1)
                .and_then(|size| size.checked_div(size_of::<u64>()))
                .ok_or_else(|| NetworkError::invariant("adapter buffer size overflow"))?;
            let mut storage = vec![0u64; word_count];
            let mut buffer_size = u32::try_from(storage.len() * size_of::<u64>())
                .map_err(|_| NetworkError::invariant("adapter buffer exceeds ULONG size"))?;

            let result = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    0,
                    ptr::null_mut(),
                    storage.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                    &mut buffer_size,
                )
            };

            if result == ERROR_SUCCESS {
                return Ok(Self { storage });
            }
            if result != ERROR_BUFFER_OVERFLOW {
                return Err(NetworkError::api("GetAdaptersAddresses", result));
            }

            let reported_size = usize::try_from(buffer_size)
                .map_err(|_| NetworkError::invariant("invalid adapter buffer size"))?;
            let doubled_size = requested_size
                .checked_mul(2)
                .ok_or_else(|| NetworkError::invariant("adapter buffer growth overflow"))?;
            requested_size = reported_size.max(doubled_size);
            if requested_size > MAX_ADAPTER_BUFFER_SIZE {
                return Err(NetworkError::invariant(format!(
                    "GetAdaptersAddresses requires {} bytes",
                    requested_size
                )));
            }
        }

        Err(NetworkError::invariant(
            "GetAdaptersAddresses exceeded the retry limit",
        ))
    }

    fn bytes(&self) -> &[u8] {
        unsafe {
            slice::from_raw_parts(
                self.storage.as_ptr().cast::<u8>(),
                self.storage.len() * size_of::<u64>(),
            )
        }
    }

    fn pointer_offset(
        &self,
        pointer: *const u8,
        required: usize,
        context: &str,
    ) -> Result<Option<usize>, NetworkError> {
        if pointer.is_null() {
            return Ok(None);
        }

        let base = self.storage.as_ptr() as usize;
        let end = base
            .checked_add(self.storage.len() * size_of::<u64>())
            .ok_or_else(|| NetworkError::invariant("adapter buffer address overflow"))?;
        let address = pointer as usize;
        let required_end = address
            .checked_add(required)
            .ok_or_else(|| NetworkError::invariant(format!("{} address overflow", context)))?;
        if address < base || required_end > end {
            return Err(NetworkError::invariant(format!(
                "{} points outside the adapter buffer",
                context
            )));
        }

        Ok(Some(address - base))
    }

    fn validate_pointer<T>(&self, pointer: *const T, context: &str) -> Result<(), NetworkError> {
        let Some(_) = self.pointer_offset(pointer.cast(), size_of::<T>(), context)? else {
            return Err(NetworkError::invariant(format!(
                "{} is unexpectedly null",
                context
            )));
        };
        if !(pointer as usize).is_multiple_of(align_of::<T>()) {
            return Err(NetworkError::invariant(format!(
                "{} is not correctly aligned",
                context
            )));
        }
        Ok(())
    }

    fn read_struct<T: Copy>(
        &self,
        pointer: *const T,
        context: &str,
    ) -> Result<Option<T>, NetworkError> {
        let Some(_) = self.pointer_offset(pointer.cast(), size_of::<T>(), context)? else {
            return Ok(None);
        };
        if !(pointer as usize).is_multiple_of(align_of::<T>()) {
            return Err(NetworkError::invariant(format!(
                "{} is not correctly aligned",
                context
            )));
        }
        Ok(Some(unsafe { ptr::read_unaligned(pointer) }))
    }

    fn validate_node_length<T>(
        &self,
        pointer: *const T,
        reported_length: u32,
        context: &str,
    ) -> Result<(), NetworkError> {
        let length = usize::try_from(reported_length)
            .map_err(|_| NetworkError::invariant(format!("{} length is invalid", context)))?;
        if length < size_of::<T>() {
            return Err(NetworkError::invariant(format!(
                "{} length {} is smaller than its structure",
                context, length
            )));
        }
        self.pointer_offset(pointer.cast(), length, context)?;
        Ok(())
    }

    fn read_c_string(
        &self,
        pointer: *const u8,
        context: &str,
    ) -> Result<Option<String>, NetworkError> {
        let Some(offset) = self.pointer_offset(pointer.cast(), 1, context)? else {
            return Ok(None);
        };
        let bytes = &self.bytes()[offset..];
        let bytes = &bytes[..bytes.len().min(MAX_STRING_BYTES)];
        let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| {
            NetworkError::invariant(format!("{} is not null terminated", context))
        })?;
        Ok(Some(String::from_utf8_lossy(&bytes[..end]).into_owned()))
    }

    fn read_utf16_string(
        &self,
        pointer: *const u16,
        context: &str,
    ) -> Result<Option<String>, NetworkError> {
        let Some(offset) = self.pointer_offset(pointer.cast(), size_of::<u16>(), context)? else {
            return Ok(None);
        };
        if !(pointer as usize).is_multiple_of(align_of::<u16>()) {
            return Err(NetworkError::invariant(format!(
                "{} is not correctly aligned",
                context
            )));
        }

        let bytes = &self.bytes()[offset..];
        let bytes = &bytes[..bytes.len().min(MAX_STRING_BYTES)];
        let mut values = Vec::new();
        for chunk in bytes.chunks_exact(size_of::<u16>()) {
            let value = u16::from_ne_bytes([chunk[0], chunk[1]]);
            if value == 0 {
                return Ok(Some(String::from_utf16_lossy(&values)));
            }
            values.push(value);
        }

        Err(NetworkError::invariant(format!(
            "{} is not null terminated",
            context
        )))
    }

    fn read_socket_address(
        &self,
        address: &SOCKET_ADDRESS,
        context: &str,
    ) -> Result<Option<ParsedSocketAddress>, NetworkError> {
        let length = if address.iSockaddrLength < 0 {
            return Err(NetworkError::invariant(format!(
                "{} has a negative length",
                context
            )));
        } else {
            address.iSockaddrLength as usize
        };
        if address.lpSockaddr.is_null() {
            if length == 0 {
                return Ok(None);
            }
            return Err(NetworkError::invariant(format!(
                "{} has a null pointer with a non-zero length",
                context
            )));
        }
        if length < size_of::<u16>() {
            return Err(NetworkError::invariant(format!(
                "{} is shorter than an address family",
                context
            )));
        }
        let Some(offset) = self.pointer_offset(address.lpSockaddr.cast(), length, context)? else {
            return Ok(None);
        };
        let bytes = self.bytes();
        let family = u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]);

        match family {
            AF_INET => {
                if length < size_of::<SOCKADDR_IN>() {
                    return Err(NetworkError::invariant(format!(
                        "{} is shorter than SOCKADDR_IN",
                        context
                    )));
                }
                let sockaddr = self
                    .read_struct(address.lpSockaddr.cast::<SOCKADDR_IN>(), context)?
                    .ok_or_else(|| NetworkError::invariant("socket address became null"))?;
                let value = unsafe { sockaddr.sin_addr.S_un.S_addr };
                Ok(Some(ParsedSocketAddress {
                    family: AddressFamily::Ipv4,
                    address: IpAddr::V4(Ipv4Addr::from(value.to_ne_bytes())),
                }))
            }
            AF_INET6 => {
                if length < size_of::<SOCKADDR_IN6>() {
                    return Err(NetworkError::invariant(format!(
                        "{} is shorter than SOCKADDR_IN6",
                        context
                    )));
                }
                let sockaddr = self
                    .read_struct(address.lpSockaddr.cast::<SOCKADDR_IN6>(), context)?
                    .ok_or_else(|| NetworkError::invariant("socket address became null"))?;
                let value = unsafe { sockaddr.sin6_addr.u.Byte };
                Ok(Some(ParsedSocketAddress {
                    family: AddressFamily::Ipv6,
                    address: IpAddr::V6(Ipv6Addr::from(value)),
                }))
            }
            _ => Ok(None),
        }
    }

    fn read_adapters(&self) -> Result<Vec<AdapterData>, NetworkError> {
        let mut current = self.storage.as_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        let mut visited = HashSet::new();
        let mut adapters = Vec::new();

        while !current.is_null() {
            if !visited.insert(current as usize) {
                return Err(NetworkError::invariant(
                    "GetAdaptersAddresses returned a cyclic adapter list",
                ));
            }
            let (adapter, next) = self.read_adapter(current)?;
            adapters.push(adapter);
            current = next;
        }

        Ok(adapters)
    }

    fn read_adapter(
        &self,
        pointer: *const IP_ADAPTER_ADDRESSES_LH,
    ) -> Result<(AdapterData, *mut IP_ADAPTER_ADDRESSES_LH), NetworkError> {
        let adapter = self
            .read_struct(pointer, "adapter node")?
            .ok_or_else(|| NetworkError::invariant("adapter node is null"))?;
        let length = unsafe { adapter.Anonymous1.Anonymous.Length };
        self.validate_node_length(pointer, length, "adapter node")?;

        let name = self
            .read_c_string(adapter.AdapterName.cast_const(), "adapter name")?
            .ok_or_else(|| NetworkError::invariant("adapter name is null"))?;
        let description = self
            .read_utf16_string(adapter.FriendlyName, "adapter friendly name")?
            .unwrap_or_default();
        let mac_address =
            parse_physical_address(&adapter.PhysicalAddress, adapter.PhysicalAddressLength)?;
        let unicast_addresses = self.read_unicast_addresses(adapter.FirstUnicastAddress)?;
        let dns_servers = self.read_dns_servers(adapter.FirstDnsServerAddress)?;
        let next = adapter.Next;
        if !next.is_null() {
            self.validate_pointer(next, "adapter Next")?;
        }

        Ok((
            AdapterData {
                name,
                description,
                mac_address,
                interface_index: unsafe { adapter.Anonymous1.Anonymous.IfIndex },
                ipv6_interface_index: adapter.Ipv6IfIndex,
                unicast_addresses,
                dns_servers,
                oper_status: adapter.OperStatus,
                interface_type: adapter.IfType,
                tunnel_type: adapter.TunnelType,
                transmit_link_speed: adapter.TransmitLinkSpeed,
                receive_link_speed: adapter.ReceiveLinkSpeed,
            },
            next,
        ))
    }

    fn read_unicast_addresses(
        &self,
        first: *mut IP_ADAPTER_UNICAST_ADDRESS_LH,
    ) -> Result<Vec<UnicastData>, NetworkError> {
        let mut current = first;
        let mut visited = HashSet::new();
        let mut addresses = Vec::new();

        while !current.is_null() {
            if !visited.insert(current as usize) {
                return Err(NetworkError::invariant(
                    "adapter returned a cyclic unicast address list",
                ));
            }
            let node = self
                .read_struct(current, "unicast address node")?
                .ok_or_else(|| NetworkError::invariant("unicast address node is null"))?;
            let length = unsafe { node.Anonymous.Anonymous.Length };
            self.validate_node_length(current, length, "unicast address node")?;
            let next = node.Next;
            if !next.is_null() {
                self.validate_pointer(next, "unicast address Next")?;
            }
            addresses.push(UnicastData {
                address: self.read_socket_address(&node.Address, "unicast socket address")?,
                prefix_origin: node.PrefixOrigin,
                suffix_origin: node.SuffixOrigin,
                prefix_len: node.OnLinkPrefixLength,
            });
            current = next;
        }

        Ok(addresses)
    }

    fn read_dns_servers(
        &self,
        first: *mut IP_ADAPTER_DNS_SERVER_ADDRESS_XP,
    ) -> Result<Vec<ParsedSocketAddress>, NetworkError> {
        let mut current = first;
        let mut visited = HashSet::new();
        let mut servers = Vec::new();

        while !current.is_null() {
            if !visited.insert(current as usize) {
                return Err(NetworkError::invariant(
                    "adapter returned a cyclic DNS server list",
                ));
            }
            let node = self
                .read_struct(current, "DNS server node")?
                .ok_or_else(|| NetworkError::invariant("DNS server node is null"))?;
            let length = unsafe { node.Anonymous.Anonymous.Length };
            self.validate_node_length(current, length, "DNS server node")?;
            let next = node.Next;
            if !next.is_null() {
                self.validate_pointer(next, "DNS server Next")?;
            }
            if let Some(address) = self.read_socket_address(&node.Address, "DNS socket address")? {
                servers.push(address);
            }
            current = next;
        }

        Ok(servers)
    }
}

fn parse_physical_address(
    address: &[u8; 8],
    reported_length: u32,
) -> Result<Option<Vec<u8>>, NetworkError> {
    let length = usize::try_from(reported_length)
        .map_err(|_| NetworkError::invariant("physical address length is invalid"))?;
    if length == 0 {
        return Ok(None);
    }
    if length > address.len() {
        return Err(NetworkError::invariant(format!(
            "physical address length {} exceeds {} bytes",
            length,
            address.len()
        )));
    }
    Ok(Some(address[..length].to_vec()))
}

pub(super) fn get_adapters() -> Result<Vec<AdapterData>, NetworkError> {
    AdapterBuffer::load()?.read_adapters()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_physical_address_longer_than_storage() {
        let address = [0u8; 8];
        let error = parse_physical_address(&address, 9).expect_err("length must be rejected");
        assert_eq!(error.code(), "invariant");
    }

    #[test]
    fn accepts_zero_and_valid_physical_address_lengths() {
        let address = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(parse_physical_address(&address, 0).unwrap(), None);
        assert_eq!(
            parse_physical_address(&address, 6).unwrap(),
            Some(vec![1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn grows_after_repeated_buffer_overflow() {
        let requested = 15_000usize;
        let reported = 16_000usize;
        assert_eq!(reported.max(requested * 2), 30_000);
    }

    #[test]
    fn rejects_unbounded_strings_and_socket_addresses() {
        let buffer = AdapterBuffer {
            storage: vec![u64::MAX; 2],
        };
        let bytes = buffer.bytes();
        let string_error = buffer
            .read_c_string(bytes.as_ptr(), "test string")
            .expect_err("unterminated strings must be rejected");
        assert_eq!(string_error.code(), "invariant");

        let utf16_error = buffer
            .read_utf16_string(bytes.as_ptr().cast(), "test UTF-16 string")
            .expect_err("unterminated UTF-16 strings must be rejected");
        assert_eq!(utf16_error.code(), "invariant");

        let socket_address = SOCKET_ADDRESS {
            lpSockaddr: bytes.as_ptr() as *mut SOCKADDR,
            iSockaddrLength: (bytes.len() + 1) as i32,
        };
        let socket_error = buffer
            .read_socket_address(&socket_address, "test socket address")
            .expect_err("socket address bounds must be checked");
        assert_eq!(socket_error.code(), "invariant");
    }
}
