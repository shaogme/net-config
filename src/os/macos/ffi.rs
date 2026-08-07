use crate::shared::{InterfaceStats, NetworkError};
use std::collections::HashSet;
use std::mem::{offset_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::slice;

const LINK_LAYER_ADDRESS_LENGTH: usize = 6;
const LINK_LAYER_DATA_LENGTH: usize = 12;
const MAX_INTERFACE_NAME_BYTES: usize = 256;
const MAX_IFADDR_RECORDS: usize = 100_000;

pub(super) enum MacosAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Link,
}

pub(super) struct MacosLinkData {
    pub(super) mac_address: Option<[u8; LINK_LAYER_ADDRESS_LENGTH]>,
    pub(super) statistics: Option<InterfaceStats>,
    pub(super) link_speed: Option<u64>,
}

pub(super) struct IfaddrsRecord {
    pub(super) name: String,
    pub(super) flags: u32,
    pub(super) address: Option<MacosAddress>,
    pub(super) netmask: Option<MacosAddress>,
    pub(super) link_data: Option<MacosLinkData>,
}

fn read_bounded_c_string(
    pointer: *const libc::c_char,
    context: &str,
) -> Result<Option<String>, NetworkError> {
    if pointer.is_null() {
        return Ok(None);
    }

    let pointer = pointer.cast::<u8>();
    let mut bytes = Vec::new();
    for index in 0..MAX_INTERFACE_NAME_BYTES {
        let byte = unsafe { ptr::read(pointer.add(index)) };
        if byte == 0 {
            return Ok(Some(String::from_utf8_lossy(&bytes).into_owned()));
        }
        bytes.push(byte);
    }

    Err(NetworkError::invariant(format!(
        "{} is not null terminated within {} bytes",
        context, MAX_INTERFACE_NAME_BYTES
    )))
}

fn read_sockaddr_header(
    address: *const libc::sockaddr,
) -> Result<Option<(usize, i32)>, NetworkError> {
    if address.is_null() {
        return Ok(None);
    }

    let base = address.cast::<u8>();
    let length_offset = offset_of!(libc::sockaddr, sa_len);
    let family_offset = offset_of!(libc::sockaddr, sa_family);
    let minimum_len = (length_offset + size_of::<u8>()).max(family_offset + size_of::<u8>());
    let sockaddr_len = unsafe { ptr::read_unaligned(base.add(length_offset)) as usize };
    if sockaddr_len < minimum_len {
        return Ok(None);
    }
    let family = unsafe { ptr::read_unaligned(base.add(family_offset)) } as i32;
    Ok(Some((sockaddr_len, family)))
}

fn read_sockaddr(address: *const libc::sockaddr) -> Result<Option<MacosAddress>, NetworkError> {
    let Some((sockaddr_len, family)) = read_sockaddr_header(address)? else {
        return Ok(None);
    };

    match family {
        libc::AF_INET => {
            if sockaddr_len < size_of::<libc::sockaddr_in>() {
                return Ok(None);
            }
            let sockaddr = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_in>()) };
            Ok(Some(MacosAddress::Ipv4(Ipv4Addr::from(
                sockaddr.sin_addr.s_addr.to_ne_bytes(),
            ))))
        }
        libc::AF_INET6 => {
            if sockaddr_len < size_of::<libc::sockaddr_in6>() {
                return Ok(None);
            }
            let sockaddr = unsafe { ptr::read_unaligned(address.cast::<libc::sockaddr_in6>()) };
            Ok(Some(MacosAddress::Ipv6(Ipv6Addr::from(
                sockaddr.sin6_addr.s6_addr,
            ))))
        }
        libc::AF_LINK => Ok(Some(MacosAddress::Link)),
        _ => Ok(None),
    }
}

fn parse_sockaddr_dl_fields(
    sockaddr_len: usize,
    name_len: usize,
    address_len: usize,
    data_offset: usize,
    data: &[u8],
) -> Option<[u8; LINK_LAYER_ADDRESS_LENGTH]> {
    if sockaddr_len < data_offset || address_len != LINK_LAYER_ADDRESS_LENGTH {
        return None;
    }
    let data_end = name_len.checked_add(address_len)?;
    if data_end > data.len() || data_offset.checked_add(data_end)? > sockaddr_len {
        return None;
    }

    let mut address = [0u8; LINK_LAYER_ADDRESS_LENGTH];
    address.copy_from_slice(&data[name_len..data_end]);
    Some(address)
}

fn read_sockaddr_dl_mac(address: *const libc::sockaddr_dl) -> Option<[u8; 6]> {
    if address.is_null() {
        return None;
    }

    let base = address.cast::<u8>();
    let data_offset = offset_of!(libc::sockaddr_dl, sdl_data);
    let family_offset = offset_of!(libc::sockaddr_dl, sdl_family);
    let name_len_offset = offset_of!(libc::sockaddr_dl, sdl_nlen);
    let address_len_offset = offset_of!(libc::sockaddr_dl, sdl_alen);
    let minimum_len = data_offset
        .max(family_offset + size_of::<u8>())
        .max(name_len_offset + size_of::<u8>())
        .max(address_len_offset + size_of::<u8>());

    let sockaddr_len = unsafe { ptr::read_unaligned(base) as usize };
    if sockaddr_len < minimum_len {
        return None;
    }

    let family = unsafe { ptr::read_unaligned(base.add(family_offset)) };
    if family as i32 != libc::AF_LINK {
        return None;
    }

    let name_len = unsafe { ptr::read_unaligned(base.add(name_len_offset)) as usize };
    let address_len = unsafe { ptr::read_unaligned(base.add(address_len_offset)) as usize };
    let available_data_len = sockaddr_len
        .saturating_sub(data_offset)
        .min(LINK_LAYER_DATA_LENGTH);
    let data = unsafe { slice::from_raw_parts(base.add(data_offset), available_data_len) };

    parse_sockaddr_dl_fields(sockaddr_len, name_len, address_len, data_offset, data)
}

fn read_link_data(address: *const libc::sockaddr, data: *const libc::c_void) -> MacosLinkData {
    let mac_address = read_sockaddr_dl_mac(address.cast::<libc::sockaddr_dl>());
    let (statistics, link_speed) = if data.is_null() {
        (None, None)
    } else {
        let data = unsafe { ptr::read_unaligned(data.cast::<libc::if_data>()) };
        let statistics = InterfaceStats {
            rx_bytes: data.ifi_ibytes as u64,
            tx_bytes: data.ifi_obytes as u64,
            rx_packets: data.ifi_ipackets as u64,
            tx_packets: data.ifi_opackets as u64,
        };
        let link_speed = (data.ifi_baudrate > 0).then_some(data.ifi_baudrate as u64);
        (Some(statistics), link_speed)
    };

    MacosLinkData {
        mac_address,
        statistics,
        link_speed,
    }
}

struct IfaddrsGuard(*mut libc::ifaddrs);

impl Drop for IfaddrsGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

pub(super) fn get_ifaddrs_records() -> Result<Vec<IfaddrsRecord>, NetworkError> {
    let mut head = ptr::null_mut();
    let result = unsafe { libc::getifaddrs(&mut head) };
    if result != 0 {
        let code = std::io::Error::last_os_error()
            .raw_os_error()
            .map_or(0, |value| value as u32);
        return Err(NetworkError::api("getifaddrs", code));
    }

    let _guard = IfaddrsGuard(head);
    let mut current = head;
    let mut visited = HashSet::new();
    let mut records = Vec::new();

    while !current.is_null() {
        if !visited.insert(current as usize) {
            return Err(NetworkError::invariant("getifaddrs returned a cyclic list"));
        }
        if visited.len() > MAX_IFADDR_RECORDS {
            return Err(NetworkError::invariant(format!(
                "getifaddrs returned more than {} records",
                MAX_IFADDR_RECORDS
            )));
        }

        let ifa = unsafe { &*current };
        let next = ifa.ifa_next;
        let Some(name) = read_bounded_c_string(ifa.ifa_name, "interface name")? else {
            current = next;
            continue;
        };
        let address = read_sockaddr(ifa.ifa_addr)?;
        let netmask = read_sockaddr(ifa.ifa_netmask)?;
        let link_data = matches!(address, Some(MacosAddress::Link))
            .then(|| read_link_data(ifa.ifa_addr, ifa.ifa_data));

        records.push(IfaddrsRecord {
            name,
            flags: ifa.ifa_flags as u32,
            address,
            netmask,
            link_data,
        });
        current = next;
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_mac_after_interface_name() {
        let mut data = [0u8; LINK_LAYER_DATA_LENGTH];
        data[4..10].copy_from_slice(&[1, 2, 3, 4, 5, 6]);

        assert_eq!(
            parse_sockaddr_dl_fields(20, 4, 6, 8, &data),
            Some([1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn rejects_address_that_exceeds_sockaddr_data() {
        let data = [0u8; LINK_LAYER_DATA_LENGTH];
        assert_eq!(parse_sockaddr_dl_fields(20, 7, 6, 8, &data), None);
    }

    #[test]
    fn rejects_invalid_lengths_and_address_sizes() {
        let data = [0u8; LINK_LAYER_DATA_LENGTH];
        assert_eq!(parse_sockaddr_dl_fields(7, 0, 6, 8, &data), None);
        assert_eq!(parse_sockaddr_dl_fields(20, 0, 5, 8, &data), None);
    }
}
