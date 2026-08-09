use crate::shared::{AddressFamily, InterfaceStats, NetworkError};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_NETLINK: i32 = 16;
const NETLINK_ROUTE: i32 = 0;
const SOCK_RAW: i32 = libc::SOCK_RAW;
const SOCK_CLOEXEC: i32 = libc::SOCK_CLOEXEC;

const RTM_GETLINK: u16 = 18;
const RTM_GETADDR: u16 = 22;
const RTM_GETROUTE: u16 = 26;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const NLMSG_ALIGNTO: usize = 4;
const NLMSG_HEADER_LEN: usize = 16;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_STATS64: u16 = 23;
const IFLA_INFO_KIND: u16 = 1;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;
const IFA_PROTO: u16 = 11;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_MULTIPATH: u16 = 9;

pub const IFAPROT_UNSPEC: u8 = 0;
pub const IFAPROT_KERNEL_LO: u8 = 1;
pub const IFAPROT_KERNEL_RA: u8 = 2;
pub const IFAPROT_KERNEL_LL: u8 = 3;

const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const RTN_BROADCAST: u8 = 3;
const RTN_ANYCAST: u8 = 4;
const RTN_MULTICAST: u8 = 5;
const RTN_BLACKHOLE: u8 = 6;
const RTN_UNREACHABLE: u8 = 7;
const RTN_PROHIBIT: u8 = 8;
const RTN_THROW: u8 = 9;
const RTN_NAT: u8 = 10;
const RTN_XRESOLVE: u8 = 11;
pub const RTPROT_DHCP: u8 = 16;

#[derive(Debug, Clone)]
pub struct LinkFact {
    pub ifindex: u32,
    pub name: String,
    pub arp_type: u16,
    pub flags: u32,
    pub operstate: Option<u8>,
    pub mac_address: Option<String>,
    pub kind: Option<String>,
    pub statistics: Option<InterfaceStats>,
}

#[derive(Debug, Clone)]
pub struct AddressFact {
    pub ifindex: u32,
    pub family: AddressFamily,
    pub address: IpAddr,
    pub prefix_len: u8,
    pub scope: u8,
    pub flags: u32,
    pub protocol: u8,
    pub preferred_lifetime: Option<u32>,
    pub valid_lifetime: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RouteFact {
    pub family: AddressFamily,
    pub destination: IpAddr,
    pub prefix_len: u8,
    pub gateway: Option<IpAddr>,
    pub ifindex: u32,
    pub metric: Option<u32>,
    pub protocol: u8,
}

#[derive(Debug, Default)]
pub struct NetlinkSnapshot {
    pub links: HashMap<u32, LinkFact>,
    pub addresses: Vec<AddressFact>,
    pub routes: Vec<RouteFact>,
}

#[derive(Debug, Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    payload: &'a [u8],
}

struct RouteNetlinkSocket {
    fd: OwnedFd,
    next_sequence: u32,
}

impl RouteNetlinkSocket {
    fn open() -> Result<Self, NetworkError> {
        let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE) };
        if fd < 0 {
            return Err(NetworkError::api(
                "open rtnetlink socket",
                last_error_code(),
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let address = SockaddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const SockaddrNl).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrNl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(NetworkError::api(
                "bind rtnetlink socket",
                last_error_code(),
            ));
        }

        let timeout = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        let timeout_result = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&timeout as *const libc::timeval).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if timeout_result < 0 {
            return Err(NetworkError::api(
                "configure rtnetlink socket",
                last_error_code(),
            ));
        }

        Ok(Self {
            fd,
            next_sequence: 1,
        })
    }

    fn dump(&mut self, message_type: u16, payload: &[u8]) -> Result<Vec<Vec<u8>>, NetworkError> {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);

        let mut request = vec![0u8; NLMSG_HEADER_LEN + payload.len()];
        let request_length = request.len() as u32;
        put_u32(&mut request[0..4], request_length);
        put_u16(&mut request[4..6], message_type);
        put_u16(&mut request[6..8], NLM_F_REQUEST | NLM_F_DUMP);
        put_u32(&mut request[8..12], sequence);
        put_u32(&mut request[12..16], 0);
        request[NLMSG_HEADER_LEN..].copy_from_slice(payload);

        let destination = SockaddrNl {
            family: AF_NETLINK as u16,
            pad: 0,
            pid: 0,
            groups: 0,
        };
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                0,
                (&destination as *const SockaddrNl).cast::<libc::sockaddr>(),
                std::mem::size_of::<SockaddrNl>() as libc::socklen_t,
            )
        };
        if sent < 0 || sent as usize != request.len() {
            return Err(NetworkError::api(
                "send rtnetlink request",
                last_error_code(),
            ));
        }

        let mut messages = Vec::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let received = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(NetworkError::io(
                    "receive rtnetlink response",
                    "/proc/netlink",
                    error,
                ));
            }
            if received == 0 {
                return Err(NetworkError::parse("rtnetlink response", "empty response"));
            }

            let mut offset = 0usize;
            let received = received as usize;
            while offset < received {
                if received - offset < NLMSG_HEADER_LEN {
                    return Err(NetworkError::parse(
                        "rtnetlink message header",
                        (received - offset).to_string(),
                    ));
                }
                let length = read_u32(&buffer[offset..offset + 4])? as usize;
                if !(NLMSG_HEADER_LEN..=received - offset).contains(&length) {
                    return Err(NetworkError::parse(
                        "rtnetlink message length",
                        length.to_string(),
                    ));
                }
                let aligned_length = align(length, NLMSG_ALIGNTO);
                if aligned_length > received - offset {
                    return Err(NetworkError::parse(
                        "rtnetlink message alignment",
                        aligned_length.to_string(),
                    ));
                }
                let kind = read_u16(&buffer[offset + 4..offset + 6])?;
                let message_sequence = read_u32(&buffer[offset + 8..offset + 12])?;
                if message_sequence != sequence {
                    offset += aligned_length;
                    continue;
                }
                let body = &buffer[offset + NLMSG_HEADER_LEN..offset + length];
                match kind {
                    NLMSG_DONE => return Ok(messages),
                    NLMSG_ERROR => {
                        if body.len() < 4 {
                            return Err(NetworkError::parse(
                                "rtnetlink error response",
                                body.len().to_string(),
                            ));
                        }
                        let error = read_i32(body)?;
                        if error != 0 {
                            return Err(NetworkError::api("rtnetlink dump", error.unsigned_abs()));
                        }
                    }
                    _ => messages.push(body.to_vec()),
                }
                offset += aligned_length;
            }
        }
    }
}

#[repr(C)]
struct SockaddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

pub fn collect() -> Result<NetlinkSnapshot, NetworkError> {
    let mut socket = RouteNetlinkSocket::open()?;
    let link_messages = socket.dump(RTM_GETLINK, &link_request_payload())?;
    let address_messages = socket.dump(RTM_GETADDR, &address_request_payload())?;
    let route_messages = socket.dump(RTM_GETROUTE, &route_request_payload())?;

    let mut snapshot = NetlinkSnapshot::default();
    for message in link_messages {
        let fact = parse_link_message(&message)?;
        snapshot.links.insert(fact.ifindex, fact);
    }
    for message in address_messages {
        snapshot.addresses.push(parse_address_message(&message)?);
    }
    for message in route_messages {
        snapshot.routes.extend(parse_route_message(&message)?);
    }
    Ok(snapshot)
}

fn link_request_payload() -> Vec<u8> {
    let mut payload = vec![0u8; 16];
    payload[0] = AF_UNSPEC;
    payload
}

fn address_request_payload() -> Vec<u8> {
    vec![AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0]
}

fn route_request_payload() -> Vec<u8> {
    vec![AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn parse_link_message(message: &[u8]) -> Result<LinkFact, NetworkError> {
    if message.len() < 16 {
        return Err(NetworkError::parse(
            "rtnetlink link message",
            message.len().to_string(),
        ));
    }
    let arp_type = read_u16(&message[2..4])?;
    let ifindex = read_u32(&message[4..8])?;
    let flags = read_u32(&message[8..12])?;
    let attrs = parse_attributes(&message[16..])?;
    let name = attrs
        .iter()
        .find(|attribute| attribute.kind == IFLA_IFNAME)
        .and_then(|attribute| c_string(attribute.payload))
        .ok_or_else(|| NetworkError::parse("rtnetlink interface name", ifindex.to_string()))?;
    let mac_address = attrs
        .iter()
        .find(|attribute| attribute.kind == IFLA_ADDRESS)
        .and_then(|attribute| format_mac(attribute.payload));
    let operstate = attrs
        .iter()
        .find(|attribute| attribute.kind == IFLA_OPERSTATE)
        .and_then(|attribute| attribute.payload.first().copied());
    let kind = attrs
        .iter()
        .find(|attribute| attribute.kind == IFLA_LINKINFO)
        .and_then(|attribute| parse_attributes(attribute.payload).ok())
        .and_then(|nested| {
            nested
                .iter()
                .find(|attribute| attribute.kind == IFLA_INFO_KIND)
                .and_then(|attribute| c_string(attribute.payload))
        });
    let statistics = attrs
        .iter()
        .find(|attribute| attribute.kind == IFLA_STATS64)
        .and_then(|attribute| parse_link_statistics(attribute.payload));

    Ok(LinkFact {
        ifindex,
        name,
        arp_type,
        flags,
        operstate,
        mac_address,
        kind,
        statistics,
    })
}

fn parse_address_message(message: &[u8]) -> Result<AddressFact, NetworkError> {
    if message.len() < 8 {
        return Err(NetworkError::parse(
            "rtnetlink address message",
            message.len().to_string(),
        ));
    }
    let family = address_family(message[0])?;
    let prefix_len = message[1];
    let header_flags = u32::from(message[2]);
    let scope = message[3];
    let ifindex = read_u32(&message[4..8])?;
    let attrs = parse_attributes(&message[8..])?;
    let flags = attrs
        .iter()
        .find(|attribute| attribute.kind == IFA_FLAGS)
        .map_or(Ok(header_flags), |attribute| read_u32(attribute.payload))?;
    let address_payload = attrs
        .iter()
        .find(|attribute| attribute.kind == IFA_LOCAL)
        .or_else(|| attrs.iter().find(|attribute| attribute.kind == IFA_ADDRESS))
        .map(|attribute| attribute.payload)
        .ok_or_else(|| NetworkError::parse("rtnetlink address value", ifindex.to_string()))?;
    let address = parse_ip(family, address_payload)?;
    let protocol = attrs
        .iter()
        .find(|attribute| attribute.kind == IFA_PROTO)
        .and_then(|attribute| attribute.payload.first().copied())
        .unwrap_or(IFAPROT_UNSPEC);
    let (preferred_lifetime, valid_lifetime) = attrs
        .iter()
        .find(|attribute| attribute.kind == IFA_CACHEINFO)
        .map(|attribute| parse_cache_info(attribute.payload))
        .transpose()?
        .unwrap_or((None, None));

    Ok(AddressFact {
        ifindex,
        family,
        address,
        prefix_len,
        scope,
        flags,
        protocol,
        preferred_lifetime,
        valid_lifetime,
    })
}

fn parse_route_message(message: &[u8]) -> Result<Vec<RouteFact>, NetworkError> {
    if message.len() < 12 {
        return Err(NetworkError::parse(
            "rtnetlink route message",
            message.len().to_string(),
        ));
    }
    let family = match address_family(message[0]) {
        Ok(family) => family,
        Err(_) => return Ok(Vec::new()),
    };
    let prefix_len = message[1];
    if prefix_len
        > match family {
            AddressFamily::Ipv4 => 32,
            AddressFamily::Ipv6 => 128,
        }
    {
        return Err(NetworkError::parse(
            "rtnetlink route prefix length",
            prefix_len.to_string(),
        ));
    }
    let route_type = message[7];
    let protocol = message[5];
    if !matches!(
        route_type,
        RTN_UNICAST
            | RTN_LOCAL
            | RTN_BROADCAST
            | RTN_ANYCAST
            | RTN_MULTICAST
            | RTN_BLACKHOLE
            | RTN_UNREACHABLE
            | RTN_PROHIBIT
            | RTN_THROW
            | RTN_NAT
            | RTN_XRESOLVE
    ) {
        return Ok(Vec::new());
    }
    let attrs = parse_attributes(&message[12..])?;
    let destination = attrs
        .iter()
        .find(|attribute| attribute.kind == RTA_DST)
        .map(|attribute| parse_ip(family, attribute.payload))
        .transpose()?
        .unwrap_or_else(|| unspecified_address(family));
    let metric = attrs
        .iter()
        .find(|attribute| attribute.kind == RTA_PRIORITY)
        .map(|attribute| read_u32(attribute.payload))
        .transpose()?;
    let default_ifindex = attrs
        .iter()
        .find(|attribute| attribute.kind == RTA_OIF)
        .map(|attribute| read_u32(attribute.payload))
        .transpose()?
        .unwrap_or(0);
    let default_gateway = attrs
        .iter()
        .find(|attribute| attribute.kind == RTA_GATEWAY)
        .map(|attribute| parse_ip(family, attribute.payload))
        .transpose()?;

    let mut routes = Vec::new();
    if let Some(multipath) = attrs
        .iter()
        .find(|attribute| attribute.kind == RTA_MULTIPATH)
    {
        routes.extend(parse_multipath_routes(
            multipath.payload,
            family,
            destination,
            prefix_len,
            metric,
            protocol,
        )?);
    }
    if routes.is_empty() && default_ifindex != 0 {
        routes.push(RouteFact {
            family,
            destination,
            prefix_len,
            gateway: default_gateway,
            ifindex: default_ifindex,
            metric,
            protocol,
        });
    }
    Ok(routes)
}

fn parse_multipath_routes(
    payload: &[u8],
    family: AddressFamily,
    destination: IpAddr,
    prefix_len: u8,
    metric: Option<u32>,
    protocol: u8,
) -> Result<Vec<RouteFact>, NetworkError> {
    let mut routes = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        if payload.len() - offset < 8 {
            return Err(NetworkError::parse(
                "rtnetlink multipath header",
                (payload.len() - offset).to_string(),
            ));
        }
        let length = read_u16(&payload[offset..offset + 2])? as usize;
        if length < 8 || length > payload.len() - offset {
            return Err(NetworkError::parse(
                "rtnetlink multipath length",
                length.to_string(),
            ));
        }
        let ifindex = read_i32(&payload[offset + 4..offset + 8])?;
        if ifindex <= 0 {
            offset += align(length, NLMSG_ALIGNTO);
            continue;
        }
        let nested = parse_attributes(&payload[offset + 8..offset + length])?;
        let gateway = nested
            .iter()
            .find(|attribute| attribute.kind == RTA_GATEWAY)
            .map(|attribute| parse_ip(family, attribute.payload))
            .transpose()?;
        routes.push(RouteFact {
            family,
            destination,
            prefix_len,
            gateway,
            ifindex: ifindex as u32,
            metric,
            protocol,
        });
        offset += align(length, NLMSG_ALIGNTO);
    }
    Ok(routes)
}

fn parse_cache_info(payload: &[u8]) -> Result<(Option<u32>, Option<u32>), NetworkError> {
    if payload.len() < 8 {
        return Err(NetworkError::parse(
            "rtnetlink address cache info",
            payload.len().to_string(),
        ));
    }
    Ok((
        Some(read_u32(&payload[0..4])?),
        Some(read_u32(&payload[4..8])?),
    ))
}

fn parse_link_statistics(payload: &[u8]) -> Option<InterfaceStats> {
    if payload.len() < 32 {
        return None;
    }
    Some(InterfaceStats {
        rx_packets: read_u64(&payload[0..8]).ok()?,
        tx_packets: read_u64(&payload[8..16]).ok()?,
        rx_bytes: read_u64(&payload[16..24]).ok()?,
        tx_bytes: read_u64(&payload[24..32]).ok()?,
    })
}

fn parse_attributes(payload: &[u8]) -> Result<Vec<Attribute<'_>>, NetworkError> {
    let mut attributes = Vec::new();
    let mut offset = 0usize;
    while offset < payload.len() {
        if payload.len() - offset < 4 {
            return Err(NetworkError::parse(
                "rtnetlink attribute header",
                (payload.len() - offset).to_string(),
            ));
        }
        let length = read_u16(&payload[offset..offset + 2])? as usize;
        if length < 4 || length > payload.len() - offset {
            return Err(NetworkError::parse(
                "rtnetlink attribute length",
                length.to_string(),
            ));
        }
        let kind = read_u16(&payload[offset + 2..offset + 4])? & 0x3fff;
        attributes.push(Attribute {
            kind,
            payload: &payload[offset + 4..offset + length],
        });
        let aligned = align(length, NLMSG_ALIGNTO);
        if aligned > payload.len() - offset {
            return Err(NetworkError::parse(
                "rtnetlink attribute alignment",
                aligned.to_string(),
            ));
        }
        offset += aligned;
    }
    Ok(attributes)
}

fn address_family(value: u8) -> Result<AddressFamily, NetworkError> {
    match value {
        AF_INET => Ok(AddressFamily::Ipv4),
        AF_INET6 => Ok(AddressFamily::Ipv6),
        _ => Err(NetworkError::parse(
            "rtnetlink address family",
            value.to_string(),
        )),
    }
}

fn parse_ip(family: AddressFamily, payload: &[u8]) -> Result<IpAddr, NetworkError> {
    match family {
        AddressFamily::Ipv4 if payload.len() >= 4 => Ok(IpAddr::V4(Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        ))),
        AddressFamily::Ipv6 if payload.len() >= 16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&payload[..16]);
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => Err(NetworkError::parse(
            "rtnetlink IP address",
            payload.len().to_string(),
        )),
    }
}

fn unspecified_address(family: AddressFamily) -> IpAddr {
    match family {
        AddressFamily::Ipv4 => Ipv4Addr::UNSPECIFIED.into(),
        AddressFamily::Ipv6 => Ipv6Addr::UNSPECIFIED.into(),
    }
}

fn c_string(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(payload.len());
    (!payload[..end].is_empty()).then(|| String::from_utf8_lossy(&payload[..end]).into_owned())
}

fn format_mac(payload: &[u8]) -> Option<String> {
    if payload.is_empty() || payload.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(
        payload
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn align(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

fn read_u16(bytes: &[u8]) -> Result<u16, NetworkError> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| NetworkError::parse("rtnetlink u16", bytes.len().to_string()))?;
    Ok(u16::from_ne_bytes(bytes))
}

fn read_u32(bytes: &[u8]) -> Result<u32, NetworkError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| NetworkError::parse("rtnetlink u32", bytes.len().to_string()))?;
    Ok(u32::from_ne_bytes(bytes))
}

fn read_u64(bytes: &[u8]) -> Result<u64, NetworkError> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| NetworkError::parse("rtnetlink u64", bytes.len().to_string()))?;
    Ok(u64::from_ne_bytes(bytes))
}

fn read_i32(bytes: &[u8]) -> Result<i32, NetworkError> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| NetworkError::parse("rtnetlink i32", bytes.len().to_string()))?;
    Ok(i32::from_ne_bytes(bytes))
}

fn put_u16(bytes: &mut [u8], value: u16) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

fn put_u32(bytes: &mut [u8], value: u32) {
    bytes.copy_from_slice(&value.to_ne_bytes());
}

fn last_error_code() -> u32 {
    io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::unsigned_abs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = 4 + payload.len();
        let mut result = vec![0u8; align(length, 4)];
        put_u16(&mut result[0..2], length as u16);
        put_u16(&mut result[2..4], kind);
        result[4..length].copy_from_slice(payload);
        result
    }

    #[test]
    fn parses_link_fixture_with_nested_kind_and_stats() {
        let mut message = vec![0u8; 16];
        message[2..4].copy_from_slice(&1u16.to_ne_bytes());
        message[4..8].copy_from_slice(&2u32.to_ne_bytes());
        message[8..12].copy_from_slice(&0x1001u32.to_ne_bytes());
        message.extend(attr(3, b"enp0s3\0"));
        message.extend(attr(1, &[8, 0, 39, 20, 163, 77]));
        message.extend(attr(16, &[6]));
        let nested = attr(1, b"ether\0");
        message.extend(attr(18, &nested));
        let mut stats = vec![0u8; 32];
        stats[0..8].copy_from_slice(&11u64.to_ne_bytes());
        stats[8..16].copy_from_slice(&12u64.to_ne_bytes());
        stats[16..24].copy_from_slice(&13u64.to_ne_bytes());
        stats[24..32].copy_from_slice(&14u64.to_ne_bytes());
        message.extend(attr(23, &stats));

        let link = parse_link_message(&message).expect("link should parse");
        assert_eq!(link.ifindex, 2);
        assert_eq!(link.name, "enp0s3");
        assert_eq!(link.kind.as_deref(), Some("ether"));
        assert_eq!(link.mac_address.as_deref(), Some("08:00:27:14:A3:4D"));
        assert_eq!(link.statistics.map(|stats| stats.rx_bytes), Some(13));
    }

    #[test]
    fn parses_address_fixture_with_extended_flags_and_protocol() {
        let mut message = vec![10, 64, 0, 0];
        message.extend(2u32.to_ne_bytes());
        message.extend(attr(
            IFA_LOCAL,
            &Ipv6Addr::new(0xfd12, 0, 0, 0x254, 0xa00, 0x27ff, 0xfe14, 0xa34d).octets(),
        ));
        message.extend(attr(IFA_FLAGS, &0x900u32.to_ne_bytes()));
        message.extend(attr(IFA_PROTO, &[IFAPROT_KERNEL_RA]));
        message.extend(attr(IFA_CACHEINFO, &[1, 0, 0, 0, 2, 0, 0, 0]));

        let address = parse_address_message(&message).expect("address should parse");
        assert_eq!(address.family, AddressFamily::Ipv6);
        assert_eq!(address.protocol, IFAPROT_KERNEL_RA);
        assert_eq!(address.flags, 0x900);
        assert_eq!(address.preferred_lifetime, Some(1));
        assert_eq!(address.valid_lifetime, Some(2));
    }

    #[test]
    fn parses_route_fixture_and_defaults_missing_destination() {
        let mut message = vec![0u8; 12];
        message[0] = AF_INET;
        message[1] = 0;
        message[7] = RTN_UNICAST;
        message.extend(attr(RTA_OIF, &2u32.to_ne_bytes()));
        message.extend(attr(RTA_GATEWAY, &[10, 0, 2, 1]));
        message.extend(attr(RTA_PRIORITY, &1002u32.to_ne_bytes()));

        let routes = parse_route_message(&message).expect("route should parse");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].destination, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            routes[0].gateway,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1)))
        );
        assert_eq!(routes[0].ifindex, 2);
    }

    #[test]
    fn rejects_malformed_attribute_lengths() {
        let result = parse_attributes(&[9, 0, 1, 0, 1, 2, 3, 4]);
        assert!(result.is_err());
    }

    #[test]
    fn uses_native_message_layouts_for_each_dump() {
        assert_eq!(link_request_payload().len(), 16);
        assert_eq!(address_request_payload().len(), 8);
        assert_eq!(route_request_payload().len(), 12);
    }
}
