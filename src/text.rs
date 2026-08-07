use crate::i18n::{self, Language, Text};
use crate::shared::{DnsConfiguration, DnsStatus, NetworkInterface, NetworkInterfaces};
use std::fmt;
use std::io::{self, Write};
use std::net::IpAddr;

const SECTION_INDENT: &str = " ";
const ITEM_INDENT: &str = "   ";
const NOTICE_INDENT: &str = "  ";
const TREE_MIDDLE: &str = "├──";
const TREE_LAST: &str = "└──";
const INDEX_SUFFIX_WIDTH: usize = 3;
const MIN_INDEX_WIDTH: usize = 2;

struct TextLayout {
    language: Language,
    interface_label_width: usize,
    nested_label_width: usize,
    statistics_label_width: usize,
}

impl TextLayout {
    fn current() -> Self {
        Self::for_language(i18n::current())
    }

    fn for_language(language: Language) -> Self {
        Self {
            language,
            interface_label_width: max_label_width(
                language,
                &[
                    Text::IfaceName,
                    Text::IfaceDescription,
                    Text::IfaceStatus,
                    Text::IfaceType,
                    Text::IfaceAllocation,
                    Text::IfaceSpeed,
                    Text::IfaceMac,
                ],
            ),
            nested_label_width: max_label_width(
                language,
                &[
                    Text::Ipv4AddrLabel,
                    Text::Ipv4MaskLabel,
                    Text::Ipv4AllocLabel,
                    Text::Ipv6AddrLabel,
                    Text::Ipv6PrefixLabel,
                    Text::Ipv6AllocLabel,
                    Text::DnsInterface,
                    Text::DnsSource,
                    Text::RouteDestination,
                    Text::RouteGateway,
                    Text::RouteInterface,
                    Text::RouteMetric,
                ],
            ),
            statistics_label_width: max_label_width(language, &[Text::RxStats, Text::TxStats]),
        }
    }

    fn text(&self, key: Text) -> &'static str {
        key.get_for(self.language)
    }

    fn label(&self, key: Text, width: usize) -> String {
        i18n::pad_right(self.text(key), width)
    }
}

fn max_label_width(language: Language, labels: &[Text]) -> usize {
    labels
        .iter()
        .map(|label| i18n::display_width(label.get_for(language)))
        .max()
        .unwrap_or(0)
}

struct IndexedLayout {
    index_width: usize,
    detail_indent: String,
}

impl IndexedLayout {
    fn for_count(item_count: usize) -> Self {
        let index_width = decimal_width(item_count).max(MIN_INDEX_WIDTH);
        let detail_indent =
            " ".repeat(i18n::display_width(ITEM_INDENT) + index_width + INDEX_SUFFIX_WIDTH);
        Self {
            index_width,
            detail_indent,
        }
    }
}

fn decimal_width(value: usize) -> usize {
    value.max(1).to_string().len()
}

pub fn render(interfaces: &NetworkInterfaces, show_all: bool) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let layout = TextLayout::current();
    render_to(interfaces, show_all, &layout, &mut output)?;
    output.flush()
}

fn render_to<W: Write>(
    interfaces: &NetworkInterfaces,
    show_all: bool,
    layout: &TextLayout,
    output: &mut W,
) -> io::Result<()> {
    writeln!(
        output,
        "=================================================================="
    )?;
    writeln!(output, " {}", layout.text(Text::ProgramTitle))?;
    writeln!(
        output,
        "=================================================================="
    )?;
    writeln!(output, "\n[{}]", layout.text(Text::PrimaryInterfaceHeader))?;
    if let Some(ref face) = interfaces.primary {
        write_interface(face, layout, output)?;
    } else {
        write_notice(output, layout.text(Text::NoPrimaryInterface))?;
    }

    if show_all {
        writeln!(output, "\n[{}]", layout.text(Text::OtherInterfaceHeader))?;
        if interfaces.other.is_empty() {
            write_notice(output, layout.text(Text::NoOtherInterface))?;
        } else {
            for face in &interfaces.other {
                write_interface(face, layout, output)?;
            }
        }
    }

    writeln!(output, "\n[{}]", layout.text(Text::SystemDns))?;
    write_dns(&interfaces.dns, layout, output)?;

    writeln!(
        output,
        "\n=================================================================="
    )?;
    Ok(())
}

fn write_dns<W: Write>(
    dns: &DnsConfiguration,
    layout: &TextLayout,
    output: &mut W,
) -> io::Result<()> {
    match dns.status {
        DnsStatus::Available => {
            let indexed_layout = IndexedLayout::for_count(dns.servers.len());
            write_section(output, layout.text(Text::DnsServers))?;
            for (index, server) in dns.servers.iter().enumerate() {
                let interface = server
                    .interface
                    .as_deref()
                    .unwrap_or(layout.text(Text::DnsInterfaceUnknown));
                write_indexed(
                    output,
                    &indexed_layout,
                    index + 1,
                    &layout.label(Text::Ipv4AddrLabel, layout.nested_label_width),
                    server.address,
                )?;
                write_indexed_detail(
                    output,
                    &indexed_layout,
                    &layout.label(Text::DnsInterface, layout.nested_label_width),
                    interface,
                )?;
                write_indexed_detail(
                    output,
                    &indexed_layout,
                    &layout.label(Text::DnsSource, layout.nested_label_width),
                    i18n::localize_dns_source_for(server.source, layout.language),
                )?;
            }
        }
        DnsStatus::None => write_notice(output, layout.text(Text::DnsNoServers))?,
        DnsStatus::Unavailable => write_notice(output, layout.text(Text::DnsUnavailable))?,
    }
    Ok(())
}

fn write_interface<W: Write>(
    face: &NetworkInterface,
    layout: &TextLayout,
    output: &mut W,
) -> io::Result<()> {
    writeln!(output, "--------------------------------------------------")?;
    write_field(
        output,
        &layout.label(Text::IfaceName, layout.interface_label_width),
        &face.name,
    )?;
    write_field(
        output,
        &layout.label(Text::IfaceDescription, layout.interface_label_width),
        &face.description,
    )?;
    write_field(
        output,
        &layout.label(Text::IfaceStatus, layout.interface_label_width),
        i18n::localize_status_for(face.status, layout.language),
    )?;
    write_field(
        output,
        &layout.label(Text::IfaceType, layout.interface_label_width),
        i18n::localize_type_for(face.interface_type, layout.language),
    )?;
    write_field(
        output,
        &layout.label(Text::IfaceAllocation, layout.interface_label_width),
        i18n::localize_allocation_for(face.allocation, layout.language),
    )?;

    let link_speed = face.link_speed.map_or_else(
        || layout.text(Text::SpeedUnknown).to_string(),
        format_link_speed,
    );
    write_field(
        output,
        &layout.label(Text::IfaceSpeed, layout.interface_label_width),
        link_speed,
    )?;

    let mac_address = face
        .mac_address
        .as_deref()
        .unwrap_or(layout.text(Text::MacUnknown));
    write_field(
        output,
        &layout.label(Text::IfaceMac, layout.interface_label_width),
        mac_address,
    )?;

    if !face.ipv4_addresses.is_empty() {
        let indexed_layout = IndexedLayout::for_count(face.ipv4_addresses.len());
        write_section(output, layout.text(Text::Ipv4Config))?;
        for (index, ipv4) in face.ipv4_addresses.iter().enumerate() {
            write_indexed(
                output,
                &indexed_layout,
                index + 1,
                &layout.label(Text::Ipv4AddrLabel, layout.nested_label_width),
                ipv4.address,
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::Ipv4MaskLabel, layout.nested_label_width),
                format!(
                    "{} ({} /{})",
                    ipv4.netmask,
                    layout.text(Text::Ipv4PrefixSuffix),
                    ipv4.prefix_len
                ),
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::Ipv4AllocLabel, layout.nested_label_width),
                i18n::localize_allocation_for(ipv4.allocation, layout.language),
            )?;
        }
    }

    if !face.ipv6_addresses.is_empty() {
        let indexed_layout = IndexedLayout::for_count(face.ipv6_addresses.len());
        write_section(output, layout.text(Text::Ipv6Config))?;
        for (index, ipv6) in face.ipv6_addresses.iter().enumerate() {
            write_indexed(
                output,
                &indexed_layout,
                index + 1,
                &layout.label(Text::Ipv6AddrLabel, layout.nested_label_width),
                ipv6.address,
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::Ipv6PrefixLabel, layout.nested_label_width),
                format!("/{}", ipv6.prefix_len),
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::Ipv6AllocLabel, layout.nested_label_width),
                i18n::localize_allocation_for(ipv6.allocation, layout.language),
            )?;
        }
    }

    if !face.routes.is_empty() {
        let indexed_layout = IndexedLayout::for_count(face.routes.len());
        write_section(output, layout.text(Text::Routes))?;
        for (index, route) in face.routes.iter().enumerate() {
            let destination = if route.is_default {
                layout.text(Text::RouteDefault).to_string()
            } else {
                format!("{}/{}", route.destination, route.prefix_len)
            };
            let gateway = match (route.gateway, route.gateway_scope.as_deref()) {
                (Some(IpAddr::V6(address)), Some(scope)) => {
                    format!("{}%{}", address, scope)
                }
                (Some(address), _) => address.to_string(),
                (None, _) => layout.text(Text::RouteGatewayNone).to_string(),
            };
            let metric = route.metric.map_or_else(
                || layout.text(Text::RouteMetricUnknown).to_string(),
                |value| value.to_string(),
            );

            write_indexed(
                output,
                &indexed_layout,
                index + 1,
                &layout.label(Text::RouteDestination, layout.nested_label_width),
                destination,
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::RouteGateway, layout.nested_label_width),
                gateway,
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::RouteInterface, layout.nested_label_width),
                &route.interface,
            )?;
            write_indexed_detail(
                output,
                &indexed_layout,
                &layout.label(Text::RouteMetric, layout.nested_label_width),
                metric,
            )?;
        }
    }

    if let Some(stats) = face.statistics {
        write_section(output, layout.text(Text::Statistics))?;
        write_tree_item(
            output,
            TREE_MIDDLE,
            &layout.label(Text::RxStats, layout.statistics_label_width),
            format!(
                "{} ({} {})",
                format_bytes(stats.rx_bytes),
                stats.rx_packets,
                layout.text(Text::Packets)
            ),
        )?;
        write_tree_item(
            output,
            TREE_LAST,
            &layout.label(Text::TxStats, layout.statistics_label_width),
            format!(
                "{} ({} {})",
                format_bytes(stats.tx_bytes),
                stats.tx_packets,
                layout.text(Text::Packets)
            ),
        )?;
    }

    Ok(())
}

fn write_notice<W: Write>(output: &mut W, message: &str) -> io::Result<()> {
    writeln!(output, "{NOTICE_INDENT}{message}")
}

fn write_section<W: Write>(output: &mut W, label: &str) -> io::Result<()> {
    writeln!(output, "{SECTION_INDENT}{label}:")
}

fn write_field<W: Write, V: fmt::Display>(output: &mut W, label: &str, value: V) -> io::Result<()> {
    write_labeled(output, SECTION_INDENT, label, value)
}

fn write_indexed<W: Write, V: fmt::Display>(
    output: &mut W,
    indexed_layout: &IndexedLayout,
    index: usize,
    label: &str,
    value: V,
) -> io::Result<()> {
    let formatted_index = format!("{index:0>width$}", width = indexed_layout.index_width);
    writeln!(output, "{ITEM_INDENT}[{formatted_index}] {label}: {value}")
}

fn write_indexed_detail<W: Write, V: fmt::Display>(
    output: &mut W,
    indexed_layout: &IndexedLayout,
    label: &str,
    value: V,
) -> io::Result<()> {
    write_labeled(output, &indexed_layout.detail_indent, label, value)
}

fn write_tree_item<W: Write, V: fmt::Display>(
    output: &mut W,
    branch: &str,
    label: &str,
    value: V,
) -> io::Result<()> {
    writeln!(output, "{ITEM_INDENT}{branch} {label}: {value}")
}

fn write_labeled<W: Write, V: fmt::Display>(
    output: &mut W,
    indent: &str,
    label: &str,
    value: V,
) -> io::Result<()> {
    writeln!(output, "{indent}{label}: {value}")
}

fn format_link_speed(bps: u64) -> String {
    if bps >= 1_000_000_000 {
        format!("{:.2} Gbps", bps as f64 / 1_000_000_000.0)
    } else if bps >= 1_000_000 {
        format!("{:.2} Mbps", bps as f64 / 1_000_000.0)
    } else {
        format!("{:.2} Kbps", bps as f64 / 1_000.0)
    }
}

fn format_bytes(bytes: u64) -> String {
    let kib = bytes as f64 / 1024.0;
    let mib = kib / 1024.0;
    let gib = mib / 1024.0;
    if gib >= 1.0 {
        format!("{:.2} GiB", gib)
    } else if mib >= 1.0 {
        format!("{:.2} MiB", mib)
    } else if kib >= 1.0 {
        format!("{:.2} KiB", kib)
    } else {
        format!("{} Bytes", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::{
        AddressFamily, DnsServer, DnsSource, InterfaceStats, InterfaceStatus, InterfaceType,
        IpAllocation, Ipv4Info, Ipv6Info, NetworkInterface, Route,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn fixture() -> NetworkInterfaces {
        let interface = NetworkInterface {
            name: "eth0".to_string(),
            description: "eth0".to_string(),
            mac_address: None,
            ipv4_addresses: Vec::new(),
            ipv6_addresses: Vec::new(),
            routes: vec![Route {
                family: AddressFamily::Ipv6,
                destination: IpAddr::V6(Ipv6Addr::from(0xff00_u128)),
                prefix_len: 8,
                gateway: None,
                gateway_scope: None,
                interface: "eth0".to_string(),
                metric: Some(256),
                is_default: false,
            }],
            status: InterfaceStatus::Up,
            interface_type: InterfaceType::Ethernet,
            allocation: IpAllocation::Unknown,
            link_speed: None,
            statistics: Some(InterfaceStats {
                rx_bytes: 1_086_175_232,
                tx_bytes: 57_961_472,
                rx_packets: 793_793,
                tx_packets: 755_720,
            }),
        };

        NetworkInterfaces {
            primary: Some(interface),
            other: Vec::new(),
            dns: DnsConfiguration {
                status: DnsStatus::Available,
                servers: vec![DnsServer {
                    address: IpAddr::V4(Ipv4Addr::new(172, 31, 96, 1)),
                    interface: None,
                    source: DnsSource::ResolvConf,
                }],
            },
        }
    }

    fn fixture_with_ten_items() -> NetworkInterfaces {
        let mut document = fixture();
        let interface = document
            .primary
            .as_mut()
            .expect("fixture should contain a primary interface");

        interface.ipv4_addresses = (1..=10)
            .map(|index| Ipv4Info {
                address: Ipv4Addr::new(192, 0, 2, index as u8),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefix_len: 24,
                allocation: IpAllocation::Unknown,
            })
            .collect();
        interface.ipv6_addresses = (1..=10)
            .map(|index| Ipv6Info {
                address: Ipv6Addr::from(index as u128),
                prefix_len: 128,
                allocation: IpAllocation::Unknown,
            })
            .collect();
        interface.routes = (1..=10)
            .map(|index| Route {
                family: AddressFamily::Ipv6,
                destination: IpAddr::V6(Ipv6Addr::from(index as u128)),
                prefix_len: 128,
                gateway: None,
                gateway_scope: None,
                interface: "eth0".to_string(),
                metric: Some(256),
                is_default: false,
            })
            .collect();
        document.dns.servers = (1..=10)
            .map(|index| DnsServer {
                address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, index as u8)),
                interface: None,
                source: DnsSource::ResolvConf,
            })
            .collect();

        document
    }

    fn render_document(document: &NetworkInterfaces, language: Language) -> String {
        let mut output = Vec::new();
        let layout = TextLayout::for_language(language);
        render_to(document, false, &layout, &mut output).expect("rendering should succeed");
        String::from_utf8(output).expect("rendered output should be UTF-8")
    }

    fn render_fixture(language: Language) -> String {
        render_document(&fixture(), language)
    }

    #[test]
    fn keeps_tree_and_detail_indentation_consistent() {
        let output = render_fixture(Language::En);

        assert!(output.lines().any(|line| line.starts_with("   [01]")));
        assert!(output.lines().any(|line| line.starts_with("       ")));
        assert!(output.lines().any(|line| line.starts_with("   ├──")));
        assert!(output.lines().any(|line| line.starts_with("   └──")));
        assert!(!output.lines().any(|line| line.starts_with("    ├──")));
        assert!(!output.lines().any(|line| line.starts_with("    └──")));
    }

    #[test]
    fn calculates_label_widths_from_requested_language() {
        let english = TextLayout::for_language(Language::En);
        let chinese = TextLayout::for_language(Language::Zh);

        assert_eq!(english.interface_label_width, 14);
        assert_eq!(english.nested_label_width, 11);
        assert_eq!(english.statistics_label_width, 16);
        assert_eq!(chinese.interface_label_width, 8);
        assert_eq!(chinese.nested_label_width, 8);
        assert_eq!(chinese.statistics_label_width, 9);
    }

    #[test]
    fn keeps_label_spacing_local_to_each_language() {
        let english = render_fixture(Language::En);
        let chinese = render_fixture(Language::Zh);

        assert!(
            english
                .lines()
                .any(|line| line.starts_with("   ├── Received (Rx)   :"))
        );
        assert!(
            english
                .lines()
                .any(|line| line.starts_with("   └── Transmitted (Tx):"))
        );
        assert!(
            chinese
                .lines()
                .any(|line| line.starts_with("   ├── 接收 (Rx):"))
        );
        assert!(
            chinese
                .lines()
                .any(|line| line.starts_with("   └── 发送 (Tx):"))
        );
    }

    #[test]
    fn aligns_all_tenth_items_with_their_predecessors() {
        let output = render_document(&fixture_with_ten_items(), Language::Zh);
        let lines: Vec<&str> = output.lines().collect();

        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("   [09]"))
                .count(),
            4
        );
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("   [10]"))
                .count(),
            4
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("   [09] 目的网络:"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("   [10] 目的网络:"))
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("        下一跳  :"))
        );
    }

    #[test]
    fn expands_index_and_detail_columns_for_hundred_items() {
        let indexed_layout = IndexedLayout::for_count(100);
        let mut output = Vec::new();

        write_indexed(&mut output, &indexed_layout, 99, "Label", "value")
            .expect("indexed row should render");
        write_indexed(&mut output, &indexed_layout, 100, "Label", "value")
            .expect("indexed row should render");
        write_indexed_detail(&mut output, &indexed_layout, "Detail", "value")
            .expect("indexed detail should render");

        let output = String::from_utf8(output).expect("rendered output should be UTF-8");
        let lines: Vec<&str> = output.lines().collect();
        assert!(lines[0].starts_with("   [099] Label"));
        assert!(lines[1].starts_with("   [100] Label"));
        assert!(lines[2].starts_with("         Detail"));
    }
}
