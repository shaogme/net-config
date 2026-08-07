mod i18n;
mod os;
mod shared;

use std::fmt;
use std::io::{self, Write};

#[derive(Debug)]
enum AppError {
    UnknownArgument(String),
    UnsupportedLanguage(String),
    Network(shared::NetworkError),
    Json(serde_json::Error),
    Output(io::Error),
}

impl From<shared::NetworkError> for AppError {
    fn from(error: shared::NetworkError) -> Self {
        Self::Network(error)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        Self::Output(error)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownArgument(argument) => {
                write!(formatter, "{}: {}", t!(UnknownArg), argument)
            }
            Self::UnsupportedLanguage(language) => write!(
                formatter,
                "{} '{}'. Supported values: 'zh', 'en'.",
                t!(UnsupportedLanguage),
                language
            ),
            Self::Network(error) => {
                write!(
                    formatter,
                    "{} [{}]: {}",
                    t!(FetchInterfaceError),
                    error.code(),
                    error
                )
            }
            Self::Json(error) => write!(formatter, "{}: {}", t!(JsonError), error),
            Self::Output(error) => write!(formatter, "{}: {}", t!(OutputError), error),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Network(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Output(error) => Some(error),
            Self::UnknownArgument(_) | Self::UnsupportedLanguage(_) => None,
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), AppError> {
    let args: Vec<String> = std::env::args().collect();

    let mut show_all = false;
    let mut show_help = false;
    let mut json_output = false;
    let mut unknown_arg = None;
    let mut custom_lang = None;

    // 健壮的命令行解析器，支持 -l / --lang 及其值
    let mut args_iter = args[1..].iter().peekable();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-a" | "--all" => show_all = true,
            "-h" | "--help" => show_help = true,
            "-j" | "--json" => json_output = true,
            "-l" | "--lang" => {
                if let Some(val) = args_iter.peek() {
                    // 如果下一个值不是以减号开头，说明是语言参数值
                    if !val.starts_with('-') {
                        custom_lang = Some((*val).clone());
                        args_iter.next(); // 消费该语言参数值
                    } else {
                        unknown_arg = Some(arg.clone());
                    }
                } else {
                    unknown_arg = Some(arg.clone());
                }
            }
            other if other.starts_with("--lang=") => {
                custom_lang = Some(other["--lang=".len()..].to_string());
            }
            other if other.starts_with("-l=") => {
                custom_lang = Some(other["-l=".len()..].to_string());
            }
            other => {
                unknown_arg = Some(other.to_string());
            }
        }
    }

    // 如果指定了自定义语言，则优先初始化全局 i18n
    if let Some(ref lang_str) = custom_lang {
        if let Some(lang) = i18n::Language::from_str(lang_str) {
            i18n::init(lang);
        } else {
            return Err(AppError::UnsupportedLanguage(lang_str.clone()));
        }
    }

    if show_help {
        print_help(&args[0])?;
        return Ok(());
    }

    if let Some(arg) = unknown_arg {
        print_help(&args[0])?;
        return Err(AppError::UnknownArgument(arg));
    }

    let mut interfaces = shared::get_network_interfaces()?;
    if !show_all {
        interfaces.other.clear();
    }

    if json_output {
        render_json(&interfaces)?;
    } else {
        render_text(&interfaces, show_all)?;
    }

    Ok(())
}

fn print_help(program_name: &str) -> Result<(), AppError> {
    let path = std::path::Path::new(program_name);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program_name);

    let stdout = io::stdout();
    let mut output = stdout.lock();
    write!(output, "{}", t!(UsageTitle))?;
    writeln!(output, "{}", t!(Usage))?;
    writeln!(output, "  {} [options]\n", name)?;
    writeln!(output, "{}", t!(OptionsHeader))?;
    writeln!(output, "{}", t!(OptAll))?;
    writeln!(output, "{}", t!(OptJson))?;
    writeln!(output, "{}", t!(OptHelp))?;
    writeln!(output, "{}", t!(OptLang))?;
    output.flush()?;
    Ok(())
}

fn render_json(interfaces: &shared::NetworkInterfaces) -> Result<(), AppError> {
    let json = serde_json::to_string_pretty(interfaces)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{}", json)?;
    output.flush()?;
    Ok(())
}

fn render_text(interfaces: &shared::NetworkInterfaces, show_all: bool) -> Result<(), AppError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();

    writeln!(
        output,
        "=================================================================="
    )?;
    writeln!(output, " {}", t!(ProgramTitle))?;
    writeln!(
        output,
        "=================================================================="
    )?;
    writeln!(output, "\n[{}]", t!(PrimaryInterfaceHeader))?;
    if let Some(ref face) = interfaces.primary {
        print_interface(face, &mut output)?;
    } else {
        writeln!(output, "{}", t!(NoPrimaryInterface))?;
    }

    if show_all {
        writeln!(output, "\n[{}]", t!(OtherInterfaceHeader))?;
        if interfaces.other.is_empty() {
            writeln!(output, "{}", t!(NoOtherInterface))?;
        } else {
            for face in &interfaces.other {
                print_interface(face, &mut output)?;
            }
        }
    }

    writeln!(output, "\n[{}]", t!(SystemDns))?;
    match interfaces.dns.status {
        shared::DnsStatus::Available => {
            writeln!(output, " {}:", t!(DnsServers))?;
            for (index, server) in interfaces.dns.servers.iter().enumerate() {
                let interface = server
                    .interface
                    .as_deref()
                    .unwrap_or(t!(DnsInterfaceUnknown));
                writeln!(
                    output,
                    "   [{}] {}: {}",
                    index + 1,
                    t!(Ipv4AddrLabel, 11),
                    server.address
                )?;
                writeln!(output, "       {}: {}", t!(DnsInterface, 11), interface)?;
                writeln!(
                    output,
                    "       {}: {}",
                    t!(DnsSource, 11),
                    i18n::localize_dns_source(server.source)
                )?;
            }
        }
        shared::DnsStatus::None => writeln!(output, "{}", t!(DnsNoServers))?,
        shared::DnsStatus::Unavailable => writeln!(output, "{}", t!(DnsUnavailable))?,
    }

    writeln!(
        output,
        "\n=================================================================="
    )?;
    output.flush()?;
    Ok(())
}

fn print_interface<W: Write>(face: &shared::NetworkInterface, output: &mut W) -> io::Result<()> {
    writeln!(output, "--------------------------------------------------")?;
    writeln!(output, " {}: {}", t!(IfaceName, 14), face.name)?;
    writeln!(
        output,
        " {}: {}",
        t!(IfaceDescription, 14),
        face.description
    )?;

    // 1. 状态与指示灯
    writeln!(
        output,
        " {}: {}",
        t!(IfaceStatus, 14),
        i18n::localize_status(face.status)
    )?;

    // 2. 接口类型
    writeln!(
        output,
        " {}: {}",
        t!(IfaceType, 14),
        i18n::localize_type(face.interface_type)
    )?;

    // 3. IP/协议栈分配方式
    writeln!(
        output,
        " {}: {}",
        t!(IfaceAllocation, 14),
        i18n::localize_allocation(face.allocation)
    )?;

    // 4. 链路速度
    if let Some(speed) = face.link_speed {
        writeln!(
            output,
            " {}: {}",
            t!(IfaceSpeed, 14),
            format_link_speed(speed)
        )?;
    } else {
        writeln!(output, " {}: {}", t!(IfaceSpeed, 14), t!(SpeedUnknown))?;
    }

    // 5. MAC 地址
    if let Some(ref mac) = face.mac_address {
        writeln!(output, " {}: {}", t!(IfaceMac, 14), mac)?;
    } else {
        writeln!(output, " {}: {}", t!(IfaceMac, 14), t!(MacUnknown))?;
    }

    // 6. IPv4 地址配置
    if !face.ipv4_addresses.is_empty() {
        writeln!(output, " {}:", t!(Ipv4Config))?;
        for (i, ipv4) in face.ipv4_addresses.iter().enumerate() {
            writeln!(
                output,
                "   [{}] {}: {}",
                i + 1,
                t!(Ipv4AddrLabel, 11),
                ipv4.address
            )?;
            writeln!(
                output,
                "       {}: {} ({} /{})",
                t!(Ipv4MaskLabel, 11),
                ipv4.netmask,
                t!(Ipv4PrefixSuffix),
                ipv4.prefix_len
            )?;
            writeln!(
                output,
                "       {}: {}",
                t!(Ipv4AllocLabel, 11),
                i18n::localize_allocation(ipv4.allocation)
            )?;
        }
    }

    // 7. IPv6 地址配置
    if !face.ipv6_addresses.is_empty() {
        writeln!(output, " {}:", t!(Ipv6Config))?;
        for (i, ipv6) in face.ipv6_addresses.iter().enumerate() {
            writeln!(
                output,
                "   [{}] {}: {}",
                i + 1,
                t!(Ipv6AddrLabel, 11),
                ipv6.address
            )?;
            writeln!(
                output,
                "       {}: /{}",
                t!(Ipv6PrefixLabel, 11),
                ipv6.prefix_len
            )?;
            writeln!(
                output,
                "       {}: {}",
                t!(Ipv6AllocLabel, 11),
                i18n::localize_allocation(ipv6.allocation)
            )?;
        }
    }

    // 8. 路由配置
    if !face.routes.is_empty() {
        writeln!(output, " {}:", t!(Routes))?;
        for (i, route) in face.routes.iter().enumerate() {
            let destination = if route.is_default {
                t!(RouteDefault).to_string()
            } else {
                format!("{}/{}", route.destination, route.prefix_len)
            };
            let gateway = match (route.gateway, route.gateway_scope.as_deref()) {
                (Some(std::net::IpAddr::V6(address)), Some(scope)) => {
                    format!("{}%{}", address, scope)
                }
                (Some(address), _) => address.to_string(),
                (None, _) => t!(RouteGatewayNone).to_string(),
            };
            let metric = route.metric.map_or_else(
                || t!(RouteMetricUnknown).to_string(),
                |value| value.to_string(),
            );

            writeln!(
                output,
                "   [{}] {}: {}",
                i + 1,
                t!(RouteDestination, 11),
                destination
            )?;
            writeln!(output, "       {}: {}", t!(RouteGateway, 11), gateway)?;
            writeln!(
                output,
                "       {}: {}",
                t!(RouteInterface, 11),
                route.interface
            )?;
            writeln!(output, "       {}: {}", t!(RouteMetric, 11), metric)?;
        }
    }

    // 9. 网络吞吐流量统计 (采用树状结构)
    if let Some(ref stats) = face.statistics {
        writeln!(output, " {}:", t!(Statistics))?;
        writeln!(
            output,
            "   ├── {}: {} ({} {})",
            t!(RxStats, 16),
            format_bytes(stats.rx_bytes),
            stats.rx_packets,
            t!(Packets)
        )?;
        writeln!(
            output,
            "   └── {}: {} ({} {})",
            t!(TxStats, 16),
            format_bytes(stats.tx_bytes),
            stats.tx_packets,
            t!(Packets)
        )?;
    }

    Ok(())
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
