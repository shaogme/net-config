mod os;
mod shared;
mod i18n;

fn main() {
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
            eprintln!("Error: Unsupported language '{}'. Supported values: 'zh', 'en'.", lang_str);
            std::process::exit(1);
        }
    }

    if show_help {
        print_help(&args[0]);
        return;
    }

    if let Some(arg) = unknown_arg {
        eprintln!("{}: {}", t!(UnknownArg), arg);
        print_help(&args[0]);
        std::process::exit(1);
    }

    if json_output {
        match shared::get_network_interfaces() {
            Ok(mut interfaces) => {
                if !show_all {
                    interfaces.other.clear();
                }
                match serde_json::to_string_pretty(&interfaces) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("{}: {}", t!(JsonError), e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("{}: {}", t!(FetchInterfaceError), e);
                std::process::exit(1);
            }
        }
        return;
    }

    println!("==================================================================");
    println!(" {}", t!(ProgramTitle));
    println!("==================================================================");

    match shared::get_network_interfaces() {
        Ok(interfaces) => {
            println!("\n[{}]", t!(PrimaryInterfaceHeader));
            if let Some(ref face) = interfaces.primary {
                print_interface(face);
            } else {
                println!("{}", t!(NoPrimaryInterface));
            }

            if show_all {
                println!("\n[{}]", t!(OtherInterfaceHeader));
                if interfaces.other.is_empty() {
                    println!("{}", t!(NoOtherInterface));
                } else {
                    for face in &interfaces.other {
                        print_interface(face);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("{}: {}", t!(FetchInterfaceError), e);
        }
    }
    println!("\n==================================================================");
}

fn print_help(program_name: &str) {
    let path = std::path::Path::new(program_name);
    let name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program_name);

    print!("{}", t!(UsageTitle));
    println!("{}", t!(Usage));
    println!("  {} [options]\n", name);
    println!("{}", t!(OptionsHeader));
    println!("{}", t!(OptAll));
    println!("{}", t!(OptJson));
    println!("{}", t!(OptHelp));
    println!("{}", t!(OptLang));
}

fn print_interface(face: &shared::NetworkInterface) {
    println!("--------------------------------------------------");
    println!(" {}: {}", t!(IfaceName, 14), face.name);
    println!(" {}: {}", t!(IfaceDescription, 14), face.description);
    
    // 1. 状态与指示灯
    println!(" {}: {}", t!(IfaceStatus, 14), i18n::localize_status(face.status));

    // 2. 接口类型
    println!(" {}: {}", t!(IfaceType, 14), i18n::localize_type(face.interface_type));

    // 3. 链路速度
    if let Some(speed) = face.link_speed {
        println!(" {}: {}", t!(IfaceSpeed, 14), format_link_speed(speed));
    } else {
        println!(" {}: {}", t!(IfaceSpeed, 14), t!(SpeedUnknown));
    }

    // 4. MAC 地址
    if let Some(ref mac) = face.mac_address {
        println!(" {}: {}", t!(IfaceMac, 14), mac);
    } else {
        println!(" {}: {}", t!(IfaceMac, 14), t!(MacUnknown));
    }

    // 5. IPv4 地址配置
    if !face.ipv4_addresses.is_empty() {
        println!(" {}:", t!(Ipv4Config));
        for (i, ipv4) in face.ipv4_addresses.iter().enumerate() {
            println!("   [{}] {}: {}", i + 1, t!(Ipv4AddrLabel, 11), ipv4.address);
            println!("       {}: {} ({} /{})", t!(Ipv4MaskLabel, 11), ipv4.netmask, t!(Ipv4PrefixSuffix), ipv4.prefix_len);
            let gw_str = if !ipv4.gateways.is_empty() {
                ipv4.gateways.iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            } else {
                t!(Ipv4GatewayNone).to_string()
            };
            println!("       {}: {}", t!(Ipv4GatewayLabel, 11), gw_str);
        }
    }

    // 6. IPv6 地址配置
    if !face.ipv6_addresses.is_empty() {
        println!(" {}:", t!(Ipv6Config));
        for (i, ipv6) in face.ipv6_addresses.iter().enumerate() {
            println!("   [{}] {}: {}", i + 1, t!(Ipv6AddrLabel, 11), ipv6.address);
            println!("       {}: /{}", t!(Ipv6PrefixLabel, 11), ipv6.prefix_len);
            let gw_str = if !ipv6.gateways.is_empty() {
                ipv6.gateways.iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()
                    .join(", ")
            } else {
                t!(Ipv6GatewayNone).to_string()
            };
            println!("       {}: {}", t!(Ipv6GatewayLabel, 11), gw_str);
        }
    }

    // 7. DNS 服务器配置 (采用树状结构)
    if !face.dns_servers.is_empty() {
        println!(" {}:", t!(DnsServers));
        let len = face.dns_servers.len();
        for (i, dns) in face.dns_servers.iter().enumerate() {
            let is_last = i == len - 1;
            let prefix = if is_last { "   └──" } else { "   ├──" };
            println!("{} {}", prefix, dns);
        }
    }

    // 8. 网络吞吐流量统计 (采用树状结构)
    if let Some(ref stats) = face.statistics {
        println!(" {}:", t!(Statistics));
        println!("   ├── {}: {} ({} {})", t!(RxStats, 16), format_bytes(stats.rx_bytes), stats.rx_packets, t!(Packets));
        println!("   └── {}: {} ({} {})", t!(TxStats, 16), format_bytes(stats.tx_bytes), stats.tx_packets, t!(Packets));
    }
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
