use crate::shared::{DnsSource, InterfaceStatus, InterfaceType, IpAllocation};
use std::sync::OnceLock;
use unicode_width::UnicodeWidthStr;

pub mod detection;

/// 支持的语言环境
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Zh,
    En,
}

impl Language {
    /// 从字符串解析语言
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "zh" | "zh-cn" | "zh_cn" | "chinese" => Some(Language::Zh),
            "en" | "en-us" | "en_us" | "english" => Some(Language::En),
            _ => None,
        }
    }

    /// 从 POSIX/Windows 区域语言环境值解析语言。
    pub(crate) fn from_locale(value: &str) -> Option<Self> {
        if let Some(language) = Self::from_str(value) {
            return Some(language);
        }
        let language = value
            .split(['.', '@'])
            .next()
            .unwrap_or(value)
            .split(['-', '_'])
            .next()
            .unwrap_or(value);
        match language.to_lowercase().as_str() {
            "zh" => Some(Self::Zh),
            "en" => Some(Self::En),
            _ => None,
        }
    }
}

// 全局静态语言变量，利用 OnceLock 实现并发安全的单次初始化
static CURRENT_LANG: OnceLock<Language> = OnceLock::new();

/// 初始化全局语言，若已设定则不作操作
pub fn init(lang: Language) {
    let _ = CURRENT_LANG.set(lang);
}

/// 获取当前语言，若未手动初始化则自动执行系统探测
pub fn current() -> Language {
    *CURRENT_LANG.get_or_init(detection::detect_system_language)
}

/// 所有需要本地化的词条枚举
#[derive(Debug, Clone, Copy)]
pub enum Text {
    ProgramTitle,
    UnknownArg,
    UnsupportedLanguage,
    JsonError,
    FetchInterfaceError,
    OutputError,
    PrimaryInterfaceHeader,
    NoPrimaryInterface,
    OtherInterfaceHeader,
    NoOtherInterface,
    Usage,
    UsageTitle,
    OptionsHeader,
    OptAll,
    OptJson,
    OptHelp,
    OptLang,
    IfaceName,
    IfaceDescription,
    IfaceStatus,
    IfaceType,
    IfaceAllocation,
    IfaceSpeed,
    IfaceMac,
    Ipv4Config,
    Ipv6Config,
    DnsServers,
    SystemDns,
    DnsNoServers,
    DnsUnavailable,
    DnsInterface,
    DnsInterfaceUnknown,
    DnsSource,
    Statistics,
    RxStats,
    TxStats,
    SpeedUnknown,
    MacUnknown,
    Packets,

    // 排版对齐专用标签
    Ipv4AddrLabel,
    Ipv4MaskLabel,
    Ipv4AllocLabel,
    Ipv6AddrLabel,
    Ipv6PrefixLabel,
    Ipv6AllocLabel,
    Ipv4PrefixSuffix,
    Routes,
    RouteDestination,
    RouteGateway,
    RouteGatewayNone,
    RouteInterface,
    RouteMetric,
    RouteMetricUnknown,
    RouteDefault,
}

impl Text {
    /// 获取翻译文本
    pub fn get(self) -> &'static str {
        self.get_for(current())
    }

    /// 按指定语言获取翻译文本，供需要稳定语言快照的渲染逻辑使用。
    pub fn get_for(self, language: Language) -> &'static str {
        match language {
            Language::Zh => match self {
                Text::ProgramTitle => "NetConfig - 跨平台网络接口拓扑分析工具",
                Text::UnknownArg => "错误: 未知的命令行参数",
                Text::UnsupportedLanguage => "错误：不支持的语言",
                Text::JsonError => "错误：序列化 JSON 失败",
                Text::FetchInterfaceError => "错误：获取网卡信息失败",
                Text::OutputError => "错误：输出失败",
                Text::PrimaryInterfaceHeader => "主网卡 (Primary Interface)",
                Text::NoPrimaryInterface => "(未检测到主网卡，可能无互联网连接)",
                Text::OtherInterfaceHeader => "其他网卡 (Other Interfaces)",
                Text::NoOtherInterface => "(无其他网卡)",
                Text::Usage => "用法:",
                Text::UsageTitle => "NetConfig - 跨平台网络接口拓扑分析工具\n",
                Text::OptionsHeader => "选项:",
                Text::OptAll => "  -a, --all      显示所有网卡接口信息（默认仅显示主/默认网卡）",
                Text::OptJson => "  -j, --json     以 JSON 格式输出结果",
                Text::OptHelp => "  -h, --help     显示帮助信息",
                Text::OptLang => "  -l, --lang     手动指定语言，支持 'zh' (中文) 或 'en' (英文)",
                Text::IfaceName => "网卡名称",
                Text::IfaceDescription => "友好描述",
                Text::IfaceStatus => "接口状态",
                Text::IfaceType => "接口类型",
                Text::IfaceAllocation => "IP 分配",
                Text::IfaceSpeed => "链路速度",
                Text::IfaceMac => "MAC 地址",
                Text::Ipv4Config => "IPv4 配置",
                Text::Ipv6Config => "IPv6 配置",
                Text::DnsServers => "DNS 服务器",
                Text::SystemDns => "系统 DNS",
                Text::DnsNoServers => "(没有配置 DNS 服务器)",
                Text::DnsUnavailable => "(DNS 配置不可用或未采集)",
                Text::DnsInterface => "接口",
                Text::DnsInterfaceUnknown => "系统级/未知接口",
                Text::DnsSource => "来源",
                Text::Statistics => "吞吐流量统计",
                Text::RxStats => "接收 (Rx)",
                Text::TxStats => "发送 (Tx)",
                Text::SpeedUnknown => "未知或未连接",
                Text::MacUnknown => "未知",
                Text::Packets => "数据包",

                // 排版对齐专用标签
                Text::Ipv4AddrLabel => "地址",
                Text::Ipv4MaskLabel => "子网掩码",
                Text::Ipv4AllocLabel => "分配方式",
                Text::Ipv6AddrLabel => "地址",
                Text::Ipv6PrefixLabel => "前缀长度",
                Text::Ipv6AllocLabel => "分配方式",
                Text::Ipv4PrefixSuffix => "前缀",
                Text::Routes => "路由",
                Text::RouteDestination => "目的网络",
                Text::RouteGateway => "下一跳",
                Text::RouteGatewayNone => "直连/无",
                Text::RouteInterface => "接口",
                Text::RouteMetric => "Metric",
                Text::RouteMetricUnknown => "未知",
                Text::RouteDefault => "默认路由",
            },
            Language::En => match self {
                Text::ProgramTitle => "NetConfig - Cross-Platform Network Interface Topology Tool",
                Text::UnknownArg => "Error: Unknown command-line argument",
                Text::UnsupportedLanguage => "Error: Unsupported language",
                Text::JsonError => "Error: Failed to serialize JSON",
                Text::FetchInterfaceError => "Error: Failed to get network interfaces",
                Text::OutputError => "Error: Failed to write output",
                Text::PrimaryInterfaceHeader => "Primary Interface",
                Text::NoPrimaryInterface => {
                    "(No primary interface detected, possibly no internet connection)"
                }
                Text::OtherInterfaceHeader => "Other Interfaces",
                Text::NoOtherInterface => "(No other interfaces)",
                Text::Usage => "Usage:",
                Text::UsageTitle => {
                    "NetConfig - A cross-platform network interface topology analysis tool\n"
                }
                Text::OptionsHeader => "Options:",
                Text::OptAll => {
                    "  -a, --all      Show all network interfaces (default shows primary/default interface only)"
                }
                Text::OptJson => "  -j, --json     Output results in JSON format",
                Text::OptHelp => "  -h, --help     Show help information",
                Text::OptLang => {
                    "  -l, --lang     Specify language, 'zh' (Chinese) or 'en' (English)"
                }
                Text::IfaceName => "Interface Name",
                Text::IfaceDescription => "Description",
                Text::IfaceStatus => "Status",
                Text::IfaceType => "Type",
                Text::IfaceAllocation => "Allocation",
                Text::IfaceSpeed => "Link Speed",
                Text::IfaceMac => "MAC Address",
                Text::Ipv4Config => "IPv4 Config",
                Text::Ipv6Config => "IPv6 Config",
                Text::DnsServers => "DNS Servers",
                Text::SystemDns => "System DNS",
                Text::DnsNoServers => "(No DNS servers configured)",
                Text::DnsUnavailable => "(DNS configuration unavailable or not collected)",
                Text::DnsInterface => "Interface",
                Text::DnsInterfaceUnknown => "System-wide / Unknown interface",
                Text::DnsSource => "Source",
                Text::Statistics => "Statistics",
                Text::RxStats => "Received (Rx)",
                Text::TxStats => "Transmitted (Tx)",
                Text::SpeedUnknown => "Unknown or disconnected",
                Text::MacUnknown => "Unknown",
                Text::Packets => "packets",

                // 排版对齐专用标签
                Text::Ipv4AddrLabel => "Address",
                Text::Ipv4MaskLabel => "Subnet Mask",
                Text::Ipv4AllocLabel => "Allocation",
                Text::Ipv6AddrLabel => "Address",
                Text::Ipv6PrefixLabel => "Prefix Len",
                Text::Ipv6AllocLabel => "Allocation",
                Text::Ipv4PrefixSuffix => "Prefix",
                Text::Routes => "Routes",
                Text::RouteDestination => "Destination",
                Text::RouteGateway => "Gateway",
                Text::RouteGatewayNone => "On-link / None",
                Text::RouteInterface => "Interface",
                Text::RouteMetric => "Metric",
                Text::RouteMetricUnknown => "Unknown",
                Text::RouteDefault => "Default",
            },
        }
    }
}

/// 计算字符串在终端中的真实显示列宽
pub fn display_width(s: &str) -> usize {
    // 未知终端类型时采用 Unicode 的非 CJK 规则：Ambiguous 字符宽度为 1。
    UnicodeWidthStr::width(s)
}

/// 将字符串向右填充空格到指定的终端列宽
pub fn pad_right(s: &str, width: usize) -> String {
    let w = display_width(s);
    if w >= width {
        s.to_string()
    } else {
        let spaces = " ".repeat(width - w);
        format!("{}{}", s, spaces)
    }
}

/// 快捷翻译宏，简化文本获取与排版对齐调用
#[macro_export]
macro_rules! t {
    ($key:ident) => {
        $crate::i18n::Text::$key.get()
    };
    ($key:ident, $width:expr) => {
        $crate::i18n::pad_right($crate::i18n::Text::$key.get(), $width)
    };
}

/// 按指定语言本地化接口状态。
pub fn localize_status_for(status: InterfaceStatus, language: Language) -> &'static str {
    match language {
        Language::Zh => match status {
            InterfaceStatus::Up => "已启用 (Up)",
            InterfaceStatus::Down => "未启用 (Down)",
            InterfaceStatus::Testing => "测试中 (Testing)",
            InterfaceStatus::Unknown => "未知 (Unknown)",
        },
        Language::En => match status {
            InterfaceStatus::Up => "Up",
            InterfaceStatus::Down => "Down",
            InterfaceStatus::Testing => "Testing",
            InterfaceStatus::Unknown => "Unknown",
        },
    }
}

/// 按指定语言本地化接口类型。
pub fn localize_type_for(itype: InterfaceType, language: Language) -> &'static str {
    match language {
        Language::Zh => match itype {
            InterfaceType::Ethernet => "以太网 (Ethernet)",
            InterfaceType::WiFi => "无线局域网 (Wi-Fi)",
            InterfaceType::Loopback => "本地环回 (Loopback)",
            InterfaceType::Virtual => "虚拟网卡 (Virtual / Bridge)",
            InterfaceType::Tunnel => "隧道接口 (Tunnel / VPN)",
            InterfaceType::Other => "其他接口 (Other)",
            InterfaceType::Unknown => "未知类型 (Unknown)",
        },
        Language::En => match itype {
            InterfaceType::Ethernet => "Ethernet",
            InterfaceType::WiFi => "Wi-Fi",
            InterfaceType::Loopback => "Loopback",
            InterfaceType::Virtual => "Virtual / Bridge",
            InterfaceType::Tunnel => "Tunnel / VPN",
            InterfaceType::Other => "Other",
            InterfaceType::Unknown => "Unknown",
        },
    }
}

/// 按指定语言本地化 IP 分配方式。
pub fn localize_allocation_for(alloc: IpAllocation, language: Language) -> &'static str {
    match language {
        Language::Zh => match alloc {
            IpAllocation::Manual => "手动配置 (Manual)",
            IpAllocation::Dhcpv4 => "DHCPv4",
            IpAllocation::Dhcpv6 => "DHCPv6",
            IpAllocation::RouterAdvertisement => "路由器通告 (RA)",
            IpAllocation::Slaac => "无状态地址自动配置 (SLAAC)",
            IpAllocation::Other => "其他来源 (Other)",
            IpAllocation::Unknown => "未知 (Unknown)",
            IpAllocation::Mixed => "混合来源 (Mixed)",
        },
        Language::En => match alloc {
            IpAllocation::Manual => "Manual",
            IpAllocation::Dhcpv4 => "DHCPv4",
            IpAllocation::Dhcpv6 => "DHCPv6",
            IpAllocation::RouterAdvertisement => "Router Advertisement (RA)",
            IpAllocation::Slaac => "SLAAC",
            IpAllocation::Other => "Other",
            IpAllocation::Unknown => "Unknown",
            IpAllocation::Mixed => "Mixed",
        },
    }
}

/// 按指定语言本地化 DNS 采集来源。
pub fn localize_dns_source_for(source: DnsSource, language: Language) -> &'static str {
    match language {
        Language::Zh => match source {
            DnsSource::SystemdResolved => "systemd-resolved",
            DnsSource::NetworkManager => "NetworkManager",
            DnsSource::ResolvConf => "resolv.conf 回退",
            DnsSource::Scutil => "scutil",
            DnsSource::WindowsAdapter => "Windows 适配器",
        },
        Language::En => match source {
            DnsSource::SystemdResolved => "systemd-resolved",
            DnsSource::NetworkManager => "NetworkManager",
            DnsSource::ResolvConf => "resolv.conf fallback",
            DnsSource::Scutil => "scutil",
            DnsSource::WindowsAdapter => "Windows adapter",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_unicode_width_for_combining_emoji_and_labels() {
        assert_eq!(display_width("中文标签"), 8);
        assert_eq!(display_width("e\u{0301}"), 1);
        assert_eq!(display_width("👩‍🔬"), 2);
        assert_eq!(display_width("#\u{FE0F}"), 2);
        assert_eq!(display_width("A·B"), 3);
    }

    #[test]
    fn pads_by_terminal_columns() {
        assert_eq!(pad_right("中文", 6), "中文  ");
        assert_eq!(pad_right("e\u{0301}", 3), "e\u{0301}  ");
        assert_eq!(pad_right("English", 4), "English");
    }
}
