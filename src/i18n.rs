use std::sync::OnceLock;

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
    JsonError,
    FetchInterfaceError,
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
    IfaceSpeed,
    IfaceMac,
    Ipv4Config,
    Ipv6Config,
    DnsServers,
    Statistics,
    RxStats,
    TxStats,
    SpeedUnknown,
    MacUnknown,
    Packets,
    
    // 排版对齐专用标签
    Ipv4AddrLabel,
    Ipv4MaskLabel,
    Ipv4GatewayLabel,
    Ipv4GatewayNone,
    Ipv6AddrLabel,
    Ipv6PrefixLabel,
    Ipv6GatewayLabel,
    Ipv6GatewayNone,
    Ipv4PrefixSuffix,
}

impl Text {
    /// 获取翻译文本
    pub fn get(self) -> &'static str {
        match current() {
            Language::Zh => match self {
                Text::ProgramTitle => "NetConfig - 跨平台网络接口拓扑分析工具",
                Text::UnknownArg => "错误: 未知的命令行参数",
                Text::JsonError => "错误：序列化 JSON 失败",
                Text::FetchInterfaceError => "错误：获取网卡信息失败",
                Text::PrimaryInterfaceHeader => "主网卡 (Primary Interface)",
                Text::NoPrimaryInterface => "  (未检测到主网卡，可能无互联网连接)",
                Text::OtherInterfaceHeader => "其他网卡 (Other Interfaces)",
                Text::NoOtherInterface => "  (无其他网卡)",
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
                Text::IfaceSpeed => "链路速度",
                Text::IfaceMac => "MAC 地址",
                Text::Ipv4Config => "IPv4 配置",
                Text::Ipv6Config => "IPv6 配置",
                Text::DnsServers => "DNS 服务器",
                Text::Statistics => "吞吐流量统计",
                Text::RxStats => "接收 (Rx)",
                Text::TxStats => "发送 (Tx)",
                Text::SpeedUnknown => "未知或未连接",
                Text::MacUnknown => "未知",
                Text::Packets => "数据包",
                
                // 排版对齐专用标签
                Text::Ipv4AddrLabel => "地址",
                Text::Ipv4MaskLabel => "子网掩码",
                Text::Ipv4GatewayLabel => "默认网关",
                Text::Ipv4GatewayNone => "无",
                Text::Ipv6AddrLabel => "地址",
                Text::Ipv6PrefixLabel => "前缀长度",
                Text::Ipv6GatewayLabel => "默认网关",
                Text::Ipv6GatewayNone => "无",
                Text::Ipv4PrefixSuffix => "前缀",
            },
            Language::En => match self {
                Text::ProgramTitle => "NetConfig - Cross-Platform Network Interface Topology Tool",
                Text::UnknownArg => "Error: Unknown command-line argument",
                Text::JsonError => "Error: Failed to serialize JSON",
                Text::FetchInterfaceError => "Error: Failed to get network interfaces",
                Text::PrimaryInterfaceHeader => "Primary Interface",
                Text::NoPrimaryInterface => "  (No primary interface detected, possibly no internet connection)",
                Text::OtherInterfaceHeader => "Other Interfaces",
                Text::NoOtherInterface => "  (No other interfaces)",
                Text::Usage => "Usage:",
                Text::UsageTitle => "NetConfig - A cross-platform network interface topology analysis tool\n",
                Text::OptionsHeader => "Options:",
                Text::OptAll => "  -a, --all      Show all network interfaces (default shows primary/default interface only)",
                Text::OptJson => "  -j, --json     Output results in JSON format",
                Text::OptHelp => "  -h, --help     Show help information",
                Text::OptLang => "  -l, --lang     Specify language, 'zh' (Chinese) or 'en' (English)",
                Text::IfaceName => "Interface Name",
                Text::IfaceDescription => "Description",
                Text::IfaceStatus => "Status",
                Text::IfaceType => "Type",
                Text::IfaceSpeed => "Link Speed",
                Text::IfaceMac => "MAC Address",
                Text::Ipv4Config => "IPv4 Config",
                Text::Ipv6Config => "IPv6 Config",
                Text::DnsServers => "DNS Servers",
                Text::Statistics => "Statistics",
                Text::RxStats => "Received (Rx)",
                Text::TxStats => "Transmitted (Tx)",
                Text::SpeedUnknown => "Unknown or disconnected",
                Text::MacUnknown => "Unknown",
                Text::Packets => "packets",
                
                // 排版对齐专用标签
                Text::Ipv4AddrLabel => "Address",
                Text::Ipv4MaskLabel => "Subnet Mask",
                Text::Ipv4GatewayLabel => "Gateway",
                Text::Ipv4GatewayNone => "None",
                Text::Ipv6AddrLabel => "Address",
                Text::Ipv6PrefixLabel => "Prefix Len",
                Text::Ipv6GatewayLabel => "Gateway",
                Text::Ipv6GatewayNone => "None",
                Text::Ipv4PrefixSuffix => "Prefix",
            }
        }
    }
}

/// 判断字符是否为东亚宽字符（终端占 2 格）
fn is_full_width(c: char) -> bool {
    let cp = c as u32;
    if cp < 0x80 {
        return false; // ASCII 字符均为窄字符（1格）
    }
    // CJK 统一表意文字及符号范围
    (0x4E00..=0x9FFF).contains(&cp) || // CJK 统一汉字
    (0x3000..=0x303F).contains(&cp) || // CJK 标点符号（如实心句号、逗号、全角空格等）
    (0xFF00..=0xFFEF).contains(&cp) || // 全角英文字母、数字及全角标点符号
    (0x1100..=0x115F).contains(&cp) || // 谚文母音
    (0x2E80..=0x3000).contains(&cp) || // CJK 部首及辅助字符
    (0x3400..=0x4DBF).contains(&cp) || // CJK 扩展 A
    (0xAC00..=0xD7A3).contains(&cp) || // 谚文音节 (韩文)
    (0xF900..=0xFAFF).contains(&cp) || // CJK 兼容表意文字
    (0xFE30..=0xFE4F).contains(&cp) || // CJK 兼容形式
    (0x20000..=0x3FFFD).contains(&cp)  // CJK 扩展 B-G
}

/// 计算字符串在终端中的真实显示列宽
pub fn display_width(s: &str) -> usize {
    s.chars().map(|c| if is_full_width(c) { 2 } else { 1 }).sum()
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

/// 接口状态的本地化封装
pub fn localize_status(status: crate::shared::InterfaceStatus) -> &'static str {
    match current() {
        Language::Zh => match status {
            crate::shared::InterfaceStatus::Up => "🟢 已启用 (Up)",
            crate::shared::InterfaceStatus::Down => "🔴 未启用 (Down)",
            crate::shared::InterfaceStatus::Testing => "🟡 测试中 (Testing)",
            crate::shared::InterfaceStatus::Unknown => "⚪ 未知 (Unknown)",
        },
        Language::En => match status {
            crate::shared::InterfaceStatus::Up => "🟢 Up",
            crate::shared::InterfaceStatus::Down => "🔴 Down",
            crate::shared::InterfaceStatus::Testing => "🟡 Testing",
            crate::shared::InterfaceStatus::Unknown => "⚪ Unknown",
        }
    }
}

/// 接口类型的本地化封装
pub fn localize_type(itype: crate::shared::InterfaceType) -> &'static str {
    match current() {
        Language::Zh => match itype {
            crate::shared::InterfaceType::Ethernet => "以太网 (Ethernet)",
            crate::shared::InterfaceType::WiFi => "无线局域网 (Wi-Fi)",
            crate::shared::InterfaceType::Loopback => "本地环回 (Loopback)",
            crate::shared::InterfaceType::Virtual => "虚拟网卡 (Virtual / Bridge)",
            crate::shared::InterfaceType::Tunnel => "隧道接口 (Tunnel / VPN)",
            crate::shared::InterfaceType::Other => "其他接口 (Other)",
            crate::shared::InterfaceType::Unknown => "未知类型 (Unknown)",
        },
        Language::En => match itype {
            crate::shared::InterfaceType::Ethernet => "Ethernet",
            crate::shared::InterfaceType::WiFi => "Wi-Fi",
            crate::shared::InterfaceType::Loopback => "Loopback",
            crate::shared::InterfaceType::Virtual => "Virtual / Bridge",
            crate::shared::InterfaceType::Tunnel => "Tunnel / VPN",
            crate::shared::InterfaceType::Other => "Other",
            crate::shared::InterfaceType::Unknown => "Unknown",
        }
    }
}
