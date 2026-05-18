use crate::i18n::Language;

/// 跨平台自动检测当前系统语言
pub fn detect_system_language() -> Language {
    // 1. 优先读取自定义环境变量，供用户手动覆盖
    if let Ok(lang) = std::env::var("NET_CONFIG_LANG")
        && let Some(parsed) = Language::from_str(&lang)
    {
        return parsed;
    }

    // 2. 读取通用 UNIX 环境变量 LANG
    if let Ok(lang) = std::env::var("LANG") {
        if lang.to_lowercase().starts_with("zh") {
            return Language::Zh;
        } else if lang.to_lowercase().starts_with("en") {
            return Language::En;
        }
    }

    // 3. 读取通用 UNIX 环境变量 LC_ALL
    if let Ok(lang) = std::env::var("LC_ALL") {
        if lang.to_lowercase().starts_with("zh") {
            return Language::Zh;
        } else if lang.to_lowercase().starts_with("en") {
            return Language::En;
        }
    }

    // 4. Windows 平台特有的原生 API 检测
    #[cfg(target_os = "windows")]
    {
        if let Some(lang) = detect_windows_ui_language() {
            return lang;
        }
    }

    // 5. 默认回退语言：En (英文)
    Language::En
}

/// Windows 平台特有的原生语言检测
#[cfg(target_os = "windows")]
fn detect_windows_ui_language() -> Option<Language> {
    use windows_sys::Win32::Globalization::{
        GetSystemDefaultUILanguage, GetUserDefaultLocaleName, GetUserDefaultUILanguage,
    };

    // 1. 检测当前用户 UI 界面显示语言 (User UI Language)
    let user_lang_id = unsafe { GetUserDefaultUILanguage() };
    if (user_lang_id & 0x03FF) == 0x11 {
        // 0x11 为 LANG_CHINESE
        return Some(Language::Zh);
    }

    // 2. 检测系统默认 UI 界面显示语言 (System UI Language)
    let sys_lang_id = unsafe { GetSystemDefaultUILanguage() };
    if (sys_lang_id & 0x03FF) == 0x11 {
        return Some(Language::Zh);
    }

    // 3. 检测用户默认区域格式语言 (User Default Locale Name)
    // 许多开发者会使用英文 UI 界面，但将区域格式设置为中文 (zh-CN)
    let mut buffer = [0u16; 85]; // LOCALE_NAME_MAX_LENGTH
    let len = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), 85) };
    if len > 0 {
        // 去除末尾的空字符并转换为 Rust 字符串
        let name = String::from_utf16_lossy(&buffer[..(len as usize).saturating_sub(1)]);
        let lower = name.to_lowercase();
        if lower.starts_with("zh") {
            return Some(Language::Zh);
        }
    }

    // 若前述所有步骤均未检测到中文，但检测到了英文，则返回英文以保持兼容性；否则返回 None 触发默认回退
    if (user_lang_id & 0x03FF) == 0x09 || (sys_lang_id & 0x03FF) == 0x09 {
        Some(Language::En)
    } else {
        None
    }
}
