use crate::i18n::Language;

/// 跨平台自动检测当前系统语言
pub fn detect_system_language() -> Language {
    // 1. 优先读取自定义环境变量，供用户手动覆盖
    if let Ok(lang) = std::env::var("NET_CONFIG_LANG") {
        if let Some(parsed) = Language::from_str(&lang) {
            return parsed;
        }
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
    use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;

    // GetUserDefaultUILanguage 返回当前用户的 UI 语言 LANGID (u16)
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    
    // LANGID 的低 10 位是 Primary Language ID
    let primary_lang_id = lang_id & 0x03FF;
    
    // 0x11 是 LANG_CHINESE (Windows SDK 定义)
    if primary_lang_id == 0x11 {
        Some(Language::Zh)
    } else {
        Some(Language::En)
    }
}
