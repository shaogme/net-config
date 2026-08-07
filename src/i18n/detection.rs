use crate::i18n::Language;

const LANGUAGE_ENV_VARS: [&str; 4] = ["NET_CONFIG_LANG", "LC_ALL", "LC_MESSAGES", "LANG"];

/// 跨平台自动检测当前系统语言
pub fn detect_system_language() -> Language {
    if let Some(language) = detect_language(|name| std::env::var(name).ok()) {
        return language;
    }

    // 环境变量未提供受支持的语言时，再使用 Windows 原生 UI 语言。
    #[cfg(target_os = "windows")]
    {
        if let Some(lang) = detect_windows_ui_language() {
            return lang;
        }
    }

    // 5. 默认回退语言：En (英文)
    Language::En
}

/// 按 POSIX 语言环境优先级检测语言。
///
/// `NET_CONFIG_LANG` 是应用级覆盖，随后依次使用 `LC_ALL`、`LC_MESSAGES`
/// 和 `LANG`。查找函数由调用方注入，避免测试依赖测试机的真实环境变量。
pub(crate) fn detect_language<F>(mut lookup: F) -> Option<Language>
where
    F: FnMut(&str) -> Option<String>,
{
    LANGUAGE_ENV_VARS
        .into_iter()
        .filter_map(|name| lookup(name).and_then(|value| Language::from_locale(&value)))
        .next()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn language_from(values: &[(&str, &str)]) -> Option<Language> {
        let values: HashMap<_, _> = values
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect();
        detect_language(|name| values.get(name).cloned())
    }

    #[test]
    fn application_override_has_highest_priority() {
        assert_eq!(
            language_from(&[
                ("NET_CONFIG_LANG", "en_US.UTF-8"),
                ("LC_ALL", "zh_CN.UTF-8"),
                ("LC_MESSAGES", "zh_TW.UTF-8"),
                ("LANG", "zh_CN.UTF-8"),
            ]),
            Some(Language::En)
        );
    }

    #[test]
    fn posix_variables_are_checked_in_standard_order() {
        assert_eq!(
            language_from(&[("LC_ALL", "en_GB.UTF-8"), ("LANG", "zh_CN.UTF-8")]),
            Some(Language::En)
        );
        assert_eq!(
            language_from(&[("LC_MESSAGES", "zh_TW.UTF-8"), ("LANG", "en_US.UTF-8")]),
            Some(Language::Zh)
        );
        assert_eq!(
            language_from(&[("LANG", "zh_CN.UTF-8")]),
            Some(Language::Zh)
        );
    }

    #[test]
    fn unsupported_or_empty_values_are_skipped() {
        assert_eq!(
            language_from(&[("LC_ALL", "fr_FR.UTF-8"), ("LANG", "en_US.UTF-8")]),
            Some(Language::En)
        );
        assert_eq!(language_from(&[("LANG", "C")]), None);
    }
}
