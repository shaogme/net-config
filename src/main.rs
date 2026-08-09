mod i18n;
mod os;
mod shared;
mod text;

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
    let mut show_version = false;
    let mut unknown_arg = None;
    let mut custom_lang = None;

    // 健壮的命令行解析器，支持 -l / --lang 及其值
    let mut args_iter = args[1..].iter().peekable();
    while let Some(arg) = args_iter.next() {
        match arg.as_str() {
            "-a" | "--all" => show_all = true,
            "-h" | "--help" => show_help = true,
            "-v" | "--version" => show_version = true,
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

    if show_version {
        print_version(&args[0])?;
        return Ok(());
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
        text::render(&interfaces, show_all)?;
    }

    Ok(())
}

fn get_program_name(program_name: &str) -> &str {
    let path = std::path::Path::new(program_name);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program_name);

    #[cfg(windows)]
    if let Some(stripped) = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".EXE"))
    {
        return stripped;
    }
    name
}

fn print_version(program_name: &str) -> Result<(), AppError> {
    let name = get_program_name(program_name);

    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{} {}", name, env!("CARGO_PKG_VERSION"))?;
    output.flush()?;
    Ok(())
}

fn print_help(program_name: &str) -> Result<(), AppError> {
    let name = get_program_name(program_name);

    let stdout = io::stdout();
    let mut output = stdout.lock();
    write!(output, "{}", t!(UsageTitle))?;
    writeln!(output, "{}", t!(Usage))?;
    writeln!(output, "  {} [options]\n", name)?;
    writeln!(output, "{}", t!(OptionsHeader))?;
    writeln!(output, "{}", t!(OptAll))?;
    writeln!(output, "{}", t!(OptJson))?;
    writeln!(output, "{}", t!(OptHelp))?;
    writeln!(output, "{}", t!(OptVersion))?;
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
