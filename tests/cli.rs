use serde_json::Value;
use std::process::Command;

fn run_cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_net-config"))
        .args(arguments)
        .output()
        .expect("CLI process should start")
}

#[test]
fn help_writes_contract_to_stdout_only() {
    let output = run_cli(&["--lang", "en", "--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success());
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("--json"));
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");
}

#[test]
fn unknown_argument_returns_failure_with_split_output() {
    let output = run_cli(&["--lang", "en", "--not-supported"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stdout.contains("Usage:"));
    assert!(stderr.contains("Unknown command-line argument"));
}

#[test]
fn unsupported_language_returns_failure_without_network_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_net-config"))
        .args(["--lang=fr", "--help"])
        .env("NET_CONFIG_LANG", "en")
        .output()
        .expect("CLI process should start");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success());
    assert!(stdout.is_empty());
    assert!(stderr.contains("Unsupported language"));
}

#[test]
#[ignore = "smoke test invokes the CLI against the host network state"]
fn json_output_has_stable_top_level_schema() {
    let output = run_cli(&["--lang", "en", "--json"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "CLI failed: stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(stderr.is_empty(), "unexpected stderr: {stderr}");

    let document: Value = serde_json::from_slice(&output.stdout).expect("stdout should be JSON");
    let object = document.as_object().expect("JSON root should be an object");
    assert!(object.contains_key("primary"));
    assert!(object.get("other").is_some_and(Value::is_array));
    assert!(object.get("dns").is_some_and(Value::is_object));

    let dns = object["dns"].as_object().expect("dns should be an object");
    assert!(dns.get("status").is_some_and(Value::is_string));
    assert!(dns.get("servers").is_some_and(Value::is_array));
}
