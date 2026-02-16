//! End-to-end tests for the CLI binary.

#[allow(deprecated)]
use assert_cmd::Command;
use predicates::prelude::*;

#[allow(deprecated)]
fn cmd() -> Command {
    Command::cargo_bin("lutetia").unwrap()
}

#[test]
fn test_cli_help() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("EVM bytecode decompiler"));
}

#[test]
fn test_cli_version() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("lutetia"));
}

#[test]
fn test_cli_decompile_stop() {
    cmd()
        .arg("00")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stop"));
}

#[test]
fn test_cli_decompile_revert() {
    cmd()
        .arg("60006000fd")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("revert"));
}

#[test]
fn test_cli_asm_output() {
    cmd()
        .arg("6001600201")
        .arg("-o")
        .arg("asm")
        .assert()
        .success()
        .stdout(predicate::str::contains("push1"))
        .stdout(predicate::str::contains("add"));
}

#[test]
fn test_cli_json_output() {
    cmd()
        .arg("00")
        .arg("-o")
        .arg("json")
        .assert()
        .success()
        .stdout(predicate::str::contains("functions"))
        .stdout(predicate::str::contains("problems"));
}

#[test]
fn test_cli_timeout_flag() {
    cmd()
        .arg("00")
        .arg("-t")
        .arg("5")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stop"));
}

#[test]
fn test_cli_0x_prefix() {
    cmd()
        .arg("0x00")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stop"));
}

#[test]
fn test_cli_file_input() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("bytecode.hex");
    std::fs::write(&file_path, "00").unwrap();

    cmd()
        .arg("-f")
        .arg(file_path.to_str().unwrap())
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stop"));
}

#[test]
fn test_cli_stdin_input() {
    cmd()
        .write_stdin("00")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stop"));
}

#[test]
fn test_cli_no_input_fails() {
    // With no bytecode, file, or stdin, should fail.
    // The test environment uses non-TTY stdin by default (piped), so
    // pass empty stdin to trigger the "empty bytecode" error.
    cmd()
        .write_stdin("")
        .assert()
        .failure();
}

#[test]
fn test_cli_complex_bytecode() {
    // PUSH1 42, PUSH1 0, SSTORE, STOP
    cmd()
        .arg("602a60005500")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("stor"));
}

#[test]
fn test_cli_selfdestruct() {
    // PUSH20 <zeros>, SELFDESTRUCT
    let hex = format!("73{}ff", "00".repeat(20));
    cmd()
        .arg(&hex)
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("selfdestruct"));
}

#[test]
fn test_cli_return_bytecode() {
    // PUSH1 32, PUSH1 0, RETURN
    cmd()
        .arg("60206000f3")
        .arg("--no-color")
        .assert()
        .success()
        .stdout(predicate::str::contains("return"));
}

#[test]
fn test_cli_push0_shanghai() {
    // PUSH0, STOP
    cmd()
        .arg("5f00")
        .arg("--no-color")
        .assert()
        .success();
}

#[test]
fn test_cli_tload_cancun() {
    // PUSH1 0, TLOAD, STOP
    cmd()
        .arg("60005c00")
        .arg("--no-color")
        .assert()
        .success();
}
