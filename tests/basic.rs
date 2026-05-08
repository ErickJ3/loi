use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_flag_prints_about_string() {
    Command::cargo_bin("loi")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("syscall tracer"));
}

#[test]
fn version_flag_succeeds() {
    Command::cargo_bin("loi")
        .unwrap()
        .arg("--version")
        .assert()
        .success();
}

#[test]
fn missing_command_argument_fails() {
    Command::cargo_bin("loi").unwrap().assert().failure();
}
