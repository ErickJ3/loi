use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_flag_prints_usage() {
    Command::cargo_bin("loi")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
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

#[cfg(target_os = "linux")]
mod linux_e2e {
    use assert_cmd::Command;
    use predicates::prelude::*;
    use serde_json::Value;

    fn run_loi(args: &[&str]) -> std::process::Output {
        Command::cargo_bin("loi")
            .unwrap()
            .args(args)
            .output()
            .expect("invoke loi binary")
    }

    fn parse_json_lines(stdout: &[u8]) -> Vec<Value> {
        std::str::from_utf8(stdout)
            .expect("stdout is valid utf-8")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .collect()
    }

    #[test]
    fn traces_bin_true_exits_zero() {
        Command::cargo_bin("loi")
            .unwrap()
            .arg("/bin/true")
            .assert()
            .success();
    }

    #[test]
    fn traces_echo_emits_write_event() {
        Command::cargo_bin("loi")
            .unwrap()
            .args(["/bin/echo", "hello"])
            .assert()
            .success()
            .stdout(predicate::str::is_match(r"write\s*\(").unwrap())
            .stdout(predicate::str::contains("\"hello"));
    }

    #[test]
    fn json_output_is_jsonl() {
        let out = run_loi(&["--output", "json", "/bin/echo", "hello"]);
        assert!(
            out.status.success(),
            "loi exited non-zero: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        let events = parse_json_lines(&out.stdout);
        assert!(
            !events.is_empty(),
            "expected at least one parseable JSON event, got stdout: {}",
            String::from_utf8_lossy(&out.stdout),
        );
        for ev in &events {
            assert!(ev.is_object(), "every JSON line must be an object: {ev}");
            for key in [
                "pid",
                "syscall_nr",
                "syscall_name",
                "ret",
                "duration",
                "args",
            ] {
                assert!(ev.get(key).is_some(), "missing key '{key}' in event: {ev}");
            }
        }
    }

    #[test]
    fn syscall_filter_only_emits_writes() {
        let out = run_loi(&["--syscall", "write", "--output", "json", "/bin/echo", "hi"]);
        assert!(
            out.status.success(),
            "loi exited non-zero: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        let events = parse_json_lines(&out.stdout);
        assert!(
            !events.is_empty(),
            "expected at least one write event, got stdout: {}",
            String::from_utf8_lossy(&out.stdout),
        );
        for ev in &events {
            assert_eq!(
                ev["syscall_name"],
                Value::String("write".to_owned()),
                "non-write event leaked through filter: {ev}",
            );
        }
    }

    #[test]
    fn fail_filter_shows_negative_ret() {
        Command::cargo_bin("loi")
            .unwrap()
            .args(["--fail", "/bin/cat", "/no/such/file"])
            .assert()
            .stdout(predicate::str::contains("openat("))
            .stdout(predicate::str::contains("ENOENT"));
    }

    #[test]
    fn snapshot_write_event_redacts_pid_and_duration() {
        let out = run_loi(&[
            "--syscall",
            "write",
            "--output",
            "json",
            "/bin/echo",
            "hello",
        ]);
        assert!(
            out.status.success(),
            "loi exited non-zero: status={:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr),
        );
        let events = parse_json_lines(&out.stdout);
        let mut payload = events
            .into_iter()
            .find(|ev| {
                ev["syscall_name"] == "write"
                    && ev["args"]
                        .as_array()
                        .and_then(|args| args.iter().find(|a| a["name"] == "buf"))
                        .and_then(|a| a["value"]["inline"].as_str())
                        .is_some_and(|s| s.contains("hello"))
            })
            .unwrap_or_else(|| {
                panic!(
                    "no write event with 'hello' payload found; stdout: {}",
                    String::from_utf8_lossy(&out.stdout),
                )
            });
        payload["pid"] = Value::String("<PID>".to_owned());
        payload["duration"] = Value::String("<DURATION>".to_owned());
        let pretty = serde_json::to_string_pretty(&payload).expect("re-serialize event");
        insta::assert_snapshot!("write_event_echo_hello", pretty);
    }
}
