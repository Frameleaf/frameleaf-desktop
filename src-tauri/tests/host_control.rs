use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::mpsc,
    time::Duration,
};

fn controller() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"));
    command.arg("--owner-pipe");
    command
}

#[test]
fn native_control_requires_the_dedicated_owner_pipe_argument() {
    for arguments in [vec![], vec!["--owner-pipe", "--extra"], vec!["--other"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_frameleaf-native-host"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let message: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(message["code"], "host_control_arguments_invalid");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn native_control_rejects_unbounded_or_invalid_configuration_without_echoing_secrets() {
    for input in [
        b"{\"password\":\"synthetic-private-password\",\"protocolVersion\":99}\n".to_vec(),
        vec![b'x'; 16 * 1024 + 1],
        b"not-json\n".to_vec(),
    ] {
        let mut child = controller()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(&input);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        let message: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(message["state"], "failed");
        assert_eq!(message["code"], "host_control_config_invalid");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-private"));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn native_control_cannot_launch_an_unsigned_candidate() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("frameleaf-control-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let candidate = root.join("candidate");
    fs::create_dir(&candidate).unwrap();
    fs::create_dir(candidate.join("payload")).unwrap();
    fs::write(candidate.join("manifest.json"), b"{}").unwrap();
    fs::write(candidate.join("manifest.sig"), [0u8; 64]).unwrap();
    let state = root.join("state");
    let mut child = controller()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    writeln!(input, "{}", config(&candidate, &state)).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let message: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(message["code"], "host_signature_invalid");
    assert!(output.stderr.is_empty());
    assert!(!state.join("database").exists());
    assert!(!state.join("agent.log").exists());
    drop(input);
    fs::remove_dir_all(root).unwrap();
}

fn config(candidate: &std::path::Path, state: &std::path::Path) -> Value {
    json!({"protocolVersion":1,"installationId":"a".repeat(12),"candidate":candidate,"state":state,
        "manifestSha256":"c220a4b95333bf89673c48afd15bb9cc482a75c7211b2a551d063da65ebc5a8d",
        "password":"synthetic-controller-password-with-enough-length",
        "databasePort":54321,"apiPort":54322})
}

#[test]
#[ignore = "requires actual factory-signed host and new FRAMELEAF_TEST_HOST_CONTROL_STATE"]
fn factory_host_control_stops_on_command_and_owner_eof_and_can_restart() {
    let candidate = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_CANDIDATE").unwrap());
    let state = PathBuf::from(std::env::var("FRAMELEAF_TEST_HOST_CONTROL_STATE").unwrap());
    assert!(candidate.is_absolute() && state.is_absolute() && !state.exists());
    let mut config = config(&candidate, &state);
    let listeners = [
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
        std::net::TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    config["databasePort"] = json!(listeners[0].local_addr().unwrap().port());
    config["apiPort"] = json!(listeners[1].local_addr().unwrap().port());
    drop(listeners);
    for command in [Some("stop\n"), None, Some("invalid\n")] {
        let mut child = controller()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let _ = tx.send(line.unwrap());
            }
        });
        writeln!(input, "{config}").unwrap();
        let ready: Value =
            serde_json::from_str(&rx.recv_timeout(Duration::from_secs(300)).unwrap()).unwrap();
        assert_eq!(ready["state"], "running");
        assert_eq!(ready["manifestSha256"], config["manifestSha256"]);
        assert_eq!(ready["protocolVersion"], 1);
        if let Some(command) = command {
            input.write_all(command.as_bytes()).unwrap();
        }
        drop(input);
        let stopped: Value =
            serde_json::from_str(&rx.recv_timeout(Duration::from_secs(170)).unwrap()).unwrap();
        if command == Some("invalid\n") {
            assert_eq!(
                stopped,
                json!({"protocolVersion":1,"state":"failed","code":"host_control_command_invalid"})
            );
            assert!(!child.wait().unwrap().success());
        } else {
            assert_eq!(stopped, json!({"protocolVersion":1,"state":"stopped"}));
            assert!(child.wait().unwrap().success());
        }
    }
}
