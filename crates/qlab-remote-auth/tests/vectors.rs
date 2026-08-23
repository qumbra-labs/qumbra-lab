use std::process::Command;

#[test]
fn exact_authorization_vector_is_stable() {
    let output = Command::new(env!("CARGO_BIN_EXE_qlab-remote-auth-spike"))
        .arg("vector")
        .output()
        .expect("authorization vector binary must start");
    assert!(
        output.status.success(),
        "vector binary failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        include_bytes!("../fixtures/authorization-v1.txt")
    );
}
