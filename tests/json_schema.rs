//! End-to-end smoke test: invoke the built binary with `--json` and validate
//! the documented top-level schema shape. This test is `#[cfg(target_os = "macos")]`
//! gated because the binary refuses to run elsewhere.

#![cfg(target_os = "macos")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: panics on failure are intentional"
)]

use std::process::Command;

fn whichway_bin() -> std::path::PathBuf {
    // Cargo conveniently exports the binary path via `CARGO_BIN_EXE_<name>`.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_whichway"))
}

#[test]
fn json_schema_top_level_shape() {
    let out = Command::new(whichway_bin())
        .arg("--json")
        .output()
        .expect("failed to run whichway");
    assert!(
        out.status.success(),
        "whichway --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("output is JSON");
    let obj = v.as_object().expect("top-level object");

    for key in [
        "collected_at",
        "platform",
        "privileged",
        "routes",
        "tunnels",
        "dns",
        "services",
        "pf",
    ] {
        assert!(obj.contains_key(key), "missing top-level key: {key}");
    }
    assert_eq!(obj["platform"], "macos");

    // Each Section must be { "data": T|null, "error": string|null }.
    for sec in ["routes", "tunnels", "dns", "services", "pf"] {
        let s = obj[sec]
            .as_object()
            .unwrap_or_else(|| panic!("{sec} is not an object"));
        assert!(s.contains_key("data"), "{sec}.data missing");
        assert!(s.contains_key("error"), "{sec}.error missing");
        let data = &s["data"];
        let error = &s["error"];
        assert!(
            data.is_null() || data.is_array() || data.is_object(),
            "{sec}.data must be null / array / object, got {data}"
        );
        assert!(
            error.is_null() || error.is_string(),
            "{sec}.error must be null or string, got {error}"
        );
    }

    // pf must be requires-root when running unprivileged (typical test env).
    let pf = &obj["pf"];
    if obj["privileged"] == false {
        assert_eq!(pf["data"], serde_json::Value::Null);
        assert_eq!(pf["error"], "requires root");
    }
}
