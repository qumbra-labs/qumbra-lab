//! Issue #238: the `ctrlc` ↔ `termination` pairing, made structural.
//!
//! Default `ctrlc` registers SIGINT only; the `termination` feature is what
//! also arms SIGTERM/SIGHUP — the signals Docker `stop` and `systemctl stop`
//! actually send (issue #145). The pairing regressed once: #158 fixed the
//! node, and `qumbra-faucet` — a later crate composing the same node — was
//! declared bare and inherited the feature only by cargo feature unification
//! through its `qumbra-node` dependency, i.e. by accident. Nothing enforced
//! the pairing, so the third composing crate would have gotten it wrong too.
//!
//! Since #238 the one declaration lives in `[workspace.dependencies]` and
//! crates take `ctrlc = { workspace = true }`. This test is the enforcement:
//! it fails the workspace suite on any `ctrlc` declaration that carries its
//! own `version`/`git`/`path` instead of the workspace entry, and on the
//! workspace entry ever dropping `termination`. A grep-shaped test over
//! manifests is ugly, but it is the piece that makes the bare redeclaration
//! unrepresentable rather than merely absent (issue #238's candidate (2)).

use std::path::Path;

/// The three dependency-kind keys a manifest can carry, both at top level and
/// under `[target.<triple>.*]`.
const DEP_KINDS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];

fn read_manifest(path: &Path) -> toml::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.parse::<toml::Value>()
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Every (kind, value) pair for a `ctrlc` entry anywhere in this manifest,
/// including target-specific tables.
fn ctrlc_entries(manifest: &toml::Value) -> Vec<(String, toml::Value)> {
    let mut found = Vec::new();
    let mut tables: Vec<(String, &toml::Value)> = DEP_KINDS
        .iter()
        .filter_map(|k| manifest.get(k).map(|t| (k.to_string(), t)))
        .collect();
    if let Some(targets) = manifest.get("target").and_then(|t| t.as_table()) {
        for (triple, per_target) in targets {
            for kind in DEP_KINDS {
                if let Some(t) = per_target.get(kind) {
                    tables.push((format!("target.{triple}.{kind}"), t));
                }
            }
        }
    }
    for (kind, table) in tables {
        if let Some(entry) = table.get("ctrlc") {
            found.push((kind, entry.clone()));
        }
    }
    found
}

#[test]
fn every_ctrlc_declaration_is_the_workspace_termination_one() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    // 1. The single source of truth: `[workspace.dependencies].ctrlc` exists
    //    and carries `termination`.
    let ws = read_manifest(&root.join("Cargo.toml"));
    let ws_ctrlc = ws
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.get("ctrlc"))
        .expect("[workspace.dependencies] must declare ctrlc — it is the one place the termination feature (issue #145) is allowed to live");
    let features: Vec<&str> = ws_ctrlc
        .get("features")
        .and_then(|f| f.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    assert!(
        features.contains(&"termination"),
        "the workspace ctrlc entry must keep the `termination` feature — without it \
         SIGTERM (docker stop / systemctl stop) never reaches any binary's shutdown \
         flush (issue #145); entry: {ws_ctrlc}"
    );

    // 2. Every member that references ctrlc, in any dependency table, takes
    //    the workspace entry — never its own version/git/path.
    let members: Vec<String> = ws
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .expect("workspace.members")
        .iter()
        .map(|v| v.as_str().expect("member path is a string").to_string())
        .collect();

    let mut users = Vec::new();
    for member in &members {
        let path = root.join(member).join("Cargo.toml");
        let manifest = read_manifest(&path);
        for (kind, entry) in ctrlc_entries(&manifest) {
            users.push(member.clone());
            let is_workspace = entry
                .get("workspace")
                .and_then(|w| w.as_bool())
                .unwrap_or(false);
            assert!(
                is_workspace,
                "{member} [{kind}]: ctrlc must be `{{ workspace = true }}` — a bare \
                 declaration is how the faucet lost its own SIGTERM pairing and kept \
                 working only by feature unification (issue #238); found: {entry}"
            );
            for source_key in ["version", "git", "path"] {
                assert!(
                    entry.get(source_key).is_none(),
                    "{member} [{kind}]: ctrlc must not carry its own `{source_key}` \
                     alongside `workspace = true` — the workspace entry is the single \
                     source of truth (issue #238); found: {entry}"
                );
            }
        }
    }

    // 3. Non-vacuity: this crate is the anchor of the #145 discipline. If
    //    qumbra-node ever stops using ctrlc, the shutdown story changed and
    //    this test must be revisited deliberately, not pass silently.
    assert!(
        users.iter().any(|m| m == "crates/qumbra-node"),
        "qumbra-node no longer declares ctrlc — the #145 shutdown seam moved; \
         revisit this enforcement test rather than deleting it (found users: {users:?})"
    );
}
