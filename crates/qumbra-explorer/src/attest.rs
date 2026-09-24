//! The per-asset attestation and the registry — lab issue #726 (L2-D1).
//!
//! Two documents, both **Annulet only** (on an L1 chain each says so and
//! serves no figures):
//!
//! - [`ATTEST_PATH`] — the attestation: per asset, the public `vPublic`
//!   issuance (Σ minted, Σ redeemed, outstanding) and the per-height flows,
//!   folded from the main chain's bodies by `qlab_node::asset_supply`, plus
//!   whether the in-process node's own supply state agrees (every
//!   disagreement named, never reconciled). The document states what it is:
//!   **issuance integrity recomputed from public block bodies — not a
//!   consensus commitment, and issuance ≠ reserves** — and carries the
//!   command that replays it (`qumbra-node audit-supply-l2`), which is the
//!   independent check: the explorer's fold and the node's state are the
//!   same code on the same data.
//! - [`REGISTRY_PATH`] — every registered asset's leaf (mode, issuer key,
//!   freeze and allow roots, flags) and the registry root, read off the
//!   in-process node's registry store. Registry leaves are public by design.
//!
//! Per-asset aggregates only, like every surface here: no balances, no
//! holders, no transfer graph (t1-explorer-split). JSON is hand-rolled as in
//! `json.rs` (no runtime `serde_json`); the attestation's field names are
//! exactly `qlab_node::asset_supply::AttestDocument`'s, so the audit tool reads
//! this document back — `served_attestation_parses_as_the_shared_document`
//! locks the agreement.

use qlab_node::asset_supply::{AssetLedger, AttestDocument};
use qlab_node::registry_store::RegistryStore;
use qlab_node::{ChainStore, Hash32, MemNode};

use crate::txlist::hex32;

/// The attestation route.
pub const ATTEST_PATH: &str = "/v1/attest";
/// The registry route.
pub const REGISTRY_PATH: &str = "/v1/assets";

/// The document an L1 chain serves on both routes.
fn not_annulet(route: &str) -> String {
    format!(
        "{{\"v\":1,\"available\":false,\"why\":\"{route} exists only on an Annulet (L2) chain: \
         this chain has no vPublic terms and no asset registry\"}}"
    )
}

/// The main chain's `(height, body)` pairs, tip to genesis.
fn main_chain_bodies<C: ChainStore>(chain: &C) -> (u64, Vec<(u64, qlab_devnet::body::BlockBody)>) {
    let mut out = Vec::new();
    let mut hash = chain.tip_hash();
    let mut tip_height = None;
    while let Some(block) = chain.block(&hash) {
        let h = block.header.height;
        tip_height.get_or_insert(h);
        out.push((h, block.body()));
        if h == 0 {
            break;
        }
        hash = block.header.prev;
    }
    (tip_height.unwrap_or(0), out)
}

/// The recomputed ledger of `node`'s main chain, and its comparison against
/// the node's own supply state. `None` on an L1 chain.
pub fn ledger_of(node: &MemNode) -> Option<(AssetLedger, Vec<String>)> {
    node.registry()?;
    let (tip, bodies) = main_chain_bodies(node.chain());
    let ledger = AssetLedger::fold(tip, bodies.iter().map(|(h, b)| (*h, b)));
    let divergences = ledger.compare_with_node(node.outstanding_supplies(), node.supply_deltas());
    Some((ledger, divergences))
}

/// The attestation document for `node`.
pub fn attest_document(node: &MemNode) -> String {
    match ledger_of(node) {
        None => not_annulet(ATTEST_PATH),
        Some((ledger, divergences)) => encode(&ledger.document(divergences)),
    }
}

/// JSON string escaping for the few free-text fields (the label, the framing,
/// divergence lines): quotes and backslashes; the rest are plain.
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Encode an [`AttestDocument`] with its serde field names. `available` is an
/// extra field the shared struct ignores (an L1 document has no figures).
pub fn encode(d: &AttestDocument) -> String {
    let assets: Vec<String> = d
        .assets
        .iter()
        .map(|r| {
            format!(
                "{{\"asset\":{},\"minted\":{},\"redeemed\":{},\"outstanding\":{}}}",
                r.asset,
                jstr(&r.minted),
                jstr(&r.redeemed),
                jstr(&r.outstanding)
            )
        })
        .collect();
    let flows: Vec<String> = d
        .flows
        .iter()
        .map(|r| {
            format!(
                "{{\"height\":{},\"asset\":{},\"minted\":{},\"redeemed\":{}}}",
                r.height,
                r.asset,
                jstr(&r.minted),
                jstr(&r.redeemed)
            )
        })
        .collect();
    let divergences: Vec<String> = d.node_divergences.iter().map(|s| jstr(s)).collect();
    format!(
        "{{\"v\":{},\"available\":true,\"label\":{},\"framing\":{},\"replay\":{},\
         \"tip_height\":{},\"assets\":[{}],\"flows\":[{}],\"node_agrees\":{},\
         \"node_divergences\":[{}]}}",
        d.v,
        jstr(&d.label),
        jstr(&d.framing),
        jstr(&d.replay),
        d.tip_height,
        assets.join(","),
        flows.join(","),
        d.node_agrees,
        divergences.join(",")
    )
}

/// Registry `mode` names (`l2-own-circuit-decision` §3.6).
fn mode_name(mode: u64) -> &'static str {
    match mode {
        0 => "cloaked",
        1 => "hybrid",
        2 => "regulated",
        _ => "unknown",
    }
}

/// Four lanes as 32 bytes, lane-major little-endian (the node's `h32`).
fn lanes_hex(l: &[u64; 4]) -> String {
    let mut b = [0u8; 32];
    for (i, lane) in l.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&lane.to_le_bytes());
    }
    hex32(&b)
}

/// The registry document for `node`.
pub fn registry_document(node: &MemNode) -> String {
    let Some(store) = node.registry() else {
        return not_annulet(REGISTRY_PATH);
    };
    let tree = store.tree();
    let leaves: Vec<String> = tree
        .leaves()
        .map(|l| {
            format!(
                "{{\"asset\":{},\"mode\":\"{}\",\"issuer_key\":\"{}\",\"freeze_root\":\"{}\",\
                 \"allow_root\":\"{}\",\"flags\":{},\"redeem_open\":{}}}",
                l.asset,
                mode_name(l.mode),
                lanes_hex(&l.issuer_key),
                lanes_hex(&l.freeze_root),
                lanes_hex(&l.allow_root),
                l.flags,
                l.flags & 1 == 1
            )
        })
        .collect();
    let root: Hash32 = store.root_bytes();
    format!(
        "{{\"v\":1,\"available\":true,\"height\":{},\"root\":\"{}\",\"assets\":[{}]}}",
        node.chain().tip_height(),
        hex32(&root),
        leaves.join(",")
    )
}
