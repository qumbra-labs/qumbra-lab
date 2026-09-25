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
pub fn ledger_of(
    node: &MemNode,
    genesis: &std::collections::BTreeMap<u16, u128>,
) -> Option<(AssetLedger, Vec<String>)> {
    node.registry()?;
    let (tip, bodies) = main_chain_bodies(node.chain());
    let ledger = AssetLedger::fold(tip, bodies.iter().map(|(h, b)| (*h, b))).with_genesis(genesis.clone());
    let divergences = ledger.compare_with_node(node.outstanding_supplies(), node.supply_deltas());
    Some((ledger, divergences))
}

/// The attestation document for `node`; `genesis` is the genesis file's
/// issuance per asset (`qlab_node::asset_supply::genesis_issuance`).
pub fn attest_document(node: &MemNode, genesis: &std::collections::BTreeMap<u16, u128>) -> String {
    match ledger_of(node, genesis) {
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
    let genesis: Vec<String> = d
        .genesis
        .iter()
        .map(|r| format!("{{\"asset\":{},\"issued\":{}}}", r.asset, jstr(&r.issued)))
        .collect();
    format!(
        "{{\"v\":{},\"available\":true,\"label\":{},\"framing\":{},\"replay\":{},\
         \"tip_height\":{},\"genesis_note\":{},\"genesis\":[{}],\"assets\":[{}],\
         \"flows\":[{}],\"node_agrees\":{},\"node_divergences\":[{}]}}",
        d.v,
        jstr(&d.label),
        jstr(&d.framing),
        jstr(&d.replay),
        d.tip_height,
        jstr(&d.genesis_note),
        genesis.join(","),
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

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_devnet::annulet::{
        body_commitment_annulet, genesis_body_commitment_annulet, AnnuletHeaderFields, L2FeeTable,
        L2ShapeTag, L2Surface, SequencerKey, VPublicTerm,
    };
    use qlab_devnet::body::{BlockBody, TxEntry, TxPublic, TxVerifier};
    use qlab_devnet::fees::ArityBucket;
    use qlab_devnet::header::BlockHeader;
    use qlab_node::registry_store::{MemRegistryStore, RegistryLeaf};
    use qlab_node::NodeState;

    struct OkProof;
    impl TxVerifier for OkProof {
        fn verify_tx(&self, e: &TxEntry) -> bool {
            e.proof == b"ok"
        }
    }

    const FEES: L2FeeTable = L2FeeTable { tier_s: 1, tier_p: 2, tier_r: 4 };

    /// Genesis notes: four fee-unit notes of 1, and 1,000 of asset 7 — real
    /// genesis plaintexts, since the node seeds its outstanding figure from
    /// them (lab #728 Q7).
    fn genesis_notes() -> Vec<qlab_devnet::annulet::GenesisNote> {
        use qlab_note::l2note::{GenesisPlaintext, L2Note};
        let note = |value: u64, asset: u64, i: u64| L2Note { value, asset, rkm: [i; 4], rho: [i, 1, 2, 3], rseed: [i, 4, 5, 6] };
        [note(1, 0, 1), note(1, 0, 2), note(1, 0, 3), note(1, 0, 4), note(1_000, 7, 5)]
            .iter()
            .map(|n| qlab_devnet::annulet::GenesisNote {
                cm: qlab_note::hash::digest_bytes(&n.commitment()),
                payload: GenesisPlaintext::of(n).0.to_vec(),
            })
            .collect()
    }

    /// The genesis issuance as the binary computes it from the genesis file.
    fn issuance() -> std::collections::BTreeMap<u16, u128> {
        let i = qlab_node::asset_supply::genesis_issuance(&genesis_notes()).unwrap();
        assert_eq!(i, std::collections::BTreeMap::from([(0u16, 4u128), (7, 1_000)]));
        i
    }

    /// Asset 0 plus asset 7 as a Hybrid leaf with a freeze root.
    fn registry() -> Vec<RegistryLeaf> {
        let mut a7 = RegistryLeaf::cloaked(7);
        a7.mode = 1;
        a7.issuer_key = [1, 2, 3, 4];
        a7.freeze_root = [5, 6, 7, 8];
        vec![RegistryLeaf::cloaked(0), a7]
    }

    fn ext() -> AnnuletHeaderFields {
        let root = MemRegistryStore::from_genesis(&registry()).unwrap().root_bytes();
        AnnuletHeaderFields { l1_anchor_height: 0, l1_anchor_root: [0; 32], registry_root: root }
    }

    fn p_tx(n: &MemNode, nf: u8, redeem: bool, amount: u64) -> TxEntry {
        let mut t = TxEntry {
            proof: b"ok".to_vec(),
            public: TxPublic {
                anchor: n.commitment_root(),
                // S/P spend three (A4): slot 3's fee-input nullifier is never a
                // uniform `[x; 32]`, so it cannot collide with another fixture's.
                nullifiers: vec![[nf; 32], [nf.wrapping_add(100); 32], {
                    let mut f = [nf; 32];
                    f[31] = !nf;
                    f
                }],
                commitments: vec![[nf.wrapping_add(1); 32], [nf.wrapping_add(101); 32]],
                bucket: ArityBucket::TwoByTwo,
                fee: FEES.tier_p,
            },
            discovery: Vec::new(),
            rider: qlab_devnet::names::RIDER_ABSENT.to_vec(),
            l2: L2Surface {
                shape: L2ShapeTag::P,
                registry_root: ext().registry_root,
                vpublic: Some([VPublicTerm::NONE, VPublicTerm { redeem, amount, asset: 7 }]),
                write: None,
            }
            .encode(),
        };
        t.discovery = qlab_devnet::annulet::placeholder_discovery_annulet(&t.public.commitments);
        t
    }

    /// An in-memory Annulet node: mint 500 of asset 7, then redeem 120.
    fn annulet_node() -> MemNode {
        let notes = genesis_notes();
        let g = BlockHeader::genesis_annulet(ext(), genesis_body_commitment_annulet(&notes), 0);
        let mut n = MemNode::in_memory_annulet(g, &notes, FEES, &registry());
        let key = SequencerKey::from_seed([0x5E; 32]);
        let mut parent = g;
        for (i, (redeem, amount)) in [(false, 500), (true, 120)].into_iter().enumerate() {
            let body = BlockBody::new(vec![p_tx(&n, 20 + 2 * i as u8, redeem, amount)], vec![]);
            let sealed = key.seal(BlockHeader::child_of_annulet(
                &parent,
                parent.timestamp + 10,
                ext(),
                body_commitment_annulet(&body),
            ));
            n.apply_sealed_block(&sealed, body, &OkProof).unwrap();
            parent = sealed.header;
        }
        n
    }

    /// The served attestation is the shared document, byte for byte in
    /// meaning: `serde_json` reads it back as `AttestDocument` (what the audit
    /// tool's `--claimed` parses), equal to the ledger's own document; it
    /// carries the label, the framing, the replay command, and agrees with the
    /// node.
    #[test]
    fn served_attestation_parses_as_the_shared_document() {
        let n = annulet_node();
        let served = attest_document(&n, &issuance());
        let parsed: AttestDocument = serde_json::from_str(&served).expect("real JSON, the shared shape");
        let (ledger, divergences) = ledger_of(&n, &issuance()).unwrap();
        assert!(divergences.is_empty(), "{divergences:?}");
        assert_eq!(parsed, ledger.document(Vec::new()));
        assert_eq!(parsed.label, "issuance ≠ reserves");
        assert_eq!(
            parsed.framing,
            "Issuance integrity recomputed from public block bodies; replay it yourself with \
             `qumbra-node audit-supply-l2`. Not a consensus commitment."
        );
        assert!(parsed.node_agrees);
        let a7 = parsed.assets.iter().find(|r| r.asset == 7).unwrap();
        assert_eq!((a7.minted.as_str(), a7.redeemed.as_str(), a7.outstanding.as_str()), ("500", "120", "1380"));
        let v: serde_json::Value = serde_json::from_str(&served).unwrap();
        assert_eq!(v["available"], true);
        // Genesis issuance is its own row AND counts toward outstanding
        // (lab #728 Q7): 1,000 + 500 − 120. The fee unit, issued only at
        // genesis, has an assets row too.
        let g7 = parsed.genesis.iter().find(|r| r.asset == 7).unwrap();
        assert_eq!(g7.issued, "1000");
        let a0 = parsed.assets.iter().find(|r| r.asset == 0).unwrap();
        assert_eq!(a0.outstanding, "4");
        assert!(parsed.genesis_note.contains("outstanding from height 0"));
        assert_eq!(parsed.v, 2);
    }

    /// Aggregates only: no key anywhere in the document could name a holder,
    /// a note or a transaction. (Keys, not text: the framing itself says
    /// "not a consensus commitment".)
    #[test]
    fn the_attestation_carries_no_per_holder_field() {
        fn keys(v: &serde_json::Value, out: &mut Vec<String>) {
            match v {
                serde_json::Value::Object(m) => {
                    for (k, x) in m {
                        out.push(k.clone());
                        keys(x, out);
                    }
                }
                serde_json::Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
                _ => {}
            }
        }
        let v: serde_json::Value = serde_json::from_str(&attest_document(&annulet_node(), &issuance())).unwrap();
        let mut all = Vec::new();
        keys(&v, &mut all);
        for k in &all {
            for forbidden in ["nullifier", "commitment", "address", "rkm", "balance", "holder", "tx"] {
                assert!(!k.contains(forbidden), "key {k} names a {forbidden}");
            }
        }
        assert!(all.contains(&"outstanding".to_string()), "the walk saw the figures");
    }

    /// The registry: every leaf, its mode by name, its roots, the root.
    #[test]
    fn the_registry_document_lists_every_leaf() {
        let n = annulet_node();
        let v: serde_json::Value = serde_json::from_str(&registry_document(&n)).unwrap();
        assert_eq!(v["available"], true);
        let assets = v["assets"].as_array().unwrap();
        assert_eq!(assets.len(), 2);
        let a7 = assets.iter().find(|a| a["asset"] == 7).unwrap();
        assert_eq!(a7["mode"], "hybrid");
        assert_eq!(a7["redeem_open"], false);
        assert_eq!(a7["freeze_root"], lanes_hex(&[5, 6, 7, 8]));
        assert_eq!(v["root"], hex32(&ext().registry_root));
        assert_eq!(v["height"], 2);
    }

    /// On an L1 chain both documents say they do not apply, and carry no
    /// figures.
    #[test]
    fn an_l1_chain_serves_no_attestation() {
        let n = MemNode::in_memory(qlab_node::genesis_block(1, 0));
        for doc in [attest_document(&n, &issuance()), registry_document(&n)] {
            let v: serde_json::Value = serde_json::from_str(&doc).unwrap();
            assert_eq!(v["available"], false);
            assert!(v.get("assets").is_none(), "{doc}");
        }
    }

    /// The done-when, against B6's devnet genesis: `USDT-test` (asset 1) shows
    /// its genesis issuance — recomputed from the genesis file's public
    /// plaintext notes — and its registry leaf; the fee unit's genesis stock
    /// is a genesis row too. Genesis issuance is outstanding from height 0
    /// (lab #728 Q7): USDT-test's outstanding figure is its genesis issuance,
    /// on the node and in the document alike.
    #[test]
    fn the_devnet_genesis_shows_usdt_test() {
        use qumbra_node::annulet_genesis::{devnet, registry_leaves, AnnuletGenesisFile};
        let g = AnnuletGenesisFile::devnet();
        let n = MemNode::in_memory_annulet(
            g.genesis_block_header(),
            &g.notes(),
            g.params.fee_table(),
            &registry_leaves(&g.registry_genesis),
        );
        let issuance = qlab_node::asset_supply::genesis_issuance(&g.notes()).unwrap();
        let doc: AttestDocument = serde_json::from_str(&attest_document(&n, &issuance)).unwrap();
        let usdt = devnet::USDT_TEST_ASSET as u16;
        let row = doc.genesis.iter().find(|r| r.asset == usdt).expect("USDT-test's genesis row");
        assert_eq!(row.issued, devnet::HOLDER_USDT_VALUE.to_string());
        assert!(doc.genesis.iter().any(|r| r.asset == 0), "the fee unit's genesis stock");
        let out = doc.assets.iter().find(|r| r.asset == usdt).expect("USDT-test's assets row");
        assert_eq!(out.outstanding, devnet::HOLDER_USDT_VALUE.to_string());
        assert_eq!(n.outstanding_supplies().get(&usdt), Some(&(devnet::HOLDER_USDT_VALUE as i128)));
        assert!(doc.node_agrees, "{:?}", doc.node_divergences);
        let reg: serde_json::Value = serde_json::from_str(&registry_document(&n)).unwrap();
        let leaf = reg["assets"].as_array().unwrap().iter().find(|a| a["asset"] == usdt).unwrap();
        assert_eq!(leaf["mode"], "hybrid");
    }
}

