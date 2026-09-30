//! Lab #785 F5-4b — **the bundle rule**: the real [`BundleVerifier`] a V6
//! node runs, built from the genesis's [`WrapperParams`]. `qlab-devnet` keeps
//! the seam and stays prover-free; this is the one place the node decodes a
//! bundle or a surface.
//!
//! # The rule, in order (F5-4 ruling, change A; the 4b ruling's (3))
//!
//! 1. the bundle decodes canonically ([`WireBundle::decode`]);
//! 2. its `l2_id` is the genesis's;
//! 3. **spacing**: at least `wrapper_spacing_blocks` since the last bundle
//!    (the first bundle is free);
//! 4. the clear exit list's shape: at most `K_exit`, no zero `rkm`, no zero
//!    `v` (each accepted exit becomes an L1 note, F5-4c);
//! 5. W's public values are 16-bit chunks, so the bundle **states** a
//!    successor surface ([`WireBundle::stated_surface`]);
//! 6. the **sequencer's signature** over [`sign_message`] (the net's V6
//!    genesis hash, `l2_id`, the stated commitment) — before any proof, so
//!    only the sequencer can make a node pay for a verification;
//! 7. [`verify_wrapper`] V0–V9 over the chain's surface, with V7 the record
//!    rule at this block;
//! 8. the verified surface is the stated one (the 4a pre-review's (j));
//! 9. the **fold's** checks ([`WrapperRule::fold_checks`]): the exit list
//!    chains to W's `exit_cmt`, the counters move forward with checked
//!    differences, `Σ v = ΔE`, `E_cum ≤ D_cum`.
//!
//! **The fold** ([`BundleVerifier::fold_bundle`]) is step 9 plus every other
//! check that needs no proof, no signature and no chain context — decode,
//! `l2_id`, version and threading against the surface it is given, the
//! stated surface's range, exit shape — and returns the same outcome by
//! construction: step 9 **is** the fold's tail, one function.
//!
//! # Versions and members (ruling condition (c), ruling 5915423092)
//!
//! [`WrapperRule::from_params`] builds the chain version, 1, with the typed
//! member verifier at the claim tariff, and nothing else. A bundle of any
//! other version is refused at V0 — explicitly here, and again by
//! `verify_wrapper` against the chain's version-1 surface. The measurement
//! versions and a stub member verifier are reachable only through the two
//! constructors behind the `wrapper-test-knobs` feature, which only
//! qlab-bench's proven fixture enables; `bundle::tests` pins that the
//! production constructor is version 1 with typed members, and that no
//! other source file calls a knob.
use std::sync::Arc;

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, Verifier, VerifyingKey};
use qlab_devnet::header::{BlockHeader, Hash32};
use qlab_devnet::body::{BundleContext, BundleOutcome, BundleRefusal, BundleVerifier, WrapperSetup};
use qlab_wrapper::codec::{
    check_exit_shape, decode_surface, digest_to_bytes, encode_surface, exit_chain, exit_sum, sign_message, stated_surface_prefix, ExitShape,
    WireBundle,
};
use qlab_wrapper::genesis::{genesis_surface, CHAIN_VERSION};
use qlab_consensus::{Config, Proof};
use qlab_wrapper::verify::{roots_at, thread_check, verify_wrapper, BundleMember, MemberVerifier, Surface, TypedMembers, VError};

use crate::genesis::GenesisError;
use crate::genesis_v6::{GenesisFileV6, WrapperParams};

/// The claim tariff member verification checks claims against: qlab-l2's
/// labelled placeholder, the value F4's fixtures and the box pass use. Its
/// real value is an Annulet-genesis parameter not yet chosen.
const FEE_TIER_CLAIM: u64 = qlab_l2::claim::FEE_TIER_CLAIM_PLACEHOLDER;

/// How member proofs are checked: the typed L2 entries, or — test builds
/// only — a caller's verifier.
enum Members {
    Typed(TypedMembers),
    #[cfg(feature = "wrapper-test-knobs")]
    Custom(Box<dyn for<'a> MemberVerifier<&'a Proof<Config>> + Send + Sync>),
}

impl<'a> MemberVerifier<&'a Proof<Config>> for Members {
    fn verify(&self, m: &BundleMember<&'a Proof<Config>>, l2_id: u64) -> Result<(), String> {
        match self {
            Members::Typed(t) => t.verify(m, l2_id),
            #[cfg(feature = "wrapper-test-knobs")]
            Members::Custom(c) => c.verify(m, l2_id),
        }
    }
}

/// The bundle rule for one V6 net.
pub struct WrapperRule {
    /// The V6 genesis hash: the net id the sequencer signs.
    net_id: Hash32,
    l2_id: u64,
    spacing: u64,
    k_exit: usize,
    sequencer_key: VerifyingKey<MlDsa65>,
    /// The wrapper version this chain runs — [`CHAIN_VERSION`] outside tests.
    version: u32,
    members: Members,
}

fn wrapper_err(e: VError) -> BundleRefusal {
    BundleRefusal::Wrapper(format!("{e:?}"))
}

fn codec_err(e: qlab_wrapper::codec::CodecError) -> BundleRefusal {
    BundleRefusal::Codec(format!("{e:?}"))
}

fn exit_shape_err(e: ExitShape) -> BundleRefusal {
    match e {
        ExitShape::TooMany { n, k_exit } => BundleRefusal::TooManyExits { n, k_exit },
        ExitShape::ZeroRkm(index) => BundleRefusal::ZeroExitRkm { index },
        ExitShape::ZeroValue(index) => BundleRefusal::ZeroExitValue { index },
    }
}

impl WrapperRule {
    /// The chain's rule from its genesis: version 1, the genesis's `l2_id`,
    /// spacing, `K_exit` and sequencer key, the V6 genesis hash as net id.
    pub fn from_genesis(genesis: &GenesisFileV6) -> Result<Self, GenesisError> {
        Self::from_params(genesis.hash(), &genesis.wrapper)
    }

    /// [`Self::from_genesis`] from its parts.
    pub fn from_params(net_id: Hash32, params: &WrapperParams) -> Result<Self, GenesisError> {
        let refused = |why: String| GenesisError::V6Refused(why);
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(params.sequencer_key.as_slice())
            .map_err(|_| refused(format!("sequencer key is {} bytes, not an ML-DSA-65 key", params.sequencer_key.len())))?;
        let k_exit = usize::try_from(params.k_exit).map_err(|_| refused("K_exit does not fit a usize".into()))?;
        Ok(WrapperRule {
            net_id,
            l2_id: params.l2_id,
            spacing: params.wrapper_spacing_blocks,
            k_exit,
            sequencer_key: VerifyingKey::<MlDsa65>::decode(&enc),
            version: CHAIN_VERSION,
            members: Members::Typed(TypedMembers { fee_tier: FEE_TIER_CLAIM }),
        })
    }

    /// A rule for a measurement version (the lane's k = 1 fixture chain).
    /// Behind `wrapper-test-knobs` (ruling condition (c)).
    #[cfg(feature = "wrapper-test-knobs")]
    pub fn for_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// A rule whose members are checked by `members` (the fixture's stub:
    /// an L2 member prove is 7–30 GiB). Behind `wrapper-test-knobs`.
    #[cfg(feature = "wrapper-test-knobs")]
    pub fn with_members(mut self, members: Box<dyn for<'a> MemberVerifier<&'a Proof<Config>> + Send + Sync>) -> Self {
        self.members = Members::Custom(members);
        self
    }

    /// The genesis surface this net starts from: the empty L2 state for its
    /// `l2_id` over the V6 genesis registry (asset 0's leaf), as canonical bytes.
    pub fn genesis_surface_bytes(l2_id: u64) -> Vec<u8> {
        encode_surface(&genesis_surface(l2_id, &crate::genesis_v6::v6_genesis_registry_root())).to_vec()
    }

    /// The node-side setup: this rule and the genesis surface at the rule's
    /// version (version 1 outside tests, so exactly
    /// [`Self::genesis_surface_bytes`]).
    pub fn into_setup(self) -> WrapperSetup {
        let roots = qlab_wrapper::genesis::genesis_roots(&crate::genesis_v6::v6_genesis_registry_root());
        let genesis_surface = encode_surface(&Surface::genesis(self.version, self.l2_id, roots)).to_vec();
        WrapperSetup { rule: Arc::new(self), genesis_surface }
    }

    /// Steps shared by the rule and the fold, over a decoded bundle and the
    /// predecessor surface — everything but spacing, the signature and the
    /// proofs. Returns the stated successor surface and the outcome.
    fn fold_checks(&self, prev: &Surface, wb: &WireBundle) -> Result<BundleOutcome, BundleRefusal> {
        if wb.l2_id != self.l2_id || wb.l2_id != prev.l2_id {
            return Err(BundleRefusal::L2Id { got: wb.l2_id, want: prev.l2_id });
        }
        if wb.version != self.version || wb.version != prev.version {
            return Err(wrapper_err(VError::Version));
        }
        check_exit_shape(&wb.exits, self.k_exit).map_err(exit_shape_err)?;
        let stated = wb.stated_surface().ok_or(BundleRefusal::NoStatedSurface)?;
        // V5 and V6, the verifier-side threading — proof-free, so the fold
        // keeps them: a logged bundle folds only onto its own predecessor.
        thread_check(&roots_at(&wb.w_pvs, 0), &prev.out).map_err(wrapper_err)?;
        if stated.prev != prev.commitment {
            return Err(wrapper_err(VError::Prev));
        }
        // V8, native (condition (h)).
        if stated.out.e_cum > stated.out.d_cum {
            return Err(wrapper_err(VError::EAboveD));
        }
        if exit_chain(&wb.exits) != stated.exit_cmt {
            return Err(BundleRefusal::ExitCommitment);
        }
        let d_batch = stated.out.d_cum.checked_sub(prev.out.d_cum).ok_or(BundleRefusal::Counters)?;
        let e_batch = stated.out.e_cum.checked_sub(prev.out.e_cum).ok_or(BundleRefusal::Counters)?;
        if exit_sum(&wb.exits) != Some(e_batch) {
            return Err(BundleRefusal::ExitSum);
        }
        Ok(BundleOutcome {
            surface: encode_surface(&stated).to_vec(),
            exits: wb.exits.iter().map(|e| (digest_to_bytes(&e.rkm), e.v)).collect(),
            d_batch,
            e_batch,
        })
    }

    fn signature_ok(&self, wb: &WireBundle, stated: &Surface) -> bool {
        let Ok(enc) = EncodedSignature::<MlDsa65>::try_from(&wb.sig[..]) else { return false };
        let Some(sig) = Signature::<MlDsa65>::decode(&enc) else { return false };
        self.sequencer_key.verify(&sign_message(&self.net_id, wb.l2_id, &stated.commitment), &sig).is_ok()
    }
}

impl BundleVerifier for WrapperRule {
    fn verify_bundle(&self, header: &BlockHeader, bundle: &[u8], ctx: &BundleContext<'_>) -> Result<BundleOutcome, BundleRefusal> {
        // 1–5: the bytes alone and the genesis parameters.
        let wb = WireBundle::decode(bundle).map_err(codec_err)?;
        if wb.l2_id != self.l2_id {
            return Err(BundleRefusal::L2Id { got: wb.l2_id, want: self.l2_id });
        }
        if let Some(last) = ctx.last_bundle_height {
            let since = header.height.saturating_sub(last);
            if since < self.spacing {
                return Err(BundleRefusal::Spacing { since, need: self.spacing });
            }
        }
        check_exit_shape(&wb.exits, self.k_exit).map_err(exit_shape_err)?;
        let stated = wb.stated_surface().ok_or(BundleRefusal::NoStatedSurface)?;
        // 6: only the sequencer can make a node pay for step 7.
        if !self.signature_ok(&wb, &stated) {
            return Err(BundleRefusal::Signature);
        }
        // 7: the proofs, over the chain's surface.
        let prev = decode_surface(ctx.surface).map_err(|_| BundleRefusal::SurfaceState)?;
        if wb.version != self.version {
            return Err(wrapper_err(VError::Version));
        }
        let anchor_ok = |d: &qlab_wrapper::hash::Digest| (ctx.anchor_ok)(&digest_to_bytes(d));
        let verified = verify_wrapper(&wb.bundle(), &prev, &self.members, &anchor_ok).map_err(wrapper_err)?;
        // 8: what the sequencer signed is what was proven.
        if verified != stated {
            return Err(BundleRefusal::StatedSurface);
        }
        // 9: the fold's tail — the same function replay runs.
        self.fold_checks(&prev, &wb)
    }

    fn fold_bundle(&self, surface: &[u8], bundle: &[u8]) -> Result<BundleOutcome, BundleRefusal> {
        let prev = decode_surface(surface).map_err(|_| BundleRefusal::SurfaceState)?;
        let wb = WireBundle::decode(bundle).map_err(codec_err)?;
        self.fold_checks(&prev, &wb)
    }

    /// The prefix read (F5-4c ruling Q1): kilobytes, no proof decoded — the
    /// snapshot paths' walk-back reads only what the stated surface needs.
    fn bundle_surface(&self, bundle: &[u8]) -> Result<Vec<u8>, BundleRefusal> {
        let stated = stated_surface_prefix(bundle).map_err(codec_err)?.ok_or(BundleRefusal::NoStatedSurface)?;
        Ok(encode_surface(&stated).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis_v6::{GenesisFileV6, REHEARSAL_GENESIS_SURFACE, REHEARSAL_L2_ID};

    /// Ruling 5915423092 (a): the production constructor is version 1 with
    /// the typed member verifier at the claim tariff.
    #[test]
    fn the_production_rule_is_version_1_with_typed_members() {
        let g = GenesisFileV6::new_rehearsal();
        let rule = WrapperRule::from_genesis(&g).unwrap();
        assert_eq!(rule.version, CHAIN_VERSION);
        assert_eq!(CHAIN_VERSION, 1);
        assert!(matches!(rule.members, Members::Typed(TypedMembers { fee_tier }) if fee_tier == qlab_l2::claim::FEE_TIER_CLAIM_PLACEHOLDER));
        assert_eq!((rule.net_id, rule.l2_id, rule.spacing, rule.k_exit), (g.hash(), REHEARSAL_L2_ID, 48, 8));
    }

    /// Ruling 5915423092 (a): no source file but this one names a knob, and
    /// here only behind the feature — so no production path can call one.
    #[test]
    fn no_production_source_calls_a_test_knob() {
        // src/, and (pre-review Q6) this crate's tests/ and examples/ too.
        let krate = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut stack: Vec<_> = ["src", "tests", "examples"].iter().map(|d| krate.join(d)).filter(|p| p.exists()).collect();
        let mut seen = 0;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") || p.file_name().is_some_and(|n| n == "bundle.rs") {
                    continue;
                }
                seen += 1;
                let text = std::fs::read_to_string(&p).unwrap();
                for knob in [concat!("for_", "version("), concat!("with_", "members(")] {
                    assert!(!text.contains(knob), "{} calls the test knob `{knob}`", p.display());
                }
            }
        }
        assert!(seen > 10, "the scan saw the crate's sources ({seen})");
        let own = include_str!("bundle.rs");
        for knob in ["pub fn for_version(", "pub fn with_members("] {
            let at = own.find(knob).expect("the knob exists");
            let before = &own[..at];
            let gate = before.rfind("#[cfg(feature = \"wrapper-test-knobs\")]").expect("gated");
            assert!(before[gate..].lines().count() <= 4, "`{knob}` sits directly under the feature gate");
        }
    }

    /// Pre-review Q6: the feature is named in exactly two manifests — this
    /// crate's `[features]` and qlab-bench's `[dev-dependencies]` — and no
    /// other crate's.
    #[test]
    fn only_two_manifests_name_the_test_knobs() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let feature = concat!("wrapper-test", "-knobs");
        let mut found = Vec::new();
        for e in std::fs::read_dir(&crates).unwrap() {
            let manifest = e.unwrap().path().join("Cargo.toml");
            let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
            let krate = manifest.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
            let mut section = String::new();
            for line in text.lines() {
                let t = line.trim();
                if t.starts_with('[') {
                    section = t.to_string();
                }
                if t.starts_with('#') || !t.contains(feature) {
                    continue;
                }
                found.push((krate.clone(), section.clone()));
            }
        }
        found.sort();
        assert_eq!(
            found,
            vec![("qlab-bench".to_string(), "[dev-dependencies]".to_string()), ("qumbra-node".to_string(), "[features]".to_string())]
        );
        let root = crates.join("..").join("Cargo.toml");
        assert!(!std::fs::read_to_string(root).unwrap().contains(feature), "the workspace manifest does not name it");
    }

    /// Ruling 5915423092 (4) and pre-review Q6: no workflow, script or
    /// deploy recipe switches the knobs on — by name or by `--all-features`.
    /// The release lanes pass explicit features for the drill builds, which
    /// is where one could be added by hand.
    #[test]
    fn no_workflow_or_script_enables_the_test_knobs() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut stack: Vec<_> = [".github", "scripts", "deploy"].iter().map(|d| root.join(d)).filter(|p| p.exists()).collect();
        assert!(!stack.is_empty(), "the scan found the repo's workflow directories");
        let mut seen = 0;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&p) else { continue };
                seen += 1;
                assert!(!text.contains(concat!("wrapper-test", "-knobs")), "{} enables the bundle rule's test knobs", p.display());
                assert!(!text.contains(concat!("--all", "-features")), "{} builds with every feature", p.display());
            }
        }
        assert!(seen > 5, "the scan read the workflow files ({seen})");
    }

    /// The genesis surface bytes decode to the pinned rehearsal surface —
    /// the node's opaque origin is the value C2 checks — and the production
    /// setup carries exactly them.
    #[test]
    fn the_genesis_surface_bytes_are_the_pinned_surface() {
        let b = WrapperRule::genesis_surface_bytes(REHEARSAL_L2_ID);
        let setup = WrapperRule::from_genesis(&GenesisFileV6::new_rehearsal()).unwrap().into_setup();
        assert_eq!(setup.genesis_surface, b);
        assert_eq!(b.len(), qlab_wrapper::codec::SURFACE_LEN);
        let s = decode_surface(&b).unwrap();
        assert_eq!((s.version, s.l2_id, s.commitment), (1, REHEARSAL_L2_ID, REHEARSAL_GENESIS_SURFACE));
    }

    /// Condition (e): V7's mapping from W's lane-major digest to the node's
    /// `Hash32` root is `digest_to_bytes`, the node store's own `root_bytes`
    /// construction, round-trip, over a non-trivial tree.
    #[test]
    fn the_v7_digest_mapping_is_the_nodes_root_bytes() {
        use qlab_node::{CommitmentStore, MemCommitmentStore};
        let mut store = MemCommitmentStore::default();
        for i in 0..5u8 {
            store.append([i; 32]);
            let root = store.tree().root();
            assert_eq!(digest_to_bytes(&root), store.root_bytes());
            assert_eq!(qlab_wrapper::codec::digest_from_bytes(&store.root_bytes()), root);
        }
    }

    /// A key that is not an ML-DSA-65 verifying key refuses at construction.
    #[test]
    fn a_bad_sequencer_key_refuses_the_rule() {
        let mut g = GenesisFileV6::new_rehearsal();
        g.wrapper.sequencer_key.pop();
        assert!(matches!(WrapperRule::from_genesis(&g), Err(GenesisError::V6Refused(_))));
    }

    /// Garbage bytes: every entry point refuses by name, before any proof.
    #[test]
    fn garbage_bundles_refuse_at_the_codec() {
        let rule = WrapperRule::from_genesis(&GenesisFileV6::new_rehearsal()).unwrap();
        let surface = WrapperRule::genesis_surface_bytes(REHEARSAL_L2_ID);
        let header = qlab_devnet::header::BlockHeader::genesis(1, 0);
        let ctx = BundleContext { surface: &surface, last_bundle_height: None, anchor_ok: &|_| true };
        for bytes in [vec![], vec![0u8; 12], vec![0xff; 4096]] {
            assert!(matches!(rule.verify_bundle(&header, &bytes, &ctx), Err(BundleRefusal::Codec(_))));
            assert!(matches!(rule.fold_bundle(&surface, &bytes), Err(BundleRefusal::Codec(_))));
            assert!(matches!(rule.bundle_surface(&bytes), Err(BundleRefusal::Codec(_))));
        }
        assert_eq!(rule.fold_bundle(&[1, 2, 3], &[]), Err(BundleRefusal::SurfaceState));
    }
}
