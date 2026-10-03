//! **The L2 index** (lab #860 R1; `l2-read-path-decision` D2): the L2 state a
//! V6 node derives from its own stored bundles, so a wallet can build an exit
//! without an Annulet node.
//!
//! **What it is.** Every main-chain bundle, in order, folded from its public
//! values alone through the statement's own state transition
//! ([`qlab_cbserver::l2fold::f4::WState::apply`] — the sequencer's fold, not a
//! second derivation): the C tree (each member's commitments in member order,
//! then the wrapper's fee note, exactly as `apply` appends them), the
//! nullifier set N, the claim-nullifier set K, and the registry from the V6
//! genesis (asset 0's Cloaked leaf). Before each bundle the index's roots must
//! equal the bundle's stated in-roots, and after it the stated out-roots
//! (`qlab_wrapper::verify::roots_at`): the index is what W proved, or it stops.
//!
//! **What it refuses, by name, and then stands still.** A bundle with an R
//! (registry write) member: its written leaf is bound through `new_root`, not
//! a PV, so it cannot be rebuilt from the wire (#860 D2) — the index freezes at
//! the last good bundle and says why ([`IndexRefusal::RegistryWrite`]). Also a
//! bundle whose bytes do not read back to its id, that does not decode, or
//! that the fold or the root check refuses. A frozen index still serves what it
//! has, at its height; it never skips a bundle.
//!
//! **What it is not.** Persisted: it is derived state, rebuilt from the log on
//! start (#860 condition (b)). A trust root: the wallet treats it as a hint
//! stream and checks against the bundle it anchors to (D3).

use qlab_cbserver::l2fold::f4::{Member, WInputs, WState, WTagShape};
use qlab_cbserver::l2fold::f3::TxSurface;
use qlab_cbserver::registry::RegistryTree;
use qlab_devnet::annulet::L2ShapeTag;
use qlab_note::hash::digest_bytes as h32;
use qlab_node::Hash32;
use qlab_wrapper::codec::stated_pvs;
use qlab_wrapper::hash::M_ABS;
use qlab_wrapper::verify::{digest_at, roots_at, u64_at};
use qlab_wrapper::wleaf::{PV_ABS, PV_DB, PV_PREV, PV_RKMS};

/// Why the index stopped — the first bundle it could not fold, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexRefusal {
    /// A registry-write (R) member: not reconstructible from the wire (D2).
    RegistryWrite { height: u64, member: usize },
    /// The stored bundle did not read back (bytes not hashing to its id,
    /// or the log moved).
    Unreadable { height: u64, why: String },
    /// The bytes are not a bundle.
    Undecodable { height: u64, why: String },
    /// The statement's fold refused the bundle.
    Fold { height: u64, why: String },
    /// The index's roots are not the bundle's stated in- or out-roots.
    Diverged { height: u64, side: &'static str },
}

impl IndexRefusal {
    /// The refusal's name and height, for `/v1/l2/index`.
    pub fn reason(&self) -> String {
        match self {
            IndexRefusal::RegistryWrite { height, member } => {
                format!("registry-write at height {height} member {member}: not reconstructible from the wire (format v1)")
            }
            IndexRefusal::Unreadable { height, why } => format!("unreadable bundle at height {height}: {why}"),
            IndexRefusal::Undecodable { height, why } => format!("undecodable bundle at height {height}: {why}"),
            IndexRefusal::Fold { height, why } => format!("the fold refused the bundle at height {height}: {why}"),
            IndexRefusal::Diverged { height, side } => {
                format!("the index diverged from the bundle's stated {side}-roots at height {height}")
            }
        }
    }
}

/// One folded bundle's facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedBundle {
    /// The L1 height of the block carrying it.
    pub height: u64,
    /// That block's hash (what a reorg check compares).
    pub block: Hash32,
    /// The bundle's id (keccak of its bytes).
    pub id: Hash32,
    /// Every member nullifier, in member order (S/P/R surfaces; claims add
    /// to K, not N).
    pub nullifiers: Vec<Hash32>,
}

/// The L2 index over a main chain's bundles.
#[derive(Clone)]
pub struct L2Index {
    state: WState,
    bundles: Vec<IndexedBundle>,
    refused: Option<IndexRefusal>,
    /// The block whose bundle froze the index — a reorg past it re-folds.
    refused_block: Option<Hash32>,
}

impl L2Index {
    /// The index at the V6 genesis: no bundle, the genesis registry.
    pub fn genesis() -> Self {
        L2Index {
            state: WState::genesis(&crate::genesis_v6::v6_genesis_registry()),
            bundles: Vec::new(),
            refused: None,
            refused_block: None,
        }
    }

    /// The bundles folded so far, in chain order.
    pub fn bundles(&self) -> &[IndexedBundle] {
        &self.bundles
    }

    /// Why the index stopped, if it did.
    pub fn refused(&self) -> Option<&IndexRefusal> {
        self.refused.as_ref()
    }

    /// The L1 height of the last folded bundle.
    pub fn height(&self) -> Option<u64> {
        self.bundles.last().map(|b| b.height)
    }

    /// The C tree's leaves, in append order — taken from the folded tree.
    pub fn leaves(&self) -> Vec<Hash32> {
        let c = &self.state.l2.c;
        (0..c.len()).map(|i| h32(&c.leaf(i))).collect()
    }

    /// The registry at the index's height.
    pub fn registry(&self) -> &RegistryTree {
        &self.state.l2.r
    }

    /// Fold one main-chain bundle, or stop the index by name. A stopped
    /// index takes nothing further (it never skips a bundle).
    pub fn apply(&mut self, height: u64, block: Hash32, id: Hash32, bytes: Result<&[u8], String>) -> Result<(), IndexRefusal> {
        if let Some(r) = &self.refused {
            return Err(r.clone());
        }
        let r = self.fold(height, block, id, bytes);
        if let Err(e) = &r {
            self.refused = Some(e.clone());
        }
        r
    }

    fn fold(&mut self, height: u64, block: Hash32, id: Hash32, bytes: Result<&[u8], String>) -> Result<(), IndexRefusal> {
        let bytes = bytes.map_err(|why| IndexRefusal::Unreadable { height, why })?;
        // PVs only: the node's bundle rule verified these proofs on arrival;
        // the index folds what was accepted (`stated_pvs`, no proof decoded).
        let b = stated_pvs(bytes).map_err(|e| IndexRefusal::Undecodable { height, why: format!("{e:?}") })?;
        let mut members = Vec::with_capacity(b.members.len());
        let mut nullifiers = Vec::new();
        for (i, (tag, pvs)) in b.members.iter().enumerate() {
            let shape = tag.shape();
            if shape == Some(L2ShapeTag::R) {
                return Err(IndexRefusal::RegistryWrite { height, member: i });
            }
            if let Some(tag) = shape {
                let tx = TxSurface { tag, pvs: pvs.clone(), write: None };
                let nfs = tx.nullifiers().map_err(|e| IndexRefusal::Fold { height, why: format!("member {i}: {e:?}") })?;
                nullifiers.extend(nfs.iter().map(h32));
            }
            members.push(Member { tag: *tag, pvs: pvs.clone(), write: None });
        }
        let w = &b.w_pvs;
        let inp = WInputs {
            prev: digest_at(w, PV_PREV),
            rkm_seq: digest_at(w, PV_RKMS),
            absorbed: core::array::from_fn(|i| digest_at(w, PV_ABS + 16 * i)),
            d_batch: u64_at(w, PV_DB),
        };
        const _: () = assert!(M_ABS > 0);
        if self.state.roots() != roots_at(w, 0) {
            return Err(IndexRefusal::Diverged { height, side: "in" });
        }
        let mut next = self.state.clone();
        next.apply(&inp, &members).map_err(|e| IndexRefusal::Fold { height, why: format!("{e:?}") })?;
        if next.roots() != roots_at(w, 1) {
            return Err(IndexRefusal::Diverged { height, side: "out" });
        }
        self.state = next;
        self.bundles.push(IndexedBundle { height, block, id, nullifiers });
        Ok(())
    }
}

/// A refusal reason as `/v1/l2/index` carries it: no `"`, `\\` or control
/// character, so the body needs no escaping and its reader refuses any.
fn scrub(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => '\'',
            '\\' => '/',
            c if c.is_control() => ' ',
            c => c,
        })
        .collect()
}

/// What the discovery listener serves from the index — a snapshot the run
/// loop publishes, read by the server thread with the lock released (the
/// [`crate::discovery_server::DiscoveryView`] discipline).
#[derive(Clone, Debug, Default)]
pub struct L2IndexView {
    /// `false` off a V6 net: every `/v1/l2/…` route answers 400 by name.
    pub v6: bool,
    /// The L1 height of the last folded bundle.
    pub height: Option<u64>,
    /// Its id.
    pub bundle_id: Option<Hash32>,
    /// The C tree's leaves, append order.
    pub leaves: Vec<Hash32>,
    /// Per bundle-carrying L1 height, its member nullifiers in member order.
    pub nullifiers: std::collections::BTreeMap<u64, Vec<Hash32>>,
    /// The registry at the index's height.
    pub registry: Option<RegistryTree>,
    /// The refusal that froze the index, by name.
    pub refused: Option<String>,
}

impl L2Index {
    /// The served snapshot.
    pub fn view(&self) -> L2IndexView {
        L2IndexView {
            v6: true,
            height: self.height(),
            bundle_id: self.bundles.last().map(|b| b.id),
            leaves: self.leaves(),
            nullifiers: self.bundles.iter().map(|b| (b.height, b.nullifiers.clone())).collect(),
            registry: Some(self.state.l2.r.clone()),
            refused: self.refused.as_ref().map(|r| scrub(&r.reason())),
        }
    }

    /// **Follow `chain`'s main chain**: fold the bundles past the index, or —
    /// when the bundle sequence changed below the index (a reorg), including
    /// at the bundle that froze it — replay from genesis. `WState` has no
    /// undo, and bundles are at least the V6 spacing apart, so a replay is a
    /// short walk. Returns whether anything changed.
    pub fn refresh<C: qlab_node::ChainStore>(&mut self, chain: &C) -> bool {
        // The main chain's bundle-carrying blocks, genesis first.
        let mut carried: Vec<(u64, Hash32, qlab_node::BundleRef)> = Vec::new();
        let mut hash = chain.tip_hash();
        while let Some(block) = chain.block(&hash) {
            if let Some(r) = block.bundle_ref() {
                carried.push((block.header.height, hash, r.clone()));
            }
            if block.header.height == 0 {
                break;
            }
            hash = block.header.prev;
        }
        carried.reverse();
        let folded = self.bundles.len();
        let same_prefix = folded <= carried.len()
            && self.bundles.iter().zip(&carried).all(|(b, (_, h, _))| b.block == *h);
        let same_stop = match (&self.refused, self.refused_block) {
            (Some(_), Some(at)) => carried.get(folded).map(|(_, h, _)| *h) == Some(at),
            _ => true,
        };
        let mut changed = false;
        if !same_prefix || !same_stop {
            *self = L2Index::genesis();
            changed = true;
        }
        for (height, block, r) in carried.into_iter().skip(self.bundles.len()) {
            if self.refused.is_some() {
                break;
            }
            let bytes = r.bytes().map_err(|e| e.to_string());
            let res = self.apply(height, block, r.id, bytes.as_deref().map_err(Clone::clone));
            if res.is_err() {
                self.refused_block = Some(block);
            }
            changed = true;
        }
        changed
    }
}
