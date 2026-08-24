//! The light-client scan flow + the normative decoy over-fetch mitigation.
//!
//! Flow (note-discovery §2):
//! 1. range-fetch `/v1/compact` → decode compact groups — **paged** (lab issue
//!    #309): a serving node bounds one response at
//!    `qlab_node::rpc::MAX_COMPACT_BLOCKS`, so the client re-fetches from the
//!    last served height + 1 until the asked range is in hand;
//! 2. decap once per `(tx, recipient)`, tag-filter the entries (cheap, no full
//!    payloads yet) to decide which `(height, tx)` to full-fetch;
//! 3. for each matched `(height, tx)`: `/full` fetch → reconstruct the
//!    `EncryptedOutputs` (compact bundle + fetched payloads) → run the ratified
//!    `qlab_note::scan::scan` (FullFo default) which AEAD-decrypts and, on
//!    FoSkip, recomputes `cm` and compares to the on-wire value;
//! 4. **decoy over-fetch**: per matched fetch, issue ≥1 randomized decoy
//!    `/full` fetches (discarded) — the §2 fetch-after-match side-channel
//!    mitigation, behind [`DecoyPolicy`].
//!
//! The HTTP client is a std `TcpStream` GET (we own both ends, localhost,
//! fixed response shapes) whose response framing lives in
//! `qlab_http_framing` (lab #631) — recorded in the plan doc.
//!
//! ## 🔴 Step 2 and step 3 no longer answer to the same authority (issue #188)
//!
//! Since baton 1 the compact bundle of step 2 is **in the block body and covered
//! by `tx_body_commitment`**. The AEAD payload of step 3 is not: D2 commits
//! `ct ‖ cm ‖ tag ‖ clue_len` and the ~585 B/note the design priced is
//! `1088/2 + 41`, with no payload in it. So a scan now has **two halves with
//! different guarantees** — detection is answerable from chain data alone, and
//! opening depends on somebody choosing to serve bytes no consensus rule obliges
//! them to hold. Against a `qumbra-node`, whose `/v1/compact` is the whole
//! surface, step 3 is a 404 by design.
//!
//! A scan flow that reports only [`ScanOutcome::notes`] therefore collapses two
//! answers a wallet must never confuse:
//!
//! | truth | old report | now |
//! |---|---|---|
//! | this key was paid nothing here | `notes: []` | `notes: []`, [`Completeness::Complete`] |
//! | this key was paid, and the payload could not be had | `Err(io)` or `notes: []` | `notes: []` + [`ScanOutcome::unopened`], [`Completeness::Incomplete`] |
//!
//! Every output the committed bundle says is ours and this scan did not open is
//! recorded in [`ScanOutcome::unopened`] with its chain coordinates and a reason.
//! **A failed `/full` fetch is no longer fatal to the whole scan**: it is one
//! output's outcome, not the run's, so a wallet against a node that serves no
//! payloads still gets the complete list of what it owns and where.
//!
//! ## 🔴 A third truth: it is here, it opens, and it is already dead (issue #215)
//!
//! `nf = keccak(nk ‖ ρ)` and **nothing else** — not value, not `rkm`, not
//! `rseed`, not the tree position, **not the diversifier**
//! (`qlab_air::narrow::derive_input`, `qlab_wallet::keys::derive_nf`). `nk` is
//! one per spend key and is shared by every diversified address a wallet hands
//! out. So two notes payable to one wallet that share ρ **share a nullifier even
//! when every other field differs**, and spending either one publishes that
//! nullifier and kills the other. Both notes are entirely valid — valid proof,
//! valid commitment, correct encryption, correct discovery. There is no
//! malformed thing to reject, which is exactly why this was invisible.
//!
//! ρ is sender-chosen (`qlab-faucet`'s `build_grant` draws it from a CSPRNG;
//! nothing checks the result), so a sender can reuse it deliberately. That is
//! the spec's *"faerie gold"* attack (`transaction-model-and-anonymity-set.md`
//! §4) and the structural fix — deriving ρ from a nullifier consumed in the same
//! transaction — is a circuit change that does not exist. This module carries the
//! **interim recipient-side defence**: the recipient is the harmed party and the
//! only party that can see both ρ values.
//!
//! | truth | verdict |
//! |---|---|
//! | this key was paid nothing here | [`Completeness::Complete`], `notes: []` |
//! | it was paid and the payload could not be had | [`Completeness::Incomplete`] |
//! | 🔴 it was paid, it opens, and it cannot be spent | [`Completeness::Shadowed`] |
//!
//! **The scan never computes `nf`.** It cannot: `nf` needs `nk`, which comes from
//! the spend key, and a scanner holds a viewing key. It does not need to — for
//! two notes payable to one wallet, `nf₁ == nf₂ ⟺ ρ₁ == ρ₂`, and ρ is in the
//! decrypted note plaintext. See [`NullifierClaim`] for the derivation and for
//! the one-wallet precondition that makes it an equivalence.
//!
//! **The value rule is in the type, not in this comment.**
//! [`ScanOutcome::notes`] holds only spendable notes — at most one per claim — so
//! summing it is correct on its own and there is no field a balance can forget.
//! The dead ones are in [`ScanOutcome::shadowed`], never folded into `notes` and
//! never dropped.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::TcpStream;

use qlab_note::kem::Dk;
use qlab_note::note::Note;
use qlab_note::scan::{detect_matches, scan, DetectedNote, EncryptedOutputs, ScanMode};
use qlab_note::wire::CM_LEN;
use rand::rngs::StdRng;
use rand::Rng;

use crate::codec::{decode_compact_response, decode_full_response, CompactBlock};

/// Decoy over-fetch policy (the §2 trust-posture mitigation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecoyPolicy {
    /// No decoys (baseline; leaks the exact matched-fetch pattern).
    Off,
    /// Per matched fetch, issue a randomized number of decoy fetches in `1..=max`
    /// (spec: "≥1 per matched fetch, randomized"). `max` ≥ 1.
    PerMatch { max: usize },
}

/// Configuration for a scan run.
#[derive(Clone, Copy)]
pub struct ScanConfig {
    pub mode: ScanMode,
    pub decoy: DecoyPolicy,
}

impl Default for ScanConfig {
    fn default() -> Self {
        // FullFo is the ratified default; decoys on at the minimum rate.
        Self { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } }
    }
}

/// The chain's own name for one output — committed coordinates and nothing a
/// server or a sender could have chosen after the fact.
///
/// `cm` is the **committed** commitment from the compact entry, never a
/// recompute of the decrypted plaintext, so this is a claim a wallet can show a
/// user and re-check against any other node.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct NoteRef {
    pub height: u64,
    pub tx_index: u64,
    pub recipient_index: usize,
    /// Index within the recipient bundle — the same index a [`DetectedNote`]
    /// carries.
    pub output_index: usize,
    pub cm: [u8; CM_LEN],
}

/// The claim a note stakes on a nullifier, as much of it as a **scanner** can
/// see — and that turns out to be all of it.
///
/// `nf = keccak(nk ‖ ρ)`, a function of `(nk, ρ)` and of nothing else: not
/// `value`, not `rkm`, not `rseed`, not the tree position, **not the
/// diversifier** (`qlab_air::narrow::derive_input`, host-mirrored in
/// `qlab_wallet::keys::derive_nf`, both single-block Keccak-f over
/// `st[0..4] = nk`, `st[4..8] = ρ`). `nk = keccak(sk ‖ D_N)` is one per spend key
/// and is shared by every diversified address the wallet hands out — `rkm` binds
/// the diversifier, `nf` does not. Therefore, for two notes payable to **one
/// wallet**:
///
/// ```text
/// nf₁ == nf₂   ⟺   ρ₁ == ρ₂     (⇐ trivially; ⇒ under Keccak collision resistance)
/// ```
///
/// so this type carries ρ and nothing else, and the scan **never computes `nf`**:
/// that would need `nk`, which comes from the spend key a scanner does not hold.
///
/// 🔴 **One wallet is a precondition, not a property of this type.** Two notes to
/// two *different* wallets may share ρ and do not collide, because their `nk`
/// differ. One [`ScanOutcome`] always satisfies the precondition — a scan takes
/// one `dk`, and a wallet's `dk_d` are all derived from one `div_seed` and hence
/// one `sk` (`qlab_wallet::viewing`). Aggregating across scans does **not**:
/// see [`ClaimSet`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NullifierClaim([u64; 4]);

impl NullifierClaim {
    /// The claim `note` stakes: its ρ, verbatim.
    pub fn of(note: &Note) -> Self {
        Self(note.rho)
    }

    /// ρ, for a caller that holds `nk` and wants the actual nullifier.
    pub fn rho(&self) -> [u64; 4] {
        self.0
    }
}

/// A detected note located within the chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocatedNote {
    pub height: u64,
    pub tx_index: u64,
    pub recipient_index: usize,
    /// The **committed** commitment of the entry this note was detected on.
    /// Recorded from the compact bundle, not recomputed from the plaintext.
    pub cm: [u8; CM_LEN],
    pub detected: DetectedNote,
}

impl LocatedNote {
    /// The chain's name for this output.
    pub fn at(&self) -> NoteRef {
        NoteRef {
            height: self.height,
            tx_index: self.tx_index,
            recipient_index: self.recipient_index,
            output_index: self.detected.index,
            cm: self.cm,
        }
    }

    /// The claim this note stakes on a nullifier.
    pub fn claim(&self) -> NullifierClaim {
        NullifierClaim::of(&self.detected.note)
    }
}

/// Why an output the committed discovery says is ours did not become a note.
///
/// Every variant is about the **payload**, because the payload is the half that
/// is not on the chain. None of them can mean "the detection was wrong": the tag
/// and the `cm` it binds are consensus-committed bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Unopened {
    /// The `/full` fetch did not complete — transport failure, a non-200, or a
    /// response that did not decode. Against a `qumbra-node` this is a 404 and it
    /// is the **honest** answer: the AEAD payload is not in the block body, so no
    /// node is obliged to hold it (issue #188, `discovery_server`'s module docs).
    PayloadUnavailable(String),
    /// The fetch completed and carried no payload at this recipient index — the
    /// server's payload list is shorter than the committed bundle it belongs to.
    PayloadMissing,
    /// A payload was returned for this output and did not authenticate under this
    /// key (AEAD tag, or the `FoSkip` commitment recompute).
    PayloadRejected,
}

/// An output located on the chain that this scan could not turn into a note.
///
/// The coordinates are the committed ones, so this is a claim a wallet can show
/// its user and re-check against any other node: *"height `h`, transaction `t`,
/// output `o`, commitment `cm` — the chain says this is yours and I could not
/// read it."*
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UnopenedOutput {
    pub height: u64,
    pub tx_index: u64,
    pub recipient_index: usize,
    /// Index within the recipient bundle — the same index [`LocatedNote`]'s
    /// `detected.index` carries.
    pub output_index: usize,
    /// The committed note commitment this output was detected on.
    pub cm: [u8; CM_LEN],
    pub why: Unopened,
}

/// An output that opened and authenticated and can **never be spent**, because
/// another note this wallet holds already claims its nullifier (issue #215).
///
/// Nothing is wrong with this note. It has a valid commitment, a valid proof
/// behind it, correct encryption and correct discovery. It is dead because
/// `nf = keccak(nk ‖ ρ)` binds neither its value nor its position nor the address
/// it was paid to, so the moment [`Self::claimed_by`] is spent this one's
/// nullifier is on the chain — and the reverse is equally true, which is why the
/// choice of which one survives is the wallet's and is stated in
/// [`ScanOutcome::notes`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShadowedNote {
    /// The note in full — a wallet must be able to show its user what it lost.
    pub note: LocatedNote,
    /// The note that claims the nullifier. Within one scan this is one of
    /// [`ScanOutcome::notes`]; after [`ScanOutcome::shadow_against`] it may be a
    /// note from an earlier scan.
    pub claimed_by: NoteRef,
    /// The shared claim, i.e. the shared ρ.
    pub claim: NullifierClaim,
}

/// Whether a scan saw everything the chain says this key owns, and whether what
/// it saw can be spent.
///
/// 🔴 This is the distinction a wallet UI must render, and it is why
/// `notes.is_empty()` is not a question a wallet may ask on its own. Since issue
/// #215 there are two independent ways for the answer to be other than
/// `Complete`, and they are **not** collapsed into one another: a payload that
/// could not be read is an availability problem someone can fix by asking another
/// node, and a note whose nullifier is already claimed is a value loss no node
/// can undo.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Completeness {
    /// Every output detected in the committed discovery was opened and
    /// authenticated, and no two of them claim the same nullifier.
    ///
    /// 🔴 **Scope, and the previous sentence here overstated it (lab #415).** This
    /// verdict speaks for **the committed discovery only** — i.e. transaction
    /// outputs. **Coinbase is not in that set and cannot be**: `CompactBlock` is
    /// `{ height, groups }` and carries no `coinbase_rkm`, so no compact-wire
    /// consumer has ever been able to see a coinbase note. `qumbra-faucet` finds
    /// its own by walking its node's main chain (`harvest.rs`) — it can, because it
    /// IS a node; a wallet is not.
    ///
    /// So an empty `notes` under this verdict means **nothing was paid to this key
    /// by a transaction in this range**. It does NOT mean nothing was paid: a
    /// mining-only wallet reads empty here forever, correctly and uselessly. The
    /// doc used to end "…nothing was paid to this key in this range, and says so on
    /// the chain's authority", which is the confident-wrong-figure shape lab #314
    /// removed one dimension of and this one removes another.
    Complete,
    /// `detected` outputs are this key's by the committed discovery, and only
    /// `opened` of them could be read. An empty `notes` under this verdict means
    /// **something is here and this scan could not read it** — never "no notes".
    Incomplete { detected: usize, opened: usize },
    /// 🔴 Everything detected was read, and `opened − spendable` of the notes are
    /// **already dead**: another note in this result claims their nullifier.
    /// *Something is here, it opens, and it cannot be spent.*
    Shadowed { opened: usize, spendable: usize },
    /// Both at once — reported together rather than one hiding the other.
    IncompleteAndShadowed { detected: usize, opened: usize, spendable: usize },
}

/// Observable outcome of a scan (drives the report + the fetch-count test).
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanStats {
    /// Total bytes of the `/v1/compact` range response, summed across every
    /// page the scan fetched (lab issue #309: a bounded server answers a wide
    /// range in pages, and the scan pages until the range is in hand).
    pub compact_bytes: usize,
    /// The lowest and highest main-chain heights the compact stream actually
    /// served, or `None` when it served no block at all (lab issue #314).
    ///
    /// 🔴 **This is not the `from`/`to` that were asked for**, and the
    /// difference is the point: a server holds what it holds, so a scan of
    /// `0..=5940` against a node at height 5930 legitimately ends at 5930, and
    /// against the reference server (whose first block is height 1) it
    /// legitimately starts at 1. A caller subtracting spends needs the range the
    /// *outputs* it is holding actually came from, because that is what its
    /// nullifier stream must cover before a balance may be quoted — comparing
    /// against the request instead would refuse every honest scan of a range
    /// wider than the chain.
    pub compact_range_served: Option<(u64, u64)>,
    /// Outputs whose **committed** tag matched this key — detection, decided from
    /// chain data alone and before any fetch. `notes_found` can only ever be a
    /// subset of this, and the difference is [`ScanOutcome::unopened`].
    pub detected_outputs: usize,
    /// `/full` fetches that followed a real tag match.
    pub matched_fetches: usize,
    /// `/full` fetches issued as decoys.
    pub decoy_fetches: usize,
    /// Notes detected, authenticated **and spendable** — the length of
    /// [`ScanOutcome::notes`].
    pub notes_found: usize,
    /// Notes detected and authenticated whose nullifier another note already
    /// claims (issue #215) — the length of [`ScanOutcome::shadowed`].
    ///
    /// `detected_outputs == notes_found + shadowed_outputs + unopened.len()`
    /// partitions every detected output exactly once.
    pub shadowed_outputs: usize,
}

/// Result of a scan.
pub struct ScanOutcome {
    /// Outputs opened, authenticated **and spendable** — at most one per
    /// [`NullifierClaim`].
    ///
    /// 🔴 **This is the list a balance sums, and summing it on its own is
    /// correct.** A note that can never be spent is not in here at all; it is in
    /// [`Self::shadowed`]. There is no field to forget and no flag to check.
    ///
    /// **The rule, when two notes claim one nullifier: the greater value is the
    /// spendable one**, ties broken toward the earlier committed position and then
    /// the committed `cm`. `nf` binds nothing but `(nk, ρ)`, so *which* member of
    /// a colliding set gets spent is the recipient's choice and not the chain's —
    /// the recipient can spend any one of them, so the realizable value of the set
    /// is its maximum and this list holds exactly that. Taking the first-seen
    /// instead would understate the balance **and hand the attacker the reported
    /// number**, since the attacker chooses the order the two notes land in.
    pub notes: Vec<LocatedNote>,
    /// Outputs detected on the chain and **not** opened. Never folded into
    /// `notes`, and never silently dropped — see [`Completeness`].
    pub unopened: Vec<UnopenedOutput>,
    /// Outputs that opened and authenticated and can never be spent, because a
    /// note in `notes` (or, after [`Self::shadow_against`], in an earlier scan)
    /// already claims their nullifier. Never folded into `notes`, never summed
    /// into a balance, never dropped.
    pub shadowed: Vec<ShadowedNote>,
    pub stats: ScanStats,
}

impl ScanOutcome {
    /// Did this scan see everything the committed discovery says is ours, and can
    /// what it saw be spent?
    pub fn completeness(&self) -> Completeness {
        let opened = self.notes.len() + self.shadowed.len();
        let spendable = self.notes.len();
        let detected = self.stats.detected_outputs;
        match (self.unopened.is_empty(), self.shadowed.is_empty()) {
            (true, true) => Completeness::Complete,
            (false, true) => Completeness::Incomplete { detected, opened },
            (true, false) => Completeness::Shadowed { opened, spendable },
            (false, false) => {
                Completeness::IncompleteAndShadowed { detected, opened, spendable }
            }
        }
    }

    /// The value a caller may credit: the sum of [`Self::notes`].
    ///
    /// `u128` because the sum of `u64` values is not a `u64`; a wallet that
    /// saturates or wraps here would be reporting an attacker-chosen number.
    pub fn spendable_value(&self) -> u128 {
        self.notes.iter().map(|n| u128::from(n.detected.note.value)).sum()
    }

    /// The value this scan detected, opened, and had to write off — the sum of
    /// [`Self::shadowed`]. Never part of a balance; this is what a wallet tells
    /// its user it lost.
    pub fn shadowed_value(&self) -> u128 {
        self.shadowed.iter().map(|s| u128::from(s.note.detected.note.value)).sum()
    }

    /// The nullifier claims this scan's spendable notes stake — what a wallet
    /// with a note store persists, and feeds to the next scan via
    /// [`Self::shadow_against`].
    pub fn claims(&self) -> ClaimSet {
        let mut set = ClaimSet::new();
        for n in &self.notes {
            set.remember(n.claim(), n.at());
        }
        set
    }

    /// Shadow every spendable note whose nullifier `prior` already claims — the
    /// **cross-scan** half of the defence.
    ///
    /// This exists because one [`ScanOutcome`] cannot see the whole attack. A scan
    /// takes one `dk`, a wallet's `dk_d` is per-diversifier
    /// (`qlab_wallet::viewing::Wallet::diversified_keypair`), and `nf` does not
    /// bind the diversifier — so two notes sharing ρ paid to two *different*
    /// diversified addresses of one wallet collide, are detected by two
    /// *different* scans, and are invisible to each scan alone. A wallet or an
    /// integrator that scans several addresses must aggregate here or the
    /// collision passes straight through.
    ///
    /// 🔴 **The incumbent wins, regardless of value** — the deliberate asymmetry
    /// with the greater-value rule inside one scan. This function cannot retract a
    /// note it did not produce, and a wallet cannot un-spend one it has already
    /// credited or spent. A caller that would rather re-decide has everything it
    /// needs in [`Self::shadowed`] (`claimed_by` names the incumbent) and may do
    /// so; this function will not do it silently.
    ///
    /// 🔴 **Same wallet only.** `prior` must come from scans of addresses of the
    /// **one** wallet this outcome was scanned for — see [`ClaimSet`].
    pub fn shadow_against(&mut self, prior: &ClaimSet) {
        let mut keep = Vec::with_capacity(self.notes.len());
        for note in std::mem::take(&mut self.notes) {
            let claim = note.claim();
            match prior.holder_of(&claim) {
                Some(claimed_by) => self.shadowed.push(ShadowedNote { note, claimed_by, claim }),
                None => keep.push(note),
            }
        }
        self.notes = keep;
        self.stats.notes_found = self.notes.len();
        self.stats.shadowed_outputs = self.shadowed.len();
    }
}

/// The nullifier claims a set of notes stakes — the state a wallet persists so
/// that a collision spanning two scans is not a collision nobody can see.
///
/// 🔴 **One wallet per set, and the type cannot enforce it.** `nf = keccak(nk ‖ ρ)`
/// collides on equal ρ only when `nk` is equal too, so a set built from two
/// wallets' scans produces **false positives** — it would write off a live note of
/// wallet B because wallet A happens to hold one with the same ρ. A wallet's own
/// diversified addresses all share one `nk` (their `dk_d` derive from one
/// `div_seed`, which derives from one `sk`), so aggregating across a wallet's
/// addresses is exactly the supported case and aggregating across wallets is
/// exactly the unsupported one.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct ClaimSet {
    claims: BTreeMap<NullifierClaim, NoteRef>,
}

impl ClaimSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Which note holds `claim`, if any.
    pub fn holder_of(&self, claim: &NullifierClaim) -> Option<NoteRef> {
        self.claims.get(claim).copied()
    }

    /// Record `at` as the holder of `claim`. **Keeps the incumbent** and returns
    /// it if the claim was already held — for the same reason
    /// [`ScanOutcome::shadow_against`] does: a wallet cannot un-spend.
    pub fn remember(&mut self, claim: NullifierClaim, at: NoteRef) -> Option<NoteRef> {
        match self.claims.get(&claim) {
            Some(incumbent) => Some(*incumbent),
            None => {
                self.claims.insert(claim, at);
                None
            }
        }
    }

    /// Fold another scan's spendable claims in, incumbents winning.
    pub fn absorb(&mut self, other: &ClaimSet) {
        for (claim, at) in &other.claims {
            self.remember(*claim, *at);
        }
    }
}

/// Is `a` the better representative of its [`NullifierClaim`] than `b`?
///
/// Greater value wins — the realizable value of a colliding set is its maximum,
/// because the recipient may spend whichever member it likes. Equal value breaks
/// toward the earlier **committed** position and then the committed `cm`, so the
/// outcome does not depend on iteration order, on which node served the range, or
/// on the order the notes happened to be decrypted in.
fn outranks(a: &LocatedNote, b: &LocatedNote) -> bool {
    match a.detected.note.value.cmp(&b.detected.note.value) {
        Ordering::Greater => true,
        Ordering::Less => false,
        Ordering::Equal => a.at() < b.at(),
    }
}

/// Partition the notes this scan opened into the spendable set and the dead set.
///
/// Keyed on ρ alone (see [`NullifierClaim`]) — no `nf`, no `nk`, no secret the
/// scanner does not already hold. Relative order within each output list is
/// preserved, so the two lists read in chain order.
fn resolve_claims(opened: Vec<LocatedNote>) -> (Vec<LocatedNote>, Vec<ShadowedNote>) {
    let mut best: BTreeMap<NullifierClaim, usize> = BTreeMap::new();
    for (i, note) in opened.iter().enumerate() {
        let claim = note.claim();
        match best.get(&claim) {
            Some(&j) if !outranks(note, &opened[j]) => {}
            _ => {
                best.insert(claim, i);
            }
        }
    }
    let holder: BTreeMap<NullifierClaim, NoteRef> =
        best.iter().map(|(claim, &i)| (*claim, opened[i].at())).collect();
    let winners: BTreeSet<usize> = best.values().copied().collect();

    let mut spendable = Vec::with_capacity(winners.len());
    let mut shadowed = Vec::new();
    for (i, note) in opened.into_iter().enumerate() {
        if winners.contains(&i) {
            spendable.push(note);
        } else {
            let claim = note.claim();
            let claimed_by = holder[&claim];
            shadowed.push(ShadowedNote { note, claimed_by, claim });
        }
    }
    (spendable, shadowed)
}

/// Run the light-client scan against `base_url` over `[from, to]`.
///
/// `Err` is reserved for a scan that **never started**: only the `/v1/compact`
/// range fetch and its decode are fatal, because without the committed bytes
/// there is nothing to report at all. A `/full` fetch that fails is one output's
/// outcome and lands in [`ScanOutcome::unopened`].
pub fn light_client_scan(
    base_url: &str,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> std::io::Result<ScanOutcome> {
    let mut fetch = |path: &str| http_get(base_url, path).map_err(|e| e.to_string());
    light_client_scan_with(&mut fetch, dk, from, to, config, rng)
}

/// The same scan, over a **caller-supplied fetch** — one `Err(String)` per
/// failed path, exactly the contract [`light_client_scan`] builds internally.
///
/// Exists for `qumbra-wallet` (issue #297): the wallet must reach an
/// https-only edge, and [`http_get`] below is plaintext-only and stays that
/// way — giving *this* crate a TLS stack would link rustls into `qlab-node`'s
/// build graph, and therefore into the consensus node's. So the wallet brings
/// its own transport and this function lends it the flow. **The scan itself is
/// not duplicated anywhere**: [`ScanDriver`] owns the one orchestration, and
/// this function only pumps it. The socket path, the wallet's TLS path and the
/// in-process [`scan_local`] therefore cannot drift on what counts as detected,
/// opened or unopened.
pub fn light_client_scan_with<F>(
    fetch: &mut F,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> std::io::Result<ScanOutcome>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    scan_over(fetch, dk, from, to, config, rng)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(feature = "devnet")]
/// The light-client scan flow, run **fully in-process** against a `&Devnet`
/// via `crate::server::route` — no socket, no `TcpStream`. Behaviourally
/// identical to [`light_client_scan`] (it *is* the same function, over a
/// different fetch); this is the composition path for an in-process driver
/// (qlab-demo) under a no-networking constraint.
pub fn scan_local(
    devnet: &crate::data::Devnet,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> ScanOutcome {
    let mut fetch = |path: &str| {
        crate::server::route(devnet, path).map_err(|(code, msg)| format!("{code} {msg}"))
    };
    // The reference server answers every well-formed internal URL this function
    // builds, so the fatal arm is unreachable here — kept as an `expect` rather
    // than a silent empty outcome for exactly that reason.
    scan_over(&mut fetch, dk, from, to, config, rng).expect("in-process compact range must resolve")
}

/// One observation from a caller-pumped [`ScanDriver`].
///
/// `Need` carries the exact path vocabulary accepted by
/// [`light_client_scan_with`]'s fetch closure. Supply that request's result with
/// [`ScanDriver::supply`], then call [`ScanDriver::step`] again. `Done` and
/// `Failed` are terminal.
pub enum ScanDriverStep {
    Need(String),
    Done(ScanOutcome),
    Failed(String),
}

enum DriverPhase {
    Compact,
    Groups { block: usize, group: usize },
    AfterMatched { block: usize, group: usize },
    Decoys { paths: Vec<String>, next: usize, block: usize, group: usize },
    Finished,
}

enum PendingKind {
    Compact,
    Matched { block: usize, group: usize, detected: Vec<(usize, Vec<usize>)> },
    Decoy,
}

struct PendingRequest {
    path: String,
    kind: PendingKind,
}

/// The sans-I/O light-client scan state machine (lab issue #350).
///
/// The driver owns the decapsulation key and every scan decision. It performs
/// no I/O: callers alternate [`step`](Self::step) and
/// [`supply`](Self::supply), and may suspend for any length of time while a
/// `Need` is outstanding. `StdRng` is deliberately passed per step rather than
/// borrowed by the driver, so it remains usable by a suspended caller and the
/// existing synchronous entry points preserve their caller-owned RNG state.
pub struct ScanDriver {
    dk: Dk,
    to: u64,
    config: ScanConfig,
    cursor: u64,
    blocks: Vec<CompactBlock>,
    tx_space: Vec<(u64, u64)>,
    stats: ScanStats,
    notes: Vec<LocatedNote>,
    unopened: Vec<UnopenedOutput>,
    phase: DriverPhase,
    pending: Option<PendingRequest>,
    fatal: Option<String>,
}

impl ScanDriver {
    pub fn new(dk: Dk, from: u64, to: u64, config: ScanConfig) -> Self {
        Self {
            dk,
            to,
            config,
            cursor: from,
            blocks: Vec::new(),
            tx_space: Vec::new(),
            stats: ScanStats::default(),
            notes: Vec::new(),
            unopened: Vec::new(),
            phase: DriverPhase::Compact,
            pending: None,
            fatal: None,
        }
    }

    /// Advance until the scan needs one path, completes, or fails.
    pub fn step(&mut self, rng: &mut StdRng) -> ScanDriverStep {
        if let Some(err) = &self.fatal {
            return ScanDriverStep::Failed(err.clone());
        }
        if let Some(pending) = &self.pending {
            return ScanDriverStep::Need(pending.path.clone());
        }

        loop {
            let phase = std::mem::replace(&mut self.phase, DriverPhase::Finished);
            match phase {
                DriverPhase::Compact => {
                    let path = format!("/v1/compact?from={}&to={}", self.cursor, self.to);
                    self.phase = DriverPhase::Compact;
                    self.pending = Some(PendingRequest {
                        path: path.clone(),
                        kind: PendingKind::Compact,
                    });
                    return ScanDriverStep::Need(path);
                }
                DriverPhase::Groups { mut block, mut group } => loop {
                    if block >= self.blocks.len() {
                        // 🔴 Issue #215: resolve colliding nullifier claims only
                        // after the entire requested range has been opened.
                        let (notes, shadowed) = resolve_claims(std::mem::take(&mut self.notes));
                        self.stats.notes_found = notes.len();
                        self.stats.shadowed_outputs = shadowed.len();
                        let outcome = ScanOutcome {
                            notes,
                            unopened: std::mem::take(&mut self.unopened),
                            shadowed,
                            stats: std::mem::take(&mut self.stats),
                        };
                        self.phase = DriverPhase::Finished;
                        return ScanDriverStep::Done(outcome);
                    }
                    if group >= self.blocks[block].groups.len() {
                        block += 1;
                        group = 0;
                        continue;
                    }

                    let compact_group = &self.blocks[block].groups[group];
                    let detected: Vec<(usize, Vec<usize>)> = compact_group
                        .recipients
                        .iter()
                        .enumerate()
                        .map(|(ri, bundle)| (ri, detect_matches(&self.dk, bundle)))
                        .filter(|(_, hits)| !hits.is_empty())
                        .collect();
                    if detected.is_empty() {
                        group += 1;
                        continue;
                    }
                    self.stats.detected_outputs +=
                        detected.iter().map(|(_, hits)| hits.len()).sum::<usize>();
                    let path = format!(
                        "/v1/block/{}/tx/{}/full",
                        self.blocks[block].height, compact_group.tx_index
                    );
                    self.phase = DriverPhase::AfterMatched { block, group };
                    self.pending = Some(PendingRequest {
                        path: path.clone(),
                        kind: PendingKind::Matched { block, group, detected },
                    });
                    return ScanDriverStep::Need(path);
                },
                DriverPhase::AfterMatched { block, group } => {
                    let mut paths = Vec::new();
                    if let DecoyPolicy::PerMatch { max } = self.config.decoy {
                        let max = max.max(1);
                        let n_decoys = 1 + (rng.next_u64() as usize % max);
                        for _ in 0..n_decoys {
                            if self.tx_space.is_empty() {
                                break;
                            }
                            let (height, n_txs) =
                                self.tx_space[rng.next_u64() as usize % self.tx_space.len()];
                            let tx_index = rng.next_u64() % n_txs;
                            paths.push(format!("/v1/block/{height}/tx/{tx_index}/full"));
                        }
                    }
                    if paths.is_empty() {
                        self.phase = DriverPhase::Groups { block, group: group + 1 };
                        continue;
                    }
                    let path = paths[0].clone();
                    self.phase = DriverPhase::Decoys { paths, next: 1, block, group };
                    self.pending =
                        Some(PendingRequest { path: path.clone(), kind: PendingKind::Decoy });
                    return ScanDriverStep::Need(path);
                }
                DriverPhase::Decoys { paths, mut next, block, group } => {
                    if next >= paths.len() {
                        self.phase = DriverPhase::Groups { block, group: group + 1 };
                        continue;
                    }
                    let path = paths[next].clone();
                    next += 1;
                    self.phase = DriverPhase::Decoys { paths, next, block, group };
                    self.pending =
                        Some(PendingRequest { path: path.clone(), kind: PendingKind::Decoy });
                    return ScanDriverStep::Need(path);
                }
                DriverPhase::Finished => {
                    self.phase = DriverPhase::Finished;
                    return ScanDriverStep::Failed("scan driver already completed".to_string());
                }
            }
        }
    }

    /// Supply the result for the currently outstanding `Need`.
    pub fn supply(&mut self, response: Result<Vec<u8>, String>) {
        let Some(pending) = self.pending.take() else {
            self.fatal = Some("scan driver received a response without requesting a path".into());
            return;
        };
        match pending.kind {
            PendingKind::Compact => self.supply_compact(response),
            PendingKind::Matched { block, group, detected } => {
                self.supply_matched(block, group, &detected, response)
            }
            PendingKind::Decoy => {
                // A decoy result is discarded by construction, including an
                // error; only the fact that the request was made is counted.
                self.stats.decoy_fetches += 1;
            }
        }
    }

    fn supply_compact(&mut self, response: Result<Vec<u8>, String>) {
        let compact = match response {
            Ok(compact) => compact,
            Err(err) => {
                self.fatal = Some(err);
                return;
            }
        };
        self.stats.compact_bytes += compact.len();
        let page = match decode_compact_response(&compact) {
            Ok(page) => page,
            Err(err) => {
                self.fatal = Some(format!("{err:?}"));
                return;
            }
        };
        let Some((first, last)) =
            page.first().zip(page.last()).map(|(first, last)| (first.height, last.height))
        else {
            self.finish_compact();
            return;
        };
        if first < self.cursor {
            self.fatal = Some(format!(
                "compact page answers below the requested range: asked from={}, \
                 got height {first} — refusing to append a page nobody asked for",
                self.cursor
            ));
            return;
        }
        self.blocks.extend(page);
        if last >= self.to {
            self.finish_compact();
        } else {
            self.cursor = last + 1;
        }
    }

    fn finish_compact(&mut self) {
        self.stats.compact_range_served = self
            .blocks
            .first()
            .zip(self.blocks.last())
            .map(|(first, last)| (first.height, last.height));
        self.tx_space = self
            .blocks
            .iter()
            .map(|block| (block.height, block.groups.len() as u64))
            .filter(|(_, n_txs)| *n_txs > 0)
            .collect();
        self.phase = DriverPhase::Groups { block: 0, group: 0 };
    }

    fn supply_matched(
        &mut self,
        block_index: usize,
        group_index: usize,
        detected: &[(usize, Vec<usize>)],
        fetched: Result<Vec<u8>, String>,
    ) {
        self.stats.matched_fetches += 1;
        let block = &self.blocks[block_index];
        let group = &block.groups[group_index];
        let payloads_per_recipient = match &fetched {
            Ok(bytes) => decode_full_response(bytes)
                .map_err(|err| format!("undecodable /full response: {err:?}")),
            Err(err) => Err(err.clone()),
        };

        match payloads_per_recipient {
            Err(why) => {
                for (recipient_index, hits) in detected {
                    for &output_index in hits {
                        self.unopened.push(UnopenedOutput {
                            height: block.height,
                            tx_index: group.tx_index,
                            recipient_index: *recipient_index,
                            output_index,
                            cm: group.recipients[*recipient_index].entries[output_index].cm,
                            why: Unopened::PayloadUnavailable(why.clone()),
                        });
                    }
                }
            }
            Ok(payloads_per_recipient) => {
                for (recipient_index, hits) in detected {
                    let (opened, missing) = match payloads_per_recipient.get(*recipient_index) {
                        Some(payloads) => {
                            let encrypted = EncryptedOutputs {
                                bundle: group.recipients[*recipient_index].clone(),
                                payloads: payloads.clone(),
                            };
                            let found = scan(&self.dk, &encrypted, self.config.mode);
                            let opened: Vec<usize> =
                                found.iter().map(|detected| detected.index).collect();
                            for detected in found {
                                let cm =
                                    group.recipients[*recipient_index].entries[detected.index].cm;
                                self.notes.push(LocatedNote {
                                    height: block.height,
                                    tx_index: group.tx_index,
                                    recipient_index: *recipient_index,
                                    cm,
                                    detected,
                                });
                            }
                            (opened, false)
                        }
                        None => (Vec::new(), true),
                    };
                    for &output_index in hits {
                        if !opened.contains(&output_index) {
                            let why = if missing {
                                Unopened::PayloadMissing
                            } else {
                                Unopened::PayloadRejected
                            };
                            self.unopened.push(UnopenedOutput {
                                height: block.height,
                                tx_index: group.tx_index,
                                recipient_index: *recipient_index,
                                output_index,
                                cm: group.recipients[*recipient_index].entries[output_index].cm,
                                why,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Synchronous adapter over the one scan orchestration in [`ScanDriver`].
fn scan_over<F>(
    fetch: &mut F,
    dk: &Dk,
    from: u64,
    to: u64,
    config: ScanConfig,
    rng: &mut StdRng,
) -> Result<ScanOutcome, String>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    let mut driver = ScanDriver::new(dk.clone(), from, to, config);
    loop {
        match driver.step(rng) {
            ScanDriverStep::Need(path) => driver.supply(fetch(&path)),
            ScanDriverStep::Done(outcome) => return Ok(outcome),
            ScanDriverStep::Failed(err) => return Err(err),
        }
    }
}

/// Minimal HTTP/1.1 GET over `TcpStream`. `base_url` is `http://host:port`;
/// returns the response body bytes. Uses `Connection: close` on the request
/// (one connection per call) and stops at the end of the body whenever the
/// response is self-delimiting — [`qlab_http_framing::read_response`], lab
/// #631. The pre-#631 reader de-chunked but ignored `Content-Length`, so a
/// keep-alive peer hung this helper to its read timeout.
///
/// **Plaintext-only, and deliberately so (issue #297).** Every caller here is a
/// test or a tool talking to a `serve()` handle on loopback; the one caller that
/// needed to reach a public https edge — `qumbra-wallet` — brings its own
/// transport and takes the scan flow through [`light_client_scan_with`]. Adding
/// TLS *here* would link rustls into `qlab-node`, and so into `qumbra-node`,
/// `qumbra-faucet`, `qumbra-explorer` and `qumbra-ffi`, for the benefit of one
/// leaf binary. So `base_url must be http://` below is not a stale copy of the
/// wallet's old refusal — it is an accurate statement about this helper.
pub fn http_get(base_url: &str, path_and_query: &str) -> std::io::Result<Vec<u8>> {
    let authority = base_url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "base_url must be http://"))?;
    let mut stream = TcpStream::connect(authority)?;
    let req = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let resp = qlab_http_framing::read_response(&mut stream)?;
    let status_ok = resp.status.as_bytes().windows(3).any(|w| w == b"200");
    if !status_ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("non-200 response: {}", resp.status),
        ));
    }
    Ok(resp.body)
}

#[cfg(all(test, feature = "devnet"))]
mod tests {
    use super::*;
    use crate::data::{Devnet, GenParams, StoredBlock, StoredRecipient, StoredTx};
    use crate::server::serve;
    use crate::tree::CommitmentTree;
    use qlab_devnet::body::{BlockBody, TxEntry, TxPublic};
    use qlab_devnet::chain::ChainState;
    use qlab_devnet::fees::{posted_fee, ArityBucket};
    use qlab_devnet::header::{BlockHeader, Hash32};
    use qlab_note::hash::digest_bytes;
    use qlab_note::kem::{generate_keypair, Ek, Keypair};
    use qlab_note::scan::encrypt_to_recipient;
    use qlab_wallet::address::Diversifier;
    use qlab_wallet::Wallet;
    use std::sync::Arc;

    fn fresh() -> (Arc<Devnet>, crate::server::ServerHandle) {
        let d = Arc::new(Devnet::generate(GenParams::default()));
        let h = serve(Arc::clone(&d));
        (d, h)
    }

    // ---- issue #215: building the attack, not simulating its symptom ---------
    //
    // A "recipient" below is one diversified address: `plan[block][tx][recipient]`
    // is `(ek_d, notes)`, and the notes are the caller's, because **choosing ρ is
    // exactly the sender's capability** and is the whole attack. Nothing is
    // hand-edited afterwards.
    //
    // Everything structural is the same composition `Devnet::generate` performs
    // and is REAL: ML-KEM-768 encapsulation + ChaCha20-Poly1305 sealing by
    // `qlab_note::scan::encrypt_to_recipient`, the ratified `cm`/`tag` wire
    // objects, the consensus Merkle node hash over the real `cm` bytes, real
    // `TxPublic`/`TxEntry`/`BlockBody` bound into the header via
    // `BlockBody::commitment()`, real `BlockHeader`s chained by `header_hash` and
    // inserted into a real `ChainState`, and — in the tests that use `serve` — a
    // real socket and the reference light client. The STARK proof bytes are opaque
    // placeholders, exactly as in `Devnet::generate`: nothing on the scan path ever
    // opens a proof.
    //
    // 🔴 Note what `TxPublic.nullifiers` is here, because it is the point of the
    // whole issue: those are the nullifiers of the notes each transaction SPENDS,
    // and they are unique. The colliding nullifier belongs to the notes these
    // transactions CREATE — it does not appear on the chain until one of them is
    // spent, which is why no validator can see this and why the recipient is the
    // only party that can.
    fn chain_paying(our: Keypair, plan: &[Vec<Vec<(&Ek, Vec<Note>)>>]) -> Devnet {
        const DIFFICULTY: u64 = 1_000;
        let mut rng = StdRng::seed_from_u64(0x215);
        let mut lane = |rng: &mut StdRng| -> [u64; 4] { core::array::from_fn(|_| rng.next_u64()) };

        let mut tree = CommitmentTree::new();
        let mut blocks = Vec::new();
        let mut leaves_at_end_of_height = Vec::new();
        let mut planted = 0usize;

        let genesis = BlockHeader::genesis(DIFFICULTY, 0);
        let mut chain = ChainState::new(genesis);
        let mut parent = genesis;

        for (bi, txs) in plan.iter().enumerate() {
            let height = bi as u64 + 1;
            let anchor: Hash32 = digest_bytes(&tree.root());
            let mut stored_txs = Vec::new();
            let mut body_txs = Vec::new();

            for (ti, recipients) in txs.iter().enumerate() {
                let mut stored = Vec::new();
                let mut commitments: Vec<Hash32> = Vec::new();
                let mut nullifiers: Vec<Hash32> = Vec::new();
                for (ek, notes) in recipients {
                    let enc = encrypt_to_recipient(ek, notes, &mut rng);
                    for e in &enc.bundle.entries {
                        tree.append_bytes(&e.cm);
                        commitments.push(e.cm);
                    }
                    // One spend nullifier per output, unique — see the note above.
                    for _ in notes {
                        nullifiers.push(digest_bytes(&lane(&mut rng)));
                    }
                    planted += notes.len();
                    stored.push(StoredRecipient { enc, ours: true });
                }
                let public = TxPublic {
                    anchor,
                    nullifiers,
                    commitments,
                    bucket: ArityBucket::TwoByTwo,
                    fee: posted_fee(ArityBucket::TwoByTwo),
                };
                let proof = format!("i215-fixture-proof:h{height}:tx{ti}").into_bytes();
                let bundles: Vec<_> = stored.iter().map(|r| r.enc.bundle.clone()).collect();
                let payloads: Vec<Vec<u8>> =
                    stored.iter().flat_map(|r| r.enc.payloads.clone()).collect();
                body_txs.push(TxEntry::new(proof, public, &bundles, &payloads));
                stored_txs.push(StoredTx { recipients: stored });
            }

            let coinbase_rkm = [height, height ^ 0xA5, height ^ 0x5A, height ^ 0xFF];
            let body = BlockBody::from_single_payee(body_txs, height, coinbase_rkm);
            let header =
                BlockHeader::child_of(&parent, height, DIFFICULTY, body.commitment());
            chain.insert_header(header).expect("chained child header inserts cleanly");
            parent = header;
            leaves_at_end_of_height.push((height, tree.len()));
            blocks.push(StoredBlock { height, header, body, txs: stored_txs });
        }

        Devnet::from_parts(blocks, tree, chain, our, planted, leaves_at_end_of_height)
    }

    /// Scan `devnet` over a **real socket** with `dk`, decoys off.
    fn scan_over_socket(devnet: Devnet, dk: &Dk, seed: u64) -> ScanOutcome {
        let tip = devnet.tip_height();
        let d = Arc::new(devnet);
        let handle = serve(Arc::clone(&d));
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = light_client_scan(&handle.base_url(), dk, 1, tip, cfg, &mut StdRng::seed_from_u64(seed))
            .expect("the scan runs");
        handle.shutdown();
        out
    }

    /// Every detected output lands in exactly one of the three lists.
    fn assert_partitions(out: &ScanOutcome) {
        assert_eq!(
            out.stats.detected_outputs,
            out.notes.len() + out.shadowed.len() + out.unopened.len(),
            "detected == spendable + shadowed + unopened, with nothing counted twice \
             and nothing dropped: {:?}",
            out.stats
        );
        assert_eq!(out.stats.notes_found, out.notes.len());
        assert_eq!(out.stats.shadowed_outputs, out.shadowed.len());
    }

    #[test]
    fn scan_finds_exactly_the_planted_notes_both_modes() {
        for mode in [ScanMode::FullFo, ScanMode::FoSkip] {
            let (d, handle) = fresh();
            let mut rng = StdRng::seed_from_u64(1);
            let cfg = ScanConfig { mode, decoy: DecoyPolicy::Off };
            let out = light_client_scan(&handle.base_url(), &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
                .expect("scan runs");
            assert_eq!(
                out.notes.len(),
                d.expected_matches,
                "{mode:?}: found all planted notes over localhost"
            );
            assert_eq!(out.stats.notes_found, d.expected_matches);
            // A server that serves both halves opens everything it detected, so
            // the verdict is Complete — the counterweight that keeps
            // `Incomplete` from being what this code always says.
            assert_eq!(out.stats.detected_outputs, d.expected_matches, "{mode:?}");
            assert!(out.unopened.is_empty(), "{mode:?}: {:?}", out.unopened);
            // Issue #215: the fixture's ρ are independent CSPRNG draws, so nothing
            // here collides. This is the counterweight that keeps `Shadowed` from
            // being what this code always says.
            assert!(out.shadowed.is_empty(), "{mode:?}: {:?}", out.shadowed);
            assert_eq!(out.completeness(), Completeness::Complete, "{mode:?}");
            assert_partitions(&out);
            handle.shutdown();
        }
    }

    #[test]
    fn decoy_fetches_at_least_one_per_match_when_on_and_zero_when_off() {
        // OFF: no decoys, matched_fetches == number of matched (height,tx).
        let (d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(7);
        let off = light_client_scan(
            &handle.base_url(),
            &d.our.dk,
            1,
            d.tip_height(),
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off },
            &mut rng,
        )
        .unwrap();
        assert_eq!(off.stats.decoy_fetches, 0, "decoys off → zero decoy fetches");
        assert!(off.stats.matched_fetches > 0, "there are real matches to fetch");
        handle.shutdown();

        // ON: ≥1 decoy per matched fetch.
        let (d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(7);
        let on = light_client_scan(
            &handle.base_url(),
            &d.our.dk,
            1,
            d.tip_height(),
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 3 } },
            &mut rng,
        )
        .unwrap();
        assert_eq!(on.stats.matched_fetches, off.stats.matched_fetches, "same real matches");
        assert!(
            on.stats.decoy_fetches >= on.stats.matched_fetches,
            "≥1 decoy per matched fetch ({} decoys vs {} matches)",
            on.stats.decoy_fetches,
            on.stats.matched_fetches
        );
        assert!(
            on.stats.decoy_fetches <= on.stats.matched_fetches * 3,
            "≤ max decoys per matched fetch"
        );
        // Decoys must not change what is found.
        assert_eq!(on.stats.notes_found, off.stats.notes_found);
        handle.shutdown();
    }

    #[test]
    fn scan_local_matches_socket_scan_and_finds_planted_notes() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(1);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_local(&d, &d.our.dk, 1, d.tip_height(), cfg, &mut rng);
        assert_eq!(out.notes.len(), d.expected_matches, "socket-free scan finds all planted notes");
        assert_eq!(out.stats.notes_found, d.expected_matches);
        assert!(out.stats.matched_fetches > 0);
    }

    #[test]
    fn scan_local_wrong_key_finds_nothing() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(3);
        let stranger = qlab_note::kem::generate_keypair(&mut StdRng::seed_from_u64(999));
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_local(&d, &stranger.dk, 1, d.tip_height(), cfg, &mut rng);
        assert_eq!(out.notes.len(), 0);
        assert_eq!(out.stats.matched_fetches, 0);
    }

    #[test]
    fn wrong_key_finds_nothing() {
        let (_d, handle) = fresh();
        let mut rng = StdRng::seed_from_u64(3);
        let stranger = qlab_note::kem::generate_keypair(&mut StdRng::seed_from_u64(999));
        let out = light_client_scan(
            &handle.base_url(),
            &stranger.dk,
            1,
            8,
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off },
            &mut rng,
        )
        .unwrap();
        assert_eq!(out.notes.len(), 0, "a stranger's key detects nothing");
        assert_eq!(out.stats.matched_fetches, 0, "no matches → no full fetches");
        // 🔴 And it says so on the chain's authority: nothing was detected, so the
        // empty result is a *complete* answer and not a failed one.
        assert_eq!(out.stats.detected_outputs, 0);
        assert!(out.unopened.is_empty());
        assert_eq!(out.completeness(), Completeness::Complete);
        handle.shutdown();
    }

    // ---- issue #188 (3/4): an incomplete scan is never an empty one -----------

    /// Serve `/v1/compact` from the reference server and answer every `/full`
    /// with `err`. This is a `qumbra-node`'s shape: the committed compact bundle
    /// is served from the block, and the AEAD payload — which is not in any block
    /// — is a 404.
    fn compact_only<'a>(
        devnet: &'a Devnet,
        err: &'a str,
    ) -> impl FnMut(&str) -> Result<Vec<u8>, String> + 'a {
        move |path: &str| {
            if path.starts_with("/v1/compact") {
                crate::server::route(devnet, path).map_err(|(c, m)| format!("{c} {m}"))
            } else {
                Err(err.to_string())
            }
        }
    }

    /// 🔴 **The distinction, in isolation.** A wallet that matches a committed tag
    /// and cannot complete the fetch reports *something other than "no notes"*.
    ///
    /// Three separate claims, because two of them would pass on an accident:
    /// the detected count is right, the unopened list carries the chain
    /// coordinates of every one of them, and the verdict is `Incomplete`.
    #[test]
    fn a_detected_output_whose_payload_cannot_be_fetched_is_reported_not_dropped() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(41);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = compact_only(&d, "non-200 response: HTTP/1.1 404 Not Found");
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
            .expect("the compact half still resolves, so the scan runs");

        assert!(d.expected_matches > 0, "the fixture plants something to lose");
        assert_eq!(
            out.stats.detected_outputs, d.expected_matches,
            "detection is answered from committed bytes and does not need the payload"
        );
        assert_eq!(out.notes.len(), 0, "nothing could be opened");
        assert_eq!(
            out.completeness(),
            Completeness::Incomplete { detected: d.expected_matches, opened: 0 },
            "🔴 a scan that could not complete must not read as a scan that found nothing"
        );
        assert_eq!(out.unopened.len(), d.expected_matches);
        for u in &out.unopened {
            assert!(
                matches!(u.why, Unopened::PayloadUnavailable(ref e) if e.contains("404")),
                "the reason names what actually happened: {:?}",
                u.why
            );
            assert!(u.height >= 1, "a chain coordinate a wallet can re-check elsewhere");
            assert_ne!(u.cm, [0u8; CM_LEN], "the committed commitment travels with it");
        }
        // The commitments reported unopened are exactly the ones the same fixture
        // opens when the payloads are served — no set is invented and none is lost.
        let (d2, handle) = fresh();
        let mut rng2 = StdRng::seed_from_u64(41);
        let good = light_client_scan(&handle.base_url(), &d2.our.dk, 1, d2.tip_height(), cfg, &mut rng2)
            .expect("scan");
        handle.shutdown();
        let mut lost: Vec<[u8; CM_LEN]> = out.unopened.iter().map(|u| u.cm).collect();
        let mut opened: Vec<[u8; CM_LEN]> = good
            .notes
            .iter()
            .map(|n| qlab_note::hash::digest_bytes(&n.detected.note.commitment()))
            .collect();
        lost.sort();
        opened.sort();
        assert_eq!(lost, opened, "the unopened set is the set that would have been opened");
    }

    /// A `/full` that answers 200 with a **shorter** payload list than the
    /// committed bundle it belongs to. The old flow's `else { continue }` dropped
    /// exactly this case in silence — a 200 that means nothing is the same absence
    /// as a 404, and it is now named separately because the two want different
    /// operator responses.
    #[test]
    fn a_short_full_response_is_payload_missing_and_not_an_empty_wallet() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(42);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            if path.starts_with("/v1/compact") {
                crate::server::route(&d, path).map_err(|(c, m)| format!("{c} {m}"))
            } else {
                // Well-formed, decodable, and carrying nobody's payloads.
                Ok(crate::codec::encode_full_response(&[]))
            }
        };
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng).expect("scan");
        assert_eq!(out.notes.len(), 0);
        assert_eq!(out.unopened.len(), d.expected_matches);
        assert!(out.unopened.iter().all(|u| u.why == Unopened::PayloadMissing), "{:?}", out.unopened);
        assert!(matches!(out.completeness(), Completeness::Incomplete { opened: 0, .. }));
    }

    /// A `/full` that answers 200 with a **truncated** body — bytes that are not
    /// the wire at all. Distinct from the short-but-well-formed case above and
    /// reported as such: the response never decoded, so the scan cannot even say
    /// which recipient it was short for, and `PayloadUnavailable` carries the
    /// decoder's own words rather than a guess.
    ///
    /// It is the shape a truncating proxy or a half-written response produces,
    /// and the property under test is that it stays **one output's outcome** —
    /// the scan still completes and still reports the coordinates it detected.
    #[test]
    fn an_undecodable_full_response_is_reported_with_the_decoders_words() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(0x188_f);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            let bytes = crate::server::route(&d, path).map_err(|(c, m)| format!("{c} {m}"))?;
            if path.starts_with("/v1/compact") {
                return Ok(bytes);
            }
            Ok(bytes[..bytes.len() / 2].to_vec()) // cut it in half
        };
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
            .expect("a bad /full is one output's outcome, never the run's");
        assert_eq!(out.notes.len(), 0);
        assert_eq!(out.unopened.len(), d.expected_matches);
        for u in &out.unopened {
            match &u.why {
                Unopened::PayloadUnavailable(e) => {
                    assert!(e.contains("undecodable /full response"), "{e}")
                }
                other => panic!("a body that is not the wire is unavailable, got {other:?}"),
            }
        }
        assert!(matches!(out.completeness(), Completeness::Incomplete { opened: 0, .. }));
    }

    /// A payload that arrives and does not authenticate. Distinct from both
    /// absences above: the bytes were served and the wallet refused them, which is
    /// the one case where the *server* is the suspect rather than the topology.
    #[test]
    fn a_tampered_payload_is_reported_rejected_rather_than_missing() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(43);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            let bytes = crate::server::route(&d, path).map_err(|(c, m)| format!("{c} {m}"))?;
            if path.starts_with("/v1/compact") {
                return Ok(bytes);
            }
            let mut payloads = crate::codec::decode_full_response(&bytes).expect("reference bytes");
            for recipient in payloads.iter_mut() {
                for p in recipient.iter_mut() {
                    if let Some(last) = p.last_mut() {
                        *last ^= 0x01; // break the Poly1305 tag, keep the shape
                    }
                }
            }
            Ok(crate::codec::encode_full_response(&payloads))
        };
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng).expect("scan");
        assert_eq!(out.notes.len(), 0, "a tampered payload authenticates nothing");
        assert_eq!(out.unopened.len(), d.expected_matches);
        assert!(
            out.unopened.iter().all(|u| u.why == Unopened::PayloadRejected),
            "{:?}",
            out.unopened
        );
    }

    // ---- issue #215 (ii): a note whose nullifier is already claimed ----------

    /// 🔴 **The premise the whole defence rests on, checked against the wallet's
    /// own derivations rather than restated.**
    ///
    /// `qlab_wallet::keys::derive_nf` is regression-locked to `build_bucket`'s
    /// public outputs, so what this test asserts about `nf` is what the circuit
    /// asserts. Five claims, and the defence is wrong if any of them is:
    ///
    /// 1. ρ decides `nf` — equal ρ, equal `nf`, whatever else differs;
    /// 2. and it is not merely sufficient: different ρ, different `nf`;
    /// 3. **the diversifier does not** — `rkm` binds it, `nf` does not, so two
    ///    diversified addresses of one wallet share a nullifier on a shared ρ;
    /// 4. so [`NullifierClaim`] can key on ρ alone, with no `nk` and no secret a
    ///    scanner does not already hold;
    /// 5. and the one-wallet precondition is real: two *wallets* sharing ρ do not
    ///    collide, which is why a [`ClaimSet`] may never span two of them.
    #[test]
    fn the_premise_rho_alone_decides_the_nullifier_and_the_diversifier_does_not() {
        let wallet = Wallet::from_seed_lanes([0x215, 7, 7, 7]);
        let rho_a: [u64; 4] = [1, 2, 3, 4];
        let rho_b: [u64; 4] = [1, 2, 3, 5]; // one lane apart

        // (1) and (2).
        assert_eq!(wallet.nullifier(&rho_a), wallet.nullifier(&rho_a));
        assert_ne!(
            wallet.nullifier(&rho_a),
            wallet.nullifier(&rho_b),
            "ρ equality is necessary as well as sufficient"
        );

        // (3) Two diversified addresses of ONE wallet.
        let d1 = wallet.diversifier_at_index(1);
        let d2 = wallet.diversifier_at_index(2);
        assert_ne!(d1.as_bytes(), d2.as_bytes(), "the fixture uses two real addresses");
        assert_ne!(wallet.rkm(d1), wallet.rkm(d2), "rkm binds the diversifier");
        let n1 = Note { value: 5, rkm: wallet.rkm(d1), rho: rho_a, rseed: [11; 4] };
        let n2 = Note { value: 900, rkm: wallet.rkm(d2), rho: rho_a, rseed: [22; 4] };
        assert_ne!(
            n1.commitment(),
            n2.commitment(),
            "two DIFFERENT notes — different value, different rkm, different rseed"
        );
        assert_eq!(
            wallet.nullifier(&n1.rho),
            wallet.nullifier(&n2.rho),
            "🔴 and one nullifier: nf binds neither the value, nor rseed, nor the diversifier"
        );

        // (4) What the scan actually keys on.
        assert_eq!(NullifierClaim::of(&n1), NullifierClaim::of(&n2));
        assert_ne!(NullifierClaim::of(&n1), NullifierClaim::of(&Note { rho: rho_b, ..n1 }));
        assert_eq!(NullifierClaim::of(&n1).rho(), rho_a);

        // (5) The precondition.
        let stranger = Wallet::from_seed_lanes([0x216, 8, 8, 8]);
        assert_ne!(
            wallet.nullifier(&rho_a),
            stranger.nullifier(&rho_a),
            "two wallets sharing ρ do NOT collide — a ClaimSet spanning wallets false-positives"
        );
    }

    /// 🔴 **The test that decides this issue.** Two notes are paid to one
    /// recipient with the **same ρ and different values**, in two different
    /// transactions in two different blocks — the coordinator's attack, built
    /// through the real construction path (real wallet, real `rkm(d)`, real
    /// ML-KEM/AEAD, real block bodies, real socket, reference light client).
    ///
    /// The scan reports the collision, does not present both as spendable, and a
    /// caller taking the spendable balance gets the value of **exactly one** of
    /// them. Both halves of the second clause matter: not the sum, and not zero.
    ///
    /// The second half of the test runs the same attack with the two values
    /// **swapped between the two chain positions**. The spendable balance is
    /// identical, which is the property that keeps the reported number out of the
    /// attacker's hands — they choose the order the notes land in, so a
    /// first-seen-wins rule would let them choose the answer.
    #[test]
    fn two_notes_sharing_rho_leave_exactly_one_spendable_note_of_the_greater_value() {
        for (big_first, label) in [(false, "small then big"), (true, "big then small")] {
            let wallet = Wallet::from_seed_lanes([0x215, 1, 1, 1]);
            let d = Diversifier::default();
            let kp = wallet.diversified_keypair(&d);
            let rkm = wallet.rkm(d);
            let rho: [u64; 4] = [0x5151, 0x5252, 0x5353, 0x5454];

            let big = Note { value: 700, rkm, rho, rseed: [0xBB; 4] };
            let small = Note { value: 300, rkm, rho, rseed: [0x55; 4] };
            assert_eq!(
                wallet.nullifier(&big.rho),
                wallet.nullifier(&small.rho),
                "{label}: the fixture really does build one nullifier"
            );
            assert_ne!(big.commitment(), small.commitment(), "{label}: two valid, distinct notes");

            let (first, second) = if big_first { (big, small) } else { (small, big) };
            // Two transactions, two blocks — nothing links them but ρ.
            let devnet = chain_paying(
                generate_keypair(&mut StdRng::seed_from_u64(0xDEAD)),
                &[vec![vec![(&kp.ek, vec![first])]], vec![vec![(&kp.ek, vec![second])]]],
            );
            let out = scan_over_socket(devnet, &kp.dk, 0x215_0001);

            assert_eq!(out.stats.detected_outputs, 2, "{label}: the chain says two are ours");
            assert!(out.unopened.is_empty(), "{label}: both payloads were served");
            assert_partitions(&out);

            // 🔴 One spendable note, and it is the one worth spending.
            assert_eq!(out.notes.len(), 1, "{label}: not both");
            assert_eq!(out.notes[0].detected.note, big, "{label}: the greater value survives");
            assert_eq!(out.spendable_value(), 700, "{label}");
            assert_ne!(out.spendable_value(), 1_000, "{label}: NOT the sum — that is the theft");
            assert_ne!(out.spendable_value(), 0, "{label}: and not zero — one of them is real money");

            // The dead one is reported in full, with the note that killed it.
            assert_eq!(out.shadowed.len(), 1, "{label}");
            let dead = &out.shadowed[0];
            assert_eq!(dead.note.detected.note, small, "{label}");
            assert_eq!(dead.claimed_by, out.notes[0].at(), "{label}: names the survivor");
            assert_eq!(dead.claim.rho(), rho, "{label}: and the claim they share");
            assert_eq!(out.shadowed_value(), 300, "{label}");
            // The chain coordinates travel with it, from the committed bundle.
            assert_eq!(dead.note.at().height, if big_first { 2 } else { 1 }, "{label}");
            assert_eq!(dead.note.cm, digest_bytes(&small.commitment()), "{label}: committed cm");

            // 🔴 And the verdict is neither of PR #214's two.
            assert_eq!(
                out.completeness(),
                Completeness::Shadowed { opened: 2, spendable: 1 },
                "{label}: 'it is here, it opens, and it is already dead'"
            );
        }
    }

    /// The negative that stops this becoming a false-positive machine: two notes
    /// to **one** address with different ρ, and the values deliberately **equal**
    /// so that nothing about the greater-value rule can be what saves them.
    #[test]
    fn two_notes_to_one_address_with_different_rho_are_both_spendable_and_both_counted() {
        let wallet = Wallet::from_seed_lanes([0x215, 2, 2, 2]);
        let d = wallet.diversifier_at_index(9);
        let kp = wallet.diversified_keypair(&d);
        let rkm = wallet.rkm(d);
        let a = Note { value: 500, rkm, rho: [1, 0, 0, 0], rseed: [0xAA; 4] };
        let b = Note { value: 500, rkm, rho: [2, 0, 0, 0], rseed: [0xAA; 4] };
        assert_ne!(wallet.nullifier(&a.rho), wallet.nullifier(&b.rho));

        // One transaction, two outputs — the ordinary 2-of-1 payment shape.
        let devnet = chain_paying(
            generate_keypair(&mut StdRng::seed_from_u64(0xBEEF)),
            &[vec![vec![(&kp.ek, vec![a, b])]]],
        );
        let out = scan_over_socket(devnet, &kp.dk, 0x215_0002);

        assert_eq!(out.stats.detected_outputs, 2);
        assert_eq!(out.notes.len(), 2, "both spendable");
        assert!(out.shadowed.is_empty(), "{:?}", out.shadowed);
        assert_eq!(out.spendable_value(), 1_000, "and both counted");
        assert_eq!(out.completeness(), Completeness::Complete);
        assert_partitions(&out);
    }

    /// The other negative the task book names, and it carries a finding.
    ///
    /// Two notes with **different ρ** paid to **two different diversified
    /// addresses** of one recipient are both spendable and both counted. A naive
    /// implementation would key on the diversifier — `rkm` binds it, so it is the
    /// obvious separator — and `nf` does not bind it, so that implementation would
    /// be wrong in both directions.
    ///
    /// 🔴 The finding is the last assertion: **a `dk` is per-diversifier**
    /// (`Wallet::diversified_keypair`), so neither scan can even *see* the other
    /// address's note. Two diversified addresses are two scans, which is why the
    /// cross-diversifier collision is structurally a cross-scan problem and needs
    /// [`ScanOutcome::shadow_against`] — see the test below.
    #[test]
    fn notes_to_two_diversified_addresses_with_different_rho_are_both_spendable() {
        let wallet = Wallet::from_seed_lanes([0x215, 3, 3, 3]);
        let (d1, d2) = (wallet.diversifier_at_index(1), wallet.diversifier_at_index(2));
        let (kp1, kp2) = (wallet.diversified_keypair(&d1), wallet.diversified_keypair(&d2));
        let n1 = Note { value: 400, rkm: wallet.rkm(d1), rho: [7, 0, 0, 0], rseed: [1; 4] };
        let n2 = Note { value: 600, rkm: wallet.rkm(d2), rho: [8, 0, 0, 0], rseed: [1; 4] };
        assert_ne!(wallet.nullifier(&n1.rho), wallet.nullifier(&n2.rho), "different ρ, no collision");

        let plan = vec![vec![vec![(&kp1.ek, vec![n1]), (&kp2.ek, vec![n2])]]];
        let a = scan_over_socket(
            chain_paying(generate_keypair(&mut StdRng::seed_from_u64(1)), &plan),
            &kp1.dk,
            0x215_0003,
        );
        let b = scan_over_socket(
            chain_paying(generate_keypair(&mut StdRng::seed_from_u64(1)), &plan),
            &kp2.dk,
            0x215_0004,
        );

        assert_eq!(a.completeness(), Completeness::Complete);
        assert_eq!(b.completeness(), Completeness::Complete);
        assert!(a.shadowed.is_empty() && b.shadowed.is_empty());
        assert_eq!(a.spendable_value(), 400);
        assert_eq!(b.spendable_value(), 600);
        assert_eq!(a.spendable_value() + b.spendable_value(), 1_000, "both counted");

        // 🔴 The finding: one scan sees one address, so aggregation is not optional.
        assert_eq!(a.stats.detected_outputs, 1, "a dk detects only its own diversifier");
        assert_eq!(b.stats.detected_outputs, 1);
        // Aggregating two honest scans changes nothing.
        let mut b2 = scan_over_socket(
            chain_paying(generate_keypair(&mut StdRng::seed_from_u64(1)), &plan),
            &kp2.dk,
            0x215_0004,
        );
        b2.shadow_against(&a.claims());
        assert_eq!(b2.completeness(), Completeness::Complete, "no false positive on aggregation");
        assert_eq!(b2.spendable_value(), 600);
    }

    /// 🔴 **The collision the coordinator's argument names, and the case one scan
    /// cannot solve.** Same ρ, two *different* diversified addresses of one
    /// recipient — a nullifier collision, because `nf` does not bind the
    /// diversifier.
    ///
    /// Each scan alone is `Complete` and reports its note as spendable, so a
    /// wallet that scans its addresses and adds the balances up **credits 2v and
    /// can realize v**: the attack, passing straight through the within-scan
    /// defence. Aggregating the claims catches it.
    ///
    /// This is the honest boundary of what a pure function over a height range can
    /// do, stated as a test rather than as a caveat: the state has to live in the
    /// wallet, and [`ClaimSet`] is the shape it has to live in.
    #[test]
    fn a_collision_across_two_diversified_addresses_needs_the_scans_aggregated() {
        let wallet = Wallet::from_seed_lanes([0x215, 4, 4, 4]);
        let (d1, d2) = (wallet.diversifier_at_index(1), wallet.diversifier_at_index(2));
        let (kp1, kp2) = (wallet.diversified_keypair(&d1), wallet.diversified_keypair(&d2));
        let rho: [u64; 4] = [0xFACE, 0, 0, 0];
        let n1 = Note { value: 250, rkm: wallet.rkm(d1), rho, rseed: [3; 4] };
        let n2 = Note { value: 250, rkm: wallet.rkm(d2), rho, rseed: [4; 4] };
        assert_eq!(wallet.nullifier(&n1.rho), wallet.nullifier(&n2.rho), "one nullifier");
        assert_ne!(n1.commitment(), n2.commitment(), "two valid notes");

        // Two transactions in two blocks, to two addresses.
        let plan =
            vec![vec![vec![(&kp1.ek, vec![n1])]], vec![vec![(&kp2.ek, vec![n2])]]];
        let mk = || chain_paying(generate_keypair(&mut StdRng::seed_from_u64(2)), &plan);
        let first = scan_over_socket(mk(), &kp1.dk, 0x215_0005);
        let mut second = scan_over_socket(mk(), &kp2.dk, 0x215_0006);

        // Individually: each says everything is fine, because for each it is.
        assert_eq!(first.completeness(), Completeness::Complete);
        assert_eq!(second.completeness(), Completeness::Complete);
        assert_eq!(
            first.spendable_value() + second.spendable_value(),
            500,
            "🔴 unaggregated, a wallet credits both — 250 of which is not money"
        );

        // Aggregated: the incumbent keeps the claim and the later note is dead.
        let claims = first.claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims.holder_of(&NullifierClaim::of(&n1)), Some(first.notes[0].at()));
        second.shadow_against(&claims);

        assert!(second.notes.is_empty(), "nothing of the second scan is spendable");
        assert_eq!(second.spendable_value(), 0);
        assert_eq!(second.shadowed.len(), 1);
        assert_eq!(second.shadowed[0].claimed_by, first.notes[0].at(), "names the incumbent");
        assert_eq!(second.shadowed[0].note.detected.note, n2);
        assert_eq!(
            second.completeness(),
            Completeness::Shadowed { opened: 1, spendable: 0 },
            "🔴 not Complete-with-no-notes: something IS here, it opened, and it is dead"
        );
        assert_eq!(
            first.spendable_value() + second.spendable_value(),
            250,
            "the aggregate balance is the value of exactly one of them"
        );
        assert_partitions(&second);

        // The incumbent rule, in isolation: `remember` never displaces.
        let mut set = ClaimSet::new();
        let claim = NullifierClaim::of(&n1);
        assert_eq!(set.remember(claim, first.notes[0].at()), None);
        let usurper = NoteRef { height: 99, tx_index: 0, recipient_index: 0, output_index: 0, cm: [9; CM_LEN] };
        assert_eq!(set.remember(claim, usurper), Some(first.notes[0].at()));
        assert_eq!(set.holder_of(&claim), Some(first.notes[0].at()), "incumbent kept");
        assert_eq!(set.len(), 1);
    }

    /// The two failure modes compose rather than hide each other: an output whose
    /// payload could not be read **and** a note that is already dead, in one scan.
    /// Folding either into the other would rebuild the defect `PR #214` removed.
    #[test]
    fn an_unreadable_payload_and_a_dead_note_are_reported_together() {
        let wallet = Wallet::from_seed_lanes([0x215, 5, 5, 5]);
        let d = Diversifier::default();
        let kp = wallet.diversified_keypair(&d);
        let rkm = wallet.rkm(d);
        let rho: [u64; 4] = [0xC0, 0, 0, 0];
        let big = Note { value: 90, rkm, rho, rseed: [1; 4] };
        let dead = Note { value: 10, rkm, rho, rseed: [2; 4] };
        let elsewhere = Note { value: 55, rkm, rho: [0xC1, 0, 0, 0], rseed: [3; 4] };

        // Block 1: the colliding pair, one transaction. Block 2: a third note.
        let devnet = chain_paying(
            generate_keypair(&mut StdRng::seed_from_u64(3)),
            &[
                vec![vec![(&kp.ek, vec![big, dead])]],
                vec![vec![(&kp.ek, vec![elsewhere])]],
            ],
        );
        // Serve `/full` for block 1 only — block 2's payload is a 404.
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            if path.starts_with("/v1/compact") || path.starts_with("/v1/block/1/") {
                crate::server::route(&devnet, path).map_err(|(c, m)| format!("{c} {m}"))
            } else {
                Err("non-200 response: HTTP/1.1 404 Not Found".to_string())
            }
        };
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_over(&mut fetch, &kp.dk, 1, 2, cfg, &mut StdRng::seed_from_u64(0x215_0007))
            .expect("the compact half resolves");

        assert_eq!(out.stats.detected_outputs, 3);
        assert_eq!(out.notes.len(), 1);
        assert_eq!(out.notes[0].detected.note, big);
        assert_eq!(out.shadowed.len(), 1);
        assert_eq!(out.shadowed[0].note.detected.note, dead);
        assert_eq!(out.unopened.len(), 1);
        assert_eq!(out.unopened[0].height, 2);
        assert!(matches!(out.unopened[0].why, Unopened::PayloadUnavailable(ref e) if e.contains("404")));
        assert_eq!(
            out.completeness(),
            Completeness::IncompleteAndShadowed { detected: 3, opened: 2, spendable: 1 },
            "both facts survive; neither one hides the other"
        );
        assert_partitions(&out);
    }

    /// A decoy fetch that fails must not decide a real scan's fate. Its result is
    /// discarded by construction, and before this the `?` on it aborted a scan
    /// that had already succeeded — which on a `qumbra-node` (every `/full` is a
    /// 404) is every scan with a match in it.
    #[test]
    fn a_failing_decoy_fetch_does_not_end_the_scan() {
        let d = Devnet::generate(GenParams::default());
        let mut rng = StdRng::seed_from_u64(44);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 3 } };
        let mut fetch = compact_only(&d, "connection refused");
        let out = scan_over(&mut fetch, &d.our.dk, 1, d.tip_height(), cfg, &mut rng)
            .expect("a failing decoy is not a failed scan");
        assert!(out.stats.decoy_fetches >= out.stats.matched_fetches, "decoys still issued");
        assert_eq!(out.stats.detected_outputs, d.expected_matches);
        assert_eq!(out.unopened.len(), d.expected_matches);
    }

    // ---- lab issue #309: the compact range is served in pages -----------------

    /// Lab issue #350 decision lock. These are the complete request traces made
    /// by the synchronous implementation before it is inverted into a driver.
    /// They deliberately pin compact paging before any matched `/full` fetches,
    /// the inclusive path vocabulary, the empty-response stop, and a fatal
    /// compact failure after an earlier page made progress.
    #[test]
    fn request_path_sequences_are_golden_before_scan_driver_refactor() {
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };

        // One compact page, followed by the two matching transactions in it.
        let single = Devnet::generate(GenParams {
            n_blocks: 1,
            txs_per_block: 2,
            ..GenParams::default()
        });
        let mut single_paths = Vec::new();
        let mut single_fetch = |path: &str| {
            single_paths.push(path.to_string());
            crate::server::route(&single, path).map_err(|(c, m)| format!("{c} {m}"))
        };
        scan_over(
            &mut single_fetch,
            &single.our.dk,
            1,
            1,
            cfg,
            &mut StdRng::seed_from_u64(0x3501),
        )
        .expect("single-page golden scan");
        drop(single_fetch);
        assert_eq!(
            single_paths,
            [
                "/v1/compact?from=1&to=1",
                "/v1/block/1/tx/0/full",
                "/v1/block/1/tx/1/full",
            ]
        );

        // Five blocks served two at a time: collect every compact page first,
        // then open each matching transaction in ascending chain order.
        let multi = Devnet::generate(GenParams {
            n_blocks: 5,
            txs_per_block: 1,
            ..GenParams::default()
        });
        let mut multi_paths = Vec::new();
        let mut multi_fetch = |path: &str| {
            multi_paths.push(path.to_string());
            let bytes =
                crate::server::route(&multi, path).map_err(|(c, m)| format!("{c} {m}"))?;
            if path.starts_with("/v1/compact") {
                let blocks = decode_compact_response(&bytes).expect("route serves compact wire");
                return Ok(crate::codec::encode_compact_response(
                    &blocks.into_iter().take(2).collect::<Vec<_>>(),
                ));
            }
            Ok(bytes)
        };
        scan_over(
            &mut multi_fetch,
            &multi.our.dk,
            1,
            5,
            cfg,
            &mut StdRng::seed_from_u64(0x3502),
        )
        .expect("multi-page golden scan");
        drop(multi_fetch);
        assert_eq!(
            multi_paths,
            [
                "/v1/compact?from=1&to=5",
                "/v1/compact?from=3&to=5",
                "/v1/compact?from=5&to=5",
                "/v1/block/1/tx/0/full",
                "/v1/block/2/tx/0/full",
                "/v1/block/3/tx/0/full",
                "/v1/block/4/tx/0/full",
                "/v1/block/5/tx/0/full",
            ]
        );

        // A range with no served blocks ends after its one empty compact page.
        let mut empty_paths = Vec::new();
        let mut empty_fetch = |path: &str| {
            empty_paths.push(path.to_string());
            crate::server::route(&single, path).map_err(|(c, m)| format!("{c} {m}"))
        };
        scan_over(
            &mut empty_fetch,
            &single.our.dk,
            9,
            9,
            cfg,
            &mut StdRng::seed_from_u64(0x3503),
        )
        .expect("empty-range golden scan");
        drop(empty_fetch);
        assert_eq!(empty_paths, ["/v1/compact?from=9&to=9"]);

        // A transport failure on the second compact page is fatal at exactly
        // that request; no opening request is issued from the partial range.
        let mut failure_paths = Vec::new();
        let mut failure_fetch = |path: &str| {
            failure_paths.push(path.to_string());
            if path == "/v1/compact?from=3&to=5" {
                return Err("golden mid-range failure".to_string());
            }
            let bytes =
                crate::server::route(&multi, path).map_err(|(c, m)| format!("{c} {m}"))?;
            let blocks = decode_compact_response(&bytes).expect("route serves compact wire");
            Ok(crate::codec::encode_compact_response(
                &blocks.into_iter().take(2).collect::<Vec<_>>(),
            ))
        };
        let err = match scan_over(
            &mut failure_fetch,
            &multi.our.dk,
            1,
            5,
            cfg,
            &mut StdRng::seed_from_u64(0x3504),
        ) {
            Err(err) => err,
            Ok(_) => panic!("mid-range compact failure remains fatal"),
        };
        drop(failure_fetch);
        assert_eq!(err, "golden mid-range failure");
        assert_eq!(
            failure_paths,
            ["/v1/compact?from=1&to=5", "/v1/compact?from=3&to=5"]
        );
    }

    fn need_from(driver: &mut ScanDriver, rng: &mut StdRng, expected: &str) -> String {
        match driver.step(rng) {
            ScanDriverStep::Need(path) => {
                assert_eq!(path, expected);
                path
            }
            ScanDriverStep::Done(_) => panic!("expected Need({expected}), got Done"),
            ScanDriverStep::Failed(err) => panic!("expected Need({expected}), got Failed({err})"),
        }
    }

    /// The driver can retain an outstanding request across an await-shaped
    /// boundary. Every step and supply below is a separate invocation; there is
    /// intentionally no pump loop in this test.
    #[test]
    fn scan_driver_pages_can_be_supplied_across_separate_suspensions() {
        fn suspend(path: String) -> String {
            path
        }

        let wallet = Wallet::from_seed_lanes([0x350, 2, 1, 1]);
        let diversifier = Diversifier::default();
        let ours = wallet.diversified_keypair(&diversifier);
        let stranger = generate_keypair(&mut StdRng::seed_from_u64(0x3505));
        let stranger_note =
            Note { value: 1, rkm: [1; 4], rho: [1; 4], rseed: [1; 4] };
        let our_note = Note {
            value: 350,
            rkm: wallet.rkm(diversifier),
            rho: [2; 4],
            rseed: [3; 4],
        };
        let devnet = chain_paying(
            generate_keypair(&mut StdRng::seed_from_u64(0x3506)),
            &[
                vec![vec![(&stranger.ek, vec![stranger_note])]],
                vec![vec![(&ours.ek, vec![our_note.clone()])]],
            ],
        );
        let cfg =
            ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::PerMatch { max: 1 } };
        let mut driver = ScanDriver::new(ours.dk.clone(), 1, 2, cfg);
        let mut rng = StdRng::seed_from_u64(0x3507);

        let first = suspend(need_from(
            &mut driver,
            &mut rng,
            "/v1/compact?from=1&to=2",
        ));
        let first_bytes = crate::server::route(&devnet, &first)
            .map_err(|(c, m)| format!("{c} {m}"))
            .expect("first compact response");
        let first_page = decode_compact_response(&first_bytes).expect("compact wire");
        driver.supply(Ok(crate::codec::encode_compact_response(&first_page[..1])));

        let second = suspend(need_from(
            &mut driver,
            &mut rng,
            "/v1/compact?from=2&to=2",
        ));
        driver.supply(
            crate::server::route(&devnet, &second).map_err(|(c, m)| format!("{c} {m}")),
        );

        let full = suspend(need_from(
            &mut driver,
            &mut rng,
            "/v1/block/2/tx/0/full",
        ));
        driver.supply(crate::server::route(&devnet, &full).map_err(|(c, m)| format!("{c} {m}")));

        // The RNG is caller-owned and used again after all three suspensions.
        // With max=1 the driver issues exactly one randomized decoy request.
        let decoy = suspend(match driver.step(&mut rng) {
            ScanDriverStep::Need(path) => path,
            ScanDriverStep::Done(_) => panic!("the post-suspension decoy was skipped"),
            ScanDriverStep::Failed(err) => panic!("post-suspension RNG step failed: {err}"),
        });
        assert!(
            ["/v1/block/1/tx/0/full", "/v1/block/2/tx/0/full"].contains(&decoy.as_str()),
            "decoy stays inside the two-transaction scan space: {decoy}"
        );
        driver.supply(Err("discarded decoy failure".to_string()));

        let outcome = match driver.step(&mut rng) {
            ScanDriverStep::Done(outcome) => outcome,
            ScanDriverStep::Need(path) => panic!("unexpected extra request: {path}"),
            ScanDriverStep::Failed(err) => panic!("suspended scan failed: {err}"),
        };
        assert_eq!(outcome.notes.len(), 1);
        assert_eq!(outcome.notes[0].height, 2);
        assert_eq!(outcome.notes[0].detected.note, our_note);
    }

    /// Paging's progress refusal belongs to the driver itself, so a caller
    /// cannot pump the same compact page forever and obtain `Complete`/zero.
    #[test]
    fn scan_driver_rejects_a_compact_page_that_does_not_advance() {
        let devnet = Devnet::generate(GenParams {
            n_blocks: 2,
            txs_per_block: 1,
            ..GenParams::default()
        });
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let mut driver = ScanDriver::new(devnet.our.dk.clone(), 1, 2, cfg);
        let mut rng = StdRng::seed_from_u64(0x3508);

        need_from(&mut driver, &mut rng, "/v1/compact?from=1&to=2");
        let stuck = crate::server::route(&devnet, "/v1/compact?from=1&to=1")
            .map_err(|(c, m)| format!("{c} {m}"));
        driver.supply(stuck.clone());

        need_from(&mut driver, &mut rng, "/v1/compact?from=2&to=2");
        driver.supply(stuck);

        match driver.step(&mut rng) {
            ScanDriverStep::Failed(err) => {
                assert!(err.contains("below the requested range"), "{err}");
                assert!(err.contains("asked from=2"), "{err}");
            }
            ScanDriverStep::Need(path) => panic!("stuck page requested again: {path}"),
            ScanDriverStep::Done(_) => panic!("stuck page must not complete the scan"),
        }
    }

    /// A fetch over `devnet` whose `/v1/compact` answers are bounded the way a
    /// deployed node's are (`qlab_node::rpc::MAX_COMPACT_BLOCKS`, shrunk here to
    /// `page_blocks`): every main-chain height in the asked range, ascending, up
    /// to that many blocks. `/full` passes through untouched, so the ONLY
    /// variable is the paging. `asked` records each compact URL, so a test can
    /// assert the client actually walked the range.
    fn paged_fetch<'a>(
        devnet: &'a Devnet,
        page_blocks: usize,
        asked: &'a std::cell::RefCell<Vec<String>>,
    ) -> impl FnMut(&str) -> Result<Vec<u8>, String> + 'a {
        move |path: &str| {
            let bytes =
                crate::server::route(devnet, path).map_err(|(c, m)| format!("{c} {m}"))?;
            if path.starts_with("/v1/compact") {
                asked.borrow_mut().push(path.to_string());
                let blocks = decode_compact_response(&bytes).expect("route serves the wire");
                let page: Vec<_> = blocks.into_iter().take(page_blocks).collect();
                return Ok(crate::codec::encode_compact_response(&page));
            }
            Ok(bytes)
        }
    }

    /// 🔴 **Lab issue #309.** The first live grant (block 5417) was invisible to
    /// its recipient: a deployed node bounds one `/v1/compact` response at
    /// `MAX_COMPACT_BLOCKS` (1,024 blocks), and this client fetched ONCE and
    /// treated the first page as the whole range — so a wallet scanning
    /// `0..=5425` trial-decapsulated heights 0..=1023 only, found nothing, and
    /// reported `Complete`/`spendable: 0` about a range it never read. Here the
    /// chain is five blocks, the page is two, and the note is in the LAST
    /// block: the single-fetch flow sees blocks [1,2] only and returns the
    /// exact live symptom; the paging flow finds the note.
    #[test]
    fn a_note_beyond_the_first_compact_page_is_found_not_reported_complete_zero() {
        let wallet = Wallet::from_seed_lanes([0x309, 1, 1, 1]);
        let d = Diversifier::default();
        let kp = wallet.diversified_keypair(&d);
        let grant =
            Note { value: 1_000_000_000, rkm: wallet.rkm(d), rho: [0x309; 4], rseed: [0x0A; 4] };

        // Blocks 1–4 pay a stranger; block 5 pays us.
        let stranger = generate_keypair(&mut StdRng::seed_from_u64(0x5417));
        let noise = |v: u64| Note { value: v, rkm: [v; 4], rho: [v; 4], rseed: [v; 4] };
        let devnet = chain_paying(
            generate_keypair(&mut StdRng::seed_from_u64(0xF00D)),
            &[
                vec![vec![(&stranger.ek, vec![noise(1)])]],
                vec![vec![(&stranger.ek, vec![noise(2)])]],
                vec![vec![(&stranger.ek, vec![noise(3)])]],
                vec![vec![(&stranger.ek, vec![noise(4)])]],
                vec![vec![(&kp.ek, vec![grant.clone()])]],
            ],
        );
        let asked = std::cell::RefCell::new(Vec::new());
        let mut fetch = paged_fetch(&devnet, 2, &asked);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out = scan_over(&mut fetch, &kp.dk, 1, 5, cfg, &mut StdRng::seed_from_u64(0x309))
            .expect("scan runs");

        // The client walked the whole range, one page at a time, resuming from
        // the last served height + 1 exactly as the serving contract says…
        assert_eq!(
            *asked.borrow(),
            vec![
                "/v1/compact?from=1&to=5".to_string(),
                "/v1/compact?from=3&to=5".to_string(),
                "/v1/compact?from=5&to=5".to_string(),
            ],
            "pages resume from the last served height + 1"
        );
        // …and the note in the last block is real money, not `Complete`/0.
        assert_eq!(out.stats.detected_outputs, 1, "the grant is detected");
        assert_eq!(out.notes.len(), 1);
        assert_eq!(out.notes[0].detected.note, grant);
        assert_eq!(out.notes[0].height, 5, "at its real chain coordinate");
        assert_eq!(out.completeness(), Completeness::Complete);
        assert_partitions(&out);
    }

    /// A server that is simply BEHIND the asked `to` ends the walk with one
    /// empty page — the honest "I hold nothing further", the same shape the
    /// leaf stream answers past its end — and the scan completes over what
    /// exists rather than erroring or looping.
    #[test]
    fn a_server_behind_the_asked_range_ends_the_walk_cleanly() {
        let d = Devnet::generate(GenParams::default());
        let tip = d.tip_height();
        let asked = std::cell::RefCell::new(Vec::new());
        let mut fetch = paged_fetch(&d, usize::MAX, &asked);
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let out =
            scan_over(&mut fetch, &d.our.dk, 1, tip + 100, cfg, &mut StdRng::seed_from_u64(0x3092))
                .expect("a chain shorter than the asked range is not an error");
        assert_eq!(out.notes.len(), d.expected_matches, "everything that exists is found");
        assert_eq!(
            asked.borrow().len(),
            2,
            "one full page, then the empty page that ends the walk"
        );
    }

    /// A page that answers BELOW the requested offset would re-scan heights
    /// already in hand (and double-count anything in them), so it is refused by
    /// name — the same misattribution discipline as the leaf stream's `from`
    /// echo. The refusal is also the progress guard: a server that always
    /// answers the same page cannot loop this client forever.
    #[test]
    fn a_page_answering_below_the_asked_offset_is_refused_not_rescanned() {
        let d = Devnet::generate(GenParams::default());
        let mut calls = 0usize;
        let mut fetch = |path: &str| -> Result<Vec<u8>, String> {
            assert!(path.starts_with("/v1/compact"), "refused before any /full fetch");
            calls += 1;
            // Always the first block, whatever was asked: a stuck or lying server.
            crate::server::route(&d, "/v1/compact?from=1&to=1")
                .map_err(|(c, m)| format!("{c} {m}"))
        };
        let cfg = ScanConfig { mode: ScanMode::FullFo, decoy: DecoyPolicy::Off };
        let err = match scan_over(
            &mut fetch,
            &d.our.dk,
            1,
            d.tip_height(),
            cfg,
            &mut StdRng::seed_from_u64(3),
        ) {
            Err(e) => e,
            Ok(_) => panic!("a stuck page must be refused, not scanned"),
        };
        assert!(err.contains("below the requested range"), "{err}");
        assert_eq!(calls, 2, "the first page is fine; the repeat is the refusal");
    }
}

// Re-export SeedableRng for the tests' StdRng::seed_from_u64 usage.
#[cfg(test)]
use rand::SeedableRng;
