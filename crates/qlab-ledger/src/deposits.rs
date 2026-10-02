//! **Pending deposits, and notes this wallet can open but never spend** (lab
//! #831 W3, ruling Q2).
//!
//! A deposit to an L2 is an ordinary L1 transaction paying `rkm_burn(l2_id)`
//! (l2-architecture §4.1), and the CLI seals its output **to the depositor's
//! own ek** so the deposit can be recovered from chain data. That makes the
//! wallet's own scan detect and open it — and the light-client scan checks no
//! `rkm` (it holds only a `dk`), so the burn would land in
//! [`ScanOutcome::notes`]: summed into the L1 balance, and picked by a send
//! whose witness lookup then refuses (`NotInTree`: the wallet rebuilds the
//! commitment under its own `rkm`, which is not the note's).
//!
//! So every caller that sums or spends a scan runs [`set_aside`] first: a note
//! whose `rkm` is not the address's leaves `notes` and is named instead —
//!
//! - **a pending deposit** when its `rkm` is `rkm_burn(l2_id)` for one of the
//!   `l2_ids` the caller knows: claimable on that L2, neither L1 nor L2
//!   balance until claimed, never counted twice;
//! - **foreign** otherwise: a note someone sealed to this key under another
//!   key's `rkm`. It opens; it is nobody's money this wallet can move.
//!
//! The scan's partition (`detected == notes + shadowed + unopened`) is kept by
//! moving the counts with the notes: what is set aside is accounted, not
//! unread, so a scan's completeness verdict does not change.

use qlab_cbserver::client::{LocatedNote, ScanOutcome};
use qlab_note::note::Note;
use qlab_wallet::Wallet;

/// What a node's `GET /v1/l2` says (lab #831 W3a-0): the L2 its chain
/// bridges, or that it bridges none. The wallet takes the `l2_id` from here —
/// the chain's own word — never from a constant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum L2Answer {
    Bridged(L2Route),
    NotBridged { why: String },
}

/// A V6 node's answer: the one `l2_id` its wrapper rule enforces, and the
/// identity it is served under. A burn gate keys on `l2_id` + `genesis`
/// only; `revision` moves with every release (and is `None` on a build that
/// carries none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2Route {
    pub l2_id: u64,
    /// The genesis claim tariff a claim's `PV_FEE` must equal (ruling Q-B2).
    pub claim_fee_tier: u64,
    pub wrapper_params: [u8; 32],
    pub revision: Option<[u8; 32]>,
    pub genesis: [u8; 32],
}

impl L2Answer {
    /// The L2 ids a scan may name deposits to: the bridged one, or none.
    pub fn l2_ids(&self) -> Vec<u64> {
        match self {
            L2Answer::Bridged(r) => vec![r.l2_id],
            L2Answer::NotBridged { .. } => Vec::new(),
        }
    }
}

/// The only `/v1/l2` version this build reads.
pub const L2_ROUTE_VERSION: u32 = 1;

/// Read a `/v1/l2` body — **exactly** the node's canonical layout
/// (`qumbra_node::discovery_server::l2_route_body` / `L2_NOT_V6`), field by
/// field in order; anything else, an unknown `v` included, is refused by name.
/// Strict on purpose: this answer gates an irreversible burn, and the node is
/// its only producer, so a reader that tolerated variation would only be
/// tolerating a different producer.
pub fn parse_l2_route(body: &[u8]) -> Result<L2Answer, String> {
    let s = std::str::from_utf8(body).map_err(|_| "/v1/l2: not UTF-8".to_string())?;
    let rest = s.strip_prefix(r#"{"v":"#).ok_or("/v1/l2: not a /v1/l2 answer")?;
    let (v, rest) = rest.split_once(',').ok_or("/v1/l2: truncated after v")?;
    if v != L2_ROUTE_VERSION.to_string() {
        return Err(format!("/v1/l2 answered version {v}; this wallet reads only version {L2_ROUTE_VERSION}"));
    }
    if let Some(rest) = rest.strip_prefix(r#""available":false,"why":""#) {
        let why = rest.strip_suffix(r#""}"#).filter(|w| !w.contains('"')).ok_or("/v1/l2: a malformed \"no\"")?;
        return Ok(L2Answer::NotBridged { why: why.to_string() });
    }
    let rest = rest.strip_prefix(r#""available":true,"l2_id":"#).ok_or("/v1/l2: neither a bridged nor a not-bridged answer")?;
    let decimal = |field: &str, s: &str| -> Result<u64, String> {
        if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
            return Err(format!("/v1/l2: {field} {s:?} is not a canonical decimal"));
        }
        s.parse().map_err(|_| format!("/v1/l2: {field} {s} does not fit a u64"))
    };
    let (id, rest) = rest.split_once(',').ok_or("/v1/l2: truncated after l2_id")?;
    let l2_id = decimal("l2_id", id)?;
    // A body without the tier (a node from before lab #831 W3a) is refused
    // here by name: a claim cannot be built without it.
    let rest = rest.strip_prefix(r#""claim_fee_tier":"#).ok_or("/v1/l2: claim_fee_tier missing (a node older than this wallet)")?;
    let (tier, rest) = rest.split_once(',').ok_or("/v1/l2: truncated after claim_fee_tier")?;
    let claim_fee_tier = decimal("claim_fee_tier", tier)?;
    let hex32 = |field: &str, rest: &str| -> Result<([u8; 32], usize), String> {
        let h = rest.get(..64).ok_or(format!("/v1/l2: {field} is not 64 hex digits"))?;
        // Byte pairs below index by byte: a multi-byte character inside the
        // window would split mid-character, so refuse it by name first — this
        // reader gates a burn and must never panic on a node's body.
        if !h.is_ascii() {
            return Err(format!("/v1/l2: {field} is not lower-case hex"));
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            let pair = &h[2 * i..2 * i + 2];
            if !pair.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                return Err(format!("/v1/l2: {field} is not lower-case hex"));
            }
            *b = u8::from_str_radix(pair, 16).expect("checked hex");
        }
        Ok((out, 64))
    };
    let rest = rest.strip_prefix(r#""wrapper_params":""#).ok_or("/v1/l2: wrapper_params missing")?;
    let (wrapper_params, n) = hex32("wrapper_params", rest)?;
    let rest = rest[n..].strip_prefix(r#"","revision":"#).ok_or("/v1/l2: revision missing")?;
    let (revision, rest) = match rest.strip_prefix("null") {
        Some(rest) => (None, rest),
        None => {
            let r = rest.strip_prefix('"').ok_or("/v1/l2: revision is neither null nor a string")?;
            let (h, n) = hex32("revision", r)?;
            (Some(h), r[n..].strip_prefix('"').ok_or("/v1/l2: revision unterminated")?)
        }
    };
    let rest = rest.strip_prefix(r#","genesis":""#).ok_or("/v1/l2: genesis missing")?;
    let (genesis, n) = hex32("genesis", rest)?;
    if &rest[n..] != r#""}"# {
        return Err("/v1/l2: bytes after genesis".into());
    }
    Ok(L2Answer::Bridged(L2Route { l2_id, claim_fee_tier, wrapper_params, revision, genesis }))
}

/// Why a note left the spendable list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetAsideKind {
    /// Paid to `rkm_burn(l2_id)` and sealed to this key: claimable on L2.
    PendingDeposit { l2_id: u64 },
    /// Paid to an `rkm` that is neither this address's nor a known burn.
    Foreign,
}

/// A note set aside, with where it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetAside {
    pub kind: SetAsideKind,
    pub div_index: u64,
    pub height: u64,
    pub tx_index: u64,
    /// The committed commitment (from the served stream).
    pub cm: [u8; 32],
    /// The opening — what a claim proves knowledge of.
    pub note: Note,
}

/// The burn address of `l2_id` as the note's `rkm` lanes.
pub fn burn_rkm(l2_id: u64) -> [u64; 4] {
    qlab_air::claim::rkm_burn(l2_id)
}

/// Which known L2 `rkm` burns to, if any.
pub fn burn_l2_id(rkm: &[u64; 4], l2_ids: &[u64]) -> Option<u64> {
    l2_ids.iter().copied().find(|id| burn_rkm(*id) == *rkm)
}

/// **Set aside every note in `outcome.notes` whose `rkm` is not address
/// `div_index`'s**, returning them classified; the scan's counts move with
/// them. Shadowed notes are left where they are: they are in no figure
/// already.
pub fn set_aside(wallet: &Wallet, div_index: u64, outcome: &mut ScanOutcome<Note>, l2_ids: &[u64]) -> Vec<SetAside> {
    set_aside_for(wallet.rkm(wallet.diversifier_at_index(div_index)), div_index, outcome, l2_ids)
}

/// [`set_aside`] given the address's own `rkm` — for a caller that holds the
/// address's keys but not the wallet (the FFI's pumped scan).
pub fn set_aside_for(own: [u64; 4], div_index: u64, outcome: &mut ScanOutcome<Note>, l2_ids: &[u64]) -> Vec<SetAside> {
    let (keep, out): (Vec<LocatedNote<Note>>, Vec<LocatedNote<Note>>) =
        std::mem::take(&mut outcome.notes).into_iter().partition(|n| n.detected.note.rkm == own);
    outcome.notes = keep;
    outcome.stats.notes_found -= out.len();
    outcome.stats.detected_outputs -= out.len();
    out.into_iter()
        .map(|n| SetAside {
            kind: match burn_l2_id(&n.detected.note.rkm, l2_ids) {
                Some(l2_id) => SetAsideKind::PendingDeposit { l2_id },
                None => SetAsideKind::Foreign,
            },
            div_index,
            height: n.height,
            tx_index: n.tx_index,
            cm: n.cm,
            note: n.detected.note,
        })
        .collect()
}

/// The lines a scan prints for what it set aside — never a figure in the
/// balance, always stated beside it.
pub fn render(set: &[SetAside]) -> String {
    let mut out = String::new();
    for s in set {
        match s.kind {
            SetAsideKind::PendingDeposit { l2_id } => out.push_str(&format!(
                "pending deposit: {} bessel to L2 {l2_id} at height {} (tx {}, address [{}]) — burned on L1, \
                 claimable on L2; in neither balance until claimed\n",
                s.note.value, s.height, s.tx_index, s.div_index
            )),
            SetAsideKind::Foreign => out.push_str(&format!(
                "set aside: a note of {} bessel at height {} (tx {}, address [{}]) opens under this key but is \
                 paid to another rkm — this wallet cannot spend it, and it is in no figure\n",
                s.note.value, s.height, s.tx_index, s.div_index
            )),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_cbserver::client::ScanStats;
    use qlab_note::scan::Detected;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};

    fn located(rkm: [u64; 4], value: u64, k: u64) -> LocatedNote<Note> {
        LocatedNote {
            height: 10 + k,
            tx_index: 0,
            recipient_index: 0,
            cm: [k as u8; 32],
            detected: Detected { index: 0, note: Note { value, rkm, rho: [k; 4], rseed: [k + 1; 4] } },
        }
    }

    /// 🔴 Q2's scan half: a self-sealed burn and a foreign-rkm note leave the
    /// spendable list (so neither the balance nor a send can pick them), the
    /// burn is named a pending deposit of its L2, and the scan's partition and
    /// verdict are unchanged.
    #[test]
    fn a_self_sealed_burn_is_a_pending_deposit_and_never_spendable() {
        let w = Wallet::from_master_seed(&MasterSeed::from_entropy([4u8; ENTROPY_LEN]), 0);
        let own = w.rkm(w.diversifier_at_index(0));
        let notes = vec![located(own, 700, 1), located(burn_rkm(1), 500, 2), located(burn_rkm(9), 40, 3), located([7; 4], 3, 4)];
        let stats = ScanStats { detected_outputs: 4, notes_found: 4, ..Default::default() };
        let mut outcome = ScanOutcome { notes, unopened: Vec::new(), shadowed: Vec::new(), stats };
        let before = outcome.completeness();

        let set = set_aside(&w, 0, &mut outcome, &[1]);

        assert_eq!(outcome.notes.len(), 1);
        assert_eq!(outcome.spendable_value(), 700, "only this address's own note is a balance");
        assert_eq!(
            set.iter().map(|s| (s.kind, s.note.value)).collect::<Vec<_>>(),
            vec![(SetAsideKind::PendingDeposit { l2_id: 1 }, 500), (SetAsideKind::Foreign, 40), (SetAsideKind::Foreign, 3)],
            "a burn to an L2 the node does not name is still never counted"
        );
        assert_eq!((outcome.stats.detected_outputs, outcome.stats.notes_found), (1, 1), "the partition holds");
        assert_eq!(outcome.completeness(), before, "set aside is accounted, not unread");
        let text = render(&set);
        assert!(text.contains("pending deposit: 500 bessel to L2 1"), "{text}");
        assert!(text.contains("in no figure"), "{text}");
    }

    /// The `/v1/l2` reader takes exactly the node's two canonical answers
    /// and refuses everything else by name — an unknown version included.
    #[test]
    fn the_l2_route_reader_takes_exactly_the_canonical_answers() {
        let h = |c: char| c.to_string().repeat(64);
        let yes = format!(
            r#"{{"v":1,"available":true,"l2_id":1,"claim_fee_tier":4,"wrapper_params":"{}","revision":"{}","genesis":"{}"}}"#,
            h('c'),
            h('7'),
            h('4')
        );
        let route = L2Route { l2_id: 1, claim_fee_tier: 4, wrapper_params: [0xcc; 32], revision: Some([0x77; 32]), genesis: [0x44; 32] };
        assert_eq!(parse_l2_route(yes.as_bytes()), Ok(L2Answer::Bridged(route.clone())));
        let null_rev = yes.replace(&format!(r#""{}","genesis""#, h('7')), r#"null,"genesis""#);
        assert_eq!(parse_l2_route(null_rev.as_bytes()), Ok(L2Answer::Bridged(L2Route { revision: None, ..route })));
        let no = br#"{"v":1,"available":false,"why":"not a V6 net"}"#;
        assert_eq!(parse_l2_route(no), Ok(L2Answer::NotBridged { why: "not a V6 net".into() }));
        assert_eq!(parse_l2_route(no).unwrap().l2_ids(), Vec::<u64>::new());
        for bad in [
            yes.replacen(r#""v":1"#, r#""v":2"#, 1),
            yes.replacen("l2_id\":1", "l2_id\":01", 1),
            yes.replacen("\"claim_fee_tier\":4,", "", 1),
            yes.replacen("claim_fee_tier\":4", "claim_fee_tier\":-4", 1),
            yes.replacen(&h('c'), &h('C'), 1),
            // A multi-byte character straddling a hex pair: refused, not a panic.
            yes.replacen(&h('c'), &format!("a\u{e9}{}", "c".repeat(61)), 1),
            format!("{yes} "),
            yes.replacen(r#""available":true,"#, "", 1),
            "404 not found".to_string(),
        ] {
            assert!(parse_l2_route(bad.as_bytes()).is_err(), "accepted {bad}");
        }
        assert!(parse_l2_route(br#"{"v":2,"available":false,"why":"x"}"#).unwrap_err().contains("version 2"));
    }
}
