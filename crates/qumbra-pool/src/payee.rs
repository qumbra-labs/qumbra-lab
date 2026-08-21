//! Payee-list assembly, form-keyed.
//!
//! - **V5**: native [`CoinbasePayee`] list, capped at
//!   [`COINBASE_PAYEE_CAP_V5`] (1 at birth). Validated through
//!   [`check_scheduled_coinbase_payees`] — we do not re-derive Σ.
//! - **V4**: N=1 single-payee (`coinbase` + `coinbase_rkm`). Accounting
//!   testability on today's net; **not** stock-xmrig (#356 UNCLEAN).
//!
//! With the birth cap at 1, PPLNS cannot yet split the mint. The
//! highest-weight miner in the window (or the pool rkm if the window
//! is empty / the winner has no registered rkm) takes the whole
//! `coinbase_exact(height)`. Raising the cap is a rule change; this
//! assembler already truncates to `cap` so the same function grows.
//!
//! ## 🔴 The payout and refusal path (lab #547 + #553)
//!
//! `coinbase_rkm` lives inside the body preimage that the header commits to,
//! so the payee is fixed *before* the miner grinds. Lab #553 puts this assembler
//! on that path: every live-node poll calls it, sends its list to
//! `GET /v1/mine/template`, and stores the returned committed body in the job
//! that is later submitted.
//!
//! [`check_payee`] remains the negative backstop. It defines the
//! set of payees the pool is willing to let reach the chain at all — the
//! configured `payout_rkm`, or an rkm owned by a login we know. Everything
//! else is refused **by name**, including the node's
//! [`UNCONFIGURED_NODE_RKM`] placeholder, which is what three T2 blocks
//! (607, 610, 611) were paid to and which nobody can spend.

use qlab_devnet::body::{check_scheduled_coinbase_payees, CoinbasePayee, COINBASE_PAYEE_CAP_V5};
use qlab_devnet::emission_exact::coinbase_exact;
use qlab_devnet::forms::GenesisForm;

use crate::hexutil;
use crate::pplns::PplnsWindow;

/// The node's "nobody told me where to pay" coinbase key, mirrored from
/// `qlab_p2p::adapter::UNCONFIGURED_MINER_RKM`.
///
/// It is **structurally valid and owned by nobody**: a fixed constant, not
/// derived from any `(sk, d)`, so no wallet holds a spend key for it. That
/// combination is exactly what let it travel — an all-zero payee is refused
/// at block validation (`BodyError::MissingCoinbasePayee`), this one is not.
///
/// Declared here rather than imported because this crate does not take
/// `qlab-p2p` (the arrow points the other way; Cargo has no per-target
/// deps). `tests/cross_assert.rs` pins the two values together, so a change
/// on the p2p side breaks a test rather than silently reopening lab #547.
pub const UNCONFIGURED_NODE_RKM: [u64; 4] = [
    0x1101_1101_1101_1101,
    0x1101_1101_1101_1101,
    0x1101_1101_1101_1101,
    0x1101_1101_1101_1101,
];

/// Why the pool refused to let a coinbase payee reach the chain.
///
/// Every variant is a refusal to submit a block the pool could otherwise
/// have submitted. **That trade is deliberate and it is not close**: a
/// refused block costs one block's issuance to whoever would have been
/// paid; a wrong payee burns that issuance permanently, for everyone, and
/// no later fix can undo it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayeeRefusal {
    /// `coinbase > 0` with `rkm == [0; 4]` — the shape a forgotten field or
    /// an un-upgraded assembler produces. Named separately from
    /// [`Self::Unowned`] because it is the one shape every node already
    /// refuses at validation, so seeing it here means we built it ourselves.
    ZeroPayee,
    /// The node's [`UNCONFIGURED_NODE_RKM`] placeholder — a node that was
    /// never told where to pay itself. Named separately because the operator
    /// fix is specific and elsewhere: set `miner_rkm` on the node.
    NodePlaceholder,
    /// A structurally fine rkm that is neither the configured `payout_rkm`
    /// nor owned by any login this pool knows. We cannot say it is
    /// unspendable — only that nobody here can show it is spendable, which
    /// is the whole of the bar.
    Unowned { rkm: [u64; 4] },
}

impl PayeeRefusal {
    /// Stable operator/refusal token, kebab-case like the config and
    /// stratum refusals. Tests assert on these, not on the prose.
    pub fn token(&self) -> &'static str {
        match self {
            PayeeRefusal::ZeroPayee => "all-zero-coinbase-payee",
            PayeeRefusal::NodePlaceholder => "node-placeholder-coinbase-payee",
            PayeeRefusal::Unowned { .. } => "unowned-coinbase-payee",
        }
    }
}

impl std::fmt::Display for PayeeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayeeRefusal::ZeroPayee => write!(
                f,
                "{}: the template mints but names no payee, which no wallet can derive",
                self.token()
            ),
            PayeeRefusal::NodePlaceholder => write!(
                f,
                "{}: the template pays the node's UNCONFIGURED_MINER_RKM placeholder, \
                 which NOBODY can spend — set `miner_rkm` on this pool's node to the \
                 same wallet as the pool's `payout_rkm`",
                self.token()
            ),
            PayeeRefusal::Unowned { rkm } => write!(
                f,
                "{}: {} is neither the configured `payout_rkm` nor an rkm owned by any \
                 login this pool knows",
                self.token(),
                rkm_hex(rkm)
            ),
        }
    }
}

impl std::error::Error for PayeeRefusal {}

/// 64 hex chars, lane-major little-endian — the same encoding
/// `miner_rkm` / `payout_rkm` / the mine-RPC wire use, so a refusal line
/// can be grepped against a config file without re-encoding.
pub fn rkm_hex(rkm: &[u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (i, lane) in rkm.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    hexutil::encode(&bytes)
}

/// Is `rkm` a payee this pool is willing to let reach the chain?
///
/// Accepted: the configured `payout_rkm`, or an rkm that some login in
/// `known_logins` resolves to (a registered account, or a 64-hex login,
/// which *is* an rkm — see [`Accounts::rkm_of`]), or an explicitly
/// registered account's rkm. Refused, by name, in that order of specificity:
/// all-zero, the node placeholder, then anything unowned.
///
/// The placeholder and zero checks come **first**, so a `payout_rkm` that
/// was itself set to one of those shapes is still refused rather than
/// laundered into acceptance by the equality test.
pub fn check_payee<'a, I>(
    rkm: [u64; 4],
    pool_rkm: [u64; 4],
    accounts: &Accounts,
    known_logins: I,
) -> Result<(), PayeeRefusal>
where
    I: IntoIterator<Item = &'a str>,
{
    if rkm == [0u64; 4] {
        return Err(PayeeRefusal::ZeroPayee);
    }
    if rkm == UNCONFIGURED_NODE_RKM {
        return Err(PayeeRefusal::NodePlaceholder);
    }
    if rkm == pool_rkm {
        return Ok(());
    }
    if accounts.owns_rkm(rkm) {
        return Ok(());
    }
    for login in known_logins {
        if accounts.rkm_of(login) == Some(rkm) {
            return Ok(());
        }
    }
    Err(PayeeRefusal::Unowned { rkm })
}

/// [`check_payee`] over a template body.
///
/// An empty list is the non-minting genesis shape. Every requested payee must
/// be owned; checking only the first would become an escape when the cap rises.
pub fn check_body_payee<'a, I>(
    body: &crate::template::TemplateBody,
    pool_rkm: [u64; 4],
    accounts: &Accounts,
    known_logins: I,
) -> Result<(), PayeeRefusal>
where
    I: IntoIterator<Item = &'a str>,
{
    let known: Vec<&str> = known_logins.into_iter().collect();
    for payee in &body.coinbase_payees {
        check_payee(payee.rkm, pool_rkm, accounts, known.iter().copied())?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembledCoinbase {
    V5 { payees: Vec<CoinbasePayee> },
    V4 { rkm: [u64; 4], amount: u64 },
}

impl AssembledCoinbase {
    pub fn payees(&self) -> Vec<CoinbasePayee> {
        match self {
            Self::V5 { payees } => payees.clone(),
            Self::V4 { rkm, amount } => vec![CoinbasePayee { rkm: *rkm, amount: *amount }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembleError {
    Schedule(String),
    ZeroPoolRkm,
}

impl std::fmt::Display for AssembleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssembleError::Schedule(s) => write!(f, "payee schedule: {s}"),
            AssembleError::ZeroPoolRkm => write!(f, "pool_rkm must not be all-zero"),
        }
    }
}

impl std::error::Error for AssembleError {}

/// login → rkm. A 64-hex login is itself an rkm (lane-major LE), matching
/// the node/faucet miner_rkm wire. Unknown logins cannot be coinbase
/// payees; they still score in PPLNS.
#[derive(Clone, Debug, Default)]
pub struct Accounts {
    by_login: std::collections::HashMap<String, [u64; 4]>,
}

impl Accounts {
    pub fn register(&mut self, login: impl Into<String>, rkm: [u64; 4]) {
        self.by_login.insert(login.into(), rkm);
    }

    pub fn rkm_of(&self, login: &str) -> Option<[u64; 4]> {
        if let Some(r) = self.by_login.get(login) {
            return Some(*r);
        }
        hexutil::rkm_lanes_from_hex(login).ok()
    }

    /// Does any registered login own `rkm`? The reverse of
    /// [`Self::rkm_of`], and deliberately *only* over the explicit
    /// registrations — an rkm cannot be reversed into a login, so the
    /// hex-login fallback needs a candidate login to test against and
    /// lives in [`check_payee`]'s `known_logins` instead.
    pub fn owns_rkm(&self, rkm: [u64; 4]) -> bool {
        self.by_login.values().any(|r| *r == rkm)
    }
}

pub fn payee_cap(form: GenesisForm) -> usize {
    match form {
        GenesisForm::V5 => COINBASE_PAYEE_CAP_V5,
        GenesisForm::V4 => 1,
    }
}

/// Assemble the coinbase for `height` under `form`.
pub fn assemble_coinbase(
    form: GenesisForm,
    height: u64,
    window: &PplnsWindow,
    accounts: &Accounts,
    pool_rkm: [u64; 4],
) -> Result<AssembledCoinbase, AssembleError> {
    if pool_rkm == [0u64; 4] {
        return Err(AssembleError::ZeroPoolRkm);
    }
    let amount = if height == 0 {
        0
    } else {
        coinbase_exact(height)
    };
    let cap = payee_cap(form);
    let winner = pick_payees(window, accounts, pool_rkm, cap, amount);
    match form {
        GenesisForm::V5 => {
            check_scheduled_coinbase_payees(height, &winner)
                .map_err(|e| AssembleError::Schedule(format!("{e:?}")))?;
            Ok(AssembledCoinbase::V5 { payees: winner })
        }
        GenesisForm::V4 => {
            let (rkm, amount) = match winner.first() {
                Some(p) => (p.rkm, p.amount),
                None => (pool_rkm, amount),
            };
            Ok(AssembledCoinbase::V4 { rkm, amount })
        }
    }
}

fn pick_payees(
    window: &PplnsWindow,
    accounts: &Accounts,
    pool_rkm: [u64; 4],
    cap: usize,
    amount: u64,
) -> Vec<CoinbasePayee> {
    if amount == 0 {
        return Vec::new();
    }
    let mut scored: Vec<([u64; 4], u128)> = Vec::new();
    for (login, weight) in window.weights() {
        let Some(rkm) = accounts.rkm_of(&login) else {
            continue;
        };
        if rkm == [0u64; 4] {
            continue;
        }
        if let Some(existing) = scored.iter_mut().find(|(r, _)| *r == rkm) {
            existing.1 += weight;
        } else {
            scored.push((rkm, weight));
        }
    }
    scored.sort_by(|a, b| b.1.cmp(&a.1));
    scored.truncate(cap);

    if scored.is_empty() {
        return vec![CoinbasePayee {
            rkm: pool_rkm,
            amount,
        }];
    }
    if scored.len() == 1 || cap == 1 {
        return vec![CoinbasePayee {
            rkm: scored[0].0,
            amount,
        }];
    }
    // Cap > 1 (future rule change): proportional split, last gets remainder.
    let total_w: u128 = scored.iter().map(|(_, w)| *w).sum();
    let mut left = amount;
    let last = scored.len() - 1;
    let mut out = Vec::with_capacity(scored.len());
    for (i, (rkm, w)) in scored.into_iter().enumerate() {
        let share = if i == last {
            left
        } else {
            let s = ((amount as u128) * w / total_w) as u64;
            left = left.saturating_sub(s);
            s
        };
        out.push(CoinbasePayee { rkm, amount: share });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pplns::WindowShare;

    fn rkm(n: u64) -> [u64; 4] {
        [n, 0, 0, 0]
    }

    fn window(pairs: &[(&str, u64)]) -> PplnsWindow {
        let mut w = PplnsWindow::new(16);
        for (login, d) in pairs {
            w.push(WindowShare {
                login: (*login).into(),
                difficulty: *d,
            });
        }
        w
    }

    #[test]
    fn v5_empty_window_pays_the_pool_and_passes_the_schedule() {
        let mut accounts = Accounts::default();
        accounts.register("alice", rkm(1));
        let assembled = assemble_coinbase(
            GenesisForm::V5,
            1,
            &PplnsWindow::default(),
            &accounts,
            rkm(9),
        )
        .unwrap();
        match assembled {
            AssembledCoinbase::V5 { payees } => {
                assert_eq!(payees.len(), 1);
                assert_eq!(payees[0].rkm, rkm(9));
                assert_eq!(payees[0].amount, coinbase_exact(1));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn v5_birth_cap_is_one_so_the_winner_takes_the_mint() {
        let mut accounts = Accounts::default();
        accounts.register("alice", rkm(1));
        accounts.register("bob", rkm(2));
        let w = window(&[("alice", 10), ("bob", 50), ("alice", 10)]);
        let assembled = assemble_coinbase(GenesisForm::V5, 2, &w, &accounts, rkm(9)).unwrap();
        match assembled {
            AssembledCoinbase::V5 { payees } => {
                assert_eq!(payees.len(), COINBASE_PAYEE_CAP_V5);
                assert_eq!(payees[0].rkm, rkm(2), "bob has more weight");
                assert_eq!(payees[0].amount, coinbase_exact(2));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn v4_is_n1_single_payee_not_a_list() {
        let mut accounts = Accounts::default();
        accounts.register("alice", rkm(1));
        let w = window(&[("alice", 1)]);
        let assembled = assemble_coinbase(GenesisForm::V4, 3, &w, &accounts, rkm(9)).unwrap();
        match assembled {
            AssembledCoinbase::V4 { rkm, amount } => {
                assert_eq!(rkm, [1, 0, 0, 0]);
                assert_eq!(amount, coinbase_exact(3));
            }
            other => panic!("{other:?}"),
        }
    }

    /// The v4 half of the documented fallback. The v5 case above was the
    /// only one asserted before lab #547, and the fallback's own doc line
    /// covers both forms.
    #[test]
    fn v4_empty_window_pays_the_configured_pool_rkm() {
        let assembled = assemble_coinbase(
            GenesisForm::V4,
            5,
            &PplnsWindow::default(),
            &Accounts::default(),
            rkm(9),
        )
        .unwrap();
        assert_eq!(
            assembled,
            AssembledCoinbase::V4 {
                rkm: rkm(9),
                amount: coinbase_exact(5),
            }
        );
    }

    /// 🔴 The value on three T2 blocks. This is the test that ties the
    /// constant in this file to the evidence on the chain: if the hex here
    /// stops matching what the explorer served, one of the two is wrong.
    #[test]
    fn the_node_placeholder_encodes_to_the_hex_seen_on_chain() {
        let hex = rkm_hex(&UNCONFIGURED_NODE_RKM);
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, "0111011101110111".repeat(4));
        assert!(
            hex.starts_with("0111011101110111"),
            "the prefix recorded on lab #547 for heights 607 / 610 / 611"
        );
    }

    #[test]
    fn check_payee_accepts_the_pool_rkm_and_a_registered_miner() {
        let mut accounts = Accounts::default();
        accounts.register("alice", rkm(1));
        assert!(check_payee(rkm(9), rkm(9), &accounts, std::iter::empty()).is_ok());
        assert!(check_payee(rkm(1), rkm(9), &accounts, std::iter::empty()).is_ok());
    }

    /// A 64-hex login *is* an rkm ([`Accounts::rkm_of`]), so a miner that
    /// never called `register` is still an owner — but only when we are
    /// given its login to test against, which is what `known_logins` is for.
    #[test]
    fn check_payee_accepts_a_hex_login_only_when_that_login_is_known() {
        let accounts = Accounts::default();
        let hex = rkm_hex(&rkm(7));
        let mine = rkm(7);
        assert!(check_payee(mine, rkm(9), &accounts, [hex.as_str()]).is_ok());
        assert_eq!(
            check_payee(mine, rkm(9), &accounts, std::iter::empty()),
            Err(PayeeRefusal::Unowned { rkm: mine }),
            "without the login there is nothing to reverse the rkm against"
        );
    }

    /// Item 3 of lab #547: both shapes refused, and refused *by name* —
    /// the tokens are the operator-visible contract, not the prose.
    #[test]
    fn the_zero_and_placeholder_shapes_are_refused_by_name() {
        let accounts = Accounts::default();
        let zero = check_payee([0; 4], rkm(9), &accounts, std::iter::empty()).unwrap_err();
        assert_eq!(zero, PayeeRefusal::ZeroPayee);
        assert_eq!(zero.token(), "all-zero-coinbase-payee");

        let ph =
            check_payee(UNCONFIGURED_NODE_RKM, rkm(9), &accounts, std::iter::empty()).unwrap_err();
        assert_eq!(ph, PayeeRefusal::NodePlaceholder);
        assert_eq!(ph.token(), "node-placeholder-coinbase-payee");
        assert!(
            ph.to_string().contains("miner_rkm"),
            "the refusal must name the operator fix, which is on the node"
        );
    }

    /// The ordering claim: a `payout_rkm` that was itself set to a refused
    /// shape must not launder that shape into acceptance by matching.
    #[test]
    fn a_refused_shape_configured_as_the_pool_rkm_is_still_refused() {
        let accounts = Accounts::default();
        assert_eq!(
            check_payee(
                UNCONFIGURED_NODE_RKM,
                UNCONFIGURED_NODE_RKM,
                &accounts,
                std::iter::empty()
            ),
            Err(PayeeRefusal::NodePlaceholder)
        );
        assert_eq!(
            check_payee([0; 4], [0; 4], &accounts, std::iter::empty()),
            Err(PayeeRefusal::ZeroPayee)
        );
    }

    #[test]
    fn an_unowned_payee_is_refused_and_named_in_hex() {
        let stranger = [0xDEAD_BEEFu64, 2, 3, 4];
        let err = check_payee(stranger, rkm(9), &Accounts::default(), std::iter::empty())
            .expect_err("nobody here owns it");
        assert_eq!(err, PayeeRefusal::Unowned { rkm: stranger });
        assert_eq!(err.token(), "unowned-coinbase-payee");
        assert!(
            err.to_string().contains(&rkm_hex(&stranger)),
            "the refusal must carry the key, in the encoding a config file uses"
        );
    }

    #[test]
    fn a_body_that_mints_nothing_and_names_nobody_passes() {
        let body = crate::template::TemplateBody {
            coinbase_payees: Vec::new(),
            txs: Vec::new(),
        };
        assert!(check_body_payee(&body, rkm(9), &Accounts::default(), std::iter::empty()).is_ok());

        // But minting to nobody is not the same thing.
        let minting = crate::template::TemplateBody {
            coinbase_payees: vec![CoinbasePayee { rkm: [0; 4], amount: 1 }],
            txs: Vec::new(),
        };
        assert_eq!(
            check_body_payee(&minting, rkm(9), &Accounts::default(), std::iter::empty()),
            Err(PayeeRefusal::ZeroPayee)
        );
    }

    #[test]
    fn owns_rkm_is_the_reverse_of_rkm_of() {
        let mut accounts = Accounts::default();
        accounts.register("alice", rkm(1));
        assert!(accounts.owns_rkm(rkm(1)));
        assert!(!accounts.owns_rkm(rkm(2)));
    }

    #[test]
    fn zero_pool_rkm_is_refused() {
        assert!(matches!(
            assemble_coinbase(
                GenesisForm::V5,
                1,
                &PplnsWindow::default(),
                &Accounts::default(),
                [0; 4],
            ),
            Err(AssembleError::ZeroPoolRkm)
        ));
    }
}
