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

use qlab_devnet::body::{check_scheduled_coinbase_payees, CoinbasePayee, COINBASE_PAYEE_CAP_V5};
use qlab_devnet::emission_exact::coinbase_exact;
use qlab_devnet::forms::GenesisForm;

use crate::hexutil;
use crate::pplns::PplnsWindow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssembledCoinbase {
    V5 { payees: Vec<CoinbasePayee> },
    V4 { rkm: [u64; 4], amount: u64 },
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
