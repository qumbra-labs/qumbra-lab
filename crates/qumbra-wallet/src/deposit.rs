//! **`deposit`** (lab #831 W3a): an L1 → L2 deposit — an ordinary L1
//! transaction paying `rkm_burn(l2_id)` (l2-architecture §4.1), **sealed to
//! this wallet's own key** (ruling Q2: MUST), so the deposit is recoverable
//! from chain data and claimable from this wallet.
//!
//! A burn is irreversible, and on a net without the wrapper rule it is a
//! burn into nothing. So before anything is selected or proved, the gate
//! ([`check_bridge`]) requires the node's own `GET /v1/l2` to answer that
//! this chain bridges an L2, **and** that its `l2_id` and genesis are the two
//! facts the user pinned (`--l2-id`, `--genesis-hash`). Either one wrong, the
//! route absent, or an answer this wallet cannot read: refused by name.
//!
//! The deposit itself rides the ordinary send flow unchanged: its payee is
//! [`burn_address`] — the burn `rkm` with this wallet's own encapsulation key
//! — so the output's discovery payload is sealed to this wallet. Its own scan
//! then sets the note aside as a pending deposit
//! (`qlab_ledger::deposits::set_aside`), never as balance.

use qlab_ledger::deposits::{burn_l2_id, burn_rkm, L2Answer, L2Route};
use qlab_wallet::address::Address;
use qlab_wallet::Wallet;

/// The node's `/v1/l2` answer, read and parsed. A transport failure (a 404
/// from a node that predates the route included) is an `Err` — never read as
/// "not bridged", and never as "bridged".
#[cfg(feature = "net")]
pub fn fetch_l2(url: &str) -> Result<L2Answer, String> {
    let body = crate::net::http_get(url, "/v1/l2").map_err(|e| format!("GET /v1/l2: {e}"))?;
    qlab_ledger::deposits::parse_l2_route(&body)
}

/// **The library's burn rule** (lab #831 W3a, Q2): a payment to the burn of
/// an L2 the node names is a deposit, and a deposit is sealed to this
/// wallet's own key — so a recipient that pays such a burn under any other
/// encapsulation key (a pasted burn address sealed to a stranger) is refused,
/// whichever surface built the send. The CLI's `send` refuses every burn
/// before this; `deposit` builds the one recipient that passes.
pub fn refuse_foreign_burn(wallet: &Wallet, recipient: &Address, l2_ids: &[u64]) -> Result<(), String> {
    match burn_l2_id(&recipient.rkm_lanes(), l2_ids) {
        Some(l2_id) if recipient.ek != wallet.address_at_index(0).ek => Err(format!(
            "the recipient is L2 {l2_id}'s burn address sealed to a key that is not this wallet's: that would burn \
             coins nobody here could claim. A deposit is made with `deposit`, sealed to this wallet"
        )),
        _ => Ok(()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// **The burn gate**: `answer` must say the chain bridges an L2, and its
/// `l2_id` and genesis must be exactly the ones the user pinned. Each
/// mismatch is named — which fact, the pinned value and the served one.
pub fn check_bridge(answer: &L2Answer, l2_id: u64, genesis: &[u8; 32]) -> Result<L2Route, String> {
    match answer {
        L2Answer::NotBridged { why } => Err(format!(
            "this node says its chain bridges no L2 ({why}). A burn here could never be claimed — refusing"
        )),
        L2Answer::Bridged(route) => {
            if route.l2_id != l2_id {
                return Err(format!(
                    "--l2-id {l2_id} does not match: this chain bridges L2 {}. Refusing to burn to an L2 it does not \
                     bridge",
                    route.l2_id
                ));
            }
            if route.genesis != *genesis {
                return Err(format!(
                    "--genesis-hash does not match: the node serves genesis {}, not the pinned {}. Refusing to burn \
                     on a chain other than the one you named",
                    hex(&route.genesis),
                    hex(genesis)
                ));
            }
            Ok(route.clone())
        }
    }
}

/// The payee of a deposit to `l2_id`: the burn `rkm`, with **this wallet's
/// own** address-0 diversifier and encapsulation key — so the output's
/// discovery payload is sealed to this wallet and nobody else (Q2).
pub fn burn_address(wallet: &Wallet, l2_id: u64) -> Address {
    let d = wallet.diversifier_at_index(0);
    let ek = wallet.diversified_keypair(&d).ek;
    Address::new(d, burn_rkm(l2_id), &ek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::seed::{MasterSeed, ENTROPY_LEN};

    fn route(l2_id: u64, genesis: [u8; 32]) -> L2Answer {
        L2Answer::Bridged(L2Route { l2_id, claim_fee_tier: 4, wrapper_params: [1; 32], revision: None, genesis })
    }

    /// Q2 and Q-W3-1: the deposit payee pays the burn and is sealed to this
    /// wallet; the gate passes only when the chain confirms BOTH pinned facts,
    /// and names which one failed otherwise.
    #[test]
    fn a_deposit_is_sealed_to_self_and_gated_on_both_pinned_facts() {
        let w = Wallet::from_master_seed(&MasterSeed::from_entropy([6u8; ENTROPY_LEN]), 0);
        let a = burn_address(&w, 1);
        assert_eq!(a.rkm_lanes(), burn_rkm(1), "pays the burn");
        assert_eq!(a.ek, w.address_at_index(0).ek, "sealed to this wallet's own key");
        assert_ne!(a.rkm_lanes(), w.address_at_index(0).rkm_lanes(), "and is not a payment to self");

        let g = [0x4f; 32];
        assert_eq!(check_bridge(&route(1, g), 1, &g).map(|r| r.l2_id), Ok(1));
        assert!(check_bridge(&route(2, g), 1, &g).unwrap_err().starts_with("--l2-id 1 does not match"));
        assert!(check_bridge(&route(1, [0; 32]), 1, &g).unwrap_err().starts_with("--genesis-hash does not match"));
        let no = L2Answer::NotBridged { why: "not a V6 net".into() };
        assert!(check_bridge(&no, 1, &g).unwrap_err().contains("bridges no L2 (not a V6 net)"));

        // The library rule: the self-sealed deposit payee passes; the same burn
        // sealed to a stranger's key is refused; an ordinary address passes.
        let stranger = Wallet::from_master_seed(&MasterSeed::from_entropy([7u8; ENTROPY_LEN]), 0);
        let foreign = burn_address(&stranger, 1);
        assert_eq!(refuse_foreign_burn(&w, &a, &[1]), Ok(()));
        assert!(refuse_foreign_burn(&w, &foreign, &[1]).unwrap_err().contains("L2 1's burn address sealed to a key"));
        assert_eq!(refuse_foreign_burn(&w, &stranger.address_at_index(0), &[1]), Ok(()));
    }
}
