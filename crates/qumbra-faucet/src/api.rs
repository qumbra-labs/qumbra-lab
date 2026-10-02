//! The faucet's JSON view — what its public page reads.
//!
//! The page is a separate, same-origin artifact (Larry, 2026-10-02): a React app in
//! `qumbra-labs/qumbra-faucet-web`, served as static files by svc1's Caddy, which
//! path-routes `/api/*`, `/request`, `/plain*` and `/healthz` here. This process
//! serves no script and holds no copy of the page, so a change to the page never
//! restarts the one host holding a hot key (a restart replays `blocks.log`, #359).
//!
//! Three documents, all derived from values the HTML page already renders, so the
//! two surfaces cannot say different things:
//!
//! * `GET /api/status` — [`status_json`] over the same [`ServiceStatus`] snapshot
//!   `render_index` reads.
//! * `POST /request` with `Accept: application/json` — [`outcome_json`] over the same
//!   [`RequestOutcome`] the form post produces. **The path is `/request` on purpose:**
//!   the access journal records the raw path, and `qumbra-deploy` OPERATOR.md's
//!   proven-grant check greps `FAUCET POST /request`. A JSON post to a new path would
//!   make that check answer "absent" for a faucet serving normally.
//! * `GET /api/r/<n>` — [`receipt_json`] over the same [`RequestState`] the receipt
//!   page renders.
//!
//! **Sentences are the server's.** `availability.explain` and `message` are the exact
//! strings the HTML page prints (`Availability::explain`, `RequestOutcome::message`),
//! so a requester reading the React page and an operator reading the log or the
//! no-JS page read one explanation. The page may add a translated headline per
//! `kind`; it never composes its own reason.
//!
//! Same redaction as everywhere else on this surface: no document carries a
//! recipient address, a ticket or a client address. The fixtures under
//! `fixtures/api/` are these functions' exact output (the tests below assert it);
//! `qumbra-faucet-web` keeps byte-for-byte copies and reads them through its typed
//! decoders, so a renamed or retyped field fails on both sides.

use serde_json::{json, Value};

use crate::http::RequestOutcome;
use crate::service::RequestState;
use crate::state::{Availability, ServiceStatus, Shortage};

/// The wire version of these documents. Bumped when an existing field changes
/// meaning or shape; a pure addition does not bump it (the page ignores fields it
/// does not know).
pub const API_VERSION: u32 = 1;

/// `GET /api/status`.
pub fn status_json(s: &ServiceStatus, address_placeholder: &str) -> Value {
    json!({
        "version": API_VERSION,
        // `null` until the node has been opened and sampled (lab #365) — the page
        // renders UNAVAILABLE, never a zero.
        "chain": s.chain.map(|c| json!({
            "applied_height": c.state_tip,
            "header_tip": c.fork_choice_tip,
            "behind_by": c.blocks(),
        })),
        "finalized_height": s.finalized_height,
        "peers": s.peers,
        "availability": availability_json(&s.availability),
        "queued": s.queued,
        "queue_capacity": s.queue_capacity,
        "wait_blocks": s.wait_blocks,
        "grant_value_bessel": s.grant_value,
        "tickets_required": s.tickets_required,
        "confirmed": s.confirmed,
        "notes_held": s.notes_held,
        // `null` until a harvest pass has produced it (lab #543).
        "notes_maturing": s.notes_maturing,
        "address_placeholder": address_placeholder,
    })
}

fn availability_json(a: &Availability) -> Value {
    let (kind, detail) = match a {
        Availability::Ready { grants } => ("ready", json!({ "grants": grants })),
        Availability::AwaitingFinality { held, anchored } => {
            ("awaiting_finality", json!({ "held": held, "anchored": anchored }))
        }
        Availability::Maturing { held, maturing, matures_at, tip, shortage } => (
            "maturing",
            json!({
                "held": held,
                "maturing": maturing,
                "matures_at": matures_at,
                "tip": tip,
                "shortage": match shortage {
                    Shortage::NoWitness => json!({ "kind": "no_witness" }),
                    Shortage::Value { need, best_inputs } => {
                        json!({ "kind": "value", "need": need, "best_inputs": best_inputs })
                    }
                },
            }),
        ),
        Availability::Starting { replayed, total } => {
            ("starting", json!({ "replayed": replayed, "total": total }))
        }
        Availability::Unharvested => ("unharvested", json!({})),
        Availability::ColdChain => ("cold_chain", json!({})),
        Availability::Empty { held } => ("empty", json!({ "held": held })),
    };
    json!({
        "kind": kind,
        "admits_requests": a.admits_requests(),
        "blocks_until_servable": a.blocks_until_servable(),
        "explain": a.explain(),
        "detail": detail,
    })
}

/// `POST /request` answered as JSON. The HTTP status is `outcome.status()`, the same
/// as the form post's.
pub fn outcome_json(o: &RequestOutcome) -> Value {
    let mut v = json!({
        "version": API_VERSION,
        "status": o.status(),
        "message": o.message(),
    });
    let extra = match o {
        RequestOutcome::Queued { receipt, position } => {
            json!({ "outcome": "queued", "receipt": receipt, "position": position })
        }
        RequestOutcome::BadAddress => json!({ "outcome": "bad_address" }),
        RequestOutcome::Refused(r) => json!({ "outcome": "refused", "refusal": refusal_kind(r) }),
        RequestOutcome::QueueFull { depth } => json!({ "outcome": "queue_full", "depth": depth }),
        RequestOutcome::Unavailable { retry_after_secs, .. } => {
            json!({ "outcome": "unavailable", "retry_after_secs": retry_after_secs })
        }
    };
    merge(&mut v, extra);
    v
}

fn refusal_kind(r: &qlab_faucet::Refusal) -> &'static str {
    use qlab_faucet::Refusal::*;
    match r {
        TicketMissing => "ticket_missing",
        TicketInvalid => "ticket_invalid",
        TicketSpent => "ticket_spent",
        SubnetThrottled => "subnet_throttled",
        GlobalThrottled => "global_throttled",
    }
}

/// `GET /api/r/<n>`.
pub fn receipt_json(receipt: u64, state: &RequestState) -> Value {
    let mut v = json!({ "version": API_VERSION, "receipt": receipt });
    let extra = match state {
        RequestState::Queued { position } => json!({ "state": "queued", "position": position }),
        // Lab #307: the height is the applied height, named as such.
        RequestState::Granted { txid_hex, value_bessel, submitted_at_tip } => json!({
            "state": "granted",
            "txid": txid_hex,
            "value_bessel": value_bessel,
            "applied_height": submitted_at_tip,
        }),
        RequestState::GaveUp { reason } => json!({ "state": "gave_up", "reason": reason }),
    };
    merge(&mut v, extra);
    v
}

/// `GET /api/r/<n>` for a receipt this process does not know.
pub fn unknown_receipt_json() -> Value {
    json!({
        "version": API_VERSION,
        "state": "unknown",
        "message": "No such receipt. Receipts are per-process: a faucet restart forgets them, \
                    and the grant — if it was made — is on the chain regardless.",
    })
}

fn merge(into: &mut Value, from: Value) {
    if let (Value::Object(a), Value::Object(b)) = (into, from) {
        a.extend(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture under `fixtures/api/`, parsed. `qumbra-faucet-web` holds copies and
    /// reads them through its decoders (`test/wire.test.ts`), so these are the one
    /// statement of the wire both ends are held to.
    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/api")
            .join(format!("{name}.json"));
        serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture exists"))
            .expect("fixture is JSON")
    }

    fn status(availability: Availability) -> ServiceStatus {
        ServiceStatus {
            chain: Some(qlab_node::StateLag::new(200, 205)),
            finalized_height: Some(200),
            peers: 3,
            availability,
            queued: 0,
            queue_capacity: 32,
            wait_blocks: 1,
            grant_value: 1_000_000_000,
            tickets_required: false,
            confirmed: 4,
            refused: 1,
            notes_held: 2,
            notes_maturing: Some(0),
        }
    }

    #[test]
    fn a_ready_status_is_the_fixture() {
        let s = status(Availability::Ready { grants: 2 });
        assert_eq!(status_json(&s, "qaddr1…"), fixture("status-ready"));
    }

    /// Lab #365 / #543 on the wire: what the faucet has not measured is `null`,
    /// never `0`.
    #[test]
    fn a_starting_status_is_the_fixture() {
        let s = ServiceStatus {
            chain: None,
            finalized_height: None,
            peers: 0,
            tickets_required: true,
            confirmed: 0,
            refused: 0,
            notes_held: 0,
            notes_maturing: None,
            ..status(Availability::Starting { replayed: 0, total: 0 })
        };
        assert_eq!(status_json(&s, "qaddr1…"), fixture("status-starting"));
    }

    #[test]
    fn request_outcomes_are_the_fixtures() {
        let queued = RequestOutcome::Queued { receipt: 9, position: 1 };
        assert_eq!(outcome_json(&queued), fixture("outcome-queued"));
        assert_eq!(outcome_json(&RequestOutcome::BadAddress), fixture("outcome-bad-address"));
    }

    #[test]
    fn a_granted_receipt_is_the_fixture() {
        let state = RequestState::Granted {
            txid_hex: "ab".repeat(32),
            value_bessel: 1_000_000_000,
            submitted_at_tip: 200,
        };
        assert_eq!(receipt_json(9, &state), fixture("receipt-granted"));
    }

    /// The sentences are the server's own: the JSON carries exactly what the HTML
    /// page prints, for every availability state and every outcome.
    #[test]
    fn the_sentences_are_the_ones_the_html_page_prints() {
        let states = [
            Availability::Ready { grants: 1 },
            Availability::AwaitingFinality { held: 2, anchored: 0 },
            Availability::Maturing {
                held: 1,
                maturing: 2,
                matures_at: 300,
                tip: 250,
                shortage: Shortage::Value { need: 10, best_inputs: 4 },
            },
            Availability::Starting { replayed: 5, total: 10 },
            Availability::Unharvested,
            Availability::ColdChain,
            Availability::Empty { held: 0 },
        ];
        for a in states {
            let v = status_json(&status(a), "qaddr1…");
            assert_eq!(v["availability"]["explain"], Value::String(a.explain()), "{a:?}");
            assert_eq!(v["availability"]["admits_requests"], Value::Bool(a.admits_requests()));
        }
        let outcomes = [
            RequestOutcome::Refused(qlab_faucet::Refusal::TicketSpent),
            RequestOutcome::QueueFull { depth: 32 },
            RequestOutcome::Unavailable { explain: "x.".into(), retry_after_secs: 75 },
        ];
        for o in outcomes {
            let v = outcome_json(&o);
            assert_eq!(v["message"], Value::String(o.message()));
            assert_eq!(v["status"], Value::from(o.status()));
        }
    }

    /// Nothing a requester submitted comes back out, and nothing names a client.
    #[test]
    fn no_document_carries_an_address_or_a_ticket() {
        let docs = [
            status_json(&status(Availability::Ready { grants: 2 }), "qaddr1…").to_string(),
            outcome_json(&RequestOutcome::Queued { receipt: 1, position: 1 }).to_string(),
        ];
        for d in docs {
            for forbidden in ["\"address\"", "\"ticket\"", "\"client\"", "\"subnet\""] {
                assert!(!d.contains(forbidden), "{forbidden} in {d}");
            }
        }
    }
}
