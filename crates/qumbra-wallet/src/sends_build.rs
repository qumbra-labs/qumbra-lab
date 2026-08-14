//! Building a `SendRecord` from a transaction this wallet just built.
//!
//! Stays in the CLI while the record TYPE lives in `qlab-ledger` (lab #407):
//! this reads `qlab_devnet::body::TxPublic` and `qlab_node`, neither of which
//! cross-compiles to iOS. A free function rather than an inherent method
//! because Rust forbids one crate adding inherent impls to another's type —
//! the construction stays in one place, which is what its own comment insists
//! on and what `tests/e2e_first_spend.rs` asserts byte-for-byte.

use qlab_ledger::sends::SendRecord;

    /// The record for a spend this wallet just built, derived from the
/// transaction's **declared public surface** — the one the wire carries and
/// the node judges.
///
/// This is the whole construction, in one place, because `send` runs it
/// behind a ~3 s / ~12 GB prove and a test that wanted to check it any
/// other way would have to copy it. `tests/e2e_first_spend.rs` calls this
/// function on a REAL proved transaction and asserts the id it derives is
/// byte-for-byte the one `POST /v1/tx` answered with.
pub fn declared_record(
    public: &qlab_devnet::body::TxPublic,
    submitted_at_tip: u64,
    amount: u64,
    recipient_short: String,
) -> SendRecord {
    SendRecord {
        // The same derivation the node runs over the same fields — the
        // statement id, so it is stable whether the transaction is pending
        // or already in a block.
        txid: qlab_node::rpc::tx_id(
            &public.anchor,
            &public.nullifiers,
            &public.commitments,
            public.bucket.logical_actions(),
            public.fee,
        ),
        submitted_at_tip,
        amount,
        fee: public.fee,
        recipient_short,
        nullifiers: public.nullifiers.clone(),
    }
}

#[cfg(test)]
mod tests {
    // Relocated from qlab-ledger with the constructor itself (lab #407): it
    // needs `qlab_devnet::body::TxPublic` and `qlab_node::rpc::tx_id`, and the
    // whole reason the constructor stayed here is that iOS cannot build those.
    use super::*;
    use qlab_ledger::sends::SendLog;
    use std::path::PathBuf;

    // Copied with the test it serves rather than exported from qlab-ledger: a
    // temp-dir helper is not API, and exporting it to share four lines would
    // widen that crate's surface for a test's convenience.
    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("qmb_wallet_sends_{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// `declared` reads the record off the transaction's own public surface —
    /// the fee and the nullifiers are the DECLARED ones rather than anything a
    /// caller passes alongside, and the id is the node's own statement-id
    /// derivation. (`tests/e2e_first_spend.rs` runs this same constructor on a
    /// REAL proved transaction and checks the id against `POST /v1/tx`'s answer;
    /// this is the debug-runnable half of that.)
    #[test]
    fn declared_reads_the_transactions_own_public_surface() {
        use qlab_devnet::body::TxPublic;
        use qlab_devnet::fees::{posted_fee, ArityBucket};

        let public = TxPublic {
            anchor: [0x01; 32],
            nullifiers: vec![[0x02; 32], [0x03; 32]],
            commitments: vec![[0x04; 32], [0x05; 32]],
            bucket: ArityBucket::TwoByTwo,
            fee: posted_fee(ArityBucket::TwoByTwo),
        };
        let r = declared_record(&public, 42, 100_000_000, "qmbs1payee".into());

        assert_eq!(r.fee, posted_fee(ArityBucket::TwoByTwo), "the declared fee, not a guess");
        assert_eq!(r.nullifiers, public.nullifiers, "the join key is what the wire carries");
        assert_eq!(r.submitted_at_tip, 42);
        assert_eq!(r.amount, 100_000_000);
        assert_eq!(
            r.txid,
            qlab_node::rpc::tx_id(
                &public.anchor,
                &public.nullifiers,
                &public.commitments,
                2,
                public.fee
            ),
            "the statement id, by the node's own derivation"
        );
        // It round-trips through the file unchanged — the record `send` writes
        // is the record `history` reads.
        let d = tmp("declared");
        SendLog::append(&d, &r).unwrap();
        assert_eq!(SendLog::load(&d).unwrap().unwrap().records, vec![r]);
    }
}
