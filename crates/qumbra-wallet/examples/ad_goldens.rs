//! **The AD1 golden literals** (lab #850, named local run 1): the length and
//! keccak of the two served-chain answers over `qlab_p2p::served::fixture`.
//! A convenience only — `qlab-p2p`'s `golden_headers_page_and_body_answer`
//! recomputes both on the lane, and the lane wins any disagreement.
//!
//! Named run 2 (AD2) prints the TEST asset-list key's fingerprint from its
//! fixed seed — the key the lane signs fixture lists with, never a production
//! key; `tests/asset_view.rs` re-derives and compares it.
//!
//! `cargo run -p qumbra-wallet --example ad_goldens`

fn main() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let page = qlab_p2p::served::fixture::headers_page();
    let body = qlab_p2p::served::fixture::body_answer();
    println!("headers page: {} B keccak {}", page.len(), hex(&qlab_devnet::hash::keccak256(&page)));
    println!("body answer:  {} B keccak {}", body.len(), hex(&qlab_devnet::hash::keccak256(&body)));
    let key = qumbra_wallet::asset_view::test_list_key::verifying();
    println!("TEST list key fingerprint: {}", hex(&key.fingerprint()));
}
