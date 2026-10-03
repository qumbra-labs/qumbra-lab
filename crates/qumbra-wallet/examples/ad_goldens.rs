//! **The AD1 golden literals** (lab #850, named local run 1): the length and
//! keccak of the two served-chain answers over `qlab_p2p::served::fixture`.
//! A convenience only — `qlab-p2p`'s `golden_headers_page_and_body_answer`
//! recomputes both on the lane, and the lane wins any disagreement.
//!
//! `cargo run -p qumbra-wallet --example ad_goldens`

fn main() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let page = qlab_p2p::served::fixture::headers_page();
    let body = qlab_p2p::served::fixture::body_answer();
    println!("headers page: {} B keccak {}", page.len(), hex(&qlab_devnet::hash::keccak256(&page)));
    println!("body answer:  {} B keccak {}", body.len(), hex(&qlab_devnet::hash::keccak256(&body)));
}
