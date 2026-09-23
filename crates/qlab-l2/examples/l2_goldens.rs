//! Print the literals `qlab-l2` pins (lab #704 Q5): the two shape digests, the
//! two fixture PV vectors, and the golden note block's commitment. **No
//! proving** — instance builders (host Keccak) and Plonky3's symbolic
//! evaluation only; seconds, well under 1 GB.
//!
//! ```text
//! cargo run --release -p qlab-l2 --example l2_goldens
//! ```

use qlab_l2::{digest, fixture, Shape};

fn main() {
    for shape in [Shape::S, Shape::P] {
        let c1 = digest::constants_digest(shape);
        let (k1, n1) = digest::constraints_digest(shape);
        let (k2, n2) = digest::constraints_digest(shape);
        let d1 = digest::shape_digest(shape);
        let d2 = digest::shape_digest(shape);
        println!("{shape:?}: width {} perms {} log_height {} pv_len {}", shape.width(), shape.perms(), shape.log_height(), shape.pv_len());
        println!("{shape:?}: constants_digest   {}", digest::hex(&c1));
        println!("{shape:?}: constraints_digest {} ({n1} constraints)", digest::hex(&k1));
        println!("{shape:?}: constraints deterministic in-process: {}", k1 == k2 && n1 == n2);
        println!("{shape:?}: shape_digest       {}", digest::hex(&d1));
        println!("{shape:?}: shape_digest deterministic in-process: {}", d1 == d2);
    }
    let pv_s = fixture::shape_s().pvs;
    let pv_p = fixture::shape_p().pvs;
    println!("const GOLDEN_PV_S: [u32; {}] = {:?};", pv_s.len(), pv_s);
    println!("const GOLDEN_PV_P: [u32; {}] = {:?};", pv_p.len(), pv_p);
    let f = |b: u64| -> [u64; 4] { core::array::from_fn(|i| b + i as u64) };
    let cm = qlab_air::l2::l2_cm(
        0x0102_0304_0506_0708,
        7,
        &f(0x1111_1111_1111_1101),
        &f(0x2222_2222_2222_2201),
        &f(0x3333_3333_3333_3301),
    );
    println!("golden note cm: [{:#018x}, {:#018x}, {:#018x}, {:#018x}]", cm[0], cm[1], cm[2], cm[3]);
}
