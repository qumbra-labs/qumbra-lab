//! `mproof` mode (lab #742, A5 lever 4c stage 0): a Merkle multi-proof codec
//! prototype, measured on REAL hiding proofs — bench-only, nothing on any wire.
//!
//! ```text
//! /usr/bin/time -v qlab-bench mproof --case l1   # the 2×2 bucket at CONSENSUS_CFG
//! /usr/bin/time -v qlab-bench mproof --case s3   # shape S3 at the L2 lane
//! /usr/bin/time -v qlab-bench mproof --case p3   # shape P3 at the L2 lane
//! ```
//!
//! **What it removes.** A FRI proof carries, per query, one Merkle path per
//! committed tree (the random-codeword, trace and quotient batches, then one
//! per commit-phase layer). Paths of different queries through the same tree
//! share every node above the level where they meet, so the siblings above
//! that level are the **same digests, repeated** — once per query. The codec
//! sends each distinct sibling digest once per `(tree, level)` and a one-byte
//! back-reference for every repeat.
//!
//! **What it deliberately does not do.** It never hashes: the sibling a query
//! needs at the meeting level is the *other* query's path node, recoverable
//! only by hashing that path up — a further saving (one digest per meeting)
//! left out so the decoder stays a pure table lookup. It needs no query
//! indices and no transcript replay: dedup is by value inside `(tree, level)`,
//! so the decode reproduces the original bytes exactly whatever the positions.
//! Roots, openings, salts and the Fiat–Shamir transcript are untouched — the
//! verifier sees the same `Proof` it sees today.
//!
//! **Format** (prototype, not a wire): `u32 LE body_len ‖ body ‖ stream`.
//! `body` = the proof with every sibling vector emptied, in the lanes' own
//! proof encoding (bincode fixint, as `qumbra-node`'s `decode_proof_strict`).
//! `stream` = for each path in traversal order: `u8 len`, then per sibling a
//! LEB128 tag — `0` + 32 digest bytes (a new digest), or `k ≥ 1` = the
//! `(k−1)`-th distinct digest already sent at this `(tree, level)`.

use std::collections::HashMap;
use std::time::Instant;

use qlab_consensus::{Config, Proof};

type Digest = [u64; 4];

/// Checks a decoded proof against the case's public values.
type Verify = Box<dyn Fn(&Proof<Config>) -> bool>;

/// Tree identity inside one proof: input batch `b` (random, trace, quotient —
/// the PCS's round order) or commit-phase layer `s`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Tree {
    Input(usize),
    Layer(usize),
}

/// Every sibling path of `proof`, in the one traversal order both directions use.
fn paths_mut(proof: &mut Proof<Config>) -> Vec<(Tree, &mut Vec<Digest>)> {
    let mut out = Vec::new();
    for q in proof.opening_proof.1.query_proofs.iter_mut() {
        for (b, batch) in q.input_proof.iter_mut().enumerate() {
            out.push((Tree::Input(b), &mut batch.opening_proof.1));
        }
        for (s, step) in q.commit_phase_openings.iter_mut().enumerate() {
            out.push((Tree::Layer(s), &mut step.opening_proof.1));
        }
    }
    out
}

fn put_leb(out: &mut Vec<u8>, mut v: usize) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn get_leb(buf: &[u8], at: &mut usize) -> usize {
    let (mut v, mut shift) = (0usize, 0);
    loop {
        let byte = buf[*at];
        *at += 1;
        v |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return v;
        }
        shift += 7;
    }
}

fn bincode_fixint<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("bincode")
}

/// What one encode saw.
#[derive(Default)]
pub(crate) struct Stats {
    pub siblings: usize,
    pub literals: usize,
    pub paths: usize,
}

pub(crate) fn encode(proof: &Proof<Config>) -> (Vec<u8>, Stats) {
    // `Proof<Config>` is not `Clone`; copy it through its own encoding.
    let mut stripped: Proof<Config> = bincode::deserialize(&bincode_fixint(proof)).expect("round-trip");
    let mut stream = Vec::new();
    let mut st = Stats::default();
    let mut tables: HashMap<(Tree, usize), Vec<Digest>> = HashMap::new();
    for (tree, path) in paths_mut(&mut stripped) {
        let len = u8::try_from(path.len()).expect("a Merkle path is shorter than 256");
        stream.push(len);
        st.paths += 1;
        for (level, d) in path.drain(..).enumerate() {
            st.siblings += 1;
            let table = tables.entry((tree, level)).or_default();
            match table.iter().position(|x| *x == d) {
                Some(k) => put_leb(&mut stream, k + 1),
                None => {
                    st.literals += 1;
                    put_leb(&mut stream, 0);
                    for w in d {
                        stream.extend_from_slice(&w.to_le_bytes());
                    }
                    table.push(d);
                }
            }
        }
    }
    let body = bincode_fixint(&stripped);
    let mut out = Vec::with_capacity(4 + body.len() + stream.len());
    out.extend_from_slice(&u32::try_from(body.len()).expect("body < 4 GiB").to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&stream);
    (out, st)
}

pub(crate) fn decode(bytes: &[u8]) -> Proof<Config> {
    use bincode::Options;
    let body_len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    let body = &bytes[4..4 + body_len];
    let mut proof: Proof<Config> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(body)
        .expect("the stripped body decodes");
    let stream = &bytes[4 + body_len..];
    let mut at = 0usize;
    let mut tables: HashMap<(Tree, usize), Vec<Digest>> = HashMap::new();
    for (tree, path) in paths_mut(&mut proof) {
        let len = usize::from(stream[at]);
        at += 1;
        for level in 0..len {
            let table = tables.entry((tree, level)).or_default();
            let tag = get_leb(stream, &mut at);
            let d = if tag == 0 {
                let mut d = [0u64; 4];
                for w in d.iter_mut() {
                    *w = u64::from_le_bytes(stream[at..at + 8].try_into().unwrap());
                    at += 8;
                }
                table.push(d);
                d
            } else {
                table[tag - 1]
            };
            path.push(d);
        }
    }
    assert_eq!(at, stream.len(), "the stream is consumed exactly");
    proof
}

/// Sibling digests of every tree, indexed `[query][level]`, in query order.
fn sibling_table(proof: &Proof<Config>) -> Vec<(Tree, Vec<Vec<Digest>>)> {
    let mut copy: Proof<Config> = bincode::deserialize(&bincode_fixint(proof)).expect("round-trip");
    let mut trees: Vec<(Tree, Vec<Vec<Digest>>)> = Vec::new();
    for (tree, path) in paths_mut(&mut copy) {
        let row = std::mem::take(path);
        match trees.iter_mut().find(|(t, _)| *t == tree) {
            Some((_, rows)) => rows.push(row),
            None => trees.push((tree, vec![row])),
        }
    }
    trees
}

/// What the HASHING variant would additionally drop, read off the proof
/// without hashing anything. Two queries' siblings at level `l` are equal
/// iff the queries share their level-`l` ancestor (digests are
/// collision-free), so grouping queries by their level-`l+1` sibling groups
/// them by level-`(l+1)` ancestor. Inside one group the level-`l` siblings
/// take one value (every member on the same side) or two (members on both
/// sides) — and in the two-valued case each side's sibling IS the other
/// side's path node, which a hashing decoder recomputes from that query's
/// leaf. Those two digests (each sent once today as a literal) go.
/// The top level (whose ancestor is a cap entry, not in the path) is not
/// counted, so this is a lower bound.
/// Returns `(input trees, FRI layer trees)`. Only the input-tree part is
/// buildable without a Fiat–Shamir replay: an input leaf is fully in the
/// proof (opened values + salt), but a commit-phase leaf also holds the
/// folded value the verifier computes from transcript challenges.
fn hashing_extra_digests(trees: &[(Tree, Vec<Vec<Digest>>)]) -> (usize, usize) {
    let (mut inputs, mut layers) = (0, 0);
    for (tree, rows) in trees {
        let mut extra = 0;
        let depth = rows.iter().map(Vec::len).min().unwrap_or(0);
        for l in 0..depth.saturating_sub(1) {
            let mut groups: HashMap<Digest, Vec<Digest>> = HashMap::new();
            for r in rows {
                let g = groups.entry(r[l + 1]).or_default();
                if !g.contains(&r[l]) {
                    g.push(r[l]);
                }
            }
            extra += groups.values().filter(|v| v.len() == 2).map(|_| 2).sum::<usize>();
        }
        match tree {
            Tree::Input(_) => inputs += extra,
            Tree::Layer(_) => layers += extra,
        }
    }
    (inputs, layers)
}

/// The hash-free codec's saving if the query positions were as spread out as
/// the tree allows — the floor any padding scheme must pad to. At a level
/// with `n` distinct nodes, `q` paths repeat at least `q − n` siblings; with a
/// cap of `2^c` the highest path level has `2^(c+1)` nodes, the next `2^(c+2)`…
/// Saving = 32·dups − one tag per sibling − one length byte per path − 4.
fn worst_case_saving(trees: &[(Tree, Vec<Vec<Digest>>)]) -> i64 {
    let cap = qlab_consensus::CAP_HEIGHT;
    let (mut dups, mut sibs, mut paths) = (0i64, 0i64, 0i64);
    for (_, rows) in trees {
        let q = rows.len() as i64;
        let depth = rows.iter().map(Vec::len).min().unwrap_or(0);
        paths += q;
        sibs += rows.iter().map(|r| r.len() as i64).sum::<i64>();
        for l in 0..depth {
            // level l (0 = leaf siblings) has 2^(depth + cap − l) nodes.
            let nodes = 1i64.checked_shl((depth + cap - l) as u32).unwrap_or(i64::MAX);
            dups += (q - nodes).max(0);
        }
    }
    32 * dups - sibs - paths - 4
}

/// One proof's row.
struct Row {
    raw: usize,
    coded: usize,
    siblings: usize,
    literals: usize,
    hash_extra_inputs: usize,
    hash_extra_layers: usize,
    enc_ms: f64,
    dec_ms: f64,
}

pub(crate) fn run_mproof(power: &str, case: &str, count: usize) {
    println!("# qumbra-lab mproof — Merkle multi-proof codec prototype, case `{case}`, {count} proof(s) (lab #742 4c)");
    println!();
    crate::print_env(power);
    // One instance per case; every prove draws fresh OS randomness (hiding),
    // so every proof has fresh Fiat–Shamir query positions.
    let (label, prove, verify): (String, Box<dyn Fn() -> Proof<Config>>, Verify) = match case {
        "l1" => {
            let (inst, _) = crate::m4gaterec::bucket_instance_seeded(0xfeed_face_cafe_beef);
            let inst = std::rc::Rc::new(inst);
            let (pvs, _) = qlab_consensus::prove_bucket(&inst);
            let label = format!("L1 2×2 bucket @ {}", qlab_consensus::CONSENSUS_CFG.label());
            let i2 = inst.clone();
            (
                label,
                Box::new(move || qlab_consensus::prove_bucket(&inst).1),
                Box::new(move |p: &Proof<Config>| qlab_consensus::verify_proof(&i2, &pvs, p)),
            )
        }
        "s3" => {
            let inst = qlab_l2::fixture::shape_s();
            let pvs = qlab_l2::prove_s(&inst).0;
            let label = format!("shape S3 @ {}", qlab_l2::L2_CFG_PROVISIONAL.label());
            (label, Box::new(move || qlab_l2::prove_s(&inst).1), Box::new(move |p: &Proof<Config>| qlab_l2::verify_s(&pvs, p)))
        }
        "p3" => {
            let inst = qlab_l2::fixture::shape_p();
            let pvs = qlab_l2::prove_p(&inst).0;
            let label = format!("shape P3 @ {}", qlab_l2::L2_CFG_PROVISIONAL.label());
            (label, Box::new(move || qlab_l2::prove_p(&inst).1), Box::new(move |p: &Proof<Config>| qlab_l2::verify_p(&pvs, p)))
        }
        other => {
            eprintln!("mproof: unknown --case `{other}`; expected l1|s3|p3");
            std::process::exit(2);
        }
    };

    println!("## {label}");
    println!();
    println!("| # | proof B | coded B | saved B | siblings | sent as digests | hashing: input-tree digests dropped | hashing: FRI-layer digests dropped | saved B, + input-tree hashing (buildable) | saved B, + all hashing | encode ms | decode ms |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    let mut rows = Vec::with_capacity(count);
    let mut worst = None;
    for k in 0..count {
        let proof = prove();
        let original = bincode_fixint(&proof);
        let t = Instant::now();
        let (coded, st) = encode(&proof);
        let enc_ms = t.elapsed().as_secs_f64() * 1e3;
        let t = Instant::now();
        let decoded = decode(&coded);
        let dec_ms = t.elapsed().as_secs_f64() * 1e3;
        assert!(bincode_fixint(&decoded) == original, "proof {k}: the codec must be lossless");
        assert!(verify(&decoded), "proof {k}: the decoded proof must verify");
        let trees = sibling_table(&proof);
        let (hash_extra_inputs, hash_extra_layers) = hashing_extra_digests(&trees);
        worst.get_or_insert_with(|| worst_case_saving(&trees));
        let r = Row { raw: original.len(), coded: coded.len(), siblings: st.siblings, literals: st.literals, hash_extra_inputs, hash_extra_layers, enc_ms, dec_ms };
        let saved = r.raw as i64 - r.coded as i64;
        println!(
            "| {k} | {} | {} | {saved} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} |",
            r.raw,
            r.coded,
            r.siblings,
            r.literals,
            r.hash_extra_inputs,
            r.hash_extra_layers,
            saved + 32 * r.hash_extra_inputs as i64,
            saved + 32 * (r.hash_extra_inputs + r.hash_extra_layers) as i64,
            r.enc_ms,
            r.dec_ms
        );
        rows.push(r);
    }
    let saved: Vec<i64> = rows.iter().map(|r| r.raw as i64 - r.coded as i64).collect();
    let buildable: Vec<i64> = rows.iter().zip(&saved).map(|(r, s)| s + 32 * r.hash_extra_inputs as i64).collect();
    let hashed: Vec<i64> =
        rows.iter().zip(&saved).map(|(r, s)| s + 32 * (r.hash_extra_inputs + r.hash_extra_layers) as i64).collect();
    let stat = |v: &[i64]| {
        let (mn, mx) = (*v.iter().min().unwrap(), *v.iter().max().unwrap());
        let mean = v.iter().sum::<i64>() as f64 / v.len() as f64;
        (mn, mean, mx)
    };
    let (smin, smean, smax) = stat(&saved);
    let (bmin, bmean, bmax) = stat(&buildable);
    let (hmin, hmean, hmax) = stat(&hashed);
    println!();
    println!("| over {count} proofs | min | mean | max |");
    println!("|---|---|---|---|");
    println!("| saved B, hash-free (measured) | {smin} | {smean:.0} | {smax} |");
    println!("| saved B, + input-tree hashing (buildable; lower bound) | {bmin} | {bmean:.0} | {bmax} |");
    println!("| saved B, + all hashing (needs a Fiat–Shamir replay; lower bound) | {hmin} | {hmean:.0} | {hmax} |");
    println!();
    println!(
        "Padding floor (hash-free, analytic worst case over query positions, cap {}): **{} B** — what a fixed-size coded proof keeps.",
        qlab_consensus::CAP_HEIGHT,
        worst.unwrap_or(0)
    );
    println!("Raw proof size is fixed per shape: {} B.", rows[0].raw);
}
