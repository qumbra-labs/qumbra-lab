//! The Address Directory client — `qs1…` → full address, checked locally
//! (design `address-directory-decision.md`, stamped 2026-10-04, design PR #364).
//!
//! ```text
//!   GET  /v1/{genesis}/stats             {"version":1,"count":N,"prefix_bits":P}
//!   GET  /v1/{genesis}/bucket/{p}/{pfx}  ver(1) ‖ p(u8) ‖ n(u32 LE) ‖ n × raw(1,233)
//!   POST /v1/{genesis}/entries           body: one encoded qaddr1…
//! ```
//!
//! # Why the directory needs no trust (A2)
//!
//! A short address is `Keccak256(DS_SHORTADDR ‖ raw)[..16]` — a 128-bit
//! commitment to the full address. [`resolve`] re-hashes every entry it is
//! served and answers [`Resolution::Found`] only for exactly one distinct full
//! address whose hash IS the short address typed. Zero is
//! [`Resolution::NotFound`]; two or more is [`Resolution::Ambiguous`], which
//! carries a count and **no addresses**, so a caller cannot turn it into a pick.
//! The worst a lying directory can do is fail.
//!
//! # Why the query carries only a prefix (A3)
//!
//! No route here takes a full short address. The wallet asks for a bucket —
//! every entry whose short hash shares the first `p` bits — and matches
//! locally. That is a **named relaxation of name-service D2** with an
//! anonymity set of the bucket (≥ 64 at the server's advised `p`); `p = 0` is
//! the whole table, D2-exact, and always the caller's option ([`choose_bits`]).
//!
//! # Transport
//!
//! Injected, as [`crate::names::sync_names`] does: every function takes a fetch
//! (or post) closure, so this module carries no TLS and tests feed it bytes.
//! `net::http_get_limited` is the intended GET, with [`MAX_STATS_BYTES`] for
//! `/stats` and [`MAX_BUCKET_BYTES`] for a bucket — two limits, because a
//! stats answer is a few dozen bytes and must not be allowed a bucket's 10 MB.
//!
//! The upload body is the address's bech32m text, UTF-8, nothing else. The
//! server parses it as text **whatever the Content-Type says**: the lab's
//! `net::http_post_bytes` sends `application/octet-stream`, a browser shell
//! may send `text/plain; charset=utf-8`, and both must work.
//!
//! Every route is scoped by the network's genesis file hash (design §1,
//! "Network scoping"): a raw address binds no network, so one directory table
//! per network keeps a `qs1…` from resolving across nets.

use qlab_wallet::address::{Address, ShortAddress};

/// The bucket wire's version byte.
pub const BUCKET_VERSION: u8 = 1;
/// The stats document's `version`.
pub const STATS_VERSION: u64 = 1;
/// The most prefix bits any query uses (the prefix travels as two bytes).
pub const MAX_PREFIX_BITS: u8 = 16;
/// The response ceiling to hand the transport for `/stats`.
pub const MAX_STATS_BYTES: usize = 1024;
/// Bucket header: `ver ‖ p ‖ n`.
pub const BUCKET_HEADER_LEN: usize = 1 + 1 + 4;
/// The most entries one bucket may carry before the client refuses it. At the
/// advised `p` a bucket holds about 64–128; this is the ceiling for a caller
/// who chose a smaller `p` (or `p = 0`) on a grown table. `[testnet-placeholder]`.
pub const MAX_BUCKET_ENTRIES: usize = 8192;
/// The response ceiling to hand the transport for one bucket (~10 MB).
pub const MAX_BUCKET_BYTES: usize = BUCKET_HEADER_LEN + MAX_BUCKET_ENTRIES * Address::RAW_LEN;

/// What `/v1/{genesis}/stats` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub count: u64,
    pub prefix_bits: u8,
}

/// The answer to "which full address is this `qs1…`?".
#[derive(Clone)]
pub enum Resolution {
    /// Exactly one distinct full address hashes to the short address.
    Found(Box<Address>),
    /// The bucket holds no entry for it.
    NotFound,
    /// Two or more distinct full addresses hash to it — a refusal. Only a
    /// 128-bit collision crafted by one party over addresses of its own can
    /// produce this, and no address is handed back to pick from.
    Ambiguous { matches: usize },
}

impl std::fmt::Debug for Resolution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Resolution::Found(a) => write!(f, "Found({})", a.short().encode()),
            Resolution::NotFound => write!(f, "NotFound"),
            Resolution::Ambiguous { matches } => write!(f, "Ambiguous {{ matches: {matches} }}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DirectoryError {
    /// The genesis id is not 64 lowercase hex characters.
    BadGenesis,
    /// A prefix length past [`MAX_PREFIX_BITS`] — a caller bug, refused
    /// rather than clamped so it cannot hide.
    BadPrefixBits(u8),
    /// The stats document is not the expected shape or version.
    BadStats(String),
    /// The bucket bytes are malformed (wrong version, `p`, length, an entry
    /// that does not parse, or one outside the requested prefix).
    BadBucket(String),
    /// The transport failed.
    Fetch(String),
    /// The directory refused an upload (non-2xx), with its status.
    Refused(u16),
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::BadGenesis => write!(f, "genesis id must be 64 lowercase hex characters"),
            DirectoryError::BadPrefixBits(p) => write!(f, "prefix length {p} > {MAX_PREFIX_BITS} bits"),
            DirectoryError::BadStats(m) => write!(f, "address directory stats: {m}"),
            DirectoryError::BadBucket(m) => write!(f, "address directory bucket: {m}"),
            DirectoryError::Fetch(m) => write!(f, "address directory unreachable: {m}"),
            DirectoryError::Refused(s) => write!(f, "address directory refused the upload: HTTP {s}"),
        }
    }
}

impl std::error::Error for DirectoryError {}

fn check_genesis(genesis: &str) -> Result<(), DirectoryError> {
    if genesis.len() == 64 && genesis.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        Ok(())
    } else {
        Err(DirectoryError::BadGenesis)
    }
}

/// The first 16 bits of a short hash, big-endian.
pub fn prefix16(short: &ShortAddress) -> u16 {
    u16::from_be_bytes([short.hash[0], short.hash[1]])
}

fn check_bits(p: u8) -> Result<(), DirectoryError> {
    if p > MAX_PREFIX_BITS { Err(DirectoryError::BadPrefixBits(p)) } else { Ok(()) }
}

/// Only ever called with `p <= MAX_PREFIX_BITS` (every public entry point
/// runs [`check_bits`] first).
fn mask(p: u8) -> u16 {
    debug_assert!(p <= MAX_PREFIX_BITS);
    if p == 0 { 0 } else { u16::MAX << (16 - p as u32) }
}

/// The bucket path for `short` at `p` bits. The prefix always travels as two
/// bytes (four hex characters) with every bit past `p` zeroed, so the path
/// says nothing beyond the `p` bits it is meant to. `p > 16` is refused.
pub fn bucket_path(genesis: &str, short: &ShortAddress, p: u8) -> Result<String, DirectoryError> {
    check_genesis(genesis)?;
    check_bits(p)?;
    Ok(format!("/v1/{genesis}/bucket/{p}/{:04x}", prefix16(short) & mask(p)))
}

/// The `p` to query with: the server's advice, capped at [`MAX_PREFIX_BITS`],
/// and never more than the caller allows. `max_bits = 0` is the D2-exact
/// whole-table fetch.
pub fn choose_bits(stats: &Stats, max_bits: u8) -> u8 {
    stats.prefix_bits.min(MAX_PREFIX_BITS).min(max_bits)
}

/// Parse the stats document. The shape is fixed and this server's own, so the
/// parser is strict: exactly the keys `version`, `count`, `prefix_bits`, each a
/// non-negative integer, in any order.
pub fn parse_stats(body: &[u8]) -> Result<Stats, DirectoryError> {
    let bad = |m: &str| DirectoryError::BadStats(m.to_string());
    let s = std::str::from_utf8(body).map_err(|_| bad("not UTF-8"))?.trim();
    let inner = s
        .strip_prefix('{')
        .and_then(|r| r.strip_suffix('}'))
        .ok_or_else(|| bad("not a JSON object"))?;
    let (mut version, mut count, mut bits) = (None, None, None);
    for field in inner.split(',') {
        let (k, v) = field.split_once(':').ok_or_else(|| bad("field without ':'"))?;
        let k = k.trim();
        let v: u64 = v.trim().parse().map_err(|_| bad("value is not a non-negative integer"))?;
        let slot = match k {
            "\"version\"" => &mut version,
            "\"count\"" => &mut count,
            "\"prefix_bits\"" => &mut bits,
            _ => return Err(bad(&format!("unknown key {k}"))),
        };
        if slot.replace(v).is_some() {
            return Err(bad(&format!("duplicate key {k}")));
        }
    }
    let version = version.ok_or_else(|| bad("missing version"))?;
    if version != STATS_VERSION {
        return Err(bad(&format!("version {version}, expected {STATS_VERSION}")));
    }
    let count = count.ok_or_else(|| bad("missing count"))?;
    let bits = bits.ok_or_else(|| bad("missing prefix_bits"))?;
    if bits > MAX_PREFIX_BITS as u64 {
        return Err(bad(&format!("prefix_bits {bits} > {MAX_PREFIX_BITS}")));
    }
    Ok(Stats { count, prefix_bits: bits as u8 })
}

/// Decode one bucket served for `(p, prefix)`. Refuses, by name, `p > 16`, a wrong
/// version, a `p` other than the one asked for, an entry count past
/// [`MAX_BUCKET_ENTRIES`] (checked before anything is allocated), a length
/// that is not exactly the header plus `n` entries, an entry that does not
/// parse as an address, and an entry outside the requested prefix.
pub fn decode_bucket(bytes: &[u8], p: u8, prefix: u16) -> Result<Vec<Address>, DirectoryError> {
    check_bits(p)?;
    let bad = |m: String| DirectoryError::BadBucket(m);
    if bytes.len() < BUCKET_HEADER_LEN {
        return Err(bad(format!("{} bytes, shorter than the header", bytes.len())));
    }
    if bytes[0] != BUCKET_VERSION {
        return Err(bad(format!("version {}, expected {BUCKET_VERSION}", bytes[0])));
    }
    if bytes[1] != p {
        return Err(bad(format!("served for p = {}, asked for p = {p}", bytes[1])));
    }
    let n = u32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]) as usize;
    if n > MAX_BUCKET_ENTRIES {
        return Err(bad(format!("{n} entries, more than {MAX_BUCKET_ENTRIES}")));
    }
    let want = BUCKET_HEADER_LEN + n * Address::RAW_LEN;
    if bytes.len() != want {
        return Err(bad(format!("{} bytes for {n} entries, expected {want}", bytes.len())));
    }
    let m = mask(p);
    let mut out = Vec::with_capacity(n);
    for (i, raw) in bytes[BUCKET_HEADER_LEN..].chunks_exact(Address::RAW_LEN).enumerate() {
        // A carrier (lab #896 G): a directory entry may be either address
        // version; the send path that uses it checks the version for its net.
        let addr = Address::from_raw_bytes_any(raw).ok_or_else(|| bad(format!("entry {i} is not an address")))?;
        if prefix16(&addr.short()) & m != prefix & m {
            return Err(bad(format!("entry {i} is outside the requested prefix")));
        }
        out.push(addr);
    }
    Ok(out)
}

/// Pick the answer for `short` out of a decoded bucket — the A2 rule.
pub fn match_entries(entries: &[Address], short: &ShortAddress) -> Resolution {
    match_by(entries, short, Address::short)
}

/// [`match_entries`] over an injected hash, so the two-match refusal can be
/// tested without a 128-bit collision.
fn match_by(entries: &[Address], short: &ShortAddress, hash: impl Fn(&Address) -> ShortAddress) -> Resolution {
    let mut found: Vec<&Address> = Vec::new();
    for a in entries.iter().filter(|a| hash(a) == *short) {
        if !found.iter().any(|f| f.to_raw_bytes() == a.to_raw_bytes()) {
            found.push(a);
        }
    }
    match found.len() {
        0 => Resolution::NotFound,
        1 => Resolution::Found(Box::new(found[0].clone())),
        matches => Resolution::Ambiguous { matches },
    }
}

/// Resolve `short` against the directory for `genesis`: stats, then one bucket
/// at [`choose_bits`]`(stats, max_bits)`, decoded and matched locally.
pub fn resolve<F>(genesis: &str, short: &ShortAddress, max_bits: u8, mut fetch: F) -> Result<Resolution, DirectoryError>
where
    F: FnMut(&str) -> Result<Vec<u8>, String>,
{
    check_genesis(genesis)?;
    let stats = parse_stats(&fetch(&format!("/v1/{genesis}/stats")).map_err(DirectoryError::Fetch)?)?;
    let p = choose_bits(&stats, max_bits);
    let path = bucket_path(genesis, short, p)?;
    let bytes = fetch(&path).map_err(DirectoryError::Fetch)?;
    let entries = decode_bucket(&bytes, p, prefix16(short) & mask(p))?;
    Ok(match_entries(&entries, short))
}

/// Publish `addr` to the directory for `genesis`. The short address returned
/// is computed here, not read from the server's answer: 200 (already held) and
/// 201 (new) both succeed; anything else is [`DirectoryError::Refused`].
pub fn publish<P>(genesis: &str, addr: &Address, mut post: P) -> Result<ShortAddress, DirectoryError>
where
    P: FnMut(&str, &[u8]) -> Result<(u16, Vec<u8>), String>,
{
    check_genesis(genesis)?;
    let (status, _) = post(&format!("/v1/{genesis}/entries"), addr.encode().as_bytes()).map_err(DirectoryError::Fetch)?;
    match status {
        200 | 201 => Ok(addr.short()),
        s => Err(DirectoryError::Refused(s)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: &str = "59d9f054bb15116dac40c42ddb67c7d377407eec3010e9f98a5cc76e9e0544b1";
    const VECTORS: &str = include_str!("../tests/fixtures/addrdir-vectors.txt");

    /// The production-encoded vectors: `(full address, its qs1…)`.
    fn vectors() -> Vec<(Address, String)> {
        VECTORS
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
            .map(|l| {
                let (a, s) = l.split_once(' ').unwrap();
                (Address::decode(a).expect("vector address decodes"), s.to_string())
            })
            .collect()
    }

    fn bucket(p: u8, entries: &[&Address]) -> Vec<u8> {
        let mut b = vec![BUCKET_VERSION, p];
        b.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for e in entries {
            b.extend_from_slice(&e.to_raw_bytes());
        }
        b
    }

    fn stats_json(count: u64, p: u8) -> Vec<u8> {
        format!("{{\"version\":1,\"count\":{count},\"prefix_bits\":{p}}}").into_bytes()
    }

    #[test]
    fn vectors_are_real_production_pairs() {
        let v = vectors();
        assert_eq!(v.len(), 3);
        for (a, s) in &v {
            assert_eq!(a.encode().len(), 1985);
            assert_eq!(s.len(), 35);
            assert_eq!(a.short().encode(), *s, "the fixture's qs1 is the production hash");
        }
    }

    #[test]
    fn whole_table_resolves_exactly_one() {
        let v = vectors();
        let all: Vec<&Address> = v.iter().map(|(a, _)| a).collect();
        let target = ShortAddress::decode(&v[1].1).unwrap();
        let mut seen = Vec::new();
        let r = resolve(G, &target, 16, |path| {
            seen.push(path.to_string());
            Ok(if path.ends_with("/stats") { stats_json(3, 0) } else { bucket(0, &all) })
        })
        .unwrap();
        match r {
            Resolution::Found(a) => assert_eq!(a.to_raw_bytes(), v[1].0.to_raw_bytes()),
            _ => panic!("expected Found"),
        }
        assert_eq!(seen, vec![format!("/v1/{G}/stats"), format!("/v1/{G}/bucket/0/0000")]);
    }

    #[test]
    fn a_substituted_address_is_not_found() {
        // The directory answers with a different (valid) address: no match, no pay.
        let v = vectors();
        let target = ShortAddress::decode(&v[0].1).unwrap();
        let r = resolve(G, &target, 16, |path| {
            Ok(if path.ends_with("/stats") { stats_json(1, 0) } else { bucket(0, &[&v[2].0]) })
        })
        .unwrap();
        assert!(matches!(r, Resolution::NotFound));
    }

    #[test]
    fn duplicates_of_one_address_are_one_match() {
        let v = vectors();
        let target = ShortAddress::decode(&v[0].1).unwrap();
        assert!(matches!(match_entries(&[v[0].0.clone(), v[0].0.clone()], &target), Resolution::Found(_)));
    }

    #[test]
    fn two_distinct_matches_are_ambiguous_with_no_address() {
        // A real collision cannot be built; a hash that maps everything to the
        // target stands in for one. Two distinct addresses => refusal, and the
        // variant carries a count, not an address to pick.
        let v = vectors();
        let target = v[0].0.short();
        let all = [v[0].0.clone(), v[1].0.clone()];
        assert!(matches!(match_by(&all, &target, |_| target), Resolution::Ambiguous { matches: 2 }));
        let three = [v[0].0.clone(), v[1].0.clone(), v[2].0.clone(), v[1].0.clone()];
        assert!(matches!(match_by(&three, &target, |_| target), Resolution::Ambiguous { matches: 3 }));
    }

    #[test]
    fn prefix_bits_and_path_carry_only_p_bits() {
        let v = vectors();
        let s = v[0].0.short();
        let full = prefix16(&s);
        assert_eq!(bucket_path(G, &s, 0).unwrap(), format!("/v1/{G}/bucket/0/0000"));
        assert_eq!(bucket_path(G, &s, 16).unwrap(), format!("/v1/{G}/bucket/16/{full:04x}"));
        let p5 = bucket_path(G, &s, 5).unwrap();
        let hex = p5.rsplit('/').next().unwrap();
        assert_eq!(u16::from_str_radix(hex, 16).unwrap(), full & 0xF800);
        assert_eq!(bucket_path(G, &s, 17), Err(DirectoryError::BadPrefixBits(17)), "refused, not clamped");
        assert_eq!(bucket_path(G, &s, 255), Err(DirectoryError::BadPrefixBits(255)));
    }

    #[test]
    fn choose_bits_honours_the_callers_ceiling() {
        let st = Stats { count: 1 << 20, prefix_bits: 13 };
        assert_eq!(choose_bits(&st, 16), 13);
        assert_eq!(choose_bits(&st, 4), 4);
        assert_eq!(choose_bits(&st, 0), 0, "D2-exact whole table");
    }

    #[test]
    fn bucket_at_p_matches_and_refuses_foreign_entries() {
        let v = vectors();
        let (a, b) = (&v[0].0, &v[1].0);
        let pa = prefix16(&a.short());
        assert_ne!(prefix16(&b.short()), pa, "precondition: the vectors' prefixes differ");
        assert_eq!(decode_bucket(&bucket(16, &[a]), 16, pa).unwrap().len(), 1);
        assert!(matches!(decode_bucket(&bucket(16, &[a, b]), 16, pa), Err(DirectoryError::BadBucket(_))));
    }

    #[test]
    fn decode_masks_below_16_bits() {
        // p = 5: the expected prefix is compared on the top 5 bits only.
        let v = vectors();
        let a = &v[0].0;
        let pa = prefix16(&a.short());
        let same_top5_other_low = (pa & 0xF800) | (!pa & 0x07FF);
        assert_eq!(decode_bucket(&bucket(5, &[a]), 5, same_top5_other_low).unwrap().len(), 1);
        let other_top5 = pa ^ 0x8000;
        assert!(matches!(decode_bucket(&bucket(5, &[a]), 5, other_top5), Err(DirectoryError::BadBucket(_))));
        assert_eq!(decode_bucket(&bucket(17, &[a]), 17, 0).err(), Some(DirectoryError::BadPrefixBits(17)));
    }

    #[test]
    fn resolve_asks_at_the_capped_p() {
        let v = vectors();
        let a = &v[0].0;
        let s = a.short();
        let mut seen = Vec::new();
        let r = resolve(G, &s, 4, |path| {
            seen.push(path.to_string());
            Ok(if path.ends_with("/stats") { stats_json(1 << 20, 13) } else { bucket(4, &[a]) })
        })
        .unwrap();
        assert!(matches!(r, Resolution::Found(_)));
        assert_eq!(seen[1], format!("/v1/{G}/bucket/4/{:04x}", prefix16(&s) & 0xF000));
    }

    #[test]
    fn malformed_buckets_are_refused_by_name() {
        let v = vectors();
        let a = &v[0].0;
        let good = bucket(0, &[a]);
        let mut wrong_ver = good.clone();
        wrong_ver[0] = 2;
        assert!(decode_bucket(&wrong_ver, 0, 0).err().unwrap().to_string().contains("version 2"));
        assert!(decode_bucket(&good, 3, 0).err().unwrap().to_string().contains("asked for p = 3"));
        assert!(decode_bucket(&good[..good.len() - 1], 0, 0).err().unwrap().to_string().contains("expected"));
        let mut extra = good.clone();
        extra.push(0);
        assert!(decode_bucket(&extra, 0, 0).is_err());
        let mut huge = vec![BUCKET_VERSION, 0];
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_bucket(&huge, 0, 0).err().unwrap().to_string().contains("more than"));
        let mut bad_entry = good.clone();
        bad_entry[BUCKET_HEADER_LEN] = 9; // address version byte
        assert!(decode_bucket(&bad_entry, 0, 0).err().unwrap().to_string().contains("not an address"));
        assert!(decode_bucket(&[1, 0], 0, 0).is_err());
    }

    #[test]
    fn stats_parser_is_strict() {
        assert_eq!(parse_stats(b" {\"prefix_bits\": 7, \"version\":1, \"count\": 10000} ").unwrap(), Stats { count: 10000, prefix_bits: 7 });
        for bad in [
            &b"{\"version\":2,\"count\":1,\"prefix_bits\":0}"[..],
            b"{\"version\":1,\"count\":1}",
            b"{\"version\":1,\"count\":1,\"prefix_bits\":17}",
            b"{\"version\":1,\"count\":-1,\"prefix_bits\":0}",
            b"{\"version\":1,\"count\":1,\"prefix_bits\":0,\"extra\":1}",
            b"{\"version\":1,\"version\":1,\"count\":1,\"prefix_bits\":0}",
            b"[1,2,3]",
        ] {
            assert!(parse_stats(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn genesis_must_be_64_lower_hex() {
        let s = vectors()[0].0.short();
        assert_eq!(bucket_path("t2", &s, 0), Err(DirectoryError::BadGenesis));
        assert_eq!(bucket_path(&G.to_uppercase(), &s, 0), Err(DirectoryError::BadGenesis));
        assert!(resolve("t2", &s, 0, |_| panic!("no fetch before the genesis check")).is_err());
    }

    #[test]
    fn publish_accepts_200_and_201_and_refuses_the_rest() {
        let a = vectors()[0].0.clone();
        for (status, ok) in [(201, true), (200, true), (400, false), (429, false)] {
            let mut body_seen = Vec::new();
            let r = publish(G, &a, |path, body| {
                assert_eq!(path, format!("/v1/{G}/entries"));
                body_seen = body.to_vec();
                Ok((status, Vec::new()))
            });
            assert_eq!(r.is_ok(), ok, "status {status}");
            assert_eq!(body_seen, a.encode().into_bytes());
        }
    }

    #[test]
    fn fetch_failure_is_reported_not_swallowed() {
        let s = vectors()[0].0.short();
        assert_eq!(
            resolve(G, &s, 16, |_| Err("connection refused".into())).unwrap_err(),
            DirectoryError::Fetch("connection refused".into())
        );
    }
}
