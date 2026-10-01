//! Lab #785 F5-4a — the wrapper's **consensus encodings**: the canonical
//! [`Surface`] bytes a node keeps as opaque derived state, the canonical
//! bundle a V6 block carries, the message the sequencer signs, and the exit
//! list's chain against `W.exit_cmt`.
//!
//! Every decoder here is total and strict (the #793 discipline): each length
//! is read through a checked [`Reader::take`] before anything is allocated,
//! every count is capped before it is used, a proof must be the exact bytes
//! its bincode re-encoding produces, and nothing may trail.
//!
//! # The surface bytes ([`SURFACE_LEN`], fixed)
//!
//! ```text
//! version u32 ‖ l2_id u64 ‖ prev 32 ‖ out ‖ newest_anchor 32 ‖ exit_cmt 32 ‖ commitment 32
//! out = N 32 ‖ n_next u64 ‖ C 32 ‖ c_next u64 ‖ R 32 ‖ SD 32 ‖ K 32 ‖ k_next u64
//!     ‖ AA 32 ‖ aa_next u64 ‖ CH 32 ‖ ch_next u64 ‖ supply 32 ‖ D_cum u64 ‖ E_cum u64
//! ```
//!
//! Integers are little-endian and digests lane-major little-endian
//! ([`digest_to_bytes`]). `commitment` is derived, so a decode recomputes it
//! and refuses a mismatch: no two byte strings decode to one surface.
//!
//! # The bundle bytes
//!
//! ```text
//! version u32 ‖ l2_id u64
//! ‖ w_pvs (W_PV_LEN × u32) ‖ w_proof_len u32 ‖ w_proof
//! ‖ dep_pvs (DEP_PV_LEN × u32) ‖ dep_proof_len u32 ‖ dep_proof
//! ‖ n_members u8 ‖ n_members × (tag u8 ‖ pvs (tag's PV_LEN × u32) ‖ proof_len u32 ‖ proof)
//! ‖ n_exits u8 ‖ n_exits × (rkm 32 ‖ v u64)
//! ‖ sequencer_sig (SEQUENCER_SIG_LEN)
//! ```
//!
//! PV words travel as `u32` and are **not** range-checked here: the 16-bit
//! and per-AIR widths are V0's, V2's and V9's refusals, and a codec that
//! narrowed them first would make those checks unreachable. `n_members` is
//! explicit for the same reason: V1 judges it against the version's `k`.
use p3_uni_stark::Proof;
use qlab_consensus::legacy::LegacyNonHidingConfig;
use qlab_consensus::Config;
use serde::{de::DeserializeOwned, Serialize};

use crate::dep::DEP_PV_LEN;
use crate::hash::{exit_state, h4, Digest, Roots, WRoots, WTag, EMPTY};
use crate::verify::{Bundle, BundleMember, Surface};
use crate::wleaf::{MAX_K, W_PV_LEN};

/// Digest → 32 bytes, lane-major little-endian: `qlab_note::hash::digest_bytes`
/// (qlab-bench pins the two equal), the node's `Hash32` of a tree root.
pub fn digest_to_bytes(d: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, lane) in d.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&lane.to_le_bytes());
    }
    out
}

/// The inverse of [`digest_to_bytes`].
pub fn digest_from_bytes(b: &[u8; 32]) -> Digest {
    core::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes")))
}

/// Why wrapper bytes were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input ended before a field (`what`).
    Truncated(&'static str),
    /// Bytes after the last field.
    Trailing,
    /// A surface whose stated commitment is not its fields'.
    SurfaceCommitment,
    /// A member tag byte that names no slot kind.
    UnknownTag(u8),
    /// More members than any version's `k`.
    TooManyMembers(u8),
    /// A proof that does not decode (`what`).
    ProofDecode(&'static str),
    /// A proof whose bytes are not its canonical re-encoding (`what`).
    /// A belt: with fixint integers, reject-trailing and a length prefix
    /// per proof, no input is known to reach it (every field of a p3 proof
    /// is a fixed-width integer, a field element — refused ≥ p by its own
    /// deserializer — or a length-prefixed sequence). It stays so that a
    /// future proof type with a non-canonical encoding refuses rather than
    /// admitting two byte strings for one proof.
    ProofNotCanonical(&'static str),
}

/// A checked cursor: every read is bounds-checked before it copies.
struct Reader<'a> {
    b: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], CodecError> {
        if n > self.b.len() {
            return Err(CodecError::Truncated(what));
        }
        let (h, t) = self.b.split_at(n);
        self.b = t;
        Ok(h)
    }
    fn u8(&mut self, what: &'static str) -> Result<u8, CodecError> {
        Ok(self.take(1, what)?[0])
    }
    fn u32(&mut self, what: &'static str) -> Result<u32, CodecError> {
        Ok(u32::from_le_bytes(self.take(4, what)?.try_into().expect("4 bytes")))
    }
    fn u64(&mut self, what: &'static str) -> Result<u64, CodecError> {
        Ok(u64::from_le_bytes(self.take(8, what)?.try_into().expect("8 bytes")))
    }
    fn digest(&mut self, what: &'static str) -> Result<Digest, CodecError> {
        Ok(digest_from_bytes(self.take(32, what)?.try_into().expect("32 bytes")))
    }
    fn words(&mut self, n: usize, what: &'static str) -> Result<Vec<u32>, CodecError> {
        // `n` is a layout constant (≤ W_PV_LEN), never a wire count.
        let raw = self.take(4 * n, what)?;
        Ok(raw.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().expect("4 bytes"))).collect())
    }
    /// A length-prefixed proof, decoded strictly and required canonical.
    fn proof<T: Serialize + DeserializeOwned>(&mut self, what: &'static str) -> Result<T, CodecError> {
        let len = self.u32(what)? as usize;
        let raw = self.take(len, what)?;
        decode_proof_strict(raw, what)
    }
    fn end(&self) -> Result<(), CodecError> {
        if self.b.is_empty() {
            Ok(())
        } else {
            Err(CodecError::Trailing)
        }
    }
}

/// Fixint bincode (what `bincode::serialize` writes), no trailing bytes, a
/// limit of the input's own length, then the re-encoding must be the input.
fn decode_proof_strict<T: Serialize + DeserializeOwned>(raw: &[u8], what: &'static str) -> Result<T, CodecError> {
    use bincode::Options;
    let p: T = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(raw.len() as u64)
        .deserialize(raw)
        .map_err(|_| CodecError::ProofDecode(what))?;
    if encode_proof(&p) != raw {
        return Err(CodecError::ProofNotCanonical(what));
    }
    Ok(p)
}

fn encode_proof<T: Serialize>(p: &T) -> Vec<u8> {
    bincode::serialize(p).expect("a proof serializes")
}

// ---------------------------------------------------------------------------
// The surface
// ---------------------------------------------------------------------------

/// The canonical surface's length: `version` and `l2_id`, 12 digests, 7 `u64`s (452 B).
pub const SURFACE_LEN: usize = 4 + 8 + 12 * 32 + 7 * 8;

/// A surface's canonical bytes.
pub fn encode_surface(s: &Surface) -> [u8; SURFACE_LEN] {
    let mut v = Vec::with_capacity(SURFACE_LEN);
    let d = |v: &mut Vec<u8>, x: &Digest| v.extend_from_slice(&digest_to_bytes(x));
    let u = |v: &mut Vec<u8>, x: u64| v.extend_from_slice(&x.to_le_bytes());
    v.extend_from_slice(&s.version.to_le_bytes());
    u(&mut v, s.l2_id);
    d(&mut v, &s.prev);
    let o = &s.out;
    d(&mut v, &o.f3.n);
    u(&mut v, o.f3.n_next);
    d(&mut v, &o.f3.c);
    u(&mut v, o.f3.c_next);
    d(&mut v, &o.f3.r);
    d(&mut v, &o.f3.sd);
    d(&mut v, &o.k);
    u(&mut v, o.k_next);
    d(&mut v, &o.aa);
    u(&mut v, o.aa_next);
    d(&mut v, &o.ch);
    u(&mut v, o.ch_next);
    d(&mut v, &o.sup);
    u(&mut v, o.d_cum);
    u(&mut v, o.e_cum);
    d(&mut v, &s.newest_anchor);
    d(&mut v, &s.exit_cmt);
    d(&mut v, &s.commitment);
    v.try_into().expect("SURFACE_LEN counts every field")
}

/// Decode canonical surface bytes: exactly [`SURFACE_LEN`], and the stated
/// commitment must be the fields'.
pub fn decode_surface(b: &[u8]) -> Result<Surface, CodecError> {
    let mut r = Reader { b };
    let version = r.u32("version")?;
    let l2_id = r.u64("l2_id")?;
    let prev = r.digest("prev")?;
    let n = r.digest("N")?;
    let n_next = r.u64("n_next")?;
    let c = r.digest("C")?;
    let c_next = r.u64("c_next")?;
    let rr = r.digest("R")?;
    let sd = r.digest("SD")?;
    let k = r.digest("K")?;
    let k_next = r.u64("k_next")?;
    let aa = r.digest("AA")?;
    let aa_next = r.u64("aa_next")?;
    let ch = r.digest("CH")?;
    let ch_next = r.u64("ch_next")?;
    let sup = r.digest("supply")?;
    let d_cum = r.u64("D_cum")?;
    let e_cum = r.u64("E_cum")?;
    let newest_anchor = r.digest("newest_anchor")?;
    let exit_cmt = r.digest("exit_cmt")?;
    let commitment = r.digest("commitment")?;
    r.end()?;
    let out = WRoots { f3: Roots { n, n_next, c, c_next, r: rr, sd }, k, k_next, aa, aa_next, ch, ch_next, sup, d_cum, e_cum };
    if Surface::commit(version, l2_id, &prev, &out, &newest_anchor, &exit_cmt) != commitment {
        return Err(CodecError::SurfaceCommitment);
    }
    Ok(Surface { version, l2_id, prev, out, newest_anchor, exit_cmt, commitment })
}

// ---------------------------------------------------------------------------
// Exits
// ---------------------------------------------------------------------------

/// One entry of a bundle's clear exit list: an asset-0 note of `v` to `rkm`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exit {
    pub rkm: Digest,
    pub v: u64,
}

/// The exit list's MD chain from [`EMPTY`] — W's `exit_cmt` construction
/// (qlab-bench's `check_wrapper_leaf` folds `exit_state` the same way).
pub fn exit_chain(exits: &[Exit]) -> Digest {
    exits.iter().fold(EMPTY, |h, e| h4(&exit_state(&h, &e.rkm, e.v)))
}

/// `Σ v`, or `None` on overflow (ruling condition (h): an overflow refuses).
pub fn exit_sum(exits: &[Exit]) -> Option<u64> {
    exits.iter().try_fold(0u64, |s, e| s.checked_add(e.v))
}

/// Why an exit list's shape is refused (the rule's step 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitShape {
    /// More than `K_exit` exits.
    TooMany { n: usize, k_exit: usize },
    /// Exit `i` pays the zero `rkm`.
    ZeroRkm(usize),
    /// Exit `i` carries no value.
    ZeroValue(usize),
}

/// The exit list's shape under the genesis's `K_exit`.
pub fn check_exit_shape(exits: &[Exit], k_exit: usize) -> Result<(), ExitShape> {
    if exits.len() > k_exit {
        return Err(ExitShape::TooMany { n: exits.len(), k_exit });
    }
    for (i, e) in exits.iter().enumerate() {
        if e.rkm == EMPTY {
            return Err(ExitShape::ZeroRkm(i));
        }
        if e.v == 0 {
            return Err(ExitShape::ZeroValue(i));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// An ML-DSA-65 signature's length (FIPS 204); qumbra-node pins it to the
/// signer's.
pub const SEQUENCER_SIG_LEN: usize = 3309;

/// The sequencer's signing domain.
pub const BUNDLE_SIG_DOMAIN: &[u8] = b"qumbra:l2-bundle:v1";

/// What the sequencer signs (F5-4 ruling, change A): the domain, the net's
/// id (the V6 genesis hash), `l2_id`, and the successor surface's commitment
/// as the bundle states it ([`stated_surface`]). A signature binds exactly
/// the transition it names, on exactly one net, **provided the caller**
/// refuses a bundle whose wire `l2_id` is not the chain's or whose
/// `verify_wrapper` surface is not the stated one (4b): `verify_wrapper`
/// proves the transition from the predecessor's `l2_id`, not the wire's.
pub fn sign_message(net_id: &[u8; 32], l2_id: u64, commitment: &Digest) -> Vec<u8> {
    let mut m = Vec::with_capacity(BUNDLE_SIG_DOMAIN.len() + 32 + 8 + 32);
    m.extend_from_slice(BUNDLE_SIG_DOMAIN);
    m.extend_from_slice(net_id);
    m.extend_from_slice(&l2_id.to_le_bytes());
    m.extend_from_slice(&digest_to_bytes(commitment));
    m
}

/// The successor surface a bundle states, read from W's PVs without
/// verifying anything. `None` unless there are exactly `W_PV_LEN` words and
/// every one is a 16-bit chunk: the codec does not range-check PVs (V0
/// does), and a wider word would overflow the limb recomposition — a panic
/// in a checked build, an aliased commitment in a release one (pre-review
/// P1). With the same `version` and `l2_id`, it is the value
/// [`crate::verify::verify_wrapper`] returns on acceptance; `verify_wrapper`
/// takes `l2_id` from the predecessor surface, so the **caller** must refuse
/// a bundle whose wire `l2_id` is not the chain's, or whose verified surface
/// is not the stated one (4b).
pub fn stated_surface(version: u32, l2_id: u64, w_pvs: &[u32]) -> Option<Surface> {
    (w_pvs.len() == W_PV_LEN && w_pvs.iter().all(|w| *w < 1 << 16)).then(|| crate::verify::surface_of(version, l2_id, w_pvs))
}

/// The successor surface a bundle states, read from its **prefix alone** —
/// `version ‖ l2_id ‖ w_pvs`, the first `12 + 4 · W_PV_LEN` bytes — with no
/// proof decoded (lab #785 F5-4c ruling Q1: a snapshot resume reads kilobytes
/// per bundle, not megabytes). `Ok(None)` when a W word is not a 16-bit
/// chunk (see [`stated_surface`]). Only for bytes a node already accepted:
/// it checks nothing after the prefix.
pub fn stated_surface_prefix(b: &[u8]) -> Result<Option<Surface>, CodecError> {
    let mut r = Reader { b };
    let version = r.u32("version")?;
    let l2_id = r.u64("l2_id")?;
    let w_pvs = r.words(W_PV_LEN, "w_pvs")?;
    Ok(stated_surface(version, l2_id, &w_pvs))
}

/// A decoded bundle: owned proofs, the clear exit list and the signature.
pub struct WireBundle {
    pub version: u32,
    pub l2_id: u64,
    pub w_pvs: Vec<u32>,
    pub w_proof: Proof<LegacyNonHidingConfig>,
    pub dep_pvs: Vec<u32>,
    pub dep_proof: Proof<Config>,
    pub members: Vec<BundleMember<Proof<Config>>>,
    pub exits: Vec<Exit>,
    pub sig: Box<[u8; SEQUENCER_SIG_LEN]>,
}

fn tag_of(b: u8) -> Option<WTag> {
    WTag::ALL.into_iter().find(|t| t.byte() == b)
}

impl WireBundle {
    /// Decode canonical bundle bytes.
    pub fn decode(b: &[u8]) -> Result<Self, CodecError> {
        let mut r = Reader { b };
        let version = r.u32("version")?;
        let l2_id = r.u64("l2_id")?;
        let w_pvs = r.words(W_PV_LEN, "w_pvs")?;
        let w_proof = r.proof("w_proof")?;
        let dep_pvs = r.words(DEP_PV_LEN, "dep_pvs")?;
        let dep_proof = r.proof("dep_proof")?;
        let n = r.u8("n_members")?;
        if n as usize > MAX_K {
            return Err(CodecError::TooManyMembers(n));
        }
        let mut members = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let t = r.u8("member tag")?;
            let tag = tag_of(t).ok_or(CodecError::UnknownTag(t))?;
            let pvs = r.words(tag.pv_len(), "member pvs")?;
            let proof = r.proof("member proof")?;
            members.push(BundleMember { tag, pvs, proof });
        }
        // At most 255 exits (a u8), each 40 bytes: bounded by the count's width.
        let n_exits = r.u8("n_exits")?;
        let mut exits = Vec::with_capacity(n_exits as usize);
        for _ in 0..n_exits {
            let rkm = r.digest("exit rkm")?;
            let v = r.u64("exit v")?;
            exits.push(Exit { rkm, v });
        }
        let sig = Box::new(<[u8; SEQUENCER_SIG_LEN]>::try_from(r.take(SEQUENCER_SIG_LEN, "sequencer_sig")?).expect("exact length"));
        r.end()?;
        Ok(WireBundle { version, l2_id, w_pvs, w_proof, dep_pvs, dep_proof, members, exits, sig })
    }

    /// The canonical bytes. Panics on a layout the decoder would refuse
    /// (a PV vector of the wrong length, more than `MAX_K` members or 255
    /// exits): an encoder bug, never peer input.
    pub fn encode(&self) -> Vec<u8> {
        assert_eq!(self.w_pvs.len(), W_PV_LEN, "W's PV count");
        assert_eq!(self.dep_pvs.len(), DEP_PV_LEN, "the deposit proof's PV count");
        assert!(self.members.len() <= MAX_K, "members ≤ MAX_K");
        let n_exits = u8::try_from(self.exits.len()).expect("≤ 255 exits");
        let mut v = Vec::new();
        let words = |v: &mut Vec<u8>, w: &[u32]| w.iter().for_each(|x| v.extend_from_slice(&x.to_le_bytes()));
        let proof = |v: &mut Vec<u8>, p: Vec<u8>| {
            v.extend_from_slice(&u32::try_from(p.len()).expect("a proof < 4 GiB").to_le_bytes());
            v.extend_from_slice(&p);
        };
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.l2_id.to_le_bytes());
        words(&mut v, &self.w_pvs);
        proof(&mut v, encode_proof(&self.w_proof));
        words(&mut v, &self.dep_pvs);
        proof(&mut v, encode_proof(&self.dep_proof));
        v.push(self.members.len() as u8);
        for m in &self.members {
            assert_eq!(m.pvs.len(), m.tag.pv_len(), "a member's PV count");
            v.push(m.tag.byte());
            words(&mut v, &m.pvs);
            proof(&mut v, encode_proof(&m.proof));
        }
        v.push(n_exits);
        for e in &self.exits {
            v.extend_from_slice(&digest_to_bytes(&e.rkm));
            v.extend_from_slice(&e.v.to_le_bytes());
        }
        v.extend_from_slice(&self.sig[..]);
        v
    }

    /// The view [`crate::verify::verify_wrapper`] takes.
    pub fn bundle(&self) -> Bundle<'_, &Proof<Config>> {
        Bundle {
            version: self.version,
            w_pvs: self.w_pvs.clone(),
            w_proof: &self.w_proof,
            members: self.members.iter().map(|m| BundleMember { tag: m.tag, pvs: m.pvs.clone(), proof: &m.proof }).collect(),
            dep_pvs: self.dep_pvs.clone(),
            dep_proof: &self.dep_proof,
        }
    }

    /// The successor surface this bundle states ([`stated_surface`]):
    /// `None` when a W PV is not a 16-bit chunk (a bundle V0 refuses).
    pub fn stated_surface(&self) -> Option<Surface> {
        stated_surface(self.version, self.l2_id, &self.w_pvs)
    }
}

/// **The bundle's clear exit list, from its bytes alone** (lab #785 F5-5d):
/// every proof is skipped by its length prefix, never decoded, so reading the
/// exits costs no proof deserialisation. Each length is bounded by the bytes
/// that remain before the reader moves (`take` refuses past the end; nothing
/// is allocated by a claimed length), and the layout is [`WireBundle::decode`]'s
/// exactly — the member count and tags checked, the signature present, no
/// trailing bytes — so a byte string this accepts is one `decode` reads the
/// same exits from, or refuses for a proof.
pub fn exit_list(b: &[u8]) -> Result<Vec<Exit>, CodecError> {
    let mut r = Reader { b };
    let skip_proof = |r: &mut Reader<'_>, what: &'static str| -> Result<(), CodecError> {
        let len = r.u32(what)? as usize;
        r.take(len, what).map(|_| ())
    };
    r.u32("version")?;
    r.u64("l2_id")?;
    r.take(4 * W_PV_LEN, "w_pvs")?;
    skip_proof(&mut r, "w_proof")?;
    r.take(4 * DEP_PV_LEN, "dep_pvs")?;
    skip_proof(&mut r, "dep_proof")?;
    let n = r.u8("n_members")?;
    if n as usize > MAX_K {
        return Err(CodecError::TooManyMembers(n));
    }
    for _ in 0..n {
        let t = r.u8("member tag")?;
        let tag = tag_of(t).ok_or(CodecError::UnknownTag(t))?;
        r.take(4 * tag.pv_len(), "member pvs")?;
        skip_proof(&mut r, "member proof")?;
    }
    let n_exits = r.u8("n_exits")?;
    let mut exits = Vec::with_capacity(n_exits as usize);
    for _ in 0..n_exits {
        let rkm = r.digest("exit rkm")?;
        let v = r.u64("exit v")?;
        exits.push(Exit { rkm, v });
    }
    r.take(SEQUENCER_SIG_LEN, "sequencer_sig")?;
    r.end()?;
    Ok(exits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{empty_registry_root, genesis_surface};

    fn sample_surface() -> Surface {
        let mut s = genesis_surface(7, &empty_registry_root());
        s.prev = [1, 2, 3, 4];
        s.out.d_cum = 900;
        s.out.e_cum = 40;
        s.out.f3.c_next = 12;
        s.exit_cmt = [5, 6, 7, 8];
        s.commitment = Surface::commit(s.version, s.l2_id, &s.prev, &s.out, &s.newest_anchor, &s.exit_cmt);
        s
    }

    #[test]
    fn digest_bytes_round_trip() {
        for d in [[0u64; 4], [1, 2, 3, 4], [u64::MAX, 0, u64::MAX >> 1, 0x0123_4567_89ab_cdef]] {
            assert_eq!(digest_from_bytes(&digest_to_bytes(&d)), d);
        }
        // Lane 0 first, little-endian.
        assert_eq!(digest_to_bytes(&[1, 0, 0, 0])[0], 1);
        assert_eq!(digest_to_bytes(&[0, 1, 0, 0])[8], 1);
    }

    #[test]
    fn surface_round_trips_at_its_fixed_length() {
        let s = sample_surface();
        let b = encode_surface(&s);
        assert_eq!(b.len(), SURFACE_LEN);
        assert_eq!(decode_surface(&b), Ok(s));
        let g = genesis_surface(1, &empty_registry_root());
        assert_eq!(decode_surface(&encode_surface(&g)), Ok(g));
    }

    #[test]
    fn surface_decode_refuses_every_malformation() {
        let b = encode_surface(&sample_surface());
        assert_eq!(decode_surface(&b[..SURFACE_LEN - 1]), Err(CodecError::Truncated("commitment")));
        assert_eq!(decode_surface(&[]), Err(CodecError::Truncated("version")));
        let mut long = b.to_vec();
        long.push(0);
        assert_eq!(decode_surface(&long), Err(CodecError::Trailing));
        // Any field changed without its commitment: refused.
        for at in [0, 4, 12, 44, 300, SURFACE_LEN - 33] {
            let mut t = b;
            t[at] ^= 1;
            assert_eq!(decode_surface(&t), Err(CodecError::SurfaceCommitment), "byte {at}");
        }
        // The commitment itself changed: refused.
        let mut t = b;
        t[SURFACE_LEN - 1] ^= 1;
        assert_eq!(decode_surface(&t), Err(CodecError::SurfaceCommitment));
    }

    #[test]
    fn exit_chain_sum_and_shape() {
        let a = Exit { rkm: [1, 0, 0, 0], v: 40 };
        let b = Exit { rkm: [2, 0, 0, 0], v: 2 };
        assert_eq!(exit_chain(&[]), EMPTY);
        assert_eq!(exit_chain(&[a]), h4(&exit_state(&EMPTY, &a.rkm, 40)));
        assert_ne!(exit_chain(&[a, b]), exit_chain(&[b, a]), "order binds");
        assert_eq!(exit_sum(&[a, b]), Some(42));
        assert_eq!(exit_sum(&[Exit { rkm: a.rkm, v: u64::MAX }, b]), None);
        assert_eq!(check_exit_shape(&[a, b], 8), Ok(()));
        assert_eq!(check_exit_shape(&[a; 9], 8), Err(ExitShape::TooMany { n: 9, k_exit: 8 }));
        assert_eq!(check_exit_shape(&[a; 8], 8), Ok(()));
        assert_eq!(check_exit_shape(&[a, Exit { rkm: EMPTY, v: 1 }], 8), Err(ExitShape::ZeroRkm(1)));
        assert_eq!(check_exit_shape(&[Exit { rkm: a.rkm, v: 0 }], 8), Err(ExitShape::ZeroValue(0)));
    }

    #[test]
    fn sign_message_binds_net_l2_id_and_commitment() {
        let (net, c) = ([9u8; 32], [1, 2, 3, 4]);
        let m = sign_message(&net, 1, &c);
        assert!(m.starts_with(BUNDLE_SIG_DOMAIN));
        assert_eq!(m.len(), BUNDLE_SIG_DOMAIN.len() + 72);
        assert_ne!(m, sign_message(&[8u8; 32], 1, &c));
        assert_ne!(m, sign_message(&net, 2, &c));
        assert_ne!(m, sign_message(&net, 1, &[1, 2, 3, 5]));
    }

    /// Pre-review P1: a W PV word ≥ 2^16 has no stated surface (the limb
    /// recomposition would overflow u64); only the exact 16-bit vector does.
    #[test]
    fn stated_surface_refuses_words_wider_than_a_chunk() {
        use crate::wleaf::PV_PREV;
        let mut w = vec![0u32; W_PV_LEN];
        assert!(stated_surface(1, 1, &w).is_some());
        w[PV_PREV + 2] = u32::MAX;
        w[PV_PREV + 3] = u32::MAX;
        assert_eq!(stated_surface(1, 1, &w), None);
        let mut w = vec![0u32; W_PV_LEN];
        w[0] = 1 << 16;
        assert_eq!(stated_surface(1, 1, &w), None);
        assert_eq!(stated_surface(1, 1, &vec![0u32; W_PV_LEN - 1]), None);
    }

    /// The prefix read: truncated inside the prefix is named; a prefix whose
    /// words are 16-bit chunks states the surface `stated_surface` does, and
    /// anything after the prefix is not read.
    #[test]
    fn the_prefix_read_states_the_surface_from_the_first_bytes() {
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(stated_surface_prefix(&b), Err(CodecError::Truncated("w_pvs")));
        let words = vec![3u32; W_PV_LEN];
        words.iter().for_each(|w| b.extend_from_slice(&w.to_le_bytes()));
        let want = stated_surface(1, 7, &words);
        assert!(want.is_some());
        assert_eq!(stated_surface_prefix(&b), Ok(want.clone()));
        b.extend_from_slice(&[0xff; 64]);
        assert_eq!(stated_surface_prefix(&b), Ok(want), "the tail is not read");
        let mut wide = b.clone();
        wide[12..16].copy_from_slice(&(1u32 << 16).to_le_bytes());
        assert_eq!(stated_surface_prefix(&wide), Ok(None));
    }

    /// The bundle codec's refusals up to the first proof, from a prefix
    /// (the proof-bearing round trip needs a real prove and lives in
    /// qlab-bench's F4 fixture tests).
    #[test]
    fn bundle_decode_refuses_short_and_oversized_prefixes() {
        assert!(matches!(WireBundle::decode(&[]), Err(CodecError::Truncated("version"))));
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u64.to_le_bytes());
        assert!(matches!(WireBundle::decode(&b), Err(CodecError::Truncated("w_pvs"))));
        b.extend(std::iter::repeat_n(0u8, 4 * W_PV_LEN));
        // The #793 class: a length prefix far past the input refuses before
        // anything is allocated.
        let mut huge = b.clone();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(WireBundle::decode(&huge), Err(CodecError::Truncated("w_proof"))));
        // A proof that is not a proof.
        let mut junk = b.clone();
        junk.extend_from_slice(&3u32.to_le_bytes());
        junk.extend_from_slice(&[1, 2, 3]);
        assert!(matches!(WireBundle::decode(&junk), Err(CodecError::ProofDecode("w_proof"))));
    }

    /// Lab #785 F5-5d: `exit_list` reads the clear exits past proofs it
    /// never decodes, and refuses by name a bundle that ends early, a length
    /// that points past the end, an unknown member tag, and trailing bytes.
    /// (That it equals `WireBundle::decode(..).exits` on a real bundle is
    /// qlab-bench's F4 fixture test.)
    #[test]
    fn exit_list_skips_proofs_by_length_and_refuses_by_name() {
        let tag = WTag::C;
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&7u64.to_le_bytes());
        b.extend(std::iter::repeat_n(0u8, 4 * W_PV_LEN));
        let opaque = |b: &mut Vec<u8>, n: usize| {
            b.extend_from_slice(&(n as u32).to_le_bytes());
            b.extend(std::iter::repeat_n(0xAB, n));
        };
        opaque(&mut b, 11); // not a proof: never decoded
        b.extend(std::iter::repeat_n(0u8, 4 * DEP_PV_LEN));
        opaque(&mut b, 5);
        b.push(1);
        b.push(tag.byte());
        b.extend(std::iter::repeat_n(0u8, 4 * tag.pv_len()));
        opaque(&mut b, 3);
        let head = b.clone();
        let exits = [Exit { rkm: [1, 2, 3, 4], v: 9 }, Exit { rkm: [5, 0, 0, 0], v: 1 }];
        b.push(exits.len() as u8);
        for e in &exits {
            b.extend_from_slice(&digest_to_bytes(&e.rkm));
            b.extend_from_slice(&e.v.to_le_bytes());
        }
        b.extend(std::iter::repeat_n(0u8, SEQUENCER_SIG_LEN));
        assert_eq!(exit_list(&b), Ok(exits.to_vec()));
        assert!(matches!(WireBundle::decode(&b), Err(CodecError::ProofDecode("w_proof"))), "decode reads the proofs");

        assert_eq!(exit_list(&b[..b.len() - 1]), Err(CodecError::Truncated("sequencer_sig")));
        assert_eq!(exit_list(&head), Err(CodecError::Truncated("n_exits")));
        let mut long = b.clone();
        long.push(0);
        assert_eq!(exit_list(&long), Err(CodecError::Trailing));
        // A proof length pointing past the end: refused, nothing allocated.
        let mut past = b[..12 + 4 * W_PV_LEN].to_vec();
        past.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(exit_list(&past), Err(CodecError::Truncated("w_proof")));
        let mut unknown = b.clone();
        let at = 12 + 4 * W_PV_LEN + 4 + 11 + 4 * DEP_PV_LEN + 4 + 5 + 1;
        unknown[at] = 0xEE;
        assert_eq!(exit_list(&unknown), Err(CodecError::UnknownTag(0xEE)));
        let mut many = b.clone();
        many[at - 1] = (MAX_K + 1) as u8;
        assert_eq!(exit_list(&many), Err(CodecError::TooManyMembers((MAX_K + 1) as u8)));
    }
}
