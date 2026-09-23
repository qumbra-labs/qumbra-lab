//! The Annulet (Qumbra L2) chain form — lab issue #706 (l2-roadmap B1).
//!
//! Everything the Annulet form adds to the devnet chain types lives here, so
//! the L1 forms' modules only ever *refuse* Annulet values, never interpret
//! them:
//!
//! - [`HeaderExt`] — the header fields only an Annulet header carries
//!   (`l1_anchor`, `registry_root`), attached to [`crate::header::BlockHeader`]
//!   as `ext`; [`HeaderExt::NONE`] on every L1 header.
//! - [`L2_SURFACE_ABSENT`] — the canonical "no L2 surface" encoding of
//!   [`crate::body::TxEntry::l2`], under the #367 rider discipline (bytes,
//!   canonical, absence is `[0x00]`, never an empty `Vec`).
//!
//! **Nothing here depends on `qlab-l2`** (lab #706 P7): `qumbra-ffi`'s iOS and
//! wasm builds depend on this crate, and `qlab-l2` would pull the prover stack
//! into them. The shape tag is local; `qumbra-node` cross-locks it against
//! `qlab_l2::Shape`.

/// The Annulet-only header fields (lab #706 Q3, layout (H-a)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnnuletHeaderFields {
    /// Height of the finalized L1 checkpoint this block reads (informational
    /// at Phase 0 — monotone only; B2).
    pub l1_anchor_height: u64,
    /// Root of that L1 checkpoint.
    pub l1_anchor_root: [u8; 32],
    /// The asset-registry root **after** this block (lab #706 Q6); every
    /// transaction's L2 surface binds the **parent** header's root.
    pub registry_root: [u8; 32],
}

/// The per-form header extension. L1 headers carry [`HeaderExt::NONE`]; the
/// v4/v5 serializers refuse anything else by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderExt {
    /// An L1 (v4/v5) header: no extension.
    L1,
    /// An Annulet header's extra fields.
    Annulet(AnnuletHeaderFields),
}

impl HeaderExt {
    /// The extension every L1 header carries.
    pub const NONE: HeaderExt = HeaderExt::L1;
}

/// The canonical encoding of "this transaction carries no L2 surface" —
/// every L1 transaction's [`crate::body::TxEntry::l2`].
pub const L2_SURFACE_ABSENT: &[u8] = &[0x00];
