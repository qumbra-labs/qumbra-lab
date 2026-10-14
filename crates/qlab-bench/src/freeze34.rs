//! **Format 34 is frozen** (lab #937 PR F; `docs/annulet-format-34-freeze.md`).
//!
//! The test below holds the frozen values itself, as literals, and compares
//! each production constant against them: it is the second, named place a
//! freeze change must be made by hand. A change to any of these is a **new
//! format version** with its own genesis, never an edit to 34 — a format-34
//! node, wallet, prover or genesis already relies on every value here.
//!
//! It lives in this crate because this crate already depends on every crate
//! that owns one of the values (`qlab-devnet`, `qlab-p2p`, `qlab-l2spend`,
//! `qlab-l2`, `qumbra-node`): the test adds no dependency edge.

#[cfg(test)]
mod tests {
    use qlab_devnet::forms::{annulet_forms_of_genesis_format_version, GenesisForm, L2AuthForm};
    use qumbra_node::annulet_genesis::{AnnuletGenesisBuild, AnnuletGenesisFile};

    const MSG: &str = "format 34 is frozen — a change is a new format version, not an edit to 34";

    #[test]
    fn format_34_is_frozen() {
        // The format number and its axis, both ways.
        assert_eq!(
            qlab_devnet::forms::ANNULET_AUTH_V3_GENESIS_FORMAT_VERSION,
            34,
            "the format-34 genesis format version: {MSG}"
        );
        assert_eq!(
            annulet_forms_of_genesis_format_version(34),
            Some((GenesisForm::Annulet, L2AuthForm::CandidateAV3)),
            "34 → (Annulet, CandidateAV3): {MSG}"
        );
        assert_eq!(L2AuthForm::CandidateAV3.annulet_genesis_format_version(), 34, "CandidateAV3 → 34: {MSG}");
        // Three S/P outputs.
        assert_eq!(L2AuthForm::CandidateAV3.sp_outputs(), 3, "S/P outputs on format 34: {MSG}");
        // The served wire-form byte.
        assert_eq!(
            qlab_p2p::served::wire_form_byte(qlab_p2p::compact::WireForm::ANNULET_AUTH_V3),
            6,
            "the format-34 served wire form id: {MSG}"
        );
        // The three-output proving bundle's version.
        assert_eq!(qlab_l2spend::bundle::BUNDLE_VERSION_THREE_OUTPUTS, 2, "the format-34 bundle version: {MSG}");
        // The v3 shape digests (the AIR's identity; `qlab-l2` recomputes them
        // in `l2_v3_shape_digests_are_pinned`).
        assert_eq!(
            qlab_l2::v3::SHAPE_S_DIGEST_V3,
            "2b65c9d45b626dcbfc02bb49ae9574d5724d87a577a759b0a297ab1e0da015b8",
            "the S v3 shape digest: {MSG}"
        );
        assert_eq!(
            qlab_l2::v3::SHAPE_P_DIGEST_V3,
            "925d542ef83f4f2910394c21c30842bd64f5c17c32fba628fa6f16434b469b34",
            "the P v3 shape digest: {MSG}"
        );
        // The format-34 devnet and rehearsal genesis: built here, hash and size.
        for (name, build, hash, size) in [
            (
                "devnet_v3",
                AnnuletGenesisFile::devnet_v3 as fn() -> AnnuletGenesisFile,
                "7673e01f2902344b902e40ad498e3bf4368e355dffa277669c947fbda700f65e",
                5_241,
            ),
            (
                "devnet_v3_rehearsal",
                AnnuletGenesisFile::devnet_v3_rehearsal,
                "439de6fca8be1efb78996c0a0906e33ae43d854f50d5e299d0dfe6049b541fb5",
                5_251,
            ),
        ] {
            let g = build();
            assert_eq!(g.hash_hex(), hash, "the {name} genesis hash: {MSG}");
            assert_eq!(g.to_bytes().len(), size, "the {name} genesis size: {MSG}");
        }
    }
}
