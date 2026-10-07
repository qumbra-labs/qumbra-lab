//! The prover's admission tokens: [`qlab_prover_token`], re-exported (lab
//! #924 PR 3e — the gateway mints with that crate alone). The tests below
//! are the ones that lived here before the move, unchanged.

pub use qlab_prover_token::*;

#[cfg(test)]
use qlab_remote_auth::Hash32;
#[cfg(test)]
use qlab_wallet::uri::{b64url_decode, b64url_encode};

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: Hash32 = [0x7a; 32];
    const NET: Hash32 = [0x33; 32];
    const NOW: u64 = 1_800_000_000;

    fn claims() -> Claims {
        Claims {
            key_id: 3,
            token_id: [0x11; 16],
            genesis_hash: NET,
            not_before: NOW - 60,
            not_after: NOW + 86_400,
            per_day: 5,
        }
    }

    fn keys() -> TokenKeys {
        TokenKeys::parse(&format!("# issuer\n3 {}\n", hex(&verifying_key(&SEED)))).unwrap()
    }

    #[test]
    fn a_minted_token_verifies_and_states_its_claims() {
        let token = mint(&SEED, &claims()).unwrap();
        assert!(token.len() <= MAX_TOKEN_CHARS, "{} chars", token.len());
        assert_eq!(keys().verify(&token, &NET, NOW), Ok(claims()));
    }

    #[test]
    fn a_token_is_refused_by_name() {
        let token = mint(&SEED, &claims()).unwrap();
        let k = keys();
        assert_eq!(k.verify(&token, &[0x34; 32], NOW), Err("token-wrong-net"));
        assert_eq!(k.verify(&token, &NET, NOW + 86_400), Err("token-expired"));
        assert_eq!(k.verify(&token, &NET, NOW - 61), Err("token-expired"));
        // Another issuer key under the same key_id.
        let forged = mint(&[0x7b; 32], &claims()).unwrap();
        assert_eq!(k.verify(&forged, &NET, NOW), Err("token-signature-invalid"));
        // An unknown key_id.
        let other = mint(
            &SEED,
            &Claims {
                key_id: 4,
                ..claims()
            },
        )
        .unwrap();
        assert_eq!(k.verify(&other, &NET, NOW), Err("token-key-unknown"));
        // A payload byte changed after signing (per_day raised).
        let mut bytes = b64url_decode(token.strip_prefix(TOKEN_PREFIX).unwrap()).unwrap();
        bytes[65] = 200;
        let raised = format!("{TOKEN_PREFIX}{}", b64url_encode(&bytes));
        assert_eq!(k.verify(&raised, &NET, NOW), Err("token-signature-invalid"));
        // Reserved flags.
        bytes[65] = 5;
        bytes[67] = 1;
        let flagged = format!("{TOKEN_PREFIX}{}", b64url_encode(&bytes));
        assert_eq!(k.verify(&flagged, &NET, NOW), Err("token-malformed"));
        // Shape.
        assert_eq!(k.verify("qpt2.AAAA", &NET, NOW), Err("token-malformed"));
        assert_eq!(
            k.verify(&format!("{token}AAAA"), &NET, NOW),
            Err("token-malformed")
        );
        assert_eq!(
            k.verify(&"a".repeat(MAX_TOKEN_CHARS + 1), &NET, NOW),
            Err("token-malformed")
        );
        // Revoked.
        let mut k = keys();
        k.set_denied(&hex(&[0x11; 16])).unwrap();
        assert_eq!(k.verify(&token, &NET, NOW), Err("token-revoked"));
    }

    #[test]
    fn the_validity_window_is_bounded_at_both_ends() {
        let long = Claims {
            not_after: NOW - 60 + MAX_TOKEN_DAYS * 86_400 + 1,
            ..claims()
        };
        assert_eq!(mint(&SEED, &long), Err("token-window-invalid"));
        let empty = Claims {
            not_after: NOW - 60,
            ..claims()
        };
        assert_eq!(mint(&SEED, &empty), Err("token-window-invalid"));
    }

    #[test]
    fn the_key_file_is_parsed_strictly() {
        let vk = hex(&verifying_key(&SEED));
        assert!(TokenKeys::parse("").is_err());
        assert!(TokenKeys::parse("3 abcd").is_err());
        assert!(TokenKeys::parse(&format!("300 {vk}")).is_err());
        assert!(TokenKeys::parse(&format!("3 {vk}\n3 {vk}")).is_err());
        assert!(keys().set_denied("zz").is_err());
    }
}
