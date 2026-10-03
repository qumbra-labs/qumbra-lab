//! Lab #847 S0 (closes #823) — **`GET /v1/wrapper`**: what a sequencer needs
//! from a V6 node to post its next bundle without guessing.
//!
//! - **`cr`, the record-covered height** — `CR(tip)`, the latest finality
//!   record carried in a body on the applied main chain. The bundle rule
//!   judges every absorbed root against the record, not against the node's
//!   local finality, which `/v1/anchors` serves and which can run a cadence or
//!   more ahead of it (#785 F5-6). A wrapper that absorbs only roots at or
//!   below `cr` is not refused on `Anchor(i)` for a record still to come.
//! - **`last_bundle_height` / `last_bundle_id`** — the latest applied bundle's
//!   block and Keccak-256 of its bytes (the `InvKind::Bundle` id). Spacing is
//!   counted from that height, and the id is how a sequencer learns that *its*
//!   bundle landed. Both `null` before the first bundle.
//! - **`tip`** — the applied tip these were read at, in the same answer, so
//!   `tip − last_bundle_height` (the client's spacing arithmetic; the node
//!   serves no derived number) never mixes two moments.
//!
//! ```text
//! {"v":1,"l2_id":<u64>,"tip":<u64>,"cr":<u64>|null,"last_bundle_height":<u64>|null,"last_bundle_id":"<64 hex>"|null}
//! ```
//!
//! **A route of its own on the telemetry listener**, versioned by its own
//! `v` (not `RPC_VERSION`: a pure route addition bumps nothing, the PR #315
//! rule). Only a V6 node serves it; elsewhere it is 404, as
//! `/v1/supply/bridge` is. The layout is canonical — fixed field order,
//! canonical decimals, lower-case hex, no whitespace — and [`parse`] reads
//! exactly it and refuses anything else by name, an unknown `v` included:
//! this answer decides when a sequencer posts and what it absorbs, and the
//! node is its only producer.

/// The route.
pub const WRAPPER_PATH: &str = "/v1/wrapper";

/// The only `/v1/wrapper` version this build writes and reads.
pub const WRAPPER_ROUTE_VERSION: u32 = 1;

/// One `/v1/wrapper` answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapperView {
    /// The one `l2_id` this net's wrapper rule enforces.
    pub l2_id: u64,
    /// The applied tip the other fields were read at.
    pub tip: u64,
    /// `CR(tip)`: the latest recorded finality height; `None` before the
    /// first record (then no bundle can pass the anchor rule at all).
    pub cr: Option<u64>,
    /// The latest applied bundle-carrying block; `None` before the first.
    pub last_bundle_height: Option<u64>,
    /// Keccak-256 of that bundle's bytes; present exactly when the height is.
    pub last_bundle_id: Option<[u8; 32]>,
}

impl WrapperView {
    /// The relations every answer holds: a record and a bundle both name a
    /// block at or below the tip, and the id is present exactly when the
    /// height is. [`parse`] refuses a body that breaks one; the node builds
    /// its answer from one snapshot, so it never writes one.
    pub fn check(&self) -> Result<(), String> {
        if let Some(cr) = self.cr {
            if cr > self.tip {
                return Err(format!("/v1/wrapper: cr {cr} is above the tip {}", self.tip));
            }
        }
        if let Some(h) = self.last_bundle_height {
            if h > self.tip {
                return Err(format!("/v1/wrapper: last_bundle_height {h} is above the tip {}", self.tip));
            }
        }
        if self.last_bundle_height.is_some() != self.last_bundle_id.is_some() {
            return Err("/v1/wrapper: last_bundle_height and last_bundle_id must both be present or both null".into());
        }
        Ok(())
    }

    /// The canonical body.
    pub fn to_body(&self) -> Vec<u8> {
        let opt = |v: Option<u64>| v.map_or("null".to_string(), |v| v.to_string());
        let id = self.last_bundle_id.map_or("null".to_string(), |id| {
            let mut s = String::with_capacity(66);
            s.push('"');
            for b in id {
                s.push_str(&format!("{b:02x}"));
            }
            s.push('"');
            s
        });
        format!(
            r#"{{"v":{WRAPPER_ROUTE_VERSION},"l2_id":{},"tip":{},"cr":{},"last_bundle_height":{},"last_bundle_id":{}}}"#,
            self.l2_id,
            self.tip,
            opt(self.cr),
            opt(self.last_bundle_height),
            id,
        )
        .into_bytes()
    }
}

/// Read a `/v1/wrapper` body — **exactly** [`WrapperView::to_body`]'s layout,
/// field by field in order, then [`WrapperView::check`]. Total: every input,
/// truncated or hostile, is an `Err` naming what is wrong, never a panic.
pub fn parse(body: &[u8]) -> Result<WrapperView, String> {
    let s = std::str::from_utf8(body).map_err(|_| "/v1/wrapper: not UTF-8".to_string())?;
    let rest = s.strip_prefix(r#"{"v":"#).ok_or("/v1/wrapper: not a /v1/wrapper answer")?;
    let (v, rest) = rest.split_once(',').ok_or("/v1/wrapper: truncated after v")?;
    if v != WRAPPER_ROUTE_VERSION.to_string() {
        return Err(format!(
            "/v1/wrapper answered version {v}; this build reads only version {WRAPPER_ROUTE_VERSION}"
        ));
    }
    let rest = rest.strip_prefix(r#""l2_id":"#).ok_or("/v1/wrapper: l2_id missing")?;
    let (l2_id, rest) = rest.split_once(',').ok_or("/v1/wrapper: truncated after l2_id")?;
    let l2_id = decimal("l2_id", l2_id)?;
    let rest = rest.strip_prefix(r#""tip":"#).ok_or("/v1/wrapper: tip missing")?;
    let (tip, rest) = rest.split_once(',').ok_or("/v1/wrapper: truncated after tip")?;
    let tip = decimal("tip", tip)?;
    let rest = rest.strip_prefix(r#""cr":"#).ok_or("/v1/wrapper: cr missing")?;
    let (cr, rest) = rest.split_once(',').ok_or("/v1/wrapper: truncated after cr")?;
    let cr = nullable("cr", cr)?;
    let rest = rest.strip_prefix(r#""last_bundle_height":"#).ok_or("/v1/wrapper: last_bundle_height missing")?;
    let (h, rest) = rest.split_once(',').ok_or("/v1/wrapper: truncated after last_bundle_height")?;
    let last_bundle_height = nullable("last_bundle_height", h)?;
    let rest = rest.strip_prefix(r#""last_bundle_id":"#).ok_or("/v1/wrapper: last_bundle_id missing")?;
    let id = rest.strip_suffix('}').ok_or("/v1/wrapper: unterminated, or bytes after last_bundle_id")?;
    let last_bundle_id = if id == "null" {
        None
    } else {
        let hex = id
            .strip_prefix('"')
            .and_then(|h| h.strip_suffix('"'))
            .ok_or("/v1/wrapper: last_bundle_id is neither null nor a string")?;
        Some(hex32("last_bundle_id", hex)?)
    };
    let view = WrapperView { l2_id, tip, cr, last_bundle_height, last_bundle_id };
    view.check()?;
    Ok(view)
}

/// A canonical decimal `u64`: digits only, no sign, no leading zero.
fn decimal(field: &str, s: &str) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return Err(format!("/v1/wrapper: {field} {s:?} is not a canonical decimal"));
    }
    s.parse().map_err(|_| format!("/v1/wrapper: {field} {s} does not fit a u64"))
}

fn nullable(field: &str, s: &str) -> Result<Option<u64>, String> {
    if s == "null" {
        Ok(None)
    } else {
        decimal(field, s).map(Some)
    }
}

/// Exactly 64 lower-case hex digits.
fn hex32(field: &str, h: &str) -> Result<[u8; 32], String> {
    // Byte-indexed below, so anything but 64 ASCII bytes is refused first —
    // a multi-byte character must never split a pair (and panic).
    if h.len() != 64 || !h.is_ascii() {
        return Err(format!("/v1/wrapper: {field} is not 64 lower-case hex digits"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = &h[2 * i..2 * i + 2];
        if !pair.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(format!("/v1/wrapper: {field} is not 64 lower-case hex digits"));
        }
        *b = u8::from_str_radix(pair, 16).map_err(|_| format!("/v1/wrapper: {field} is not hex"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn landed() -> WrapperView {
        WrapperView { l2_id: 1, tip: 268, cr: Some(232), last_bundle_height: Some(268), last_bundle_id: Some([0xab; 32]) }
    }

    fn fresh() -> WrapperView {
        WrapperView { l2_id: 1, tip: 0, cr: None, last_bundle_height: None, last_bundle_id: None }
    }

    /// The layout is pinned byte for byte: the strict reader is the other half
    /// of this string, so a drift on either side must be a red test here.
    #[test]
    fn the_body_is_canonical() {
        assert_eq!(
            String::from_utf8(landed().to_body()).unwrap(),
            format!(
                r#"{{"v":1,"l2_id":1,"tip":268,"cr":232,"last_bundle_height":268,"last_bundle_id":"{}"}}"#,
                "ab".repeat(32)
            )
        );
        assert_eq!(
            String::from_utf8(fresh().to_body()).unwrap(),
            r#"{"v":1,"l2_id":1,"tip":0,"cr":null,"last_bundle_height":null,"last_bundle_id":null}"#
        );
    }

    #[test]
    fn every_answer_round_trips() {
        for view in [
            landed(),
            fresh(),
            WrapperView { cr: Some(40), last_bundle_height: None, last_bundle_id: None, ..landed() },
            WrapperView { l2_id: u64::MAX, tip: u64::MAX, cr: Some(u64::MAX), last_bundle_height: Some(0), last_bundle_id: Some([0; 32]) },
        ] {
            assert_eq!(parse(&view.to_body()), Ok(view));
        }
    }

    /// An unknown version is refused by name — the reader never guesses at a
    /// layout it was not built for.
    #[test]
    fn an_unknown_version_is_refused_by_name() {
        let body = String::from_utf8(fresh().to_body()).unwrap().replacen(r#""v":1"#, r#""v":2"#, 1);
        let err = parse(body.as_bytes()).unwrap_err();
        assert!(err.contains("version 2") && err.contains("only version 1"), "{err}");
    }

    /// Every strict prefix of a valid body is refused, never accepted and
    /// never a panic; so is any trailing byte.
    #[test]
    fn every_truncation_and_any_tail_is_refused() {
        let body = landed().to_body();
        for n in 0..body.len() {
            assert!(parse(&body[..n]).is_err(), "prefix of {n} bytes accepted");
        }
        for tail in [" ", "\n", "}", ",", "x"] {
            let mut b = body.clone();
            b.extend_from_slice(tail.as_bytes());
            assert!(parse(&b).is_err(), "tail {tail:?} accepted");
        }
    }

    #[test]
    fn non_canonical_fields_are_refused_by_name() {
        let good = String::from_utf8(landed().to_body()).unwrap();
        let cases = [
            (good.replacen(r#""tip":268"#, r#""tip":0268"#, 1), "tip"),
            (good.replacen(r#""tip":268"#, r#""tip":-268"#, 1), "tip"),
            (good.replacen(r#""tip":268"#, r#""tip":18446744073709551616"#, 1), "does not fit"),
            (good.replacen(r#""cr":232"#, r#""cr":"232""#, 1), "cr"),
            (good.replacen(&"ab".repeat(32), &"AB".repeat(32), 1), "lower-case hex"),
            (good.replacen(&"ab".repeat(32), &"ab".repeat(31), 1), "64 lower-case hex"),
            (good.replacen(&"ab".repeat(32), &format!("{}é", "ab".repeat(31)), 1), "64 lower-case hex"),
            (good.replacen(r#","tip""#, r#", "tip""#, 1), "tip missing"),
            (good.replacen(r#""l2_id":1,"tip":268,"#, r#""tip":268,"l2_id":1,"#, 1), "l2_id missing"),
        ];
        for (body, why) in cases {
            let err = parse(body.as_bytes()).unwrap_err();
            assert!(err.contains(why), "{body}: {err}");
        }
        assert!(parse(&[0xff, 0xfe]).unwrap_err().contains("not UTF-8"));
    }

    /// The relations are checked on read: a body whose heights or presence
    /// disagree is refused, so a reader never acts on a contradiction.
    #[test]
    fn contradictions_are_refused() {
        let cases = [
            (WrapperView { cr: Some(269), ..landed() }, "cr 269 is above the tip"),
            (WrapperView { last_bundle_height: Some(269), ..landed() }, "last_bundle_height 269 is above the tip"),
            (WrapperView { last_bundle_id: None, ..landed() }, "both present or both null"),
            (WrapperView { last_bundle_height: None, ..landed() }, "both present or both null"),
        ];
        for (view, why) in cases {
            assert!(view.check().unwrap_err().contains(why));
            assert!(parse(&view.to_body()).unwrap_err().contains(why));
        }
    }
}
