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
//! - **`anchors`** (v2, lab #847 S0b) — the facts V7 judges an absorbed root
//!   by: every commitment root at a height in the anchor window of the next
//!   block (`tip + 1 − MAX_ANCHOR_AGE_BLOCKS ..= tip`), each with the
//!   ascending heights it was the root at, newest first. The node serves the
//!   facts, not the conclusion: a sequencer selects with
//!   [`WrapperView::absorbable`], which calls the consensus rule itself
//!   (`qlab_devnet::body::v6_anchor_ok(heights, tip + 1, cr)`) — one rule in
//!   one place. The cut-off is the next block, `tip + 1`: a bundle mined later
//!   ages its roots, and one that ages out is refused `Anchor(i)` and
//!   re-planned (the sequencer's bounded re-post).
//!
//! ```text
//! {"v":2,"l2_id":<u64>,"tip":<u64>,"cr":<u64>|null,"last_bundle_height":<u64>|null,
//!  "last_bundle_id":"<64 hex>"|null,"anchors":[{"root":"<64 hex>","heights":[<u64>,…]},…]}
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

/// The only `/v1/wrapper` version this build writes and reads. 2 since lab
/// #847 S0b added `anchors` (the strict reader pins the layout, so an added
/// field is a new version).
pub const WRAPPER_ROUTE_VERSION: u32 = 2;

/// One commitment root in the anchor window and the heights it was the root
/// at, ascending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorFact {
    pub root: [u8; 32],
    pub heights: Vec<u64>,
}

/// One `/v1/wrapper` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The anchor window's roots and their heights, newest first.
    pub anchors: Vec<AnchorFact>,
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
        let mut newest_prev: Option<u64> = None;
        for (i, a) in self.anchors.iter().enumerate() {
            let Some(&last) = a.heights.last() else {
                return Err(format!("/v1/wrapper: anchor {i} names no height"));
            };
            if a.heights.windows(2).any(|w| w[0] >= w[1]) {
                return Err(format!("/v1/wrapper: anchor {i}'s heights are not strictly ascending"));
            }
            if last > self.tip {
                return Err(format!("/v1/wrapper: anchor {i} names height {last}, above the tip {}", self.tip));
            }
            if newest_prev.is_some_and(|p| last >= p) {
                return Err(format!("/v1/wrapper: anchor {i} is not older than the one before it"));
            }
            newest_prev = Some(last);
            if self.anchors[..i].iter().any(|b| b.root == a.root) {
                return Err(format!("/v1/wrapper: anchor {i}'s root appears twice"));
            }
        }
        Ok(())
    }

    /// The roots a bundle in the **next** block (`tip + 1`) may absorb,
    /// newest first: those V7 accepts — `v6_anchor_ok(heights, tip + 1, cr)`,
    /// the consensus rule itself, never a re-derivation. Empty before the
    /// first finality record (no root passes without one).
    pub fn absorbable(&self) -> Vec<[u8; 32]> {
        self.anchors
            .iter()
            .filter(|a| qlab_devnet::body::v6_anchor_ok(&a.heights, self.tip.saturating_add(1), self.cr))
            .map(|a| a.root)
            .collect()
    }

    /// The canonical body.
    pub fn to_body(&self) -> Vec<u8> {
        let opt = |v: Option<u64>| v.map_or("null".to_string(), |v| v.to_string());
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let id = self.last_bundle_id.map_or("null".to_string(), |id| format!("\"{}\"", hex(&id)));
        let anchors: Vec<String> = self
            .anchors
            .iter()
            .map(|a| {
                let hs: Vec<String> = a.heights.iter().map(u64::to_string).collect();
                format!(r#"{{"root":"{}","heights":[{}]}}"#, hex(&a.root), hs.join(","))
            })
            .collect();
        format!(
            r#"{{"v":{WRAPPER_ROUTE_VERSION},"l2_id":{},"tip":{},"cr":{},"last_bundle_height":{},"last_bundle_id":{},"anchors":[{}]}}"#,
            self.l2_id,
            self.tip,
            opt(self.cr),
            opt(self.last_bundle_height),
            id,
            anchors.join(","),
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
    let (last_bundle_id, rest) = if let Some(rest) = rest.strip_prefix("null") {
        (None, rest)
    } else {
        let r = rest.strip_prefix('"').ok_or("/v1/wrapper: last_bundle_id is neither null nor a string")?;
        let (h, r) = r.split_once('"').ok_or("/v1/wrapper: last_bundle_id unterminated")?;
        (Some(hex32("last_bundle_id", h)?), r)
    };
    let mut rest = rest.strip_prefix(r#","anchors":["#).ok_or("/v1/wrapper: anchors missing")?;
    let mut anchors = Vec::new();
    if let Some(r) = rest.strip_prefix(']') {
        rest = r;
    } else {
        loop {
            let i = anchors.len();
            let r = rest.strip_prefix(r#"{"root":""#).ok_or_else(|| format!("/v1/wrapper: anchor {i} is malformed"))?;
            let (h, r) = r.split_once('"').ok_or_else(|| format!("/v1/wrapper: anchor {i}'s root unterminated"))?;
            let root = hex32("anchor root", h)?;
            let r = r.strip_prefix(r#","heights":["#).ok_or_else(|| format!("/v1/wrapper: anchor {i}'s heights missing"))?;
            let (hs, r) = r.split_once("]}").ok_or_else(|| format!("/v1/wrapper: anchor {i}'s heights unterminated"))?;
            let heights = if hs.is_empty() {
                Vec::new()
            } else {
                hs.split(',').map(|h| decimal("anchor height", h)).collect::<Result<Vec<u64>, String>>()?
            };
            anchors.push(AnchorFact { root, heights });
            if let Some(r) = r.strip_prefix(',') {
                rest = r;
            } else {
                rest = r.strip_prefix(']').ok_or_else(|| format!("/v1/wrapper: the anchor list is malformed after anchor {i}"))?;
                break;
            }
        }
    }
    if rest != "}" {
        return Err("/v1/wrapper: unterminated, or bytes after anchors".into());
    }
    let view = WrapperView { l2_id, tip, cr, last_bundle_height, last_bundle_id, anchors };
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
        WrapperView {
            l2_id: 1,
            tip: 268,
            cr: Some(232),
            last_bundle_height: Some(268),
            last_bundle_id: Some([0xab; 32]),
            anchors: vec![
                AnchorFact { root: [1; 32], heights: vec![240, 241] },
                AnchorFact { root: [2; 32], heights: vec![230] },
            ],
        }
    }

    fn fresh() -> WrapperView {
        WrapperView { l2_id: 1, tip: 0, cr: None, last_bundle_height: None, last_bundle_id: None, anchors: Vec::new() }
    }

    /// The layout is pinned byte for byte: the strict reader is the other half
    /// of this string, so a drift on either side must be a red test here.
    #[test]
    fn the_body_is_canonical() {
        assert_eq!(
            String::from_utf8(landed().to_body()).unwrap(),
            format!(
                r#"{{"v":2,"l2_id":1,"tip":268,"cr":232,"last_bundle_height":268,"last_bundle_id":"{}","anchors":[{{"root":"{}","heights":[240,241]}},{{"root":"{}","heights":[230]}}]}}"#,
                "ab".repeat(32),
                "01".repeat(32),
                "02".repeat(32)
            )
        );
        assert_eq!(
            String::from_utf8(fresh().to_body()).unwrap(),
            r#"{"v":2,"l2_id":1,"tip":0,"cr":null,"last_bundle_height":null,"last_bundle_id":null,"anchors":[]}"#
        );
    }

    #[test]
    fn every_answer_round_trips() {
        for view in [
            landed(),
            fresh(),
            WrapperView { cr: Some(40), last_bundle_height: None, last_bundle_id: None, ..landed() },
            WrapperView {
                l2_id: u64::MAX,
                tip: u64::MAX,
                cr: Some(u64::MAX),
                last_bundle_height: Some(0),
                last_bundle_id: Some([0; 32]),
                anchors: vec![AnchorFact { root: [0; 32], heights: vec![0, u64::MAX] }],
            },
        ] {
            assert_eq!(parse(&view.to_body()), Ok(view));
        }
    }

    /// Another version — v1 included, the layout before `anchors` — is
    /// refused by name: the reader never guesses at a layout it was not built
    /// for.
    #[test]
    fn an_unknown_version_is_refused_by_name() {
        let v1 = r#"{"v":1,"l2_id":1,"tip":0,"cr":null,"last_bundle_height":null,"last_bundle_id":null}"#;
        let err = parse(v1.as_bytes()).unwrap_err();
        assert!(err.contains("version 1") && err.contains("only version 2"), "{err}");
        let v3 = String::from_utf8(fresh().to_body()).unwrap().replacen(r#""v":2"#, r#""v":3"#, 1);
        assert!(parse(v3.as_bytes()).unwrap_err().contains("version 3"));
    }

    /// Selection is the consensus rule's: the newest root, whose only height
    /// is above CR, is skipped; a root past the anchor window of the next
    /// block is skipped; nothing passes before the first record.
    #[test]
    fn absorbable_is_v6_anchor_ok_at_the_next_block() {
        let view = WrapperView {
            tip: 2000,
            cr: Some(1500),
            last_bundle_height: None,
            last_bundle_id: None,
            anchors: vec![
                AnchorFact { root: [3; 32], heights: vec![1700] },
                AnchorFact { root: [4; 32], heights: vec![1490, 1500] },
                AnchorFact { root: [5; 32], heights: vec![900] },
                AnchorFact { root: [6; 32], heights: vec![840] },
            ],
            ..fresh()
        };
        assert_eq!(view.check(), Ok(()));
        // 2001 − 900 = 1101 ≤ 1152 passes; 2001 − 840 = 1161 does not.
        assert_eq!(view.absorbable(), vec![[4; 32], [5; 32]]);
        assert_eq!(WrapperView { cr: None, ..view.clone() }.absorbable(), Vec::<[u8; 32]>::new());
        assert_eq!(parse(&view.to_body()).unwrap().absorbable(), vec![[4; 32], [5; 32]]);
        // A served tip at u64::MAX saturates the next block's height rather
        // than wrapping it to 0 (which would read every root as from the
        // future): the root one block back still passes. Checked by value,
        // so it holds in release, where overflow checks are off.
        let edge = WrapperView {
            tip: u64::MAX,
            cr: Some(u64::MAX - 1),
            anchors: vec![AnchorFact { root: [7; 32], heights: vec![u64::MAX - 1] }],
            ..view.clone()
        };
        assert_eq!(edge.check(), Ok(()));
        assert_eq!(edge.absorbable(), vec![[7; 32]]);
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
        let anchors = |a: Vec<AnchorFact>| WrapperView { anchors: a, ..landed() };
        let cases = [
            (anchors(vec![AnchorFact { root: [1; 32], heights: vec![] }]), "names no height"),
            (anchors(vec![AnchorFact { root: [1; 32], heights: vec![241, 240] }]), "not strictly ascending"),
            (anchors(vec![AnchorFact { root: [1; 32], heights: vec![269] }]), "above the tip"),
            (
                anchors(vec![AnchorFact { root: [1; 32], heights: vec![230] }, AnchorFact { root: [2; 32], heights: vec![240] }]),
                "not older than the one before it",
            ),
            (
                anchors(vec![AnchorFact { root: [1; 32], heights: vec![240] }, AnchorFact { root: [1; 32], heights: vec![230] }]),
                "appears twice",
            ),
            (WrapperView { cr: Some(269), ..landed() }, "cr 269 is above the tip"),
            (WrapperView { last_bundle_height: Some(269), ..landed() }, "last_bundle_height 269 is above the tip"),
            (WrapperView { last_bundle_id: None, ..landed() }, "must both be present or both null"),
            (WrapperView { last_bundle_height: None, ..landed() }, "must both be present or both null"),
        ];
        for (view, why) in cases {
            assert!(view.check().unwrap_err().contains(why));
            assert!(parse(&view.to_body()).unwrap_err().contains(why));
        }
    }
}
