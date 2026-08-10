//! QR rendering for payment URIs (lab #342 stage 2).
//!
//! The matrix comes from the `qrcode` crate (v0.14, pure Rust, zero transitive
//! deps with default features off); both renderings are emitted by hand here —
//! Unicode half-blocks for the terminal, plain-text SVG for a file — so no
//! `image`/PNG stack and no render feature of the encoder is pulled in.
//!
//! **Error-correction level is L, deliberately.** A full-address URI is
//! `qumbra:` + 1,985 chars + query; QR byte-mode capacity at version 40 is
//! 2,953 B only at EC-L (M is 2,331 B — a bare full-address URI would not
//! fit). The URI's bech32m checksum already detects corruption end-to-end, so
//! the QR's own redundancy is not load-bearing. Capacity is arithmetic, and
//! [`tests::capacity_boundary_is_2953`] asserts it rather than trusting this
//! comment.
//!
//! Terminal rendering paints **dark modules as ink** (`█`), the printed-page
//! convention — correct wherever the foreground is darker than the background.
//! On an inverted (light-on-dark) terminal a scanner may need the terminal
//! theme flipped; the CLI prints the URI text beside the QR either way, so the
//! QR is never the only path.

use qrcode::types::Color;
use qrcode::{EcLevel, QrCode};

/// QR byte-mode capacity at version 40, EC level L — the largest input any
/// QR code can carry. Locked by test against the encoder's actual refusal
/// boundary.
pub const QR_MAX_BYTES: usize = 2953;

/// Modules of quiet zone on each side (the QR spec asks for 4).
const QUIET: usize = 4;

/// Typed render errors — an over-capacity input is a refusal, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrRenderError {
    /// The data does not fit any QR version at EC-L (byte-mode max
    /// [`QR_MAX_BYTES`]). Carries the offending length so the caller can say
    /// how far over it is (a long memo is the usual cause).
    TooLong { len: usize },
    /// Any other encoder refusal (unreachable for byte-mode inputs under the
    /// capacity bound, kept typed rather than swallowed).
    Encoder(String),
}

impl std::fmt::Display for QrRenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QrRenderError::TooLong { len } => write!(
                f,
                "{len} bytes does not fit a QR code (byte-mode capacity is {QR_MAX_BYTES} at \
                 EC-L) — a long memo or label is the usual cause; shorten it or share the URI \
                 as text"
            ),
            QrRenderError::Encoder(e) => write!(f, "QR encoding failed: {e}"),
        }
    }
}

impl std::error::Error for QrRenderError {}

/// The dark/light matrix plus its width, one source for both renderers.
fn matrix(data: &str) -> Result<(Vec<Color>, usize), QrRenderError> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L).map_err(|e| match e {
        qrcode::types::QrError::DataTooLong => QrRenderError::TooLong { len: data.len() },
        other => QrRenderError::Encoder(other.to_string()),
    })?;
    let width = code.width();
    Ok((code.to_colors(), width))
}

/// Render to Unicode half-blocks (two module rows per text line), quiet zone
/// included. Dark modules are ink (`█`/`▀`/`▄`); light modules are spaces.
pub fn render_unicode(data: &str) -> Result<String, QrRenderError> {
    let (colors, width) = matrix(data)?;
    let side = width + 2 * QUIET;
    let dark = |x: usize, y: usize| -> bool {
        let (Some(mx), Some(my)) = (x.checked_sub(QUIET), y.checked_sub(QUIET)) else {
            return false;
        };
        if mx >= width || my >= width {
            return false;
        }
        colors[my * width + mx] == Color::Dark
    };
    let mut out = String::with_capacity((side + 1) * side.div_ceil(2) * 3);
    for y in (0..side).step_by(2) {
        for x in 0..side {
            let upper = dark(x, y);
            let lower = y + 1 < side && dark(x, y + 1);
            out.push(match (upper, lower) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
    }
    Ok(out)
}

/// Render to a standalone SVG document (plain text, dependency-free to emit):
/// one white background rect, one black `<path>` of unit squares, quiet zone
/// included, 4 px per module.
pub fn render_svg(data: &str) -> Result<String, QrRenderError> {
    let (colors, width) = matrix(data)?;
    let side = width + 2 * QUIET;
    const PX: usize = 4;
    let mut path = String::new();
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == Color::Dark {
                // M<x> <y>h1v1h-1z — a unit square in module coordinates.
                path.push_str(&format!("M{} {}h1v1h-1z", x + QUIET, y + QUIET));
            }
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {side} {side}\" \
         width=\"{w}\" height=\"{w}\" shape-rendering=\"crispEdges\">\n\
         <rect width=\"{side}\" height=\"{side}\" fill=\"#ffffff\"/>\n\
         <path d=\"{path}\" fill=\"#000000\"/>\n\
         </svg>\n",
        w = side * PX,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qlab_wallet::address::Address;
    use qlab_wallet::uri;

    /// Same fixed-bytes construction as `qlab_wallet::uri`'s golden address:
    /// version 1, then `(7i + 3) % 256`. URI/QR work never needs a valid key.
    fn golden_address() -> Address {
        let mut raw = vec![0u8; Address::RAW_LEN];
        raw[0] = 1;
        for (i, b) in raw.iter_mut().enumerate().skip(1) {
            *b = ((7 * i + 3) % 256) as u8;
        }
        Address::from_raw_bytes(&raw).expect("fixed golden bytes decode")
    }

    /// The frozen 1 QMB = 10⁸ bessel constant is defined twice by design —
    /// `qlab-wallet` takes no dependency, `qlab-node` owns the consensus copy.
    /// This is the cross-lock the URI module's docs promise.
    #[test]
    fn bessel_per_qmb_matches_the_consensus_constant() {
        assert_eq!(uri::BESSEL_PER_QMB, qlab_node::emission::BESSEL_PER_QMB);
    }

    /// The task book's arithmetic, asserted: a bare address is 1,985 chars,
    /// the URI wrapper adds ≥ 7 (`qumbra:`), and byte-mode capacity at
    /// version 40 EC-L is 2,953 B — so a full-address URI MUST encode.
    #[test]
    fn full_address_uri_encodes() {
        let addr = golden_address();
        let full = uri::encode(&addr, Some(150_000_000), Some("rent"), Some(b"unit 4B"));
        assert!(full.len() >= 1_985 + 7, "premise: {} chars", full.len());
        assert!(full.len() <= QR_MAX_BYTES, "premise: fits v40 EC-L");
        render_unicode(&full).expect("terminal render");
        render_svg(&full).expect("svg render");
    }

    /// Capacity is arithmetic: 2,953 B encodes, 2,954 B is a typed error —
    /// never a panic. This also locks EC-L as the level in use (at EC-M the
    /// boundary would be 2,331 and the first assertion would fail).
    #[test]
    fn capacity_boundary_is_2953() {
        let at = "q".repeat(QR_MAX_BYTES);
        render_unicode(&at).expect("exactly at capacity encodes");
        let over = "q".repeat(QR_MAX_BYTES + 1);
        assert_eq!(
            render_unicode(&over).unwrap_err(),
            QrRenderError::TooLong { len: QR_MAX_BYTES + 1 }
        );
        assert_eq!(
            render_svg(&over).unwrap_err(),
            QrRenderError::TooLong { len: QR_MAX_BYTES + 1 }
        );
        // An over-capacity URI (long memo) is the real-world shape of this.
        let memo = vec![b'm'; 3000];
        let uri = uri::encode(&golden_address(), None, None, Some(&memo));
        assert!(matches!(render_unicode(&uri).unwrap_err(), QrRenderError::TooLong { .. }));
    }

    #[test]
    fn unicode_render_shape() {
        let s = render_unicode("qumbra:test").expect("small render");
        let lines: Vec<&str> = s.lines().collect();
        // v1 QR is 21 modules; + 8 quiet = 29 → 15 half-block lines of 29 chars.
        assert_eq!(lines.len(), 15);
        assert!(lines.iter().all(|l| l.chars().count() == 29), "rectangular");
        assert!(
            s.chars().all(|c| matches!(c, '█' | '▀' | '▄' | ' ' | '\n')),
            "only half-block glyphs"
        );
        // Quiet zone: the first two text lines (4 module rows) are blank.
        assert!(lines[0].chars().all(|c| c == ' '));
        assert!(lines[1].chars().all(|c| c == ' '));
        // A finder pattern makes the first content line start dark after the
        // quiet zone (module (0,0) and (0,1) are both finder-border dark).
        assert_eq!(lines[2].chars().nth(QUIET), Some('█'));
    }

    #[test]
    fn svg_render_shape() {
        let s = render_svg("qumbra:test").expect("small svg");
        assert!(s.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(s.trim_end().ends_with("</svg>"));
        // 21 modules + 8 quiet.
        assert!(s.contains("viewBox=\"0 0 29 29\""));
        // Exactly one background rect and one ink path; ink is present.
        assert_eq!(s.matches("<rect").count(), 1);
        assert_eq!(s.matches("<path").count(), 1);
        assert!(s.contains("h1v1h-1z"));
    }
}
