//! The journal timestamp — one native UTC prefix for every operator-read line
//! (lab #512).
//!
//! The binaries' journal lines (`TELEMETRY`, `ROUND`, `LOOP`, `MINEGATE`,
//! `REPUSH`, `DIAL`, the faucet/explorer request lines, the pool lines) carried
//! no timestamps of their own; operators depended on `docker logs -t`, which
//! makes the same line two different strings with and without the flag — the
//! `^`-anchor trap that cost two wrong findings on 2026-07-31 — and invites the
//! UTC-vs-local labeling trap. From this image on the stamp is native:
//! `YYYY-MM-DDTHH:MM:SS.mmmZ ` (RFC 3339, milliseconds, **always UTC**, labeled
//! by the trailing `Z` — never host-local).
//!
//! This is NOT a log framework. It is one formatting function and two macros
//! that prefix the existing `println!`-class sites; levels, targets and filters
//! stay deliberately absent. It lives in this crate for one reason: every crate
//! that prints a journal line (`qlab-p2p`, `qlab-node`, `qumbra-node`,
//! `qumbra-faucet`, `qumbra-explorer`, `qumbra-pool`) already depends on
//! `qlab-devnet`, feature-free — the one spot below all of them that needs no
//! new crate and no new edge.
//!
//! The stamp is applied **at the print site, never inside a line constructor**:
//! `to_line()`/`journal()`-style strings that tests assert on are byte-for-byte
//! unchanged, and the house grep rule (content anchors, no `^`) keeps working
//! across the cutover because the line's own tokens do not move.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for the current wall clock.
pub fn utc_stamp() -> String {
    utc_stamp_at(SystemTime::now())
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for an arbitrary instant — the testable seam.
///
/// A clock before the epoch renders as the epoch itself rather than panicking:
/// a broken host clock must not stop a node from journaling, same posture as
/// `qlab_node::replay_progress`'s swallowed flush errors.
pub fn utc_stamp_at(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    let (year, month, day) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Proleptic-Gregorian civil date from days since 1970-01-01 (Howard Hinnant's
/// `civil_from_days`, the standard integer-exact algorithm — no floats, per the
/// #303 law on anything a rule or a record might one day lean on).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32; // [1, 12]
    let year = yoe as i64 + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// One journal line: stamp, then the optional severity token, then the body —
/// a single `String` so the stamp, token and line are one write and concurrent
/// writers cannot interleave them. The one format every journal line goes
/// through; the macros below are thin wrappers over it.
pub fn stamped_line(token: Option<&str>, body: std::fmt::Arguments<'_>) -> String {
    match token {
        Some(t) => format!("{} {t} {body}", utc_stamp()),
        None => format!("{} {body}", utc_stamp()),
    }
}

/// `println!` with the journal stamp prefixed — the drop-in for every stdout
/// journal site.
///
/// **Severity tokens (lab #512 amendment, deliberately narrow):** an abnormal
/// line — and only an abnormal line — names its severity as an ASCII token
/// right after the timestamp: `jprintln!(WARN, "…")` for degraded-but-serving
/// (the ⚠️-class), `jprintln!(ERROR, "…")` for the 🔴-class (swallowed-write
/// reports, refusals that indicate operator action). This is NOT log leveling:
/// the journal's line TYPE stays the house's level axis, nothing filters on
/// the token, and a nominal line carries no token — **absence means nominal**.
/// Existing emoji stay in the body for human eyes; the token is for grep/Loki.
/// The token is orthogonal to the stream: severity does not move a line
/// between stdout and stderr.
#[macro_export]
macro_rules! jprintln {
    (WARN, $($arg:tt)*) => {
        ::std::println!("{}", $crate::journal::stamped_line(Some("WARN"), ::std::format_args!($($arg)*)))
    };
    (ERROR, $($arg:tt)*) => {
        ::std::println!("{}", $crate::journal::stamped_line(Some("ERROR"), ::std::format_args!($($arg)*)))
    };
    ($($arg:tt)*) => {
        ::std::println!("{}", $crate::journal::stamped_line(None, ::std::format_args!($($arg)*)))
    };
}

/// `eprintln!` with the journal stamp prefixed — the stderr twin, same
/// severity arms as [`jprintln!`].
#[macro_export]
macro_rules! jeprintln {
    (WARN, $($arg:tt)*) => {
        ::std::eprintln!("{}", $crate::journal::stamped_line(Some("WARN"), ::std::format_args!($($arg)*)))
    };
    (ERROR, $($arg:tt)*) => {
        ::std::eprintln!("{}", $crate::journal::stamped_line(Some("ERROR"), ::std::format_args!($($arg)*)))
    };
    ($($arg:tt)*) => {
        ::std::eprintln!("{}", $crate::journal::stamped_line(None, ::std::format_args!($($arg)*)))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, millis: u32) -> String {
        utc_stamp_at(UNIX_EPOCH + Duration::new(secs, millis * 1_000_000))
    }

    /// Golden vectors at well-known epoch constants — each is a date-math edge
    /// (epoch start, day boundary, a leap day in a leap century year, a year
    /// boundary, and a non-leap century year).
    #[test]
    fn golden_stamps() {
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(86_399, 999), "1970-01-01T23:59:59.999Z");
        // 2000 IS a leap year (divisible by 400): Feb 29 exists.
        assert_eq!(at(951_782_400, 0), "2000-02-29T00:00:00.000Z");
        // 2024-01-01T00:00:00Z is 1_704_067_200; one second earlier is the
        // last instant of 2023.
        assert_eq!(at(1_704_067_199, 0), "2023-12-31T23:59:59.000Z");
        assert_eq!(at(1_704_067_200, 1), "2024-01-01T00:00:00.001Z");
        // 2100 is NOT a leap year (divisible by 100, not 400).
        assert_eq!(at(4_102_444_800, 0), "2100-01-01T00:00:00.000Z");
    }

    /// The shape itself: fixed width, `T` and `Z` where RFC 3339 puts them —
    /// what an operator's content-anchored grep and a Loki timestamp parser
    /// both key on.
    #[test]
    fn stamp_shape_is_fixed_width_rfc3339_millis_utc() {
        let s = utc_stamp();
        assert_eq!(s.len(), 24, "{s}");
        assert_eq!(&s[4..5], "-", "{s}");
        assert_eq!(&s[7..8], "-", "{s}");
        assert_eq!(&s[10..11], "T", "{s}");
        assert_eq!(&s[13..14], ":", "{s}");
        assert_eq!(&s[16..17], ":", "{s}");
        assert_eq!(&s[19..20], ".", "{s}");
        assert_eq!(&s[23..], "Z", "{s}");
    }

    /// A pre-epoch clock journals the epoch instead of panicking.
    #[test]
    fn pre_epoch_clock_degrades_to_epoch() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(utc_stamp_at(before), "1970-01-01T00:00:00.000Z");
    }

    /// The severity token sits right after the timestamp, space-delimited on
    /// both sides — the position an operator's `grep ' WARN '` / a Loki stage
    /// keys on — and a nominal line carries nothing there (absence means
    /// nominal, so the nominal shape must stay byte-identical to pre-token).
    #[test]
    fn severity_token_rides_right_after_the_stamp_and_only_when_abnormal() {
        let warn = stamped_line(Some("WARN"), format_args!("thing degraded"));
        assert_eq!(&warn[24..30], " WARN ", "{warn}");
        assert!(warn.ends_with("thing degraded"), "{warn}");
        let err = stamped_line(Some("ERROR"), format_args!("write failed"));
        assert_eq!(&err[24..31], " ERROR ", "{err}");
        let plain = stamped_line(None, format_args!("TELEMETRY tip=1"));
        assert_eq!(&plain[24..25], " ", "{plain}");
        assert!(plain.ends_with("TELEMETRY tip=1"), "{plain}");
        assert!(!plain.contains(" WARN ") && !plain.contains(" ERROR "), "{plain}");
    }

    /// The acceptance-bar negatives grep `^error` (line-anchored, lowercase)
    /// cannot match a journal `ERROR` line **by construction**: every journal
    /// line begins with the stamp's year digit, and the token itself is
    /// uppercase. Locked here so a future format change that breaks either
    /// property announces itself.
    #[test]
    fn error_token_cannot_collide_with_the_ci_negatives_grep() {
        let line = stamped_line(Some("ERROR"), format_args!("error: something failed"));
        assert!(line.as_bytes()[0].is_ascii_digit(), "{line}");
        assert!(!line.starts_with("error"), "{line}");
        assert!(line.contains(" ERROR "), "{line}");
    }
}
