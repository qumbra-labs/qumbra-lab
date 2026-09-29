//! The outer lanes a wrapper leaf W is proven on (non-hiding,
//! `qlab_consensus::legacy`). Moved from qlab-bench's `m4interior` /
//! `f3::bench` (lab #785, F5-1), unchanged: version 1 proves W on [`B2_CFG`].
use qlab_consensus::FriCfg;

/// **b4/q43/g22/fp16/a16** — the interior's fallback outer lane (qlab-bench
/// `m4interior::INTERIOR_B4_CFG`).
pub const B4_CFG: FriCfg = FriCfg {
    log_blowup: 2,
    num_queries: 43, // q43 (B″, issue #41 — was q40)
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// **b2/q86/g22/fp16/a16** — the decided interior outer lane (qlab-bench
/// `m4interior::INTERIOR_B2_CFG`).
pub const B2_CFG: FriCfg = FriCfg {
    log_blowup: 1,
    num_queries: 86, // q86 (B″, issue #41 — was q80; the decided interior lane)
    grind_bits: 22,
    log_final_poly_len: 4,
    max_log_arity: 4,
};

/// The outer lane a leaf is proven on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outer {
    B2,
    B4,
}

impl Outer {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "b2" => Ok(Self::B2),
            "b4" => Ok(Self::B4),
            _ => Err("--outer must be b2|b4".into()),
        }
    }
    pub fn cfg(self) -> FriCfg {
        match self {
            Self::B2 => B2_CFG,
            Self::B4 => B4_CFG,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::B2 => "b2/q86/g22/fp16/a16",
            Self::B4 => "b4/q43/g22/fp16/a16",
        }
    }
}
