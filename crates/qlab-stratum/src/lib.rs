//! # qlab-stratum — Monero-convention stratum codec (pool stage 0)
//!
//! Protocol library for the Qumbra pool's stratum surface. **No I/O, no
//! accounting, no template source** — those land in `qumbra-pool` (stage 1+).
//!
//! This crate sketches the job/submit codec against the **v5** header layout
//! ruled by [pool-t1-brief] §3 (nonce at preimage offset 39–46; miner window
//! 39–42; pool extra-nonce 43–46). The field-by-field mapping and the crate-
//! shape decision live in [`docs/pool-stratum-mapping.md`].
//!
//! Modules:
//! - [`blob`] — v5 preimage offsets + miner/extra-nonce window helpers.
//! - [`target`] — difficulty ↔ 8-byte raw LE target (xmrig-compatible).
//! - [`types`] — login / job / submit value types.
//! - [`codec`] — JSON-RPC 2.0 newline-delimited encode/decode.
//!
//! [pool-t1-brief]: https://github.com/qumbra-labs/qumbra-design/blob/main/pool-t1-brief.md
//! [`docs/pool-stratum-mapping.md`]: ../../../docs/pool-stratum-mapping.md

pub mod blob;
pub mod codec;
pub mod target;
pub mod types;

pub use blob::{
    assemble_nonce, apply_miner_nonce, extranonce_of, miner_nonce_of, set_extranonce,
    V5_BLOB_LEN, V5_EXTRANONCE_LEN, V5_EXTRANONCE_OFF, V5_HEADER_VERSION, V5_MINER_NONCE_LEN,
    V5_MINER_NONCE_OFF,
};
pub use codec::{decode_line, encode_line, CodecError};
pub use target::{difficulty_from_target, encode_target_le_hex, parse_target_hex, target_from_difficulty};
pub use types::{
    Job, JobNotification, KeepalivedParams, LoginParams, LoginResult, StatusResult, StratumError,
    StratumRequest, StratumResponse, SubmitParams,
};
