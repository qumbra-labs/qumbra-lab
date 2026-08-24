//! HTTP/1.1 **response framing** for the hand-rolled client in
//! [`crate::node_rpc`] (lab #626).
//!
//! The decoder itself lives in [`qlab_http_framing`] as of lab #631 — one
//! implementation, four clients. This module re-exports it so existing
//! `crate::http` paths keep compiling.

pub use qlab_http_framing::*;
