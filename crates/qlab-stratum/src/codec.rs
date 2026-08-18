//! Newline-delimited JSON-RPC 2.0 encode/decode for stratum lines.
//!
//! Monero stratum rides plain TCP with one JSON object per line (LF-terminated).
//! This module does not open sockets — it only round-trips the bytes.

use crate::types::{StratumRequest, StratumResponse};

/// Codec errors.
#[derive(Debug)]
pub enum CodecError {
    Json(serde_json::Error),
    /// Line was empty after trimming.
    Empty,
    /// Line was neither a recognizable request nor a response.
    Ambiguous,
}

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecError::Json(e) => write!(f, "json: {e}"),
            CodecError::Empty => write!(f, "empty stratum line"),
            CodecError::Ambiguous => write!(f, "line is neither request nor response"),
        }
    }
}

impl std::error::Error for CodecError {}

impl From<serde_json::Error> for CodecError {
    fn from(e: serde_json::Error) -> Self {
        CodecError::Json(e)
    }
}

/// A decoded stratum line.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodedLine {
    Request(StratumRequest),
    Response(StratumResponse),
}

/// Encode a request as a single LF-terminated line.
pub fn encode_request(req: &StratumRequest) -> Result<String, CodecError> {
    let mut s = serde_json::to_string(req)?;
    s.push('\n');
    Ok(s)
}

/// Encode a response as a single LF-terminated line.
pub fn encode_response(resp: &StratumResponse) -> Result<String, CodecError> {
    let mut s = serde_json::to_string(resp)?;
    s.push('\n');
    Ok(s)
}

/// Encode either side; convenience for fixtures that mix directions.
pub fn encode_line(line: &DecodedLine) -> Result<String, CodecError> {
    match line {
        DecodedLine::Request(r) => encode_request(r),
        DecodedLine::Response(r) => encode_response(r),
    }
}

/// Decode one stratum line (with or without trailing newline).
///
/// Heuristic: if the object has a `method` field it is a request/notification;
/// otherwise it is a response. (Matches how xmrig / pools demux the stream.)
pub fn decode_line(line: &str) -> Result<DecodedLine, CodecError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(CodecError::Empty);
    }
    let v: serde_json::Value = serde_json::from_str(line)?;
    if v.get("method").is_some() {
        let req: StratumRequest = serde_json::from_value(v)?;
        Ok(DecodedLine::Request(req))
    } else if v.get("result").is_some() || v.get("error").is_some() {
        let resp: StratumResponse = serde_json::from_value(v)?;
        Ok(DecodedLine::Response(resp))
    } else {
        Err(CodecError::Ambiguous)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LoginParams, SubmitParams};

    #[test]
    fn login_line_round_trips() {
        let req = StratumRequest::login(
            1,
            &LoginParams {
                login: "miner1".into(),
                pass: "x".into(),
                agent: Some("XMRig/6.21.0".into()),
                algo: Some(vec!["rx/0".into()]),
                rigid: None,
            },
        )
        .unwrap();
        let line = encode_request(&req).unwrap();
        assert!(line.ends_with('\n'));
        match decode_line(&line).unwrap() {
            DecodedLine::Request(r) => {
                assert_eq!(r.method, "login");
                let p = r.parse_login_params().unwrap();
                assert_eq!(p.login, "miner1");
                assert_eq!(p.algo.unwrap(), vec!["rx/0"]);
            }
            other => panic!("expected request, got {other:?}"),
        }
    }

    #[test]
    fn submit_line_round_trips() {
        let req = StratumRequest::submit(
            2,
            &SubmitParams {
                id: "sess-1".into(),
                job_id: "job-1".into(),
                nonce: "d0030040".into(),
                result: "11".repeat(32),
                algo: Some("rx/0".into()),
            },
        )
        .unwrap();
        let line = encode_request(&req).unwrap();
        match decode_line(&line).unwrap() {
            DecodedLine::Request(r) => {
                let p = r.parse_submit_params().unwrap();
                assert_eq!(p.nonce, "d0030040");
                assert_eq!(p.result.len(), 64);
            }
            other => panic!("expected request, got {other:?}"),
        }
    }
}
