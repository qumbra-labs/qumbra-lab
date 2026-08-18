//! Stratum value types — Monero / xmrig-proxy convention.
//!
//! Field names and shapes follow
//! [`xmrig-proxy/doc/STRATUM.md`](https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM.md)
//! and the RandomX extensions (`algo`, `height`, `seed_hash`, `next_seed_hash`).

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StratumError {
    pub code: i64,
    pub message: String,
}

/// Miner → pool `login` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginParams {
    pub login: String,
    pub pass: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Algorithm negotiation list (e.g. `["rx/0"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algo: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rigid: Option<String>,
}

/// A job object — embedded in login result or pushed as a `job` notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    /// Hex-encoded hashing blob (for Qumbra v5: 97-byte header preimage).
    pub blob: String,
    pub job_id: String,
    /// Hex-encoded target (we emit 8-byte LE raw; see [`crate::target`]).
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    /// 32-byte hex RandomX seed (key-block hash).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed_hash: Option<String>,
    /// 32-byte hex next seed, when a rotation is approaching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_seed_hash: Option<String>,
    /// Session / client id echo some pools put on the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// Successful login result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResult {
    /// Client / session id (referenced by subsequent submits).
    pub id: String,
    pub job: Job,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
}

/// Miner → pool `submit` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitParams {
    /// Client id from login.
    pub id: String,
    pub job_id: String,
    /// 4-byte hex miner nonce (little-endian).
    pub nonce: String,
    /// 32-byte hex PoW hash result.
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algo: Option<String>,
}

/// Miner → pool `keepalived` params.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeepalivedParams {
    pub id: String,
}

/// Generic `{ "status": "OK" }` / `{ "status": "KEEPALIVED" }` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub status: String,
}

/// Pool → miner `job` notification params (= a [`Job`]).
pub type JobNotification = Job;

/// A stratum request (miner → pool), discriminated by `method`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StratumRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default = "jsonrpc_default", skip_serializing_if = "String::is_empty")]
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

fn jsonrpc_default() -> String {
    "2.0".to_string()
}

/// A stratum response (pool → miner) for a prior request id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StratumResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(default = "jsonrpc_default", skip_serializing_if = "String::is_empty")]
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<StratumError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl StratumRequest {
    pub fn login(id: u64, params: &LoginParams) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            method: "login".into(),
            params: serde_json::to_value(params)?,
        })
    }

    pub fn submit(id: u64, params: &SubmitParams) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            method: "submit".into(),
            params: serde_json::to_value(params)?,
        })
    }

    pub fn keepalived(id: u64, params: &KeepalivedParams) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            method: "keepalived".into(),
            params: serde_json::to_value(params)?,
        })
    }

    pub fn parse_login_params(&self) -> Result<LoginParams, serde_json::Error> {
        serde_json::from_value(self.params.clone())
    }

    pub fn parse_submit_params(&self) -> Result<SubmitParams, serde_json::Error> {
        serde_json::from_value(self.params.clone())
    }
}

impl StratumResponse {
    pub fn ok_login(id: u64, result: &LoginResult) -> Result<Self, serde_json::Error> {
        Ok(Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            error: None,
            result: Some(serde_json::to_value(result)?),
        })
    }

    pub fn ok_status(id: u64, status: &str) -> Self {
        Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            error: None,
            result: Some(serde_json::json!({ "status": status })),
        }
    }

    pub fn err(id: u64, code: i64, message: impl Into<String>) -> Self {
        Self {
            id: Some(id),
            jsonrpc: "2.0".into(),
            error: Some(StratumError {
                code,
                message: message.into(),
            }),
            result: None,
        }
    }

    pub fn parse_login_result(&self) -> Result<LoginResult, serde_json::Error> {
        serde_json::from_value(self.result.clone().unwrap_or(serde_json::Value::Null))
    }
}

/// Build a pool → miner job notification (no `id` — it's a notification).
pub fn job_notification(job: &Job) -> Result<StratumRequest, serde_json::Error> {
    Ok(StratumRequest {
        id: None,
        jsonrpc: "2.0".into(),
        method: "job".into(),
        params: serde_json::to_value(job)?,
    })
}
