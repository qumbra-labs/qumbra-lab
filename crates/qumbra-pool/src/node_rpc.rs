//! Node-RPC template source + block submitter (lab #511).
//!
//! Talks to the node's discovery listener:
//! - `GET /v1/mine/template`
//! - `POST /v1/mine/block`
//!
//! Hand-rolled HTTP/1.1 over `std::net::TcpStream` — this crate does not
//! take `ureq`/`hyper`. The pool talks to its own node on the same host.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use qlab_devnet::forms::GenesisForm;
use serde::{Deserialize, Serialize};

use crate::hexutil;
use crate::pool::BlockSubmitter;
use crate::template::{
    header_from_parts, parse_form, Template, TemplateBody, TemplateError, TemplateSource,
};

const TEMPLATE_PATH: &str = "/v1/mine/template";
const BLOCK_PATH: &str = "/v1/mine/block";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MineTemplateWire {
    form: String,
    prev: String,
    height: u64,
    timestamp: u64,
    difficulty: u64,
    nonce: u64,
    tx_body_commitment: String,
    seed_hash: String,
    next_seed_hash: Option<String>,
    coinbase: u64,
    coinbase_rkm: String,
    txs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MineBlockWire {
    form: String,
    header: String,
    coinbase: u64,
    coinbase_rkm: String,
    txs: Vec<String>,
}

/// HTTP client for one node RPC base (`http://host:port`).
#[derive(Clone, Debug)]
pub struct NodeRpcClient {
    host: String,
    port: u16,
}

impl NodeRpcClient {
    pub fn parse(url: &str) -> Result<Self, String> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("node_rpc must be http://host:port, got `{url}`"))?;
        let rest = rest.trim_end_matches('/');
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| format!("node_rpc missing port: `{url}`"))?;
        let host = host.trim_start_matches('[').trim_end_matches(']').to_string();
        if host.is_empty() {
            return Err("node_rpc host is empty".into());
        }
        let port: u16 = port
            .parse()
            .map_err(|_| format!("node_rpc bad port `{port}`"))?;
        Ok(Self { host, port })
    }

    pub fn fetch_template(&self) -> Result<Template, String> {
        let (status, body) = self.request("GET", TEMPLATE_PATH, None)?;
        if !status.contains("200") {
            return Err(format!("template GET {status}: {body}"));
        }
        let wire: MineTemplateWire =
            serde_json::from_str(&body).map_err(|e| format!("template JSON: {e}"))?;
        template_from_wire(wire).map_err(|e| e.to_string())
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<(String, String), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut s = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        s.set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| e.to_string())?;
        let host_hdr = format!("{}:{}", self.host, self.port);
        match body {
            None => write!(
                s,
                "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n"
            )
            .map_err(|e| e.to_string())?,
            Some(b) => {
                write!(
                    s,
                    "{method} {path} HTTP/1.1\r\nHost: {host_hdr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    b.len()
                )
                .map_err(|e| e.to_string())?;
                s.write_all(b).map_err(|e| e.to_string())?;
            }
        }
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).map_err(|e| e.to_string())?;
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("HTTP response missing header terminator")?;
        let head = String::from_utf8_lossy(&raw[..sep]);
        let status = head.lines().next().unwrap_or_default().to_string();
        let body = String::from_utf8_lossy(&raw[sep + 4..]).to_string();
        Ok((status, body))
    }
}

impl BlockSubmitter for NodeRpcClient {
    fn submit_block(
        &self,
        form: GenesisForm,
        header_preimage: &[u8],
        body: &TemplateBody,
    ) -> Result<String, String> {
        let form_s = match form {
            GenesisForm::V4 => "v4",
            GenesisForm::V5 => "v5",
        };
        let wire = MineBlockWire {
            form: form_s.into(),
            header: hexutil::encode(header_preimage),
            coinbase: body.coinbase,
            coinbase_rkm: rkm_hex(&body.coinbase_rkm),
            txs: body.txs.iter().map(|t| hexutil::encode(t)).collect(),
        };
        let json = serde_json::to_vec(&wire).map_err(|e| e.to_string())?;
        let (status, resp) = self.request("POST", BLOCK_PATH, Some(&json))?;
        if status.contains("202") || status.contains("200") {
            Ok(resp)
        } else {
            Err(format!("{status}: {resp}"))
        }
    }
}

/// [`TemplateSource`] that polls the node. `current` refreshes; a failed
/// poll keeps the last good template so login does not fail mid-block.
pub struct NodeRpcTemplateSource {
    client: NodeRpcClient,
    cached: Mutex<Template>,
}

impl NodeRpcTemplateSource {
    /// Fetch once. Fails construction if the node is not serving.
    pub fn connect(url: &str) -> Result<Self, String> {
        let client = NodeRpcClient::parse(url)?;
        let template = client.fetch_template()?;
        Ok(Self {
            client,
            cached: Mutex::new(template),
        })
    }

    pub fn client(&self) -> NodeRpcClient {
        self.client.clone()
    }

    /// Last fetched template, no HTTP.
    pub fn snapshot(&self) -> Template {
        self.cached.lock().expect("template mutex").clone()
    }

    /// Refresh. `Ok(true)` if the template moved (caller should re-issue jobs).
    pub fn poll(&self) -> Result<bool, String> {
        let next = self.client.fetch_template()?;
        let mut g = self.cached.lock().expect("template mutex");
        if *g == next {
            return Ok(false);
        }
        *g = next;
        Ok(true)
    }
}

impl TemplateSource for NodeRpcTemplateSource {
    fn current(&self) -> Template {
        if let Ok(next) = self.client.fetch_template() {
            *self.cached.lock().expect("template mutex") = next;
        }
        self.cached.lock().expect("template mutex").clone()
    }
}

fn template_from_wire(w: MineTemplateWire) -> Result<Template, TemplateError> {
    let form = parse_form(&w.form)?;
    let mut header = header_from_parts(
        &w.prev,
        w.height,
        w.timestamp,
        w.difficulty,
        &w.tx_body_commitment,
    )?;
    header.nonce = w.nonce;
    let seed_hash = hexutil::decode_exact(&w.seed_hash)?;
    let next_seed_hash = match w.next_seed_hash {
        Some(s) if !s.is_empty() => Some(hexutil::decode_exact(&s)?),
        _ => None,
    };
    let coinbase_rkm = hexutil::rkm_lanes_from_hex(&w.coinbase_rkm).unwrap_or([0; 4]);
    let mut txs = Vec::with_capacity(w.txs.len());
    for t in w.txs {
        txs.push(hexutil::decode(&t)?);
    }
    Ok(Template {
        form,
        header,
        seed_hash,
        next_seed_hash,
        body: Some(TemplateBody {
            coinbase: w.coinbase,
            coinbase_rkm,
            txs,
        }),
    })
}

fn rkm_hex(rkm: &[u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (i, lane) in rkm.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    hexutil::encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_loopback_url() {
        let c = NodeRpcClient::parse("http://127.0.0.1:9420").unwrap();
        assert_eq!(c.host, "127.0.0.1");
        assert_eq!(c.port, 9420);
        assert!(NodeRpcClient::parse("https://x:1").is_err());
        assert!(NodeRpcClient::parse("http://noport").is_err());
    }
}
