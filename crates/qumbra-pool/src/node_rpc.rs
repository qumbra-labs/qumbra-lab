//! Node-RPC template source + block submitter (lab #511).
//!
//! Talks to the node's discovery listener:
//! - `GET /v1/mine/template`
//! - `POST /v1/mine/block`
//!
//! Hand-rolled HTTP/1.1 over `std::net::TcpStream` — this crate does not
//! take `ureq`/`hyper`. The pool talks to its own node on the same host.
//!
//! **Response framing lives in [`crate::http`]** (lab #626). Read that
//! module before changing anything below `request`: the version of this
//! file that treated "everything after `\r\n\r\n`" as the body took the
//! T2 pool offline for 2 h 32 min the first time a transaction sat in the
//! node's mempool.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use qlab_devnet::body::CoinbasePayee;
use qlab_devnet::forms::{BodySections, GenesisForm};
use serde::{Deserialize, Serialize};

use crate::hexutil;
use crate::pool::BlockSubmitter;
use crate::template::{
    header_from_parts, parse_form, Template, TemplateBody, TemplateError, TemplateSource,
};

const TEMPLATE_PATH: &str = "/v1/mine/template";
const CONTEXT_PATH: &str = "/v1/mine/context";
const BLOCK_PATH: &str = "/v1/mine/block";

/// The body cap on every answer from the node's mine RPC (lab #785 F5-5a).
/// A template carries the block's transactions as hex, so its size follows
/// the block's: a V6 body is at most `MAX_V6_BODY_WIRE_BYTES` (15 MiB), 2× in
/// hex plus JSON; 64 MiB covers it. Past it, the answer is refused by name.
pub const NODE_RPC_MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MineTemplateContextWire {
    form: String,
    height: u64,
    /// `"v6"` from a V6 node (lab #785), absent otherwise.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sections: String,
}

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
    coinbase_payees: Vec<CoinbasePayeeWire>,
    txs: Vec<String>,
    /// V6 only (lab #785): the node's finality record, hex; absent on V4/V5.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    finality: String,
    /// `"v6"` on a V6 node (lab #785): the template's section axis, echoed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sections: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MineBlockWire {
    form: String,
    header: String,
    coinbase_payees: Vec<CoinbasePayeeWire>,
    txs: Vec<String>,
    /// V6 only (lab #785): echoed from the template — the header commits it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    finality: String,
    /// `"v6"` on a V6 node (lab #785): the template's section axis, echoed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    sections: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CoinbasePayeeWire { rkm: String, amount: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MineTemplateContext {
    pub form: GenesisForm,
    pub height: u64,
    /// The node's body-section axis (lab #785): keys the payee cap.
    pub sections: BodySections,
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

    pub fn fetch_context(&self) -> Result<MineTemplateContext, String> {
        let (status, body) = self.request("GET", CONTEXT_PATH, None)?;
        if !status.contains("200") {
            return Err(format!("context GET {status}: {body}"));
        }
        let wire: MineTemplateContextWire = serde_json::from_str(&body)
            .map_err(|e| format!("context JSON: {e}"))?;
        Ok(MineTemplateContext {
            form: parse_form(&wire.form).map_err(|e| e.to_string())?,
            height: wire.height,
            sections: parse_sections(&wire.sections).map_err(|e| e.to_string())?,
        })
    }

    pub fn fetch_template(&self, payees: &[CoinbasePayee]) -> Result<Template, String> {
        let path = format!("{TEMPLATE_PATH}?{}", payee_query(payees));
        let (status, body) = self.request("GET", &path, None)?;
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
        // One request per connection: `Connection: close` still asks the
        // server to tear it down rather than leaving a socket this client
        // will never reuse. Since #626 the body read no longer DEPENDS on
        // the server honouring it — `crate::http` stops at the end of the
        // body whenever the response is self-delimiting.
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
        // Lab #626: the framing is READ, not assumed. This used to be a
        // `read_to_end` plus "everything after `\r\n\r\n` is the body", which
        // handed `serde_json` the chunk header `2000\r\n…` the moment a
        // transaction pushed the template past `tiny_http`'s chunking
        // threshold — one pending transaction, pool offline for 2 h 32 min.
        //
        // It also means the read now stops at the end of the BODY. The old
        // one stopped at EOF, i.e. only because the server closed; against a
        // keep-alive peer every template poll would have hung to the 30 s
        // read timeout instead of returning.
        let resp = crate::http::read_response_capped(&mut s, NODE_RPC_MAX_BODY).map_err(|e| e.to_string())?;
        let body = resp.body_string();
        Ok((resp.status, body))
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
            GenesisForm::Annulet => {
                return Err("a pool mines PoW blocks; an Annulet (sequencer) net has none (lab #706)".into());
            }
        };
        let wire = block_wire(form_s, header_preimage, body);
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
    pub fn connect(url: &str, payees: &[CoinbasePayee]) -> Result<Self, String> {
        let client = NodeRpcClient::parse(url)?;
        let template = client.fetch_template(payees)?;
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
    pub fn poll(&self, payees: &[CoinbasePayee]) -> Result<bool, String> {
        let next = self.client.fetch_template(payees)?;
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
        self.cached.lock().expect("template mutex").clone()
    }
}

/// The `POST /v1/mine/block` body for a completed header and its template
/// body — the V6 record echoed back (lab #785), absent on V4/V5.
fn block_wire(form_s: &str, header_preimage: &[u8], body: &TemplateBody) -> MineBlockWire {
    MineBlockWire {
        form: form_s.into(),
        header: hexutil::encode(header_preimage),
        coinbase_payees: payees_to_wire(&body.coinbase_payees),
        txs: body.txs.iter().map(|t| hexutil::encode(t)).collect(),
        finality: hexutil::encode(&body.finality),
        sections: match body.sections {
            BodySections::V6 => "v6".into(),
            BodySections::None => String::new(),
        },
    }
}

/// The section token a node sends (lab #785): `"v6"` or absent. Anything
/// else is refused by name — a pool must not guess a body shape.
fn parse_sections(s: &str) -> Result<BodySections, TemplateError> {
    match s {
        "" => Ok(BodySections::None),
        "v6" => Ok(BodySections::V6),
        other => Err(TemplateError::UnknownForm(format!("sections {other}"))),
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
    let coinbase_payees = payees_from_wire(&w.coinbase_payees)?;
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
            coinbase_payees,
            txs,
            finality: hexutil::decode(&w.finality)?,
            sections: parse_sections(&w.sections)?,
        }),
    })
}

fn payee_query(payees: &[CoinbasePayee]) -> String {
    payees.iter().map(|p| format!("payee={}:{}", rkm_hex(&p.rkm), p.amount))
        .collect::<Vec<_>>().join("&")
}

fn payees_to_wire(payees: &[CoinbasePayee]) -> Vec<CoinbasePayeeWire> {
    payees.iter().map(|p| CoinbasePayeeWire { rkm: rkm_hex(&p.rkm), amount: p.amount }).collect()
}

fn payees_from_wire(payees: &[CoinbasePayeeWire]) -> Result<Vec<CoinbasePayee>, TemplateError> {
    payees.iter().map(|p| Ok(CoinbasePayee {
        rkm: hexutil::rkm_lanes_from_hex(&p.rkm).map_err(TemplateError::Hex)?,
        amount: p.amount,
    })).collect()
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

    /// Lab #785: a V6 template's record reaches the pool's body and is echoed
    /// on submit (the header commits it); a V5 template has none and its
    /// submit JSON carries no `finality` key at all.
    #[test]
    fn the_v6_record_round_trips_through_the_pool_and_v5_stays_unchanged() {
        let json = |finality: &str| {
            let extra = if finality.is_empty() { String::new() } else { format!(r#","finality":"{finality}""#) };
            format!(
                r#"{{"form":"v5","prev":"{p}","height":1,"timestamp":75,"difficulty":8,"nonce":0,"tx_body_commitment":"{c}","seed_hash":"{s}","next_seed_hash":null,"coinbase_payees":[],"txs":[]{extra}}}"#,
                p = "11".repeat(32),
                c = "22".repeat(32),
                s = "33".repeat(32),
            )
        };
        let v6: MineTemplateWire = serde_json::from_str(&json("0a0b")).unwrap();
        let t6 = template_from_wire(v6).unwrap();
        let body6 = t6.body.expect("a node template carries a body");
        assert_eq!(body6.finality, vec![0x0a, 0x0b]);
        let v5: MineTemplateWire = serde_json::from_str(&json("")).unwrap();
        let body5 = template_from_wire(v5).unwrap().body.unwrap();
        assert!(body5.finality.is_empty());

        let submit = |body: &TemplateBody| block_wire("v5", &[], body);
        assert!(serde_json::to_string(&submit(&body6)).unwrap().contains(r#""finality":"0a0b""#));
        assert!(!serde_json::to_string(&submit(&body5)).unwrap().contains("finality"));
    }

    /// Lab #785, M1: the node's `sections` token reaches the context and the
    /// template, is echoed on submit, and an unknown token is refused by name.
    #[test]
    fn the_sections_token_is_read_echoed_and_never_guessed() {
        let ctx: MineTemplateContextWire = serde_json::from_str(r#"{"form":"v5","height":9,"sections":"v6"}"#).unwrap();
        assert_eq!(parse_sections(&ctx.sections).unwrap(), BodySections::V6);
        let plain: MineTemplateContextWire = serde_json::from_str(r#"{"form":"v5","height":9}"#).unwrap();
        assert_eq!(parse_sections(&plain.sections).unwrap(), BodySections::None);
        assert!(parse_sections("v7").is_err());
        let body = TemplateBody {
            coinbase_payees: vec![],
            txs: vec![],
            finality: vec![],
            sections: BodySections::V6,
        };
        assert!(serde_json::to_string(&block_wire("v5", &[], &body)).unwrap().contains(r#""sections":"v6""#));
    }
}
