use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use qumbra_prover_service::{
    Api, ApiError, Config, SecretBytes, SubmitRequest, Worker, WorkerConfig, WorkerOutcome,
    MAX_ARTIFACT_BYTES, MAX_BUNDLE_BYTES, MAX_REQUEST_BYTES,
};
use serde::Serialize;

const MAX_HTTP_HANDLERS: usize = 16;
const WORKER_PROTOCOL: &str = "qumbra-prover-worker-v1";
const MAX_WORKER_ERROR_BYTES: usize = 64;

fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("worker") => worker_entry(),
        Some("healthcheck") => healthcheck_entry(),
        Some("--help" | "-h") => {
            println!(
                "qumbra-prover-service\n\nRun with fail-closed QUMBRA_PROVER_* configuration.\nThe worker subcommand is internal. This build is VALUELESS-EXPERIMENT ONLY."
            );
            Ok(())
        }
        Some(_) => Err("unknown argument".to_string()),
        None => server_entry(),
    };
    if let Err(error) = result {
        eprintln!("qumbra-prover-service: {error}");
        std::process::exit(1);
    }
}

fn healthcheck_entry() -> Result<(), String> {
    let configured =
        std::env::var("QUMBRA_PROVER_LISTEN").unwrap_or_else(|_| "127.0.0.1:8087".to_string());
    let mut address: std::net::SocketAddr = configured
        .parse()
        .map_err(|_| "QUMBRA_PROVER_LISTEN is not an IP socket address".to_string())?;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        });
    }
    let mut stream = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|_| "health listener unavailable".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| "health read timeout unavailable".to_string())?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| "health request failed".to_string())?;
    let mut prefix = [0u8; 12];
    stream
        .read_exact(&mut prefix)
        .map_err(|_| "health response was incomplete".to_string())?;
    if &prefix != b"HTTP/1.1 200" {
        return Err("health endpoint was not ready".into());
    }
    Ok(())
}

fn server_entry() -> Result<(), String> {
    let config = Arc::new(Config::from_env()?);
    let worker = Arc::new(ProcessWorker {
        executable: std::env::current_exe()
            .map_err(|_| "cannot resolve the prover-service executable".to_string())?,
        config: config.worker_config(),
    });
    let api = Api::new(Arc::clone(&config), worker);
    let server = tiny_http::Server::http(config.listen)
        .map_err(|_| "prover listener could not bind".to_string())?;
    let bound = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| "prover listener did not bind an IP socket".to_string())?;

    let stopping = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&stopping);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release))
        .map_err(|_| "termination handler could not be installed".to_string())?;
    let inflight = Arc::new(AtomicUsize::new(0));

    eprintln!(
        "qumbra-prover-service: listening on {bound}; mode=valueless-current-witness-v1; build={}",
        qumbra_prover_service::build_revision()
    );
    while !stopping.load(Ordering::Acquire) {
        let Some(request) = server
            .recv_timeout(Duration::from_millis(250))
            .map_err(|_| "listener failed receiving a request".to_string())?
        else {
            continue;
        };
        if inflight.fetch_add(1, Ordering::AcqRel) >= MAX_HTTP_HANDLERS {
            inflight.fetch_sub(1, Ordering::AcqRel);
            respond_error(
                request,
                ApiError {
                    status: 503,
                    code: "ingress-busy",
                },
            );
            continue;
        }
        let api = api.clone();
        let config = Arc::clone(&config);
        let handler_count = Arc::clone(&inflight);
        std::thread::Builder::new()
            .name("prover-http".into())
            .spawn(move || {
                handle_http(request, &api, &config);
                handler_count.fetch_sub(1, Ordering::AcqRel);
            })
            .map_err(|_| "HTTP handler thread could not start".to_string())?;
    }
    eprintln!("qumbra-prover-service: stopping admission");
    Ok(())
}

fn handle_http(mut request: tiny_http::Request, api: &Api, config: &Config) {
    let raw_url = request.url().to_string();
    let (path, query) = raw_url.split_once('?').unwrap_or((&raw_url, ""));
    if !query.is_empty() {
        respond_error(
            request,
            ApiError {
                status: 404,
                code: "not-found",
            },
        );
        return;
    }

    if path == "/healthz" {
        if *request.method() != tiny_http::Method::Get {
            respond_method(request, "GET");
        } else {
            respond_json(request, 200, &api.health(), None);
        }
        return;
    }

    let authorization = unique_header(&request, "Authorization");
    if !authorization.is_some_and(|value| config.authorizes(value)) {
        respond_error(
            request,
            ApiError {
                status: 401,
                code: "unauthorized",
            },
        );
        return;
    }

    if path == "/v1/jobs" {
        if *request.method() != tiny_http::Method::Post {
            respond_method(request, "POST");
            return;
        }
        if !unique_header(&request, "Content-Type")
            .is_some_and(|value| value.eq_ignore_ascii_case("application/json"))
        {
            respond_error(
                request,
                ApiError {
                    status: 415,
                    code: "content-type-required",
                },
            );
            return;
        }
        let Some(idempotency_key) = unique_header(&request, "Idempotency-Key").map(str::to_string)
        else {
            respond_error(
                request,
                ApiError {
                    status: 400,
                    code: "idempotency-key-required",
                },
            );
            return;
        };
        if request
            .body_length()
            .is_some_and(|length| length > MAX_REQUEST_BYTES)
        {
            respond_error(
                request,
                ApiError {
                    status: 413,
                    code: "request-too-large",
                },
            );
            return;
        }
        let mut body = Vec::new();
        if request
            .as_reader()
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            respond_error(
                request,
                ApiError {
                    status: 400,
                    code: "request-unreadable",
                },
            );
            return;
        }
        if body.len() > MAX_REQUEST_BYTES {
            respond_error(
                request,
                ApiError {
                    status: 413,
                    code: "request-too-large",
                },
            );
            return;
        }
        let parsed: SubmitRequest = match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => {
                use zeroize::Zeroize;
                body.zeroize();
                respond_error(
                    request,
                    ApiError {
                        status: 400,
                        code: "request-json-invalid",
                    },
                );
                return;
            }
        };
        use zeroize::Zeroize;
        body.zeroize();
        match api.submit(&idempotency_key, parsed) {
            Ok((view, created)) => {
                let location = format!("/v1/jobs/{}", view.job_id);
                respond_json(
                    request,
                    if created { 202 } else { 200 },
                    &view,
                    Some(&location),
                );
            }
            Err(error) => respond_error(request, error),
        }
        return;
    }

    let Some(job_id) = path.strip_prefix("/v1/jobs/") else {
        respond_error(
            request,
            ApiError {
                status: 404,
                code: "not-found",
            },
        );
        return;
    };
    if job_id.contains('/') {
        respond_error(
            request,
            ApiError {
                status: 404,
                code: "job-not-found",
            },
        );
        return;
    }
    match *request.method() {
        tiny_http::Method::Get => match api.get(job_id) {
            Ok(view) => respond_json(request, 200, &view, None),
            Err(error) => respond_error(request, error),
        },
        tiny_http::Method::Delete => match api.cancel(job_id) {
            Ok(view) => respond_json(request, 200, &view, None),
            Err(error) => respond_error(request, error),
        },
        _ => respond_method(request, "GET, DELETE"),
    }
}

fn unique_header<'a>(request: &'a tiny_http::Request, name: &'static str) -> Option<&'a str> {
    let mut matching = request
        .headers()
        .iter()
        .filter(|header| header.field.equiv(name));
    let value = matching.next()?.value.as_str();
    matching.next().is_none().then_some(value)
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

fn respond_error(request: tiny_http::Request, error: ApiError) {
    respond_json(
        request,
        error.status,
        &ErrorBody { error: error.code },
        None,
    );
}

fn respond_method(request: tiny_http::Request, allow: &'static str) {
    let allow = tiny_http::Header::from_bytes("Allow", allow).expect("static Allow header");
    let response =
        base_response(405, br#"{"error":"method-not-allowed"}"#.to_vec()).with_header(allow);
    let _ = request.respond(response);
}

fn respond_json<T: Serialize>(
    request: tiny_http::Request,
    status: u16,
    value: &T,
    location: Option<&str>,
) {
    let body = serde_json::to_vec(value)
        .unwrap_or_else(|_| br#"{"error":"response-encode-failed"}"#.to_vec());
    let mut response = base_response(status, body);
    if let Some(location) = location {
        if let Ok(header) = tiny_http::Header::from_bytes("Location", location) {
            response.add_header(header);
        }
    }
    let _ = request.respond(response);
}

fn base_response(status: u16, body: Vec<u8>) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let content_type =
        tiny_http::Header::from_bytes("Content-Type", "application/json").expect("static header");
    let cache_control =
        tiny_http::Header::from_bytes("Cache-Control", "no-store").expect("static header");
    let nosniff =
        tiny_http::Header::from_bytes("X-Content-Type-Options", "nosniff").expect("static header");
    tiny_http::Response::from_data(body)
        .with_status_code(status)
        .with_header(content_type)
        .with_header(cache_control)
        .with_header(nosniff)
}

struct ProcessWorker {
    executable: std::path::PathBuf,
    config: WorkerConfig,
}

impl Worker for ProcessWorker {
    fn prove(&self, bundle: SecretBytes, cancel: &AtomicBool) -> WorkerOutcome {
        let mut command = Command::new(&self.executable);
        command
            .arg("worker")
            .env_clear()
            .env("QUMBRA_PROVER_WORKER_PROTOCOL", WORKER_PROTOCOL)
            .env("QUMBRA_PROVER_SCAN_URL", &self.config.scan_url)
            .env("QUMBRA_PROVER_NODE_URL", &self.config.node_url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => return WorkerOutcome::Refused("worker-spawn-failed"),
        };
        if write_worker_request(&mut child, bundle.as_slice()).is_err() {
            terminate(&mut child);
            return WorkerOutcome::Refused("worker-input-failed");
        }
        let Some(stdout) = child.stdout.take() else {
            terminate(&mut child);
            return WorkerOutcome::Refused("worker-output-missing");
        };
        let reader = std::thread::spawn(move || read_worker_response(stdout));
        let started = Instant::now();
        loop {
            if cancel.load(Ordering::Acquire) {
                terminate(&mut child);
                let _ = reader.join();
                return WorkerOutcome::Refused("cancelled");
            }
            if started.elapsed() >= self.config.prove_timeout {
                terminate(&mut child);
                let _ = reader.join();
                return WorkerOutcome::Refused("worker-timeout");
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    let output = reader.join().ok().and_then(Result::ok);
                    return if status.success() {
                        output.unwrap_or(WorkerOutcome::Refused("worker-output-invalid"))
                    } else {
                        WorkerOutcome::Refused("worker-failed")
                    };
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(_) => {
                    terminate(&mut child);
                    let _ = reader.join();
                    return WorkerOutcome::Refused("worker-wait-failed");
                }
            }
        }
    }
}

fn write_worker_request(child: &mut Child, bundle: &[u8]) -> std::io::Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("worker stdin absent"))?;
    let length = u32::try_from(bundle.len()).map_err(|_| std::io::Error::other("bundle length"))?;
    stdin.write_all(&length.to_le_bytes())?;
    stdin.write_all(bundle)?;
    stdin.flush()
}

fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_worker_response(mut stdout: impl Read) -> Result<WorkerOutcome, &'static str> {
    let mut kind = [0u8; 1];
    stdout
        .read_exact(&mut kind)
        .map_err(|_| "worker-output-torn")?;
    let mut encoded_length = [0u8; 4];
    stdout
        .read_exact(&mut encoded_length)
        .map_err(|_| "worker-output-torn")?;
    let length = u32::from_le_bytes(encoded_length) as usize;
    let limit = if kind[0] == 0 {
        MAX_ARTIFACT_BYTES
    } else {
        MAX_WORKER_ERROR_BYTES
    };
    if length > limit {
        return Err("worker-output-too-large");
    }
    let mut payload = vec![0u8; length];
    stdout
        .read_exact(&mut payload)
        .map_err(|_| "worker-output-torn")?;
    let mut trailing = [0u8; 1];
    if stdout
        .read(&mut trailing)
        .map_err(|_| "worker-output-unreadable")?
        != 0
    {
        return Err("worker-output-trailing");
    }
    match kind[0] {
        0 => Ok(WorkerOutcome::Succeeded(SecretBytes::new(payload))),
        1 => {
            let code = std::str::from_utf8(&payload).map_err(|_| "worker-error-invalid")?;
            Ok(WorkerOutcome::Refused(worker_error_code(code)))
        }
        _ => Err("worker-output-kind-unknown"),
    }
}

fn worker_error_code(code: &str) -> &'static str {
    match code {
        "bundle-refused" => "bundle-refused",
        "node-preflight-refused" => "node-preflight-refused",
        "proof-refused" => "proof-refused",
        "artifact-too-large" => "artifact-too-large",
        "worker-protocol-refused" => "worker-protocol-refused",
        _ => "worker-error-unknown",
    }
}

fn worker_entry() -> Result<(), String> {
    if std::env::var("QUMBRA_PROVER_WORKER_PROTOCOL").as_deref() != Ok(WORKER_PROTOCOL) {
        return Err("internal worker protocol is absent".into());
    }
    let outcome = std::panic::catch_unwind(worker_once);
    match outcome {
        Ok(Ok(artifact)) => write_worker_response(0, &artifact),
        Ok(Err(code)) => write_worker_response(1, code.as_bytes()),
        Err(_) => write_worker_response(1, b"worker-protocol-refused"),
    }
}

fn worker_once() -> Result<Vec<u8>, &'static str> {
    let scan_url =
        std::env::var("QUMBRA_PROVER_SCAN_URL").map_err(|_| "worker-protocol-refused")?;
    let node_url =
        std::env::var("QUMBRA_PROVER_NODE_URL").map_err(|_| "worker-protocol-refused")?;
    let mut length = [0u8; 4];
    std::io::stdin()
        .read_exact(&mut length)
        .map_err(|_| "worker-protocol-refused")?;
    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_BUNDLE_BYTES {
        return Err("bundle-refused");
    }
    let mut raw = vec![0u8; length];
    std::io::stdin()
        .read_exact(&mut raw)
        .map_err(|_| "bundle-refused")?;
    let bytes = SecretBytes::new(raw);
    let bundle = qumbra_wallet::bundle::WitnessBundle::from_bytes(bytes.as_slice())
        .map_err(|_| "bundle-refused")?;
    drop(bytes);

    // These are the only network calls reachable from the worker: GET valid
    // anchors and bulk nullifiers from operator-pinned bases. There is no call
    // to qumbra_wallet::spend::submit anywhere in this binary.
    let current = qumbra_wallet::spend::preflight_urls(&scan_url, &node_url)
        .map_err(|_| "node-preflight-refused")?;
    let artifact =
        qumbra_wallet::spend::prove(&bundle, &current, &mut |_| {}).map_err(|_| "proof-refused")?;
    if artifact.wire_bytes.len() > MAX_ARTIFACT_BYTES {
        return Err("artifact-too-large");
    }
    Ok(artifact.wire_bytes)
}

fn write_worker_response(kind: u8, payload: &[u8]) -> Result<(), String> {
    let length =
        u32::try_from(payload.len()).map_err(|_| "worker response too large".to_string())?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&[kind])
        .map_err(|_| "worker stdout closed".to_string())?;
    stdout
        .write_all(&length.to_le_bytes())
        .map_err(|_| "worker stdout closed".to_string())?;
    stdout
        .write_all(payload)
        .and_then(|()| stdout.flush())
        .map_err(|_| "worker stdout closed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_errors_are_an_allowlist_not_detail_passthrough() {
        assert_eq!(worker_error_code("bundle-refused"), "bundle-refused");
        assert_eq!(
            worker_error_code("selected nullifier deadbeef was spent"),
            "worker-error-unknown"
        );
    }

    #[test]
    fn worker_response_refuses_oversize_before_allocating_payload() {
        let mut wire = vec![0u8];
        wire.extend_from_slice(&((MAX_ARTIFACT_BYTES as u32) + 1).to_le_bytes());
        assert!(matches!(
            read_worker_response(wire.as_slice()),
            Err("worker-output-too-large")
        ));
    }
}
