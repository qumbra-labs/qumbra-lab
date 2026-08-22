//! Plain TCP, one JSON-RPC object per LF-terminated line.
//!
//! Deliberately not `qlab-p2p` transport (framed binary) and not
//! `qlab-cbserver` HTTP. Steal discipline, not code — mapping doc §6.2.
//!
//! Job re-issue (lab #545): a shared latest-value [`JobOutbox`] is the
//! path from the poll thread to each connection's writer. The accept
//! loop stays thread-per-connection; each thread drains its session's
//! slot on the read timeout (and after every request) so a tip change
//! does not wait on the miner to speak.
//!
//! Public-endpoint guards (lab #544): the accept loop admits through a
//! [`ConnGuard`] **before** `thread::spawn`. A line longer than the bound,
//! a request that does not finish inside its deadline, or a connection
//! that never completes a first line, is refused by name and counted.

use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use qlab_stratum::codec::{encode_request, encode_response};
use qlab_stratum::types::{job_notification, StratumResponse};

use crate::guard::{
    ConnGuard, ConnSlot, REASON_CONNECTION_TIMEOUT, REASON_LINE_TOO_LONG, REASON_REQUEST_TIMEOUT,
};
use crate::outbox::{JobOutbox, SessionPush};
use crate::pool::{Outgoing, Pool, ERR_INVALID};

/// Wake often enough that a pushed job is not stuck behind a long read.
/// This is **not** the request or connection deadline — those live on
/// [`crate::guard::ListenLimits`] and are what catch a trickling client.
const READ_TIMEOUT: Duration = Duration::from_millis(100);

/// Bind and accept until `stop` is set. Each **admitted** connection is a
/// thread. A peer past the cap is closed on this loop with a named error;
/// it never becomes a thread.
pub fn serve(
    listener: TcpListener,
    pool: Arc<Pool>,
    stop: Arc<AtomicBool>,
    outbox: Arc<JobOutbox>,
    guard: Arc<ConnGuard>,
) -> std::io::Result<()> {
    pool.set_outbox(Arc::clone(&outbox));
    listener.set_nonblocking(true)?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => match guard.admit(addr.ip()) {
                Ok(slot) => {
                    let pool = Arc::clone(&pool);
                    let stop = Arc::clone(&stop);
                    let outbox = Arc::clone(&outbox);
                    let guard = Arc::clone(&guard);
                    thread::spawn(move || {
                        if let Err(e) = handle_conn(stream, pool, stop, outbox, guard, slot, addr) {
                            qlab_devnet::jeprintln!(WARN, "qumbra-pool conn: {e}");
                        }
                    });
                }
                Err(err) => refuse_at_accept(stream, addr, &err.reason(guard.limits()), &guard),
            },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Named refusal on the accept thread: write the token, log the counters,
/// close. A short write timeout so a silent client cannot stall accept.
fn refuse_at_accept(stream: TcpStream, addr: SocketAddr, reason: &str, guard: &ConnGuard) {
    let mut stream = stream;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    write_named(&mut stream, reason);
    log_refuse(reason, addr, guard);
    let _ = stream.shutdown(Shutdown::Both);
}

fn handle_conn(
    stream: TcpStream,
    pool: Arc<Pool>,
    stop: Arc<AtomicBool>,
    outbox: Arc<JobOutbox>,
    guard: Arc<ConnGuard>,
    _slot: ConnSlot,
    addr: SocketAddr,
) -> std::io::Result<()> {
    let limits = guard.limits().clone();
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(limits.request_timeout))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut session: Option<String> = None;
    let mut registered: Option<String> = None;
    let conn_deadline = Instant::now() + limits.connection_timeout;
    let mut completed_any = false;
    let mut buf: Vec<u8> = Vec::new();
    let mut saw_byte = false;
    let mut request_deadline: Option<Instant> = None;

    let result = loop {
        if stop.load(Ordering::SeqCst) {
            break Ok(());
        }
        let now = Instant::now();
        if saw_byte {
            if let Some(deadline) = request_deadline {
                if now >= deadline {
                    guard.record_request_timeout();
                    write_named(&mut writer, REASON_REQUEST_TIMEOUT);
                    log_refuse(REASON_REQUEST_TIMEOUT, addr, &guard);
                    break Ok(());
                }
            }
        }
        if !completed_any && now >= conn_deadline {
            guard.record_connection_timeout();
            write_named(&mut writer, REASON_CONNECTION_TIMEOUT);
            log_refuse(REASON_CONNECTION_TIMEOUT, addr, &guard);
            break Ok(());
        }

        match reader.fill_buf() {
            Ok([]) => break Ok(()),
            Ok(data) => {
                if data.is_empty() {
                    break Ok(());
                }
                if !saw_byte {
                    saw_byte = true;
                    request_deadline = Some(Instant::now() + limits.request_timeout);
                }
                if let Some(i) = data.iter().position(|&b| b == b'\n') {
                    let n = i + 1;
                    if buf.len() + n > limits.max_line_bytes {
                        reader.consume(n);
                        guard.record_line_too_long();
                        write_named(&mut writer, REASON_LINE_TOO_LONG);
                        log_refuse(REASON_LINE_TOO_LONG, addr, &guard);
                        break Ok(());
                    }
                    buf.extend_from_slice(&data[..n]);
                    reader.consume(n);
                    let line = match String::from_utf8(std::mem::take(&mut buf)) {
                        Ok(s) => s,
                        Err(_) => {
                            let resp = StratumResponse::err(
                                0,
                                ERR_INVALID,
                                "line is not utf-8".to_string(),
                            );
                            let _ = write_out(&mut writer, Outgoing::Reply(resp));
                            break Ok(());
                        }
                    };
                    match pool.handle_line(&mut session, &line) {
                        Ok(out) => {
                            sync_registration(&pool, &outbox, &session, &mut registered);
                            for item in out {
                                write_out(&mut writer, item)?;
                            }
                            if !drain_outbox(&mut writer, &outbox, registered.as_deref())? {
                                break Ok(());
                            }
                        }
                        Err(e) => {
                            let resp = StratumResponse::err(0, ERR_INVALID, e.to_string());
                            write_out(&mut writer, Outgoing::Reply(resp))?;
                        }
                    }
                    completed_any = true;
                    saw_byte = false;
                    request_deadline = None;
                    buf.clear();
                } else {
                    let n = data.len();
                    if buf.len() + n > limits.max_line_bytes {
                        reader.consume(n);
                        guard.record_line_too_long();
                        write_named(&mut writer, REASON_LINE_TOO_LONG);
                        log_refuse(REASON_LINE_TOO_LONG, addr, &guard);
                        break Ok(());
                    }
                    buf.extend_from_slice(data);
                    reader.consume(n);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !drain_outbox(&mut writer, &outbox, registered.as_deref())? {
                    break Ok(());
                }
            }
            Err(e) => break Err(e),
        }
    };
    if let Some(sid) = registered.take() {
        outbox.unregister(&sid);
        pool.drop_session(&sid);
    }
    result
}

fn log_refuse(reason: &str, addr: SocketAddr, guard: &ConnGuard) {
    let snap = guard.snapshot();
    qlab_devnet::jeprintln!(
        WARN,
        "qumbra-pool refuse reason={reason} addr={addr} cap={} per_ip_cap={} {}",
        guard.limits().max_connections,
        guard.limits().max_connections_per_ip,
        snap.journal_fields()
    );
}

fn write_named(w: &mut TcpStream, reason: &str) {
    let resp = StratumResponse::err(0, ERR_INVALID, reason.to_string());
    let _ = write_out(w, Outgoing::Reply(resp));
}

fn sync_registration(
    pool: &Pool,
    outbox: &JobOutbox,
    session: &Option<String>,
    registered: &mut Option<String>,
) {
    if session.as_deref() == registered.as_deref() {
        return;
    }
    if let Some(old) = registered.take() {
        outbox.unregister(&old);
        pool.drop_session(&old);
    }
    if let Some(sid) = session.as_ref() {
        outbox.register(sid.clone());
        *registered = Some(sid.clone());
    }
}

/// Drain this session's outbox slot. A suspended session stays registered;
/// `Ok(false)` is reserved for a terminal refusal or sustained outage.
fn drain_outbox(
    writer: &mut TcpStream,
    outbox: &JobOutbox,
    sid: Option<&str>,
) -> std::io::Result<bool> {
    let Some(sid) = sid else {
        return Ok(true);
    };
    match outbox.take(sid) {
        Some(SessionPush::Job(job)) => {
            let req = job_notification(&job).map_err(std::io::Error::other)?;
            write_out(writer, Outgoing::Notify(req))?;
            Ok(true)
        }
        Some(SessionPush::Suspended(reason)) => {
            write_out(
                writer,
                Outgoing::Reply(StratumResponse::err(0, ERR_INVALID, reason)),
            )?;
            Ok(true)
        }
        Some(SessionPush::Unavailable(reason)) => {
            write_out(
                writer,
                Outgoing::Reply(StratumResponse::err(0, ERR_INVALID, reason)),
            )?;
            Ok(false)
        }
        None => Ok(true),
    }
}

fn write_out(w: &mut TcpStream, item: Outgoing) -> std::io::Result<()> {
    let bytes = match item {
        Outgoing::Reply(resp) => encode_response(&resp).map_err(std::io::Error::other)?,
        Outgoing::Notify(req) => encode_request(&req).map_err(std::io::Error::other)?,
    };
    w.write_all(bytes.as_bytes())?;
    w.flush()
}

/// Encode a job as a stratum notification line (endpoint / tests).
pub fn encode_job_notify(job: &qlab_stratum::types::Job) -> Result<String, std::io::Error> {
    let req = job_notification(job).map_err(std::io::Error::other)?;
    encode_request(&req).map_err(std::io::Error::other)
}
